/* Synthetic Winsock sender/receiver. One process owns one TCP stream. */
#include <winsock2.h>
#include <windows.h>

static char buffer[65536];

static void sample(ULONGLONG bytes, ULONGLONG time) {
    char line[64], digits[20];
    ULONGLONG values[] = {bytes, time};
    unsigned used = 0;
    for (unsigned i = 0; i < 2; i++) {
        unsigned n = 0;
        do {
            digits[n++] = '0' + values[i] % 10;
            values[i] /= 10;
        } while (values[i]);
        while (n)
            line[used++] = digits[--n];
        line[used++] = i ? '\n' : ' ';
    }
    DWORD wrote;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), line, used, &wrote, NULL);
}

void mainCRTStartup(void) {
    char host[32], port[8], label[8], mode[8], gate[128];
    if (!GetEnvironmentVariableA("FG_TEST_HOST", host, sizeof(host)) ||
        !GetEnvironmentVariableA("FG_TEST_PORT", port, sizeof(port)) ||
        !GetEnvironmentVariableA("FG_TEST_LABEL", label, sizeof(label)) ||
        !GetEnvironmentVariableA("FG_TEST_MODE", mode, sizeof(mode)))
        ExitProcess(2);
    unsigned number = 0;
    for (unsigned i = 0; port[i] >= '0' && port[i] <= '9'; i++)
        number = number * 10 + port[i] - '0';
    WSADATA w;
    if (!number || number > 65535 || WSAStartup(0x202, &w))
        ExitProcess(3);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in remote;
    for (unsigned i = 0; i < sizeof(remote); i++)
        ((volatile char *)&remote)[i] = 0;
    remote.sin_family = AF_INET;
    remote.sin_port = htons((unsigned short)number);
    remote.sin_addr.s_addr = inet_addr(host);
    char hello[] = {label[0], '\n'};
    if (s == INVALID_SOCKET || connect(s, (struct sockaddr *)&remote, sizeof(remote)) ||
        send(s, hello, sizeof(hello), 0) != sizeof(hello))
        ExitProcess(4);
    ULONGLONG bytes = 0, last = GetTickCount64();
    sample(bytes, last);
    if (mode[0] == 'u' && GetEnvironmentVariableA("FG_TEST_GATE", gate, sizeof(gate))) {
        while (GetFileAttributesA(gate) == INVALID_FILE_ATTRIBUTES)
            Sleep(30);
    }
    ULONGLONG started = GetTickCount64();
    for (;;) {
        int n = mode[0] == 'u' ? send(s, buffer, sizeof(buffer), 0) : recv(s, buffer, sizeof(buffer), 0);
        if (n <= 0)
            ExitProcess(5);
        bytes += (unsigned)n;
        ULONGLONG now = GetTickCount64();
        if (mode[0] == 'u') {
            // Offer 80 Mbit/s per stream. It exceeds the test limiter budget
            // without flooding the emulated link during management reads.
            ULONGLONG due = started + bytes / 10000;
            if (due > now)
                Sleep((DWORD)(due - now));
        }
        if (now - last >= 200) {
            sample(bytes, now);
            last = now;
        }
    }
}
