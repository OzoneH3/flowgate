/* Many concurrent outgoing UDP sockets for Wine runtime-census saturation tests.
 * Each socket is opened by its own thread, so every first datagram needs a cold
 * ownership census. Payload: TOKEN|socket|sequence. No application names,
 * service addresses or prefix assumptions; the receiver port comes from the
 * environment and the destination is loopback.
 *
 * Trace markers: SATURATION_READY (all sockets open, waiting for the optional
 * FLOWGATE_TEST_GO barrier), SATURATION_BEGIN (released), SATURATION_SENT (every
 * worker finished its send loop, before the socket linger), one
 * "STATS socket attempted ok failed exit" line per socket, SATURATION_DONE.
 * Any setup failure is reported as SATURATION_ERROR and a non-zero exit. */
#include <winsock2.h>
#include <windows.h>
#define MAX_SOCKETS 64
static char token[96];
static unsigned port, datagrams = 20, interval = 50, count = 1;
static HANDLE go, sent_all;
static volatile LONG finished;
static SOCKET sockets[MAX_SOCKETS];
static unsigned attempted[MAX_SOCKETS], ok[MAX_SOCKETS], failed[MAX_SOCKETS];
static void say(const char *s) {
    DWORD n, len = 0; while (s[len]) len++;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s, len, &n, 0);
    char path[2048];
    if (GetEnvironmentVariableA("FLOWGATE_TEST_TRACE", path, sizeof(path))) {
        HANDLE f = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
        if (f != INVALID_HANDLE_VALUE) { WriteFile(f, s, len, &n, 0); CloseHandle(f); }
    }
}
static unsigned number(const char *name, unsigned fallback, unsigned max) {
    char text[16]; unsigned v = 0, i = 0;
    if (!GetEnvironmentVariableA(name, text, sizeof(text))) return fallback;
    for (; text[i] >= '0' && text[i] <= '9' && i < 6; i++) v = v * 10 + (unsigned)(text[i] - '0');
    return (i && v && v <= max) ? v : 0;
}
static unsigned append(char *out, unsigned at, unsigned v) {
    char tmp[12]; unsigned n = 0;
    do { tmp[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) out[at++] = tmp[--n];
    return at;
}
static void fail(const char *why, unsigned code) {
    say("SATURATION_ERROR "); say(why); say("\n"); ExitProcess(code);
}
static DWORD WINAPI client(void *arg) {
    unsigned index = (unsigned)(UINT_PTR)arg;
    SOCKET s = sockets[index];
    struct sockaddr_in a; for (unsigned i = 0; i < sizeof(a); i++) ((volatile char *)&a)[i] = 0;
    a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port); a.sin_addr.s_addr = htonl(0x7f000001);
    if (WaitForSingleObject(go, INFINITE) != WAIT_OBJECT_0) return 10;
    char msg[160]; unsigned base = 0;
    while (token[base]) { msg[base] = token[base]; base++; }
    msg[base++] = '|'; base = append(msg, base, index); msg[base++] = '|';
    for (unsigned seq = 0; seq < datagrams; seq++) {
        unsigned len = append(msg, base, seq);
        attempted[index]++;
        if (sendto(s, msg, (int)len, 0, (struct sockaddr *)&a, sizeof(a)) == (int)len) ok[index]++; else failed[index]++;
        Sleep(interval);
    }
    if (InterlockedIncrement(&finished) == (LONG)count) SetEvent(sent_all);
    Sleep(2000); closesocket(s); return 0;
}
void mainCRTStartup(void) {
    count = number("FLOWGATE_TEST_SOCKETS", 1, MAX_SOCKETS);
    datagrams = number("FLOWGATE_TEST_DATAGRAMS", 20, 100000);
    interval = number("FLOWGATE_TEST_INTERVAL_MS", 50, 10000);
    port = number("FLOWGATE_TEST_PORT", 0, 65535);
    if (!count || !datagrams || !interval || !port) fail("invalid numeric configuration", 2);
    if (!GetEnvironmentVariableA("FLOWGATE_TEST_TOKEN", token, sizeof(token))) fail("missing token", 2);
    WSADATA w; if (WSAStartup(0x202, &w)) fail("WSAStartup", 3);
    go = CreateEventA(0, TRUE, FALSE, 0); sent_all = CreateEventA(0, TRUE, FALSE, 0);
    if (!go || !sent_all) fail("CreateEvent", 4);
    /* Open every socket before READY, so the barrier releases sending only. */
    for (unsigned i = 0; i < count; i++) {
        sockets[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockets[i] == INVALID_SOCKET) fail("socket", 5);
    }
    HANDLE threads[MAX_SOCKETS];
    for (unsigned i = 0; i < count; i++) { threads[i] = CreateThread(0, 0, client, (void *)(UINT_PTR)i, 0, 0); if (!threads[i]) fail("CreateThread", 6); }
    say("SATURATION_READY\n");
    /* Optional start barrier so several separately launched processes burst together. */
    char gate[1024];
    if (GetEnvironmentVariableA("FLOWGATE_TEST_GO", gate, sizeof(gate))) {
        for (unsigned waited = 0; GetFileAttributesA(gate) == INVALID_FILE_ATTRIBUTES; waited += 20) {
            if (waited > 300000) fail("start barrier timeout", 7);
            Sleep(20);
        }
    } else Sleep(1500);
    say("SATURATION_BEGIN\n");
    SetEvent(go);
    if (WaitForSingleObject(sent_all, 600000) != WAIT_OBJECT_0) fail("send completion timeout", 8);
    say("SATURATION_SENT\n");
    if (WaitForMultipleObjects(count, threads, TRUE, 600000) != WAIT_OBJECT_0) fail("worker exit timeout", 9);
    unsigned bad = 0;
    for (unsigned i = 0; i < count; i++) {
        DWORD code = 99; if (!GetExitCodeThread(threads[i], &code)) code = 98;
        if (code) bad = 1;
        char line[96]; unsigned at = 0; const char *p = "STATS ";
        while (*p) line[at++] = *p++;
        at = append(line, at, i); line[at++] = ' ';
        at = append(line, at, attempted[i]); line[at++] = ' ';
        at = append(line, at, ok[i]); line[at++] = ' ';
        at = append(line, at, failed[i]); line[at++] = ' ';
        at = append(line, at, code); line[at++] = '\n'; line[at] = 0;
        say(line);
    }
    say("SATURATION_DONE\n");
    ExitProcess(bad ? 11 : 0);
}
