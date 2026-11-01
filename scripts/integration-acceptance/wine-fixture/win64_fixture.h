/* Minimal Win64 ABI declarations for this freestanding synthetic fixture.
 * No runtime library or system installation. The opaque WSADATA allocation is
 * deliberately larger than the API result; no fields are interpreted. */
#ifndef FG_FIXTURE_WIN64_H
#define FG_FIXTURE_WIN64_H
#define WINAPI
#define API __declspec(dllimport)
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned long long UINT_PTR;
typedef long long LONG_PTR;
typedef unsigned long long SOCKET;
typedef void *HANDLE;
typedef struct { DWORD dwLowDateTime,dwHighDateTime; } FILETIME;
typedef struct __declspec(align(8)) { char opaque[512]; } WSADATA;
struct in_addr { unsigned long s_addr; };
struct sockaddr { unsigned short sa_family; char sa_data[14]; };
struct sockaddr_in { short sin_family; unsigned short sin_port; struct in_addr sin_addr; char sin_zero[8]; };
_Static_assert(sizeof(DWORD)==4 && sizeof(UINT_PTR)==8 && sizeof(FILETIME)==8 && sizeof(struct sockaddr_in)==16,"Win64 ABI required");
#define INVALID_SOCKET ((SOCKET)-1)
#define INADDR_NONE ((unsigned long)-1)
#define INVALID_HANDLE_VALUE ((HANDLE)(LONG_PTR)-1)
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define INFINITE ((DWORD)-1)
#define AF_INET 2
#define SOCK_DGRAM 2
#define WAIT_OBJECT_0 0
#define TRUE 1
#define FALSE 0
#define FILE_APPEND_DATA 4
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define OPEN_ALWAYS 4
#define FILE_ATTRIBUTE_NORMAL 128
#define STD_OUTPUT_HANDLE ((DWORD)-11)
API DWORD GetEnvironmentVariableA(const char*,char*,DWORD);
API int WriteFile(HANDLE,const void*,DWORD,DWORD*,void*);
API HANDLE GetStdHandle(DWORD);
API HANDLE CreateFileA(const char*,DWORD,DWORD,void*,DWORD,DWORD,HANDLE);
API int CloseHandle(HANDLE);
API void ExitProcess(unsigned);
API void Sleep(DWORD);
API void GetSystemTimePreciseAsFileTime(FILETIME*);
API DWORD WaitForSingleObject(HANDLE,DWORD);
API DWORD WaitForMultipleObjects(DWORD,const HANDLE*,int,DWORD);
API HANDLE CreateEventA(void*,int,int,const char*);
API int SetEvent(HANDLE);
API HANDLE CreateThread(void*,UINT_PTR,DWORD(*)(void*),void*,DWORD,DWORD*);
API int GetExitCodeThread(HANDLE,DWORD*);
API DWORD GetFileAttributesA(const char*);
static LONG InterlockedIncrement(volatile LONG *x) { return __atomic_add_fetch(x,1,__ATOMIC_SEQ_CST); }
API int WSAStartup(unsigned short,WSADATA*);
API SOCKET socket(int,int,int);
API int sendto(SOCKET,const char*,int,int,const struct sockaddr*,int);
API int closesocket(SOCKET);
API int bind(SOCKET,const struct sockaddr*,int);
API int getsockname(SOCKET,struct sockaddr*,int*);
API unsigned short htons(unsigned short);
API unsigned short ntohs(unsigned short);
API unsigned long htonl(unsigned long);
API unsigned long inet_addr(const char*);
#endif
