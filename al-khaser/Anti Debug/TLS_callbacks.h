#include <Windows.h>
#include <tchar.h>

const int TLS_CALLBACK_OFS_THREAD_EVENT_HANDLE = 1;
const int TLS_CALLBACK_OFS_PROCESS_EVENT_HANDLE = 1;
const int TLS_CALLBACK_OFS_THREAD = 2;
const int TLS_CALLBACK_OFS_PROCESS = 3;
static volatile UINT64* tls_callback_data = NULL;

VOID WINAPI tls_callback(PVOID hModule, DWORD dwReason, PVOID pContext);
BOOL TLSCallbackThread();
BOOL TLSCallbackProcess();
