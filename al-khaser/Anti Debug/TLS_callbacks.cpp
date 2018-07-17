#include "stdafx.h"

#include "TLS_callbacks.h"

// The Thread Local Storage (TLS) callback is called before the execution of the EntryPoint of the application
// Malware takes advantages to perform anti-debug and anti-vm checks.
// There could be more than one callback, and sometimes, inside one call back, one can create one in the fly.


volatile bool has_run = false;

VOID WINAPI tls_callback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (!has_run)
	{
		has_run = true;
		tls_callback_thread_event = CreateEvent(NULL, FALSE, FALSE, NULL);
		tls_callback_process_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	}

	if (dwReason == DLL_THREAD_ATTACH)
	{
		tls_callback_thread_data = 0xDEADBEEF;
		SetEvent(tls_callback_thread_event);
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		tls_callback_process_data = 0xDEADBEEF;
		SetEvent(tls_callback_process_event);
	}
}

BOOL TLSCallbackThread()
{
	const int BLOWN = 1000;

	int fuse = 0;
	while (tls_callback_thread_event == NULL && ++fuse != BLOWN) { SwitchToThread(); }
	if (fuse == BLOWN)
		return TRUE;

	if (WaitForSingleObject(tls_callback_thread_event, 2000) != WAIT_OBJECT_0)
		return TRUE;

	return tls_callback_thread_data == 0xDEADBEEF ? FALSE : TRUE;
}

BOOL TLSCallbackProcess()
{
	const int BLOWN = 1000;

	int fuse = 0;
	while (tls_callback_process_event == NULL && ++fuse != BLOWN) { SwitchToThread(); }
	if (fuse == BLOWN)
		return TRUE;

	if (WaitForSingleObject(tls_callback_process_event, 2000) != WAIT_OBJECT_0)
		return TRUE;

	return tls_callback_process_data == 0xDEADBEEF ? FALSE : TRUE;
}

#ifdef _WIN64
	#pragma comment (linker, "/INCLUDE:_tls_used")
	#pragma comment (linker, "/INCLUDE:tls_callback_func")
#else
	#pragma comment (linker, "/INCLUDE:__tls_used")
	#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#endif


#ifdef _WIN64
	#pragma const_seg(".CRT$XLF")
	EXTERN_C const
#else
	#pragma data_seg(".CRT$XLF")
	EXTERN_C
#endif

PIMAGE_TLS_CALLBACK tls_callback_func = tls_callback;

#ifdef _WIN64
	#pragma const_seg()
#else
	#pragma data_seg()
#endif //_WIN64
