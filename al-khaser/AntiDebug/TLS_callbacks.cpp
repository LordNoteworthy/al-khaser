#include "pch.h"

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
		OutputDebugString(L"TLS callback: thread attach");
		tls_callback_thread_data = 0xDEADBEEF;
		SetEvent(tls_callback_thread_event);
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		OutputDebugString(L"TLS callback: process attach");
		tls_callback_process_data = 0xDEADBEEF;
		SetEvent(tls_callback_process_event);
	}
}

DWORD WINAPI TLSCallbackDummyThread(
	_In_ LPVOID lpParameter
)
{
	OutputDebugString(L"TLS callback: dummy thread launched");
	return 0;
}

BOOL TLSCallbackThread()
{
	const int BLOWN = 1000;

	if (CreateThread(NULL, 0, &TLSCallbackDummyThread, NULL, 0, NULL) == NULL)
	{
		OutputDebugString(L"TLS callback: couldn't start dummy thread");
	}

	int fuse = 0;
	while (tls_callback_thread_event == NULL && ++fuse != BLOWN) { SwitchToThread(); }
	if (fuse >= BLOWN)
	{
		OutputDebugString(L"TLSCallbackThread timeout on event creation.");
		return TRUE;
	}

	DWORD waitStatus = WaitForSingleObject(tls_callback_thread_event, 5000);
	if (waitStatus != WAIT_OBJECT_0)
	{
		if (waitStatus == WAIT_FAILED)
			OutputDebugString(L"TLSCallbackThread wait failed.");
		else if (waitStatus == WAIT_ABANDONED)
			OutputDebugString(L"TLSCallbackThread wait abandoned.");
		else
			OutputDebugString(L"TLSCallbackThread timeout on event wait.");
		return TRUE;
	}

	if (tls_callback_thread_data != 0xDEADBEEF)
		OutputDebugString(L"TLSCallbackThread data did not match.");
	else
		OutputDebugString(L"All seems fine for TLSCallbackThread.");

	return tls_callback_thread_data == 0xDEADBEEF ? FALSE : TRUE;
}

BOOL TLSCallbackProcess()
{
	const int BLOWN = 1000;

	int fuse = 0;
	while (tls_callback_process_event == NULL && ++fuse != BLOWN) { SwitchToThread(); }
	if (fuse >= BLOWN)
	{
		OutputDebugString(L"TLSCallbackProcess timeout on event creation.");
		return TRUE;
	}

	DWORD waitStatus = WaitForSingleObject(tls_callback_process_event, 5000);
	if (waitStatus != WAIT_OBJECT_0)
	{
		if (waitStatus == WAIT_FAILED)
			OutputDebugString(L"TLSCallbackProcess wait failed.");
		else if (waitStatus == WAIT_ABANDONED)
			OutputDebugString(L"TLSCallbackProcess wait abandoned.");
		else
			OutputDebugString(L"TLSCallbackProcess timeout on event wait.");
		return TRUE;
	}

	if (tls_callback_process_data != 0xDEADBEEF)
		OutputDebugString(L"TLSCallbackProcess data did not match.");
	else
		OutputDebugString(L"All seems fine for TLSCallbackProcess.");

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
