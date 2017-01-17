#include "TLS_callbacks.h"

// The Thread Local Storage (TLS) callback is called before the execution of the EntryPoint of the application
// Malware takes advantages to perform anti-debug and anti-vm checks.
// Their could be more than one callback, and sometimes, inside one call back, one can create one in the fly.

VOID  WINAPI tls_callback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (dwReason == DLL_THREAD_ATTACH)
	{
		// This will be loaded in each DLL thread attach
		// MessageBox(0, _T("I am running from a TLS callbacks, did you see that?"), _T("DLL_THREAD_ATTACH"), 0);
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		MessageBox(0, _T("I am running from a TLS callbacks, did you see that?"), _T("DLL_PROCESS_ATTACH"), 0);
	}
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
