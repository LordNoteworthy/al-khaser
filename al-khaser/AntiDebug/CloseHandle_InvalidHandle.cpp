#include "pch.h"


 /* 
 APIs making user of the ZwClose syscall (such as CloseHandle, indirectly) 
 can be used to detect a debugger. When a process is debugged, calling ZwClose 
 with an invalid handle will generate a STATUS_INVALID_HANDLE (0xC0000008) exception.
 As with all anti-debugs that rely on information made directly available.
*/


BOOL NtClose_InvalideHandle()
{
	auto NtClose_ = static_cast<pNtClose>(API::GetAPI(API_IDENTIFIER::API_NtClose));

	__try {
		NtClose_(reinterpret_cast<HANDLE>(0x99999999ULL));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;

}

BOOL CloseHandle_InvalideHandle()
{
	// Let's try first with user mode API: CloseHandle
	__try {
		CloseHandle(reinterpret_cast<HANDLE>(0x99999999ULL));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	// Direct call to NtClose to bypass user mode hooks
	if (NtClose_InvalideHandle())
		return TRUE;
	else
		return FALSE;
}

