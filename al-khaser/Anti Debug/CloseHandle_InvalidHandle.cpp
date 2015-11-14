#include <Windows.h>
#include <tchar.h>

 /* 
 APIs making user of the ZwClose syscall (such as CloseHandle, indirectly) 
 can be used to detect a debugger. When a process is debugged, calling ZwClose 
 with an invalid handle will generate a STATUS_INVALID_HANDLE (0xC0000008) exception.
 As with all anti-debugs that rely on information made directly available.
*/

LONG WINAPI MyVectorExceptionFilter(PEXCEPTION_POINTERS p)
{
	_tprintf(_T("in my vectored exxc handler\r\n"));
	return EXCEPTION_CONTINUE_SEARCH;
}

BOOL NtClose_InvalideHandle()
{
	// Function Pointer Typedef for NtClose
	typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);

	// We have to import the function
	pNtClose NtClose_ = NULL;

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}

	NtClose_ = (pNtClose)GetProcAddress(hNtdll, "NtClose");
	if (NtClose_ == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	__try {
		// Time to finally make the call
		NtClose_((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;

}

BOOL CloseHandle_InvalideHandle()
{

	AddVectoredExceptionHandler(1, MyVectorExceptionFilter);

	/* Let's try first with user mode API: CloseHandle*/
	__try {
		CloseHandle((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	/* Direct call to NtClose to bypass user mode hooks */
	if (NtClose_InvalideHandle())
		return TRUE;
	else
		return FALSE;
}

