#include "NtSetInformationThread_ThreadHideFromDebugger.h"

/*
Calling NtSetInformationThread will attempt with ThreadInformationClass set to  x11 (ThreadHideFromDebugger)
to hide a thread from the debugger, Passing NULL for hThread will cause the function to hide the thread the
function is running in. Also, the function returns false on failure and true on success. When  the  function
is called, the thread will continue  to run but a debugger will no longer receive any events related to that thread.
*/

BOOL NtSetInformationThread_ThreadHideFromDebugger()
{
	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);

	// ThreadHideFromDebugger
	const int ThreadHideFromDebugger =  0x11;

	// We have to import the function
	pNtSetInformationThread NtSetInformationThread = NULL;

	// Other Vars
	NTSTATUS Status;
	BOOL IsBeingDebug = FALSE;

	HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
	if(hNtDll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
    NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");
	
	if(NtSetInformationThread == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	 // Time to finally make the call
	Status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
    
	if(Status)
		IsBeingDebug = TRUE;

return IsBeingDebug;
}