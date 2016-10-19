#include "NtYieldExecution.h"

/*
The ntdll function NtYieldExecution or its kernel32 equivalent SwitchToThread function allows the current
thread to offer to give up the rest of its time slice, and allow the next scheduled thread to
execute. If no threads are scheduled to execute (or when the system is busy in particular ways and will
not allow a switch to occur), then the ntdll NtYieldExecution() function returns the
STATUS_NO_YIELD_PERFORMED (0x40000024) status, which causes the kernel32 SwitchToThread() function to
return a zero. When an application is being debugged, the act of single-stepping through the
code causes debug events and often results in no yield being allowed. However, this is a hopelessly
unreliable method for detecting a debugger because it will also detect the presence of a thread that is running with high priority. 
*/


BOOL NtYieldExecutionAPI()
{
	//NOTE: this check is unreliable, don't actually use this in a real environment

	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS(WINAPI* pNtYieldExecution)();

	// We have to import the function
	pNtYieldExecution NtYieldExecution = NULL;

	// Other Vars
	HMODULE hNtdll;
	INT iDebugged = 0;

	hNtdll = LoadLibrary(_T("ntdll.dll"));

	if (hNtdll == NULL) {
		// somthing bad happened
	}


	NtYieldExecution = (pNtYieldExecution)GetProcAddress(hNtdll, "NtYieldExecution");
	if (NtYieldExecution == NULL)
	{
		/// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}


	for (int i = 0; i < 0x20; i++)
	{
		Sleep(0xf);

		if (NtYieldExecution() != STATUS_NO_YIELD_PERFORMED)
			iDebugged++;
	}

	if (iDebugged <= 3)
		return FALSE;
	else
		return TRUE;
	

}