#include "timing.h"

VOID timing_Sleep()
{
	Sleep(5000);
}


VOID timing_SleepEx()
{
	SleepEx(5000, FALSE);
}

VOID timing_NtDelayexecution()
{
	// Function pointer Typedef for NtDelayExecution
	typedef NTSTATUS(WINAPI *pNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);

	// We have to import the function
	pNtDelayExecution NtDelayExecution = NULL;

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}

	NtDelayExecution = (pNtDelayExecution)GetProcAddress(hNtdll, "NtDelayExecution");
	if (NtDelayExecution == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	// Time to finally make the call
	NtDelayExecution(FALSE, (PLARGE_INTEGER)10000);

}