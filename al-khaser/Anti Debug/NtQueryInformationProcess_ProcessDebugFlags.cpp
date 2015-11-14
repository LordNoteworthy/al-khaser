#include "NtQueryInformationProcess_ProcessDebugFlags.h"

/*
When NtQueryProcessInformation is called with the ProcessDebugFlags class, the function will return the inverse of EPROCESS->NoDebugInherit,
which means that if a debugger is present, then this function will return FALSE if the process is being debugged.
 */

BOOL NtQueryInformationProcess_ProcessDebugFlags()
{


   	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);
 
	// ProcessDebugFlags
	const int ProcessDebugFlags =  0x1f;

	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	// Other Vars
	NTSTATUS Status;
	DWORD NoDebugInherit = 0; 

	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	if(hNtDll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
    NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	
	if(NtQueryInfoProcess == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}
	
	// Time to finally make the call
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD), NULL);
	if (Status == 0x00000000 && NoDebugInherit == 0)
		return TRUE;
	else        
		return FALSE;
}