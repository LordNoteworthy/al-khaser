#include "NtQueryInformationProcess_ProcessDebugObject.h"

/*
This function uses NtQuerySystemInformation to try to retrieve a handle to the current process's debug object handle.
If the function is successful it'll return true which means we're being debugged or it'll return false if it fails
the process isn't being debugged
*/

BOOL NtQueryInformationProcess_ProcessDebugObject()
{

   	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);

	// ProcessDebugFlags
	const int ProcessDebugObjectHandle =  0x1e;

	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	// Other Vars
	NTSTATUS Status;
	HANDLE hDebugObject = NULL; 

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
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(DWORD), NULL);
    
	if (Status == 0x00000000 && hDebugObject)
        return TRUE;
    else
        return FALSE;
}