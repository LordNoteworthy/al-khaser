#include "NtQueryInformationProcess_ProcessDbgPort.h"

/* I
nstead of calling CheckRemoteDebuggerPresent an individual could also make directly the call to
NtQueryInformationProcess process theirself.
*/

BOOL NtQueryInformationProcess_ProcessDbgPort ()
{
	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);

	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;
 
	// ProcessDebugPort
	const int ProcessDbgPort = 7;
 
	// Other Vars
	NTSTATUS Status;
	DWORD IsRemotePresent = NULL;
 
	HMODULE hNtdll = LoadLibrary(TEXT("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if(NtQueryInfoProcess == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}
 
	// Time to finally make the call
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDbgPort, &IsRemotePresent, sizeof(ULONG), NULL);
	if(Status == 0x00000000 && IsRemotePresent != 0)
		return TRUE;
	else 
		return FALSE;
}

