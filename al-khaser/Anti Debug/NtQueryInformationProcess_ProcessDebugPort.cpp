#include "stdafx.h"

#include "NtQueryInformationProcess_ProcessDebugPort.h"

/* 
Instead of calling CheckRemoteDebuggerPresent an individual could also make directly the call to
NtQueryInformationProcess process theirself.
*/

BOOL NtQueryInformationProcess_ProcessDebugPort ()
{
	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;
 
	// ProcessDebugPort
	const int ProcessDbgPort = 7;
 
	// Other Vars
	NTSTATUS Status;
	
#if defined (ENV64BIT)
	DWORD dProcessInformationLength = sizeof(ULONG) * 2;
	DWORD64 IsRemotePresent = 0;

#elif defined(ENV32BIT)
	DWORD dProcessInformationLength = sizeof(ULONG);
	DWORD32 IsRemotePresent = 0;
#endif

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}
 
	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	// Sanity check although there's no reason for it to have failed
	if (NtQueryInfoProcess == NULL)
		return 0;
 
	// Time to finally make the call
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDbgPort, &IsRemotePresent, dProcessInformationLength, NULL);
	if(Status == 0x00000000 && IsRemotePresent != 0)
		return TRUE;
	else 
		return FALSE;
}

