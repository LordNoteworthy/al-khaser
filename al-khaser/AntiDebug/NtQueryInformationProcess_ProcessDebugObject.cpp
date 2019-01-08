#include "pch.h"

#include "NtQueryInformationProcess_ProcessDebugObject.h"

/*
This function uses NtQuerySystemInformation to try to retrieve a handle to the current process's debug object handle.
If the function is successful it'll return true which means we're being debugged or it'll return false if it fails
the process isn't being debugged
*/

BOOL NtQueryInformationProcess_ProcessDebugObject()
{
	// ProcessDebugFlags
	const int ProcessDebugObjectHandle =  0x1e;

	auto NtQueryInfoProcess = static_cast<pNtQueryInformationProcess>(API::GetAPI(API_IDENTIFIER::API_NtQueryInformationProcess));

	// Other Vars
	NTSTATUS Status;
	HANDLE hDebugObject = NULL; 

#if defined (ENV64BIT)
	DWORD dProcessInformationLength = sizeof(ULONG) * 2;
	DWORD64 IsRemotePresent = 0;

#elif defined(ENV32BIT)
	DWORD dProcessInformationLength = sizeof(ULONG);
	DWORD32 IsRemotePresent = 0;
#endif

	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, dProcessInformationLength, NULL);
    
	if (Status == 0x00000000 && hDebugObject)
        return TRUE;
    else
        return FALSE;
}
