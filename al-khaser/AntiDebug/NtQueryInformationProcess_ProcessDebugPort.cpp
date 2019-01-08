#include "pch.h"

#include "NtQueryInformationProcess_ProcessDebugPort.h"

/* 
Instead of calling CheckRemoteDebuggerPresent an individual could also make directly the call to
NtQueryInformationProcess process theirself.
*/

BOOL NtQueryInformationProcess_ProcessDebugPort ()
{
	auto NtQueryInfoProcess = static_cast<pNtQueryInformationProcess>(API::GetAPI(API_IDENTIFIER::API_NtQueryInformationProcess));
 
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

	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDbgPort, &IsRemotePresent, dProcessInformationLength, NULL);
	if(Status == 0x00000000 && IsRemotePresent != 0)
		return TRUE;
	else 
		return FALSE;
}

