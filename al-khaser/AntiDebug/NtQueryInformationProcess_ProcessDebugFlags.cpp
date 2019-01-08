#include "pch.h"

#include "NtQueryInformationProcess_ProcessDebugFlags.h"

/*
When NtQueryProcessInformation is called with the ProcessDebugFlags class, the function will return the inverse of EPROCESS->NoDebugInherit,
which means that if a debugger is present, then this function will return FALSE if the process is being debugged.
 */

BOOL NtQueryInformationProcess_ProcessDebugFlags()
{
   	// ProcessDebugFlags
	const int ProcessDebugFlags =  0x1f;

	auto NtQueryInfoProcess = static_cast<pNtQueryInformationProcess>(API::GetAPI(API_IDENTIFIER::API_NtQueryInformationProcess));

	// Other Vars
	NTSTATUS Status;
	DWORD NoDebugInherit = 0; 

	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD), NULL);
	if (Status == 0x00000000 && NoDebugInherit == 0)
		return TRUE;
	else        
		return FALSE;
}
