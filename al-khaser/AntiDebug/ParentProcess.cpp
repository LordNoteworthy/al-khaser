#include "pch.h"
#include "ParentProcess.h"

DWORD GetExplorerPIDbyShellWindow()
{
	DWORD dwProcessId = 0;

	// Get the PID of explorer by its windows handle
	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);

	return dwProcessId;
}

DWORD GetParentProcessId()
{
	auto NtQueryInfoProcess = static_cast<pNtQueryInformationProcess>(API::GetAPI(API_IDENTIFIER::API_NtQueryInformationProcess));

	// Some locals
	NTSTATUS Status = 0;
	ALK_PROCESS_BASIC_INFORMATION pbi;
	SecureZeroMemory(&pbi, sizeof(ALK_PROCESS_BASIC_INFORMATION));

	// Now we can call NtQueryInformationProcess, the second param 0 == ProcessBasicInformation
	Status = NtQueryInfoProcess(GetCurrentProcess(), 0, (PVOID)&pbi, sizeof(ALK_PROCESS_BASIC_INFORMATION), 0);

	if (Status != 0x00000000)
		return 0;
	else
		return (DWORD)pbi.ParentProcessId;
}


BOOL IsParentExplorerExe()
{
	//NOTE this check is wank because you can use an alternative file manager
	DWORD dwExplorerProcessId = GetParentProcessId();
	if (dwExplorerProcessId != GetExplorerPIDbyShellWindow())
		return TRUE;
	else
		return FALSE;
}
