#include "stdafx.h"
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
	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	// Some locals
	NTSTATUS Status = 0;
	ALK_PROCESS_BASIC_INFORMATION pbi;
	SecureZeroMemory(&pbi, sizeof(ALK_PROCESS_BASIC_INFORMATION));

	// Get NtQueryInformationProcess
	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");

	// Sanity check although there's no reason for it to have failed
	if (NtQueryInfoProcess == 0)
		return 0;

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
