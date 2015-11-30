#include "ParentProcess.h"

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	void* PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION;

DWORD GetExplorerPIDbyShellWindow()
{
	DWORD dwProcessId = 0;

	// Get the PID of explorer by its windows handle
	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);

	return dwProcessId;
}

DWORD GetParentProcessId()
{
	// Function Pointer Typedef for NtQueryInformationProcess
	typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	// We have to import the function
	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	// Some locals
	NTSTATUS Status = 0;
	PROCESS_BASIC_INFORMATION pbi;
	SecureZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

	// Get NtQueryInformationProcess
	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");

	// Sanity check although there's no reason for it to have failed
	if (NtQueryInfoProcess == 0)
		return 0;

	// Now we can call NtQueryInformationProcess, the second param 0 == ProcessBasicInformation
	Status = NtQueryInfoProcess(GetCurrentProcess(), 0, (void*)&pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);

	if (Status != 0x00000000)
		return 0;
	else
		return pbi.ParentProcessId;
}


BOOL IsParentExplorerExe()
{
	DWORD dwExplorerProcessId = GetParentProcessId();
	if (dwExplorerProcessId != GetExplorerPIDbyShellWindow())
		return TRUE;
	else
		return FALSE;
}