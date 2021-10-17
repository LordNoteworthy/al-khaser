#include "pch.h"
#include "ParentProcess.h"

#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <experimental/filesystem>

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

	NTSTATUS Status = 0;
	ALK_PROCESS_BASIC_INFORMATION pbi;
	SecureZeroMemory(&pbi, sizeof(ALK_PROCESS_BASIC_INFORMATION));

	const UINT ProcessBasicInformation = 0;

	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessBasicInformation, (PVOID)&pbi, sizeof(ALK_PROCESS_BASIC_INFORMATION), 0);

	if (Status != 0)
	{
		return 0;
	}
	else
	{
		return (DWORD)pbi.ParentProcessId;
	}
}

BOOL IsParentExplorerExe()
{
	// this check will throw a false positive if you're running an alternative shell.

	DWORD parentPid = GetParentProcessId();

	bool parentPidEqualsExplorerPid = false;

	if (parentPid > 0)
	{
		// first check 
		HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
		if (hParent != INVALID_HANDLE_VALUE)
		{
			WCHAR winDir[MAX_PATH];
			WCHAR parentProcessPath[MAX_PATH];
			if (GetModuleFileNameExW(hParent, NULL, parentProcessPath, MAX_PATH) && GetWindowsDirectory(winDir, MAX_PATH))
			{
				CloseHandle(hParent);

				// get path to X:\Windows\explorer.exe
				auto expectedPath = std::experimental::filesystem::path(winDir);
				expectedPath = expectedPath.append("explorer.exe");

				// get path to parent process
				auto actualPath = std::experimental::filesystem::path(parentProcessPath);

				// if the paths are equivalent, no detection.
				return std::experimental::filesystem::equivalent(expectedPath, actualPath) ? FALSE : TRUE;
			}
			CloseHandle(hParent);
		}

		// if the first check couldn't be completed, fall back to the shell window approach.
		// this check is less ideal because it throws false positives if you have explorer process isolation enabled (i.e. one process per explorer window)
		DWORD explorerPid = GetExplorerPIDbyShellWindow();
		if (explorerPid > 0)
		{
			if (parentPid != explorerPid)
			{
				return TRUE;
			}
		}
	}

	return FALSE;
}
