#include "stdafx.h"

#include "SeDebugPrivilege.h"

/*
If we're being debugged and the process has SeDebugPrivileges privileges then OpenProcess call will be successful.
This requires administrator privilege !
In Windows XP, Vista and 7, calling OpenProcess with PROCESS_ALL_ACCESS will fait even with SeDebugPrivilege enabled,
That's why I used PROCESS_QUERY_LIMITED_INFORMATION
*/


DWORD GetCsrssProcessId()
{
	// If Windows XP or Greater, use CsrGetProcessId() to get csrss PID
	if (IsWindowsXPOrGreater())
	{
		// Function Pointer Typedef for NtQueryInformationProcess
		typedef DWORD(NTAPI* pCsrGetId)(VOID);

		// Grab the export from NtDll
		pCsrGetId CsrGetProcessId = (pCsrGetId)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "CsrGetProcessId");

		if (CsrGetProcessId)
			return CsrGetProcessId();
		else
			return 0;
	}
	else
		return GetProcessIdFromName(_T("csrss.exe"));
}


BOOL CanOpenCsrss()
{
	 HANDLE hCsrss = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCsrssProcessId());
	 if (hCsrss != NULL)
	{
		CloseHandle(hCsrss);
		return TRUE;
	}
	else
		return FALSE;
}
