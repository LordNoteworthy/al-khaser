#include "pch.h"

#include "SeDebugPrivilege.h"

/*
If we're being debugged and the process has SeDebugPrivileges privileges then OpenProcess call will be successful.
This requires administrator privilege !
In Windows XP, Vista and 7, calling OpenProcess with PROCESS_ALL_ACCESS will fait even with SeDebugPrivilege enabled,
That's why I used PROCESS_QUERY_LIMITED_INFORMATION
*/


DWORD GetCsrssProcessId()
{
	if (API::IsAvailable(API_IDENTIFIER::API_CsrGetProcessId))
	{
		auto CsrGetProcessId = static_cast<pCsrGetId>(API::GetAPI(API_IDENTIFIER::API_CsrGetProcessId));

		return CsrGetProcessId();
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
