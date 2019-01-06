#include "pch.h"

#include "Parallels.h"

/*
Check for process list
*/

VOID parallels_process()
{
	const TCHAR *szProcesses[] = {
		_T("prl_cc.exe"),
		_T("prl_tools.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking Parallels processes: %s"), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}


/*
Check Parallels NIC MAC address
*/
BOOL parallels_check_mac()
{
	// Parallels, Inc. 
	return check_mac_addr(_T("\x00\x1C\x42"));
}
