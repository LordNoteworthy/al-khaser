#include "VirtualPC.h"

/*
Check for process list
*/

VOID parallels_process()
{
	TCHAR *szProcesses[] = {
		_T("prl_cc.exe"),
		_T("prl_tools.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		_tprintf(TEXT("[*] Checking Parallels process: %s"), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_detected();
		else
			print_not_detected();
	}
}
