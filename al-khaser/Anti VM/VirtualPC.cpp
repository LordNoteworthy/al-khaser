#include "VirtualPC.h"

/*
Check for process list
*/

VOID virtual_pc_process()
{
	TCHAR *szProcesses[] = {
		_T("VMSrvc.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		_tprintf(TEXT("[*] Checking process of malware analysis tool: %s: "), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_detected();
		else
			print_not_detected();
	}
}
