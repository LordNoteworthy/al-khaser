#include "VirtualPC.h"

/*
Check for process list
*/

VOID virtual_pc_process()
{
	TCHAR *szProcesses[] = {
		_T("VMSrvc.exe"),
		_T("VMUSrvc.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		_tprintf(TEXT("[*] Checking VirtualPC process: %s"), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_detected();
		else
			print_not_detected();
	}
}
