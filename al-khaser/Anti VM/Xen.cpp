#include "Xen.h"

/*
Check for process list
*/

VOID xen_process()
{
	TCHAR *szProcesses[] = {
		_T("xenservice.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		_tprintf(TEXT("[*] Checking Citrix Xen process: %s"), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_detected();
		else
			print_not_detected();
	}
}
