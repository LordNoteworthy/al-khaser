#include "pch.h"

#include "VirtualPC.h"

/*
Check for process list
*/

VOID virtual_pc_process()
{
	const TCHAR *szProcesses[] = {
		_T("VMSrvc.exe"),
		_T("VMUSrvc.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking Virtual PC processes %s "), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}



VOID virtual_pc_reg_keys()
{
	/* Array of strings of blacklisted registry keys */
	const TCHAR* szKeys[] = {
		_T("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"),
	};

	WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	/* Check one by one */
	for (int i = 0; i < dwlength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key %s "), szKeys[i]);
		if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, szKeys[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}
