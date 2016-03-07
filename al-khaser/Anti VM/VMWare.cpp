#include "VMWare.h"

/*
Check against VMWare registry key values
*/
VOID vmware_reg_key_value()
{
	/* Array of strings of blacklisted registry key values */
	TCHAR *szEntries[][3] = {
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
	};

	WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

	for (int i = 0; i < dwLength; i++)
	{
		_tprintf(_T("[*] Checking reg key %s:"), szEntries[i][0]);
		if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			print_detected();
		else
			print_not_detected();
	}
}


/*
Check against VMWre registry keys
*/
VOID vmware_reg_keys()
{
	/* Array of strings of blacklisted registry keys */
	TCHAR* szKeys[] = {
		_T("SOFTWARE\\VMware, Inc.\\VMware Tools"),
	};

	WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	/* Check one by one */
	for (int i = 0; i < dwlength; i++)
	{
		_tprintf(TEXT("[*] Checking reg key %s: "), szKeys[i]);
		if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, szKeys[i]))
			print_detected();
		else
			print_not_detected();
	}
}
