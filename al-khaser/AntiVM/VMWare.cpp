#include "pch.h"

#include "VMWare.h"

/*
Check against VMWare registry key values
*/
VOID vmware_reg_key_value()
{
	/* Array of strings of blacklisted registry key values */
	const TCHAR *szEntries[][3] = {
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("SYSTEM\\ControlSet001\\Control\\SystemInformation"), _T("SystemManufacturer"), _T("VMWARE") },
		{ _T("SYSTEM\\ControlSet001\\Control\\SystemInformation"), _T("SystemProductName"), _T("VMWARE") },
	};

	WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

	for (int i = 0; i < dwLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key %s"), szEntries[i][0]);
		if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}



/*
Check against VMWare registry keys
*/
VOID vmware_reg_keys()
{
	/* Array of strings of blacklisted registry keys */
	const TCHAR* szKeys[] = {
		_T("SOFTWARE\\VMware, Inc.\\VMware Tools"),
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


/*
Check against VMWare blacklisted files
*/
VOID vmware_files()
{
	/* Array of strings of blacklisted paths */
	const TCHAR* szPaths[] = {
		_T("system32\\drivers\\vmmouse.sys"),
		_T("system32\\drivers\\vmhgfs.sys"),
		_T("system32\\drivers\\vm3dmp.sys"),
		_T("system32\\drivers\\vmci.sys"),
		_T("system32\\drivers\\vmhgfs.sys"),
		_T("system32\\drivers\\vmmemctl.sys"),
		_T("system32\\drivers\\vmmouse.sys"),
		_T("system32\\drivers\\vmrawdsk.sys"),
		_T("system32\\drivers\\vmusbmouse.sys"),
	};

	/* Getting Windows Directory */
	WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
	TCHAR szWinDir[MAX_PATH] = _T("");
	TCHAR szPath[MAX_PATH] = _T("");
	GetWindowsDirectory(szWinDir, MAX_PATH);

	/* Check one by one */
	for (int i = 0; i < dwlength; i++)
	{
		PathCombine(szPath, szWinDir, szPaths[i]);
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking file %s "), szPath);
		if (is_FileExists(szPath))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}

/*
Check against VMWare blacklisted directories
*/
BOOL vmware_dir()
{
	TCHAR szProgramFile[MAX_PATH];
	TCHAR szPath[MAX_PATH] = _T("");
	TCHAR szTarget[MAX_PATH] = _T("VMWare\\");

	if (IsWoW64())
		ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
	else
		SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombine(szPath, szProgramFile, szTarget);
	return is_DirectoryExists(szPath);
}


/*
Check VMWare NIC MAC addresses
*/
VOID vmware_mac()
{
	/* VMWre blacklisted mac adr */
	const TCHAR *szMac[][2] = {
		{ _T("\x00\x05\x69"), _T("00:05:69") }, // VMWare, Inc.
		{ _T("\x00\x0C\x29"), _T("00:0c:29") }, // VMWare, Inc.
		{ _T("\x00\x1C\x14"), _T("00:1C:14") }, // VMWare, Inc.
		{ _T("\x00\x50\x56"), _T("00:50:56") },	// VMWare, Inc.
	};

	WORD dwLength = sizeof(szMac) / sizeof(szMac[0]);

	/* Check one by one */
	for (int i = 0; i < dwLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking MAC starting with %s"), szMac[i][1]);
		if (check_mac_addr(szMac[i][0]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}


/*
Check against VMWare adapter name
*/
BOOL vmware_adapter_name()
{
	const TCHAR* szAdapterName = _T("VMWare");
	if (check_adapter_name(szAdapterName))
		return TRUE;
	else
		return FALSE;
}


/*
Check against VMWare pseaudo-devices
*/
VOID vmware_devices()
{
	const TCHAR *devices[] = {
		_T("\\\\.\\HGFS"),
		_T("\\\\.\\vmci"),
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking device %s "), devices[i]);
		
		if (hFile != INVALID_HANDLE_VALUE) {
			CloseHandle(hFile);
			print_results(TRUE, msg);
		}
		else
			print_results(FALSE, msg);
	}
}


/*
Check for process list
*/

VOID vmware_processes()
{
	const TCHAR *szProcesses[] = {
		_T("vmtoolsd.exe"),
		_T("vmwaretray.exe"),
		_T("vmwareuser.exe"),
		_T("VGAuthService.exe"),
		_T("vmacthlp.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking VWware process %s "), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}

/*
Check for SMBIOS firmware
*/
BOOL vmware_firmware_SMBIOS()
{
	BOOL result = FALSE;
	const DWORD Signature = static_cast<DWORD>('RSMB');

	DWORD smbiosSize = 0;
	PBYTE smbios = get_system_firmware(static_cast<DWORD>('RSMB'), 0x0000, &smbiosSize);
	if (smbios != NULL)
	{
		PBYTE vmwareString = (PBYTE)"VMware";
		size_t vmwwareStringLen = 6;

		if (find_str_in_data(vmwareString, vmwwareStringLen, smbios, smbiosSize))
		{
			result = TRUE;
		}

		free(smbios);
	}

	return result;
}

/*
Check for ACPI firmware
*/
BOOL vmware_firmware_ACPI()
{
	BOOL result = FALSE;

	PDWORD tableNames = static_cast<PDWORD>(malloc(4096));

	if (tableNames == NULL)
		return FALSE;

	SecureZeroMemory(tableNames, 4096);
	DWORD tableSize = enum_system_firmware_tables(static_cast<DWORD>('ACPI'), tableNames, 4096);

	// API not available
	if (tableSize == -1)
		return FALSE;

	DWORD tableCount = tableSize / 4;
	if (tableSize < 4 || tableCount == 0)
	{
		result = TRUE;
	}
	else
	{
		for (DWORD i = 0; i < tableCount; i++) {
			DWORD tableSize = 0;
			PBYTE table = get_system_firmware(static_cast<DWORD>('ACPI'), tableNames[i], &tableSize);

			if (table) {

				PBYTE vmwareString = (PBYTE)"VMWARE";
				size_t vmwwareStringLen = 6;

				if (find_str_in_data(vmwareString, vmwwareStringLen, table, tableSize)) {
					result = TRUE;
				}

				free(table);
			}
		}
	}

	free(tableNames);
	return result;
}

