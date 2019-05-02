#include "pch.h"

#include "VirtualBox.h"

/*
Registry key values
*/
VOID vbox_reg_key_value()
{
	/* Array of strings of blacklisted registry key values */
	const TCHAR *szEntries[][3] = {
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("SystemBiosVersion"), _T("VBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("VideoBiosVersion"), _T("VIRTUALBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("SystemBiosDate"), _T("06/23/99") },
	};

	const WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

	for (auto i = 0; i < dwLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking reg key HARDWARE\\Description\\System - %s is set to %s"), szEntries[i][1], szEntries[i][2]);
		if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}


/*
Check against virtualbox registry keys
*/
VOID vbox_reg_keys()
{
	/* Array of strings of blacklisted registry keys */
	const TCHAR* szKeys[] = {
		_T("HARDWARE\\ACPI\\DSDT\\VBOX__"),
		_T("HARDWARE\\ACPI\\FADT\\VBOX__"),
		_T("HARDWARE\\ACPI\\RSDT\\VBOX__"),
		_T("SOFTWARE\\Oracle\\VirtualBox Guest Additions"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxGuest"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxMouse"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxService"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxSF"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxVideo")
	};

	const WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	/* Check one by one */
	for (auto i = 0; i < dwlength; i++)
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
Check against virtualbox blacklisted files
*/
VOID vbox_files()
{
	/* Array of strings of blacklisted paths */
	const TCHAR* szPaths[] = {
		_T("system32\\drivers\\VBoxMouse.sys"),
		_T("system32\\drivers\\VBoxGuest.sys"),
		_T("system32\\drivers\\VBoxSF.sys"),
		_T("system32\\drivers\\VBoxVideo.sys"),
		_T("system32\\vboxdisp.dll"),
		_T("system32\\vboxhook.dll"),
		_T("system32\\vboxmrxnp.dll"),
		_T("system32\\vboxogl.dll"),
		_T("system32\\vboxoglarrayspu.dll"),
		_T("system32\\vboxoglcrutil.dll"),
		_T("system32\\vboxoglerrorspu.dll"),
		_T("system32\\vboxoglfeedbackspu.dll"),
		_T("system32\\vboxoglpackspu.dll"),
		_T("system32\\vboxoglpassthroughspu.dll"),
		_T("system32\\vboxservice.exe"),
		_T("system32\\vboxtray.exe"),
		_T("system32\\VBoxControl.exe"),
	};

	/* Getting Windows Directory */
	const WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
	TCHAR szWinDir[MAX_PATH] = _T("");
	TCHAR szPath[MAX_PATH] = _T("");
	GetWindowsDirectory(szWinDir, MAX_PATH);

	/* Check one by one */
	for (auto i = 0; i < dwlength; i++)
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
Check against virtualbox blacklisted directories
*/
BOOL vbox_dir()
{
	TCHAR szProgramFile[MAX_PATH];
	TCHAR szPath[MAX_PATH] = _T("");
	TCHAR szTarget[MAX_PATH] = _T("oracle\\virtualbox guest additions\\");

	if (IsWoW64())
		ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
	else
		SHGetSpecialFolderPath(nullptr, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombine(szPath, szProgramFile, szTarget);
	return is_DirectoryExists(szPath);
}


/*
Check virtualbox NIC MAC address
*/
BOOL vbox_check_mac()
{
	// PCS Systemtechnik CmbH (VirtualBox)
	return check_mac_addr(_T("\x08\x00\x27"));
}


/*
Check against pseaudo-devices
*/
VOID vbox_devices()
{
	const TCHAR *devices[] = {
		_T("\\\\.\\VBoxMiniRdrDN"),
		_T("\\\\.\\VBoxGuest"),
		_T("\\\\.\\pipe\\VBoxMiniRdDN"),
		_T("\\\\.\\VBoxTrayIPC"),
		_T("\\\\.\\pipe\\VBoxTrayIPC")
	};

	const WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (auto i = 0; i < iLength; i++)
	{
		const auto hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
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
Check for Window class
*/
BOOL vbox_window_class()
{
	const auto hClass = FindWindow(_T("VBoxTrayToolWndClass"), nullptr);
	const auto hWindow = FindWindow(nullptr, _T("VBoxTrayToolWnd"));

	if (hClass || hWindow)
		return TRUE;
	return FALSE;
}


/*
Check for shared folders network profider
*/
BOOL vbox_network_share()
{
	TCHAR szProviderName[MAX_PATH] = _T("");
	DWORD lpBufferSize = MAX_PATH;

	if (WNetGetProviderName(WNNC_NET_RDR2SAMPLE, szProviderName, &lpBufferSize) == NO_ERROR)
	{
		if (StrCmpI(szProviderName, _T("VirtualBox Shared Folders")) == 0)
			return TRUE;
		return FALSE;
	}
	return FALSE;
}


/*
Check for process list
*/
VOID vbox_processes()
{
	const TCHAR *szProcesses[] = {
		_T("vboxservice.exe"),
		_T("vboxtray.exe")
	};

	const WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (auto i = 0; i < iLength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking VirtualBox process %s "), szProcesses[i]);
		if (GetProcessIdFromName(szProcesses[i]))
			print_results(TRUE, msg);
		else
			print_results(FALSE, msg);
	}
}


/*
Check vbox mac @ using WMI
*/
BOOL vbox_mac_wmi()
{
	IWbemServices *pSvc = nullptr;
	IWbemLocator *pLoc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	auto bFound = FALSE;

	// Init WMI
	auto bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_NetworkAdapterConfiguration"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = nullptr;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator)
			{
				auto hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("MACAddress"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL) {

						if (vtProp.vt | VT_BSTR == VT_BSTR) //TODO: V501 https://www.viva64.com/en/w/v501/ There are identical sub-expressions to the left and to the right of the '==' operator: VT_BSTR == VT_BSTR
						{
							// Do our comparison
							if (_tcsstr(vtProp.bstrVal, _T("08:00:27")) != nullptr) {
								bFound = TRUE;
							}
						}

						// release the current result object
						VariantClear(&vtProp);					
					}
				}
				pclsObj->Release();

				// break from while
				if (bFound)
					break;
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}


/*
Check vbox event log using WMI
*/
BOOL vbox_eventlogfile_wmi()
{
	IWbemServices *pSvc = nullptr;
	IWbemLocator *pLoc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	BOOL bFound = FALSE;

	const TCHAR *szVBoxSources[] = {
		_T("vboxvideo"),
		_T("VBoxVideoW8"),
		_T("VBoxWddm")
	};

	const USHORT MaxVBoxSources = _countof(szVBoxSources);

	// Init WMI
	BOOL bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_NTEventlogFile"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = nullptr;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator && !bFound)
			{
				HRESULT hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the FileName property
				hRes = pclsObj->Get(_T("FileName"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes) && (V_VT(&vtProp) != VT_NULL)) {

					if (vtProp.vt | VT_BSTR == VT_BSTR)
					{
						// Do our comparaison
						if (StrCmpI(vtProp.bstrVal, _T("System")) == 0) {

							// Now, grab the Source property
							VariantClear(&vtProp);
							hRes = pclsObj->Get(_T("Sources"), 0, &vtProp, nullptr, nullptr);

							// Get the number of elements of our SAFEARRAY
							const auto saSources = vtProp.parray;
							LONG* pVals;
							const auto hr = SafeArrayAccessData(saSources, reinterpret_cast<VOID**>(&pVals)); // direct access to SA memory
							if (SUCCEEDED(hr)) {
								LONG lowerBound, upperBound;
								SafeArrayGetLBound(saSources, 1, &lowerBound);
								SafeArrayGetUBound(saSources, 1, &upperBound);
								const LONG iLength = upperBound - lowerBound + 1;

								// Iteare over our array of BTSR
								TCHAR* bstrItem;
								for (LONG ix = 0; ix < iLength; ix++) {
									SafeArrayGetElement(saSources, &ix, static_cast<void *>(&bstrItem));

									for (UINT id = 0; id < MaxVBoxSources; id++) {
										if (_tcsicmp(bstrItem, szVBoxSources[id]) == 0)
										{
											bFound = TRUE;
											break;
										}
									}
									// break from upper level "for" on detection success
									if (bFound)
										break;
								}
								//unlock data
								SafeArrayUnaccessData(saSources);
							}
						}
					}
					
					// release the current result object
					VariantClear(&vtProp);
				}
				pclsObj->Release();
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();

		}
	}

	return bFound;
}


BOOL vbox_firmware_SMBIOS()
{
	auto result = FALSE;

	DWORD smbiosSize = 0;
	const auto smbios = get_system_firmware(static_cast<DWORD>('RSMB'), 0x0000, &smbiosSize);
	if (smbios != nullptr)
	{
		const PBYTE virtualBoxString = (PBYTE)"VirtualBox";
		const size_t virtualBoxStringLen = 10;
		const PBYTE vboxLowerString = (PBYTE)"vbox";
		const size_t vboxLowerStringLen = 4;
		const PBYTE vboxUpperString = (PBYTE)"VBOX";
		const size_t vboxUpperStringLen = 4;

		if (find_str_in_data(virtualBoxString, virtualBoxStringLen, smbios, smbiosSize) ||
			find_str_in_data(vboxLowerString, vboxLowerStringLen, smbios, smbiosSize) ||
			find_str_in_data(vboxUpperString, vboxUpperStringLen, smbios, smbiosSize))
		{
			result = TRUE;
		}

		free(smbios);
	}

	return result;
}


BOOL vbox_firmware_ACPI()
{
	auto result = FALSE;

	const auto tableNames = static_cast<PDWORD>(malloc(4096));

	if (tableNames == nullptr)
		return FALSE;

	SecureZeroMemory(tableNames, 4096);
	const DWORD tableSize = enum_system_firmware_tables(static_cast<DWORD>('ACPI'), tableNames, 4096);

	// API not available
	if (tableSize == -1)
		return FALSE;

	const auto tableCount = tableSize / 4;

	if (tableSize < 4 || tableCount == 0)
	{
		result = TRUE;
	}
	else
	{
		for (DWORD i = 0; i < tableCount; i++)
		{
			DWORD tableSize_ = 0;
			const auto table = get_system_firmware(static_cast<DWORD>('ACPI'), tableNames[i], &tableSize_);

			if (table) {
				const PBYTE virtualBoxString = (PBYTE)"VirtualBox";
				const size_t virtualBoxStringLen = 10;
				const PBYTE vboxLowerString = (PBYTE)"vbox";
				const size_t vboxLowerStringLen = 4;
				const PBYTE vboxUpperString = (PBYTE)"VBOX";
				const size_t vboxUpperStringLen = 4;

				if (find_str_in_data(virtualBoxString, virtualBoxStringLen, table, tableSize_) ||
					find_str_in_data(vboxLowerString, vboxLowerStringLen, table, tableSize_) ||
					find_str_in_data(vboxUpperString, vboxUpperStringLen, table, tableSize_))
				{
					result = TRUE;
				}

				free(table);
			}
		}
	}

	free(tableNames);
	return result;
}


/*
Check vbox devices using WMI
*/
BOOL vbox_pnpentity_pcideviceid_wmi()
{
	IWbemServices *pSvc = nullptr;
	IWbemLocator *pLoc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	BOOL bFound = FALSE;

	// Init WMI
	BOOL bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_PnPEntity"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = nullptr;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				HRESULT hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("DeviceId"), 0, &vtProp, nullptr, nullptr);

				if (SUCCEEDED(hRes)) {
					if (vtProp.vt == VT_BSTR) {

						// Do our comparaison
						if (_tcsstr(vtProp.bstrVal, _T("PCI\\VEN_80EE&DEV_CAFE")) != nullptr)
						{
							bFound = TRUE;
						}
					}
					VariantClear(&vtProp);
				}

				// release the current result object				
				pclsObj->Release();

				if (bFound)
					break;
			}

			// Cleanup
			pSvc->Release();
			pLoc->Release();
			pEnumerator->Release();
			CoUninitialize();
		}
	}

	return bFound;
}


/*
Check Win32_PnPEntity for known VirtualBox hardware
*/
BOOL vbox_pnpentity_controllers_wmi()
{
	IWbemServices *pSvc = nullptr;
	IWbemLocator *pLoc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	auto bFound = FALSE;

	// Init WMI
	BOOL bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_PnPEntity"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = nullptr;
			ULONG uReturn = 0;
			VARIANT vtProp;

			auto findCount = 0;
			const auto findThreshold = 3;

			// Iterate over our enumator
			while (pEnumerator)
			{
				HRESULT hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("Name"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL) {

						if (vtProp.vt | VT_BSTR == VT_BSTR)
						{
							// increment the find counter if this instance matches any of the known VBox hardware
							if (_tcsstr(vtProp.bstrVal, _T("82801FB")) != nullptr) {
								findCount++;
							}
							else if (_tcsstr(vtProp.bstrVal, _T("82441FX")) != nullptr) {
								findCount++;
							}
							else if (_tcsstr(vtProp.bstrVal, _T("82371SB")) != nullptr) {
								findCount++;
							}
							else if (_tcsstr(vtProp.bstrVal, _T("OpenHCD")) != nullptr) {
								findCount++;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}
				pclsObj->Release();
			}

			if (findCount >= findThreshold)
			{
				bFound = TRUE;
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}


/*
Check Win32_Bus to see if only ACPIBus_BUS_0, PCI_BUS_0, PNP_BUS_0 are present
*/
BOOL vbox_bus_wmi()
{
	IWbemServices *pSvc = nullptr;
	IWbemLocator *pLoc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	auto bFound = FALSE;

	// Init WMI
	BOOL bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_Bus"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = nullptr;
			ULONG uReturn = 0;
			VARIANT vtProp;

			auto count = 0;
			auto findCount = 0;
			const auto findThreshold = 3;

			// Iterate over our enumator
			while (pEnumerator)
			{
				HRESULT hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				count++;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("Name"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL)
					{
						if (vtProp.vt | VT_BSTR == VT_BSTR)
						{
							// increment the find counter if this is 
							if (_tcsstr(vtProp.bstrVal, _T("ACPIBus_BUS_0")) != nullptr) {
								findCount++;
							}
							else if (_tcsstr(vtProp.bstrVal, _T("PCI_BUS_0")) != nullptr) {
								findCount++;
							}
							else if (_tcsstr(vtProp.bstrVal, _T("PNP_BUS_0")) != nullptr) {
								findCount++;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}
				pclsObj->Release();
			}

			// check that there are 3 instances and they match the strings above
			if (count == findThreshold &&
				findCount == findThreshold)
			{
				bFound = TRUE;
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}


/*
Check Win32_BaseBoard
*/
BOOL vbox_baseboard_wmi()
{
	IWbemServices *pSvc = nullptr;
	IWbemLocator *pLoc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	auto bStatus = FALSE;
	HRESULT hRes;
	auto bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_BaseBoard"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = nullptr;
			ULONG uReturn = 0;
			VARIANT vtProp = { 0 };

			// Iterate over our enumator
			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Product property
				hRes = pclsObj->Get(_T("Product"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL) {

						if (vtProp.vt | VT_BSTR == VT_BSTR)
						{
							// Do our comparison
							if (_tcsstr(vtProp.bstrVal, _T("VirtualBox")) != nullptr) {
								bFound = TRUE;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}

				vtProp = { 0 };

				// Get the value of the Manufacturer property
				hRes = pclsObj->Get(_T("Manufacturer"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL) {

						if (vtProp.vt | VT_BSTR == VT_BSTR)
						{
							// Do our comparison
							if (_tcsstr(vtProp.bstrVal, _T("Oracle Corporation")) != nullptr) {
								bFound = TRUE;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}

				pclsObj->Release();

				// break from while
				if (bFound)
					break;
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}


/*
Check Win32_PnPDevice for VBOX entries
*/
BOOL vbox_pnpentity_vboxname_wmi()
{
	IWbemServices *pSvc = nullptr;
	IWbemLocator *pLoc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	auto bFound = FALSE;

	// Init WMI
	BOOL bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_PnPDevice"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = nullptr;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator)
			{
				HRESULT hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("Name"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL) {

						if (vtProp.vt | VT_BSTR == VT_BSTR)
						{
							// Do our comparison
							if (_tcsstr(vtProp.bstrVal, _T("VBOX")) != nullptr) {
								bFound = TRUE;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}

				// Get the value of the Caption property
				hRes = pclsObj->Get(_T("Caption"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL) {

						if (vtProp.vt | VT_BSTR == VT_BSTR)
						{
							// Do our comparison
							if (_tcsstr(vtProp.bstrVal, _T("VBOX")) != nullptr) {
								bFound = TRUE;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}

				// Get the value of the PNPDeviceID property
				hRes = pclsObj->Get(_T("PNPDeviceID"), 0, &vtProp, nullptr, nullptr);
				if (SUCCEEDED(hRes)) {

					if (V_VT(&vtProp) != VT_NULL) {

						if (vtProp.vt | VT_BSTR == VT_BSTR)
						{
							// Do our comparison
							if (_tcsstr(vtProp.bstrVal, _T("VEN_VBOX")) != nullptr) {
								bFound = TRUE;
							}
						}

						// release the current result object
						VariantClear(&vtProp);
					}
				}

				pclsObj->Release();

				// break from while
				if (bFound)
					break;
			}

			// Cleanup
			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}
