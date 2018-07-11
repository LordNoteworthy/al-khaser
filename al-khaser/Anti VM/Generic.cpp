#include "Generic.h"

/*
Check if the DLL is loaded in the context of the process
*/
VOID loaded_dlls()
{
	/* Some vars */
	HMODULE hDll;

	/* Array of strings of blacklisted dlls */
	TCHAR* szDlls[] = {
		_T("avghookx.dll"),		// AVG
		_T("avghooka.dll"),		// AVG
		_T("snxhk.dll"),		// Avast
		_T("sbiedll.dll"),		// Sandboxie
		_T("dbghelp.dll"),		// WindBG
		_T("api_log.dll"),		// iDefense Lab
		_T("dir_watch.dll"),	// iDefense Lab
		_T("pstorec.dll"),		// SunBelt Sandbox
		_T("vmcheck.dll"),		// Virtual PC
		_T("wpespy.dll"),		// WPE Pro

	};

	WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
	for (int i = 0; i < dwlength; i++)
	{
		TCHAR msg[256] = _T("");
		_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking if process loaded modules contains: %s "), szDlls[i]);

		/* Check if process loaded modules contains the blacklisted dll */
		hDll = GetModuleHandle(szDlls[i]);
		if (hDll == NULL)
			print_results(FALSE, msg);
		else
			print_results(TRUE, msg);
	}
}


/*
Number of Processors in VM
*/

BOOL NumberOfProcessors()
{
#if defined (ENV64BIT)
	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x60) + 0xB8);

#elif defined(ENV32BIT)
	PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64) ;

#endif

	if (*ulNumberProcessors < 2)
		return TRUE;
	else
		return FALSE;
}


/*
This trick  involves looking at pointers to critical operating system tables
that are typically relocated on a virtual machine. One such table is the
Interrupt Descriptor Table (IDT), which tells the system where various operating
system interrupt handlers are located in memory. On real machines, the IDT is
located lower in memory than it is on guest (i.e., virtual) machines
PS: Does not seem to work on newer version of VMWare Workstation (Tested on v12)
*/
BOOL idt_trick()
{
	UINT idt_base = get_idt_base();
	if ((idt_base >> 24) == 0xff) 
		return TRUE;

	else
		return FALSE;
}

/*
Same for Local Descriptor Table (LDT) 
*/
BOOL ldt_trick()
{
	UINT ldt_base = get_ldt_base();

	if (ldt_base == 0xdead0000) 
		return FALSE;
	else 
		return TRUE; // VMWare detected	
}


/*
Same for Global Descriptor Table (GDT)
*/
BOOL gdt_trick()
{
	UINT gdt_base = get_gdt_base();

	if ((gdt_base >> 24) == 0xff)
		return TRUE; // VMWare detected	

	else
		return FALSE;
}


/*
The instruction STR (Store Task Register) stores the selector segment of the TR
register (Task Register) in the specified operand (memory or other general purpose register).
All x86 processors can manage tasks in the same way as an operating system would do it.
That is, keeping the task state and recovering it when that task is executed again. All 
the states of a task are kept in its TSS; there is one TSS per task. How can we know which
is the TSS associated to the execution task? Using STR instruction, due to the fact that
the selector segment that was brought back points into the TSS of the present task.
In all the tests that were done, the value brought back by STR from within a virtual machine
was different to the obtained from a native system, so apparently, it can be used as a another
mechanism of a unique instruction in assembler to detect virtual machines.
*/
BOOL str_trick()
{
	UCHAR *mem = get_str_base();

	if ((mem[0] == 0x00) && (mem[1] == 0x40))
		return TRUE; // VMWare detected	
	else
		return FALSE;
}


/*
Check number of cores using WMI
*/
BOOL number_cores_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_Processor"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("NumberOfCores"), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					// Do our comparaison
					if (vtProp.uintVal < 2) {
						bFound = TRUE; break;
					}

					// release the current result object
					VariantClear(&vtProp);
					pclsObj->Release();
				}
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
Check hard disk size using WMI
*/
BOOL disk_size_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;
	UINT64 minHardDiskSize = (80ULL * (1024ULL * (1024ULL * (1024ULL))));

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));
	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_LogicalDisk"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			// Iterate over our enumator
			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("Size"), 0, &vtProp, NULL, 0);
				if (V_VT(&vtProp) != VT_NULL)
				{
					// convert disk size string to bytes
					errno = 0;
					unsigned long long diskSizeBytes = _tcstoui64_l(vtProp.bstrVal, NULL, 10, _get_current_locale());
					// do the check only if we successfuly got the disk size
					if (errno == 0)
					{
						// Do our comparison
						if (diskSizeBytes < minHardDiskSize) { // Less than 80GB
							bFound = TRUE;
							break;
						}
					}

					// release the current result object
					VariantClear(&vtProp);
					pclsObj->Release();
				}
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
DeviceIoControl works with disks directly rather than partitions (GetDiskFreeSpaceEx)
We can send IOCTL_DISK_GET_LENGTH_INFO code to get the raw byte size of the physical disk
*/
BOOL dizk_size_deviceiocontrol()
{
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	GET_LENGTH_INFORMATION size = { 0 };
	DWORD lpBytesReturned = 0;
	LONGLONG minHardDiskSize = (80LL * (1024LL * (1024LL * (1024LL))));
	LARGE_INTEGER totalDiskSize;
	totalDiskSize.QuadPart = 0LL;

	// This technique requires admin priviliege starting from Windows Vista
	if (!IsElevated() && IsWindowsVistaOrGreater())
		return FALSE;

	// This code tries to get the physical disk(s) associated with the drive that Windows is on.
	// This is not always C:\ or PhysicalDrive0 so we need to do some work to account for multi-disk volumes.
	// By default we fall back to PhysicalDrive0 if any of this fails.

	bool defaultToDrive0 = true;

	// get the Windows system directory
	wchar_t winDirBuffer[MAX_PATH];
	SecureZeroMemory(winDirBuffer, MAX_PATH);
	UINT winDirLen = GetSystemWindowsDirectory(winDirBuffer, MAX_PATH);
	if (winDirLen != 0)
	{
		// get the drive number (0-25 for A-Z) associated with the directory
		int driveNumber = PathGetDriveNumber(winDirBuffer);
		if (driveNumber >= 0)
		{
			// convert the drive number to a root path (e.g. C:\)
			wchar_t driveRootPathBuffer[MAX_PATH];
			SecureZeroMemory(driveRootPathBuffer, MAX_PATH);
			wchar_t* rootPath = PathBuildRoot(driveRootPathBuffer, driveNumber);
			if (rootPath != NULL)
			{
				// open a handle to the drive
				HANDLE hDrive = CreateFile(
					rootPath,
					GENERIC_READ,
					FILE_SHARE_READ,
					NULL,
					OPEN_EXISTING,
					0,
					NULL
				);
				if (hDrive != INVALID_HANDLE_VALUE)
				{
					// allocate enough space to describe a 256-disk array
					// it would be weird to have more!
					const int extentSize = sizeof(VOLUME_DISK_EXTENTS) + (sizeof(DISK_EXTENT) * 256);
					auto diskExtents = static_cast<VOLUME_DISK_EXTENTS*>(malloc(extentSize));
					DWORD sizeResult;
					BOOL extentsIoctlOK = DeviceIoControl(
						hDevice,
						IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
						NULL,
						0,
						&diskExtents,
						sizeof(diskExtents),
						&sizeResult,
						NULL
					);
					
					if (extentsIoctlOK && diskExtents->NumberOfDiskExtents > 0)
					{
						// loop through disks associated with this drive
						// we want to sum the disk
						wchar_t physicalPathBuffer[MAX_PATH];
						for (DWORD i = 0; i < diskExtents->NumberOfDiskExtents; i++)
						{
							if (wnsprintf(physicalPathBuffer, MAX_PATH, _T("\\\\.\\PhysicalDrive%d"), diskExtents->Extents[i].DiskNumber) <= 0)
							{
								// open the physical disk
								hDevice = CreateFile(
									physicalPathBuffer,
									GENERIC_READ,
									FILE_SHARE_READ,
									NULL,
									OPEN_EXISTING,
									0,
									NULL);

								if (hDevice != INVALID_HANDLE_VALUE)
								{
									// fetch the size info
									bResult = DeviceIoControl(
										hDevice,					// device to be queried
										IOCTL_DISK_GET_LENGTH_INFO, // operation to perform
										NULL, 0,					// no input buffer
										&size, sizeof(GET_LENGTH_INFORMATION),
										&lpBytesReturned,			// bytes returned
										(LPOVERLAPPED)NULL);   // synchronous I/O

									if (bResult)
									{
										// add size :)
										totalDiskSize.QuadPart += size.Length.QuadPart;
										// we've been successful so far, so let's say it's fine
										defaultToDrive0 = false;
									}
									else
									{
										// failed IOCTL call
										defaultToDrive0 = true;
										break;
									}

									CloseHandle(hDevice);
								}
								else
								{
									// failed to open the drive
									defaultToDrive0 = true;
									break;
								}
							}
							else
							{
								// failed to construct the path string for some reason
								defaultToDrive0 = true;
								break;
							}
						}
					}

					CloseHandle(hDrive);
				}
			}
		}
	}

	// for some reason we couldn't enumerate the disks associated with the system drive
	// so we'll just check PhysicalDrive0 as a backup
	if (defaultToDrive0)
	{
		hDevice = CreateFile(_T("\\\\.\\PhysicalDrive0"),
			GENERIC_READ,               // no access to the drive
			FILE_SHARE_READ, 			// share mode
			NULL,						// default security attributes
			OPEN_EXISTING,				// disposition
			0,							// file attributes
			NULL);						// do not copy file attributes

		if (hDevice == INVALID_HANDLE_VALUE) {
			CloseHandle(hDevice);
			return FALSE;
		}

		bResult = DeviceIoControl(
			hDevice,					// device to be queried
			IOCTL_DISK_GET_LENGTH_INFO, // operation to perform
			NULL, 0,					// no input buffer
			&size, sizeof(GET_LENGTH_INFORMATION),
			&lpBytesReturned,			// bytes returned
			(LPOVERLAPPED) NULL);   // synchronous I/O

		if (bResult != NULL)
		{
			totalDiskSize.QuadPart = size.Length.QuadPart;
		}
	}

	if (totalDiskSize.QuadPart < minHardDiskSize) // 80GB
		bResult = TRUE;
	else
		bResult = FALSE;

	CloseHandle(hDevice);
	return bResult;
}


BOOL setupdi_diskdrive()
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD i;
	BOOL bFound = FALSE;

	// Create a HDEVINFO with all present devices.
	hDevInfo = SetupDiGetClassDevs((LPGUID)&GUID_DEVCLASS_DISKDRIVE,
		0, // Enumerator
		0,
		DIGCF_PRESENT);

	if (hDevInfo == INVALID_HANDLE_VALUE)
		return FALSE;

	// Enumerate through all devices in Set.
	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	/* Init some vars */
	DWORD dwPropertyRegDataType;
	LPTSTR buffer = NULL;
	DWORD dwSize = 0;

	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++)
	{
		while (!SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_HARDWAREID,
			&dwPropertyRegDataType, (PBYTE)buffer, dwSize, &dwSize))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				// Change the buffer size.
				if (buffer)LocalFree(buffer);
				// Double the size to avoid problems on 
				// W2k MBCS systems per KB 888609. 
				buffer = (LPTSTR)LocalAlloc(LPTR, dwSize * 2);
			}
			else
				break;

		}

		// Do our comparaison
		if ((StrStrI(buffer, _T("vbox")) != NULL) ||
			(StrStrI(buffer, _T("vmware")) != NULL) || 
			(StrStrI(buffer, _T("qemu")) != NULL) ||
			(StrStrI(buffer, _T("virtual")) != NULL))
		{
			bFound =  TRUE;
			break;
		}
	}

	if (buffer)
		LocalFree(buffer);

	if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS)
		return FALSE;

	//  Cleanup
	SetupDiDestroyDeviceInfoList(hDevInfo);

	if (bFound)
		return TRUE;

	else
		return FALSE;
}


BOOL ata_identify() {

	// this check requires admin privs
	if (!IsElevated())
		return FALSE;
	
	HANDLE hDevice = CreateFile(_T("\\\\.\\PhysicalDrive0"),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		OutputDebugString(_T("Couldn't open PhysicalDrive0."));
		return FALSE;
	}

	ATA_IDENTITY_BUFFER identityBuffer;
	SecureZeroMemory(&identityBuffer, sizeof(ATA_IDENTITY_BUFFER));

	identityBuffer.Request.AtaFlags = ATA_FLAGS_DATA_IN | ATA_FLAGS_DRDY_REQUIRED;
	identityBuffer.Request.Length = sizeof(ATA_PASS_THROUGH_EX);
	identityBuffer.Request.DataBufferOffset = offsetof(ATA_IDENTITY_BUFFER, Response);
	identityBuffer.Request.DataTransferLength = sizeof(IDENTIFY_DEVICE_DATA);
	identityBuffer.Request.TimeOutValue = 2;
	identityBuffer.Request.CurrentTaskFile[6] = ID_CMD;

	ULONG bytesRead;
	if (!DeviceIoControl(
		hDevice,
		IOCTL_ATA_PASS_THROUGH,
		&identityBuffer, sizeof(ATA_IDENTITY_BUFFER),
		&identityBuffer, sizeof(ATA_IDENTITY_BUFFER),
		&bytesRead, NULL))
	{
		OutputDebugString(_T("IDENTIFY IOCTL failed."));
		return FALSE;
	}

	OutputDebugString(_T("Successfully executed IDENTIFY command."));

	//SwapStringEndianA((char*)&identityBuffer.Response, sizeof(IDENTIFY_DEVICE_DATA));
	SwapStringEndianA((char*)identityBuffer.Response.ModelNumber, 40);
	SwapStringEndianA((char*)identityBuffer.Response.SerialNumber, 20);
	SwapStringEndianA((char*)identityBuffer.Response.FirmwareRevision, 8);

//#ifdef _DEBUG
	const int infoBufferLen = 4096;
	wchar_t* infoBuffer = reinterpret_cast<wchar_t*>(calloc(infoBufferLen, sizeof(wchar_t)));
	SecureZeroMemory(infoBuffer, sizeof(wchar_t) * infoBufferLen);
	wnsprintf(infoBuffer, infoBufferLen, _T("Model: %.40S"), identityBuffer.Response.ModelNumber);
	OutputDebugString(infoBuffer);
	SecureZeroMemory(infoBuffer, sizeof(wchar_t) * infoBufferLen);
	wnsprintf(infoBuffer, infoBufferLen, _T("Serial: %.20S"), identityBuffer.Response.SerialNumber);
	OutputDebugString(infoBuffer);
	SecureZeroMemory(infoBuffer, sizeof(wchar_t) * infoBufferLen);
	wnsprintf(infoBuffer, infoBufferLen, _T("Firmware: %.8S"), identityBuffer.Response.FirmwareRevision);
	OutputDebugString(infoBuffer);
	SecureZeroMemory(infoBuffer, sizeof(wchar_t) * infoBufferLen);
	wnsprintf(infoBuffer, infoBufferLen, _T("Sectors/track: %hu"), identityBuffer.Response.NumSectorsPerTrack);
	OutputDebugString(infoBuffer);
//#endif

	dump_response(identityBuffer);


	return FALSE;
}

VOID dump_response(ATA_IDENTITY_BUFFER identityBuffer)
{
	const int dbglen = 4096;
	wchar_t* dbg = reinterpret_cast<wchar_t*>(calloc(dbglen, sizeof(wchar_t)));

	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.Reserved1 = %hu"), identityBuffer.Response.GeneralConfiguration.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.Retired3 = %hu"), identityBuffer.Response.GeneralConfiguration.Retired3);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.ResponseIncomplete = %hu"), identityBuffer.Response.GeneralConfiguration.ResponseIncomplete);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.Retired2 = %hu"), identityBuffer.Response.GeneralConfiguration.Retired2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.FixedDevice = %hu"), identityBuffer.Response.GeneralConfiguration.FixedDevice);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.RemovableMedia = %hu"), identityBuffer.Response.GeneralConfiguration.RemovableMedia);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.Retired1 = %hu"), identityBuffer.Response.GeneralConfiguration.Retired1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("GeneralConfiguration.DeviceType = %hu"), identityBuffer.Response.GeneralConfiguration.DeviceType);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NumCylinders = %hu"), identityBuffer.Response.NumCylinders);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SpecificConfiguration = %hu"), identityBuffer.Response.SpecificConfiguration);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NumHeads = %hu"), identityBuffer.Response.NumHeads);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Retired1 = %.2p"), identityBuffer.Response.Retired1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NumSectorsPerTrack = %hu"), identityBuffer.Response.NumSectorsPerTrack);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("VendorUnique1 = %.3p"), identityBuffer.Response.VendorUnique1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialNumber = %.20S"), identityBuffer.Response.SerialNumber);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Retired2 = %.2p"), identityBuffer.Response.Retired2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Obsolete1 = %hu"), identityBuffer.Response.Obsolete1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("FirmwareRevision = %.8S"), identityBuffer.Response.FirmwareRevision);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ModelNumber = %.40S"), identityBuffer.Response.ModelNumber);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MaximumBlockTransfer = %u"), identityBuffer.Response.MaximumBlockTransfer);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("VendorUnique2 = %u"), identityBuffer.Response.VendorUnique2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("TrustedComputing.FeatureSupported = %hu"), identityBuffer.Response.TrustedComputing.FeatureSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("TrustedComputing.Reserved = %hu"), identityBuffer.Response.TrustedComputing.Reserved);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.CurrentLongPhysicalSectorAlignment = %u"), identityBuffer.Response.Capabilities.CurrentLongPhysicalSectorAlignment);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.ReservedByte49 = %u"), identityBuffer.Response.Capabilities.ReservedByte49);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.DmaSupported = %u"), identityBuffer.Response.Capabilities.DmaSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.LbaSupported = %u"), identityBuffer.Response.Capabilities.LbaSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.IordyDisable = %u"), identityBuffer.Response.Capabilities.IordyDisable);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.IordySupported = %u"), identityBuffer.Response.Capabilities.IordySupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.Reserved1 = %u"), identityBuffer.Response.Capabilities.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.StandybyTimerSupport = %u"), identityBuffer.Response.Capabilities.StandybyTimerSupport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.Reserved2 = %u"), identityBuffer.Response.Capabilities.Reserved2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Capabilities.ReservedWord50 = %hu"), identityBuffer.Response.Capabilities.ReservedWord50);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ObsoleteWords51 = %.2p"), identityBuffer.Response.ObsoleteWords51);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("TranslationFieldsValid = %hu"), identityBuffer.Response.TranslationFieldsValid);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Reserved3 = %hu"), identityBuffer.Response.Reserved3);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("FreeFallControlSensitivity = %hu"), identityBuffer.Response.FreeFallControlSensitivity);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NumberOfCurrentCylinders = %hu"), identityBuffer.Response.NumberOfCurrentCylinders);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NumberOfCurrentHeads = %hu"), identityBuffer.Response.NumberOfCurrentHeads);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CurrentSectorsPerTrack = %hu"), identityBuffer.Response.CurrentSectorsPerTrack);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CurrentSectorCapacity = %lu"), identityBuffer.Response.CurrentSectorCapacity);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CurrentMultiSectorSetting = %u"), identityBuffer.Response.CurrentMultiSectorSetting);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MultiSectorSettingValid = %u"), identityBuffer.Response.MultiSectorSettingValid);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedByte59 = %u"), identityBuffer.Response.ReservedByte59);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SanitizeFeatureSupported = %u"), identityBuffer.Response.SanitizeFeatureSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CryptoScrambleExtCommandSupported = %u"), identityBuffer.Response.CryptoScrambleExtCommandSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("OverwriteExtCommandSupported = %u"), identityBuffer.Response.OverwriteExtCommandSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("BlockEraseExtCommandSupported = %u"), identityBuffer.Response.BlockEraseExtCommandSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("UserAddressableSectors = %lu"), identityBuffer.Response.UserAddressableSectors);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ObsoleteWord62 = %hu"), identityBuffer.Response.ObsoleteWord62);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MultiWordDMASupport = %hu"), identityBuffer.Response.MultiWordDMASupport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MultiWordDMAActive = %hu"), identityBuffer.Response.MultiWordDMAActive);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdvancedPIOModes = %hu"), identityBuffer.Response.AdvancedPIOModes);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedByte64 = %hu"), identityBuffer.Response.ReservedByte64);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MinimumMWXferCycleTime = %hu"), identityBuffer.Response.MinimumMWXferCycleTime);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("RecommendedMWXferCycleTime = %hu"), identityBuffer.Response.RecommendedMWXferCycleTime);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MinimumPIOCycleTime = %hu"), identityBuffer.Response.MinimumPIOCycleTime);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MinimumPIOCycleTimeIORDY = %hu"), identityBuffer.Response.MinimumPIOCycleTimeIORDY);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.ZonedCapabilities = %hu"), identityBuffer.Response.AdditionalSupported.ZonedCapabilities);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.NonVolatileWriteCache = %hu"), identityBuffer.Response.AdditionalSupported.NonVolatileWriteCache);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.ExtendedUserAddressableSectorsSupported = %hu"), identityBuffer.Response.AdditionalSupported.ExtendedUserAddressableSectorsSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.DeviceEncryptsAllUserData = %hu"), identityBuffer.Response.AdditionalSupported.DeviceEncryptsAllUserData);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.ReadZeroAfterTrimSupported = %hu"), identityBuffer.Response.AdditionalSupported.ReadZeroAfterTrimSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.Optional28BitCommandsSupported = %hu"), identityBuffer.Response.AdditionalSupported.Optional28BitCommandsSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.IEEE1667 = %hu"), identityBuffer.Response.AdditionalSupported.IEEE1667);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.DownloadMicrocodeDmaSupported = %hu"), identityBuffer.Response.AdditionalSupported.DownloadMicrocodeDmaSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.SetMaxSetPasswordUnlockDmaSupported = %hu"), identityBuffer.Response.AdditionalSupported.SetMaxSetPasswordUnlockDmaSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.WriteBufferDmaSupported = %hu"), identityBuffer.Response.AdditionalSupported.WriteBufferDmaSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.ReadBufferDmaSupported = %hu"), identityBuffer.Response.AdditionalSupported.ReadBufferDmaSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.DeviceConfigIdentifySetDmaSupported = %hu"), identityBuffer.Response.AdditionalSupported.DeviceConfigIdentifySetDmaSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.LPSAERCSupported = %hu"), identityBuffer.Response.AdditionalSupported.LPSAERCSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.DeterministicReadAfterTrimSupported = %hu"), identityBuffer.Response.AdditionalSupported.DeterministicReadAfterTrimSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalSupported.CFastSpecSupported = %hu"), identityBuffer.Response.AdditionalSupported.CFastSpecSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWords70 = %.5p"), identityBuffer.Response.ReservedWords70);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("QueueDepth = %hu"), identityBuffer.Response.QueueDepth);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord75 = %hu"), identityBuffer.Response.ReservedWord75);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.Reserved0 = %hu"), identityBuffer.Response.SerialAtaCapabilities.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.SataGen1 = %hu"), identityBuffer.Response.SerialAtaCapabilities.SataGen1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.SataGen2 = %hu"), identityBuffer.Response.SerialAtaCapabilities.SataGen2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.SataGen3 = %hu"), identityBuffer.Response.SerialAtaCapabilities.SataGen3);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.Reserved1 = %hu"), identityBuffer.Response.SerialAtaCapabilities.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.NCQ = %hu"), identityBuffer.Response.SerialAtaCapabilities.NCQ);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.HIPM = %hu"), identityBuffer.Response.SerialAtaCapabilities.HIPM);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.PhyEvents = %hu"), identityBuffer.Response.SerialAtaCapabilities.PhyEvents);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.NcqUnload = %hu"), identityBuffer.Response.SerialAtaCapabilities.NcqUnload);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.NcqPriority = %hu"), identityBuffer.Response.SerialAtaCapabilities.NcqPriority);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.HostAutoPS = %hu"), identityBuffer.Response.SerialAtaCapabilities.HostAutoPS);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.DeviceAutoPS = %hu"), identityBuffer.Response.SerialAtaCapabilities.DeviceAutoPS);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.ReadLogDMA = %hu"), identityBuffer.Response.SerialAtaCapabilities.ReadLogDMA);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.Reserved2 = %hu"), identityBuffer.Response.SerialAtaCapabilities.Reserved2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.CurrentSpeed = %hu"), identityBuffer.Response.SerialAtaCapabilities.CurrentSpeed);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.NcqStreaming = %hu"), identityBuffer.Response.SerialAtaCapabilities.NcqStreaming);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.NcqQueueMgmt = %hu"), identityBuffer.Response.SerialAtaCapabilities.NcqQueueMgmt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.NcqReceiveSend = %hu"), identityBuffer.Response.SerialAtaCapabilities.NcqReceiveSend);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.DEVSLPtoReducedPwrState = %hu"), identityBuffer.Response.SerialAtaCapabilities.DEVSLPtoReducedPwrState);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaCapabilities.Reserved3 = %hu"), identityBuffer.Response.SerialAtaCapabilities.Reserved3);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.Reserved0 = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.NonZeroOffsets = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.NonZeroOffsets);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.DmaSetupAutoActivate = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.DmaSetupAutoActivate);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.DIPM = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.DIPM);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.InOrderData = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.InOrderData);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.HardwareFeatureControl = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.HardwareFeatureControl);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.SoftwareSettingsPreservation = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.SoftwareSettingsPreservation);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.NCQAutosense = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.NCQAutosense);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.DEVSLP = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.DEVSLP);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.HybridInformation = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.HybridInformation);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesSupported.Reserved1 = %hu"), identityBuffer.Response.SerialAtaFeaturesSupported.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.Reserved0 = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.NonZeroOffsets = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.NonZeroOffsets);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.DmaSetupAutoActivate = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.DmaSetupAutoActivate);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.DIPM = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.DIPM);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.InOrderData = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.InOrderData);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.HardwareFeatureControl = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.HardwareFeatureControl);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.SoftwareSettingsPreservation = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.SoftwareSettingsPreservation);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.DeviceAutoPS = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.DeviceAutoPS);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.DEVSLP = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.DEVSLP);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.HybridInformation = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.HybridInformation);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SerialAtaFeaturesEnabled.Reserved1 = %hu"), identityBuffer.Response.SerialAtaFeaturesEnabled.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MajorRevision = %hu"), identityBuffer.Response.MajorRevision);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MinorRevision = %hu"), identityBuffer.Response.MinorRevision);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.SmartCommands = %hu"), identityBuffer.Response.CommandSetSupport.SmartCommands);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.SecurityMode = %hu"), identityBuffer.Response.CommandSetSupport.SecurityMode);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.RemovableMediaFeature = %hu"), identityBuffer.Response.CommandSetSupport.RemovableMediaFeature);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.PowerManagement = %hu"), identityBuffer.Response.CommandSetSupport.PowerManagement);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Reserved1 = %hu"), identityBuffer.Response.CommandSetSupport.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.WriteCache = %hu"), identityBuffer.Response.CommandSetSupport.WriteCache);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.LookAhead = %hu"), identityBuffer.Response.CommandSetSupport.LookAhead);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.ReleaseInterrupt = %hu"), identityBuffer.Response.CommandSetSupport.ReleaseInterrupt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.ServiceInterrupt = %hu"), identityBuffer.Response.CommandSetSupport.ServiceInterrupt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.DeviceReset = %hu"), identityBuffer.Response.CommandSetSupport.DeviceReset);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.HostProtectedArea = %hu"), identityBuffer.Response.CommandSetSupport.HostProtectedArea);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Obsolete1 = %hu"), identityBuffer.Response.CommandSetSupport.Obsolete1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.WriteBuffer = %hu"), identityBuffer.Response.CommandSetSupport.WriteBuffer);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.ReadBuffer = %hu"), identityBuffer.Response.CommandSetSupport.ReadBuffer);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Nop = %hu"), identityBuffer.Response.CommandSetSupport.Nop);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Obsolete2 = %hu"), identityBuffer.Response.CommandSetSupport.Obsolete2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.DownloadMicrocode = %hu"), identityBuffer.Response.CommandSetSupport.DownloadMicrocode);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.DmaQueued = %hu"), identityBuffer.Response.CommandSetSupport.DmaQueued);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Cfa = %hu"), identityBuffer.Response.CommandSetSupport.Cfa);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.AdvancedPm = %hu"), identityBuffer.Response.CommandSetSupport.AdvancedPm);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Msn = %hu"), identityBuffer.Response.CommandSetSupport.Msn);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.PowerUpInStandby = %hu"), identityBuffer.Response.CommandSetSupport.PowerUpInStandby);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.ManualPowerUp = %hu"), identityBuffer.Response.CommandSetSupport.ManualPowerUp);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Reserved2 = %hu"), identityBuffer.Response.CommandSetSupport.Reserved2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.SetMax = %hu"), identityBuffer.Response.CommandSetSupport.SetMax);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.Acoustics = %hu"), identityBuffer.Response.CommandSetSupport.Acoustics);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.BigLba = %hu"), identityBuffer.Response.CommandSetSupport.BigLba);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.DeviceConfigOverlay = %hu"), identityBuffer.Response.CommandSetSupport.DeviceConfigOverlay);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.FlushCache = %hu"), identityBuffer.Response.CommandSetSupport.FlushCache);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.FlushCacheExt = %hu"), identityBuffer.Response.CommandSetSupport.FlushCacheExt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.WordValid83 = %hu"), identityBuffer.Response.CommandSetSupport.WordValid83);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.SmartErrorLog = %hu"), identityBuffer.Response.CommandSetSupport.SmartErrorLog);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.SmartSelfTest = %hu"), identityBuffer.Response.CommandSetSupport.SmartSelfTest);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.MediaSerialNumber = %hu"), identityBuffer.Response.CommandSetSupport.MediaSerialNumber);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.MediaCardPassThrough = %hu"), identityBuffer.Response.CommandSetSupport.MediaCardPassThrough);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.StreamingFeature = %hu"), identityBuffer.Response.CommandSetSupport.StreamingFeature);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.GpLogging = %hu"), identityBuffer.Response.CommandSetSupport.GpLogging);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.WriteFua = %hu"), identityBuffer.Response.CommandSetSupport.WriteFua);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.WriteQueuedFua = %hu"), identityBuffer.Response.CommandSetSupport.WriteQueuedFua);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.WWN64Bit = %hu"), identityBuffer.Response.CommandSetSupport.WWN64Bit);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.URGReadStream = %hu"), identityBuffer.Response.CommandSetSupport.URGReadStream);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.URGWriteStream = %hu"), identityBuffer.Response.CommandSetSupport.URGWriteStream);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.ReservedForTechReport = %hu"), identityBuffer.Response.CommandSetSupport.ReservedForTechReport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.IdleWithUnloadFeature = %hu"), identityBuffer.Response.CommandSetSupport.IdleWithUnloadFeature);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupport.WordValid = %hu"), identityBuffer.Response.CommandSetSupport.WordValid);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.SmartCommands = %hu"), identityBuffer.Response.CommandSetActive.SmartCommands);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.SecurityMode = %hu"), identityBuffer.Response.CommandSetActive.SecurityMode);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.RemovableMediaFeature = %hu"), identityBuffer.Response.CommandSetActive.RemovableMediaFeature);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.PowerManagement = %hu"), identityBuffer.Response.CommandSetActive.PowerManagement);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Reserved1 = %hu"), identityBuffer.Response.CommandSetActive.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.WriteCache = %hu"), identityBuffer.Response.CommandSetActive.WriteCache);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.LookAhead = %hu"), identityBuffer.Response.CommandSetActive.LookAhead);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.ReleaseInterrupt = %hu"), identityBuffer.Response.CommandSetActive.ReleaseInterrupt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.ServiceInterrupt = %hu"), identityBuffer.Response.CommandSetActive.ServiceInterrupt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.DeviceReset = %hu"), identityBuffer.Response.CommandSetActive.DeviceReset);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.HostProtectedArea = %hu"), identityBuffer.Response.CommandSetActive.HostProtectedArea);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Obsolete1 = %hu"), identityBuffer.Response.CommandSetActive.Obsolete1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.WriteBuffer = %hu"), identityBuffer.Response.CommandSetActive.WriteBuffer);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.ReadBuffer = %hu"), identityBuffer.Response.CommandSetActive.ReadBuffer);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Nop = %hu"), identityBuffer.Response.CommandSetActive.Nop);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Obsolete2 = %hu"), identityBuffer.Response.CommandSetActive.Obsolete2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.DownloadMicrocode = %hu"), identityBuffer.Response.CommandSetActive.DownloadMicrocode);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.DmaQueued = %hu"), identityBuffer.Response.CommandSetActive.DmaQueued);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Cfa = %hu"), identityBuffer.Response.CommandSetActive.Cfa);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.AdvancedPm = %hu"), identityBuffer.Response.CommandSetActive.AdvancedPm);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Msn = %hu"), identityBuffer.Response.CommandSetActive.Msn);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.PowerUpInStandby = %hu"), identityBuffer.Response.CommandSetActive.PowerUpInStandby);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.ManualPowerUp = %hu"), identityBuffer.Response.CommandSetActive.ManualPowerUp);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Reserved2 = %hu"), identityBuffer.Response.CommandSetActive.Reserved2);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.SetMax = %hu"), identityBuffer.Response.CommandSetActive.SetMax);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Acoustics = %hu"), identityBuffer.Response.CommandSetActive.Acoustics);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.BigLba = %hu"), identityBuffer.Response.CommandSetActive.BigLba);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.DeviceConfigOverlay = %hu"), identityBuffer.Response.CommandSetActive.DeviceConfigOverlay);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.FlushCache = %hu"), identityBuffer.Response.CommandSetActive.FlushCache);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.FlushCacheExt = %hu"), identityBuffer.Response.CommandSetActive.FlushCacheExt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Resrved3 = %hu"), identityBuffer.Response.CommandSetActive.Resrved3);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Words119_120Valid = %hu"), identityBuffer.Response.CommandSetActive.Words119_120Valid);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.SmartErrorLog = %hu"), identityBuffer.Response.CommandSetActive.SmartErrorLog);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.SmartSelfTest = %hu"), identityBuffer.Response.CommandSetActive.SmartSelfTest);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.MediaSerialNumber = %hu"), identityBuffer.Response.CommandSetActive.MediaSerialNumber);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.MediaCardPassThrough = %hu"), identityBuffer.Response.CommandSetActive.MediaCardPassThrough);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.StreamingFeature = %hu"), identityBuffer.Response.CommandSetActive.StreamingFeature);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.GpLogging = %hu"), identityBuffer.Response.CommandSetActive.GpLogging);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.WriteFua = %hu"), identityBuffer.Response.CommandSetActive.WriteFua);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.WriteQueuedFua = %hu"), identityBuffer.Response.CommandSetActive.WriteQueuedFua);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.WWN64Bit = %hu"), identityBuffer.Response.CommandSetActive.WWN64Bit);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.URGReadStream = %hu"), identityBuffer.Response.CommandSetActive.URGReadStream);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.URGWriteStream = %hu"), identityBuffer.Response.CommandSetActive.URGWriteStream);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.ReservedForTechReport = %hu"), identityBuffer.Response.CommandSetActive.ReservedForTechReport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.IdleWithUnloadFeature = %hu"), identityBuffer.Response.CommandSetActive.IdleWithUnloadFeature);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActive.Reserved4 = %hu"), identityBuffer.Response.CommandSetActive.Reserved4);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("UltraDMASupport = %hu"), identityBuffer.Response.UltraDMASupport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("UltraDMAActive = %hu"), identityBuffer.Response.UltraDMAActive);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NormalSecurityEraseUnit.TimeRequired = %hu"), identityBuffer.Response.NormalSecurityEraseUnit.TimeRequired);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NormalSecurityEraseUnit.ExtendedTimeReported = %hu"), identityBuffer.Response.NormalSecurityEraseUnit.ExtendedTimeReported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("EnhancedSecurityEraseUnit.TimeRequired = %hu"), identityBuffer.Response.EnhancedSecurityEraseUnit.TimeRequired);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("EnhancedSecurityEraseUnit.ExtendedTimeReported = %hu"), identityBuffer.Response.EnhancedSecurityEraseUnit.ExtendedTimeReported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CurrentAPMLevel = %hu"), identityBuffer.Response.CurrentAPMLevel);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord91 = %hu"), identityBuffer.Response.ReservedWord91);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MasterPasswordID = %hu"), identityBuffer.Response.MasterPasswordID);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("HardwareResetResult = %hu"), identityBuffer.Response.HardwareResetResult);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CurrentAcousticValue = %hu"), identityBuffer.Response.CurrentAcousticValue);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("RecommendedAcousticValue = %hu"), identityBuffer.Response.RecommendedAcousticValue);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("StreamMinRequestSize = %hu"), identityBuffer.Response.StreamMinRequestSize);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("StreamingTransferTimeDMA = %hu"), identityBuffer.Response.StreamingTransferTimeDMA);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("StreamingAccessLatencyDMAPIO = %hu"), identityBuffer.Response.StreamingAccessLatencyDMAPIO);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("StreamingPerfGranularity = %lu"), identityBuffer.Response.StreamingPerfGranularity);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Max48BitLBA = %.2p"), identityBuffer.Response.Max48BitLBA);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("StreamingTransferTime = %hu"), identityBuffer.Response.StreamingTransferTime);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("DsmCap = %hu"), identityBuffer.Response.DsmCap);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("PhysicalLogicalSectorSize.LogicalSectorsPerPhysicalSector = %hu"), identityBuffer.Response.PhysicalLogicalSectorSize.LogicalSectorsPerPhysicalSector);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("PhysicalLogicalSectorSize.Reserved0 = %hu"), identityBuffer.Response.PhysicalLogicalSectorSize.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("PhysicalLogicalSectorSize.LogicalSectorLongerThan256Words = %hu"), identityBuffer.Response.PhysicalLogicalSectorSize.LogicalSectorLongerThan256Words);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("PhysicalLogicalSectorSize.MultipleLogicalSectorsPerPhysicalSector = %hu"), identityBuffer.Response.PhysicalLogicalSectorSize.MultipleLogicalSectorsPerPhysicalSector);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("PhysicalLogicalSectorSize.Reserved1 = %hu"), identityBuffer.Response.PhysicalLogicalSectorSize.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("InterSeekDelay = %hu"), identityBuffer.Response.InterSeekDelay);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("WorldWideName = %.4p"), identityBuffer.Response.WorldWideName);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedForWorldWideName128 = %.4p"), identityBuffer.Response.ReservedForWorldWideName128);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedForTlcTechnicalReport = %hu"), identityBuffer.Response.ReservedForTlcTechnicalReport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("WordsPerLogicalSector = %.2p"), identityBuffer.Response.WordsPerLogicalSector);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.ReservedForDrqTechnicalReport = %hu"), identityBuffer.Response.CommandSetSupportExt.ReservedForDrqTechnicalReport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.WriteReadVerify = %hu"), identityBuffer.Response.CommandSetSupportExt.WriteReadVerify);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.WriteUncorrectableExt = %hu"), identityBuffer.Response.CommandSetSupportExt.WriteUncorrectableExt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.ReadWriteLogDmaExt = %hu"), identityBuffer.Response.CommandSetSupportExt.ReadWriteLogDmaExt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.DownloadMicrocodeMode3 = %hu"), identityBuffer.Response.CommandSetSupportExt.DownloadMicrocodeMode3);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.FreefallControl = %hu"), identityBuffer.Response.CommandSetSupportExt.FreefallControl);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.SenseDataReporting = %hu"), identityBuffer.Response.CommandSetSupportExt.SenseDataReporting);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.ExtendedPowerConditions = %hu"), identityBuffer.Response.CommandSetSupportExt.ExtendedPowerConditions);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.Reserved0 = %hu"), identityBuffer.Response.CommandSetSupportExt.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetSupportExt.WordValid = %hu"), identityBuffer.Response.CommandSetSupportExt.WordValid);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.ReservedForDrqTechnicalReport = %hu"), identityBuffer.Response.CommandSetActiveExt.ReservedForDrqTechnicalReport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.WriteReadVerify = %hu"), identityBuffer.Response.CommandSetActiveExt.WriteReadVerify);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.WriteUncorrectableExt = %hu"), identityBuffer.Response.CommandSetActiveExt.WriteUncorrectableExt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.ReadWriteLogDmaExt = %hu"), identityBuffer.Response.CommandSetActiveExt.ReadWriteLogDmaExt);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.DownloadMicrocodeMode3 = %hu"), identityBuffer.Response.CommandSetActiveExt.DownloadMicrocodeMode3);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.FreefallControl = %hu"), identityBuffer.Response.CommandSetActiveExt.FreefallControl);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.SenseDataReporting = %hu"), identityBuffer.Response.CommandSetActiveExt.SenseDataReporting);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.ExtendedPowerConditions = %hu"), identityBuffer.Response.CommandSetActiveExt.ExtendedPowerConditions);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.Reserved0 = %hu"), identityBuffer.Response.CommandSetActiveExt.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CommandSetActiveExt.Reserved1 = %hu"), identityBuffer.Response.CommandSetActiveExt.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedForExpandedSupportandActive = %.6p"), identityBuffer.Response.ReservedForExpandedSupportandActive);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MsnSupport = %hu"), identityBuffer.Response.MsnSupport);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord127 = %hu"), identityBuffer.Response.ReservedWord127);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.SecuritySupported = %hu"), identityBuffer.Response.SecurityStatus.SecuritySupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.SecurityEnabled = %hu"), identityBuffer.Response.SecurityStatus.SecurityEnabled);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.SecurityLocked = %hu"), identityBuffer.Response.SecurityStatus.SecurityLocked);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.SecurityFrozen = %hu"), identityBuffer.Response.SecurityStatus.SecurityFrozen);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.SecurityCountExpired = %hu"), identityBuffer.Response.SecurityStatus.SecurityCountExpired);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.EnhancedSecurityEraseSupported = %hu"), identityBuffer.Response.SecurityStatus.EnhancedSecurityEraseSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.Reserved0 = %hu"), identityBuffer.Response.SecurityStatus.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.SecurityLevel = %hu"), identityBuffer.Response.SecurityStatus.SecurityLevel);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SecurityStatus.Reserved1 = %hu"), identityBuffer.Response.SecurityStatus.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord129 = %.31p"), identityBuffer.Response.ReservedWord129);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CfaPowerMode1.MaximumCurrentInMA = %hu"), identityBuffer.Response.CfaPowerMode1.MaximumCurrentInMA);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CfaPowerMode1.CfaPowerMode1Disabled = %hu"), identityBuffer.Response.CfaPowerMode1.CfaPowerMode1Disabled);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CfaPowerMode1.CfaPowerMode1Required = %hu"), identityBuffer.Response.CfaPowerMode1.CfaPowerMode1Required);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CfaPowerMode1.Reserved0 = %hu"), identityBuffer.Response.CfaPowerMode1.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CfaPowerMode1.Word160Supported = %hu"), identityBuffer.Response.CfaPowerMode1.Word160Supported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedForCfaWord161 = %.7p"), identityBuffer.Response.ReservedForCfaWord161);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NominalFormFactor = %hu"), identityBuffer.Response.NominalFormFactor);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord168 = %hu"), identityBuffer.Response.ReservedWord168);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("DataSetManagementFeature.SupportsTrim = %hu"), identityBuffer.Response.DataSetManagementFeature.SupportsTrim);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("DataSetManagementFeature.Reserved0 = %hu"), identityBuffer.Response.DataSetManagementFeature.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("AdditionalProductID = %.4p"), identityBuffer.Response.AdditionalProductID);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedForCfaWord174 = %.2p"), identityBuffer.Response.ReservedForCfaWord174);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CurrentMediaSerialNumber = %.30p"), identityBuffer.Response.CurrentMediaSerialNumber);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.Supported = %hu"), identityBuffer.Response.SCTCommandTransport.Supported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.Reserved0 = %hu"), identityBuffer.Response.SCTCommandTransport.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.WriteSameSuported = %hu"), identityBuffer.Response.SCTCommandTransport.WriteSameSuported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.ErrorRecoveryControlSupported = %hu"), identityBuffer.Response.SCTCommandTransport.ErrorRecoveryControlSupported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.FeatureControlSuported = %hu"), identityBuffer.Response.SCTCommandTransport.FeatureControlSuported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.DataTablesSuported = %hu"), identityBuffer.Response.SCTCommandTransport.DataTablesSuported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.Reserved1 = %hu"), identityBuffer.Response.SCTCommandTransport.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("SCTCommandTransport.VendorSpecific = %hu"), identityBuffer.Response.SCTCommandTransport.VendorSpecific);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord207 = %.2p"), identityBuffer.Response.ReservedWord207);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("BlockAlignment.AlignmentOfLogicalWithinPhysical = %hu"), identityBuffer.Response.BlockAlignment.AlignmentOfLogicalWithinPhysical);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("BlockAlignment.Word209Supported = %hu"), identityBuffer.Response.BlockAlignment.Word209Supported);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("BlockAlignment.Reserved0 = %hu"), identityBuffer.Response.BlockAlignment.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("WriteReadVerifySectorCountMode3Only = %.2p"), identityBuffer.Response.WriteReadVerifySectorCountMode3Only);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("WriteReadVerifySectorCountMode2Only = %.2p"), identityBuffer.Response.WriteReadVerifySectorCountMode2Only);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheCapabilities.NVCachePowerModeEnabled = %hu"), identityBuffer.Response.NVCacheCapabilities.NVCachePowerModeEnabled);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheCapabilities.Reserved0 = %hu"), identityBuffer.Response.NVCacheCapabilities.Reserved0);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheCapabilities.NVCacheFeatureSetEnabled = %hu"), identityBuffer.Response.NVCacheCapabilities.NVCacheFeatureSetEnabled);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheCapabilities.Reserved1 = %hu"), identityBuffer.Response.NVCacheCapabilities.Reserved1);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheCapabilities.NVCachePowerModeVersion = %hu"), identityBuffer.Response.NVCacheCapabilities.NVCachePowerModeVersion);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheCapabilities.NVCacheFeatureSetVersion = %hu"), identityBuffer.Response.NVCacheCapabilities.NVCacheFeatureSetVersion);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheSizeLSW = %hu"), identityBuffer.Response.NVCacheSizeLSW);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheSizeMSW = %hu"), identityBuffer.Response.NVCacheSizeMSW);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NominalMediaRotationRate = %hu"), identityBuffer.Response.NominalMediaRotationRate);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord218 = %hu"), identityBuffer.Response.ReservedWord218);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheOptions.NVCacheEstimatedTimeToSpinUpInSeconds = %u"), identityBuffer.Response.NVCacheOptions.NVCacheEstimatedTimeToSpinUpInSeconds);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("NVCacheOptions.Reserved = %u"), identityBuffer.Response.NVCacheOptions.Reserved);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("WriteReadVerifySectorCountMode = %hu"), identityBuffer.Response.WriteReadVerifySectorCountMode);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord220 = %hu"), identityBuffer.Response.ReservedWord220);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord221 = %hu"), identityBuffer.Response.ReservedWord221);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("TransportMajorVersion.MajorVersion = %hu"), identityBuffer.Response.TransportMajorVersion.MajorVersion);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("TransportMajorVersion.TransportType = %hu"), identityBuffer.Response.TransportMajorVersion.TransportType);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("TransportMinorVersion = %hu"), identityBuffer.Response.TransportMinorVersion);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord224 = %.6p"), identityBuffer.Response.ReservedWord224);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ExtendedNumberOfUserAddressableSectors = %.2p"), identityBuffer.Response.ExtendedNumberOfUserAddressableSectors);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MinBlocksPerDownloadMicrocodeMode03 = %hu"), identityBuffer.Response.MinBlocksPerDownloadMicrocodeMode03);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("MaxBlocksPerDownloadMicrocodeMode03 = %hu"), identityBuffer.Response.MaxBlocksPerDownloadMicrocodeMode03);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("ReservedWord236 = %.19p"), identityBuffer.Response.ReservedWord236);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("Signature = %hu"), identityBuffer.Response.Signature);
	OutputDebugString(dbg);
	wnsprintf(dbg, dbglen, _T("CheckSum = %hu"), identityBuffer.Response.CheckSum);
	OutputDebugString(dbg);
}

/*
Check if there is any mouse movement in the sandbox.
*/
BOOL mouse_movement() {

	POINT positionA = {};
	POINT positionB = {};

	/* Retrieve the position of the mouse cursor, in screen coordinates */
	GetCursorPos(&positionA);

	/* Wait a moment */
	Sleep(5000);

	/* Retrieve the poition gain */
	GetCursorPos(&positionB);

	if ((positionA.x == positionB.x) && (positionA.y == positionB.y))
		/* Probably a sandbox, because mouse position did not change. */
		return TRUE;

	else 
		return FALSE;
}

/*
Check if the machine have enough memory space, usually VM get a small ammount,
one reason if because several VMs are running on the same servers so they can run
more tasks at the same time.
*/
BOOL memory_space()
{
	DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 1LL))); // 1GB
	MEMORYSTATUSEX statex = {0};

	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);

	return (statex.ullTotalPhys < ullMinRam) ? TRUE : FALSE;
}

/*
This trick consists of getting information about total amount of space.
This can be used to expose a sandbox.
*/
BOOL disk_size_getdiskfreespace()
{
	ULONGLONG minHardDiskSize = (80ULL * (1024ULL * (1024ULL * (1024ULL))));
	LPCWSTR pszDrive = NULL;
	BOOL bStatus = FALSE;

	// 64 bits integer, low and high bytes
	ULARGE_INTEGER totalNumberOfBytes;

	// If the function succeeds, the return value is nonzero. If the function fails, the return value is 0 (zero).
	bStatus = GetDiskFreeSpaceEx(pszDrive, NULL, &totalNumberOfBytes, NULL);
	if (bStatus) {
		if (totalNumberOfBytes.QuadPart < minHardDiskSize)  // 80GB
			return TRUE;
	}

	return FALSE;;
}

/*
Sleep and check if time have been accelerated
*/
BOOL accelerated_sleep()
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 60*1000;

	/* Retrieves the number of milliseconds that have elapsed since the system was started */
	dwStart = GetTickCount();

	/* Let's sleep 1 minute so Sandbox is interested to patch that */
	Sleep(dwMillisecondsToSleep);

	/* Do it again */
	dwEnd = GetTickCount();

	/* If the Sleep function was patched*/
	dwDiff = dwEnd - dwStart;
	if (dwDiff > dwMillisecondsToSleep - 1000) // substracted 1s just to be sure
		return FALSE;
	else 
		return TRUE;
}

/*
The CPUID instruction is a processor supplementary instruction (its name derived from 
CPU IDentification) for the x86 architecture allowing software to discover details of 
the processor. By calling CPUID with EAX =1, The 31bit of ECX register if set will
reveal the precense of a hypervisor.
*/
BOOL cpuid_is_hypervisor()
{
	INT CPUInfo[4] = { -1 };

	/* Query hypervisor precense using CPUID (EAX=1), BIT 31 in ECX */
	__cpuid(CPUInfo, 1);
	if ((CPUInfo[2] >> 31) & 1) 
		return TRUE;
	else
		return FALSE;
}


/*
If HV presence confirmed then it is good to know which type of hypervisor we have
When CPUID is called with EAX=0x40000000, cpuid return the hypervisor signature.
*/
BOOL cpuid_hypervisor_vendor()
{
	INT CPUInfo[4] = {-1};
	CHAR szHypervisorVendor[0x40];
	TCHAR* szBlacklistedHypervisors[] = {
		_T("KVMKVMKVM\0\0\0"),	/* KVM */
		_T("Microsoft Hv"),		/* Microsoft Hyper-V or Windows Virtual PC */
		_T("VMwareVMware"),		/* VMware */
		_T("XenVMMXenVMM"),		/* Xen */
		_T("prl hyperv  "),		/* Parallels */
		_T("VBoxVBoxVBox"),		/* VirtualBox */
	};
	WORD dwlength = sizeof(szBlacklistedHypervisors) / sizeof(szBlacklistedHypervisors[0]);

	// __cpuid with an InfoType argument of 0 returns the number of
	// valid Ids in CPUInfo[0] and the CPU identification string in
	// the other three array elements. The CPU identification string is
	// not in linear order. The code below arranges the information 
	// in a human readable form.
	__cpuid(CPUInfo, 0x40000000);
	memset(szHypervisorVendor, 0, sizeof(szHypervisorVendor));
	memcpy(szHypervisorVendor, CPUInfo + 1, 12);

	for (int i = 0; i < dwlength; i++)
	{
		if (_tcscmp(ascii_to_wide_str(szHypervisorVendor), szBlacklistedHypervisors[i]) == 0)
			return TRUE;
	}

	return FALSE;
}


/*
Check SerialNumber devices using WMI
*/
BOOL serial_number_bios_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));

	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_BIOS"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("SerialNumber"), 0, &vtProp, 0, 0);

				// Do our comparaison
				if (
					(StrStrI(vtProp.bstrVal, _T("VMWare")) != 0) ||
					(StrStrI(vtProp.bstrVal, _T("0")) != 0) || // VBox
					(StrStrI(vtProp.bstrVal, _T("Xen")) != 0) ||
					(StrStrI(vtProp.bstrVal, _T("Virtual")) != 0) ||
					(StrStrI(vtProp.bstrVal, _T("A M I")) != 0)
					)
				{
					bFound = TRUE;
					break;
				}

				// release the current result object
				VariantClear(&vtProp);
				pclsObj->Release();
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
Check Model from ComputerSystem using WMI
*/
BOOL model_computer_system_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));

	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_ComputerSystem"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("Model"), 0, &vtProp, 0, 0);

				// Do our comparaison
				if (
					(StrStrI(vtProp.bstrVal, _T("VirtualBox")) != 0) ||
					(StrStrI(vtProp.bstrVal, _T("HVM domU")) != 0) || //Xen
					(StrStrI(vtProp.bstrVal, _T("VMWare")) != 0)
					)
				{
					bFound = TRUE;
					break;
				}

				// release the current result object
				VariantClear(&vtProp);
				pclsObj->Release();
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
Check Manufacturer from ComputerSystem using WMI
*/
BOOL manufacturer_computer_system_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));

	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_ComputerSystem"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("Manufacturer"), 0, &vtProp, 0, 0);

				// Do our comparaison
				if (
					(StrStrI(vtProp.bstrVal, _T("VMWare")) != 0) || 
					(StrStrI(vtProp.bstrVal, _T("Xen")) != 0) ||
					(StrStrI(vtProp.bstrVal, _T("innotek GmbH")) != 0) || // Vbox
					(StrStrI(vtProp.bstrVal, _T("QEMU")) != 0)
					)
				{
					bFound = TRUE;
					break;
				}

				// release the current result object
				VariantClear(&vtProp);
				pclsObj->Release();
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
Check Current Temperature using WMI, this requires admin privileges
In my tests, it works against vbox, vmware, kvm and xen.
*/
BOOL current_temperature_acpi_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// This technique required admin priviliege
	if (!IsElevated())
		return FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("root\\WMI"));

	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM MSAcpi_ThermalZoneTemperature"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn) {
					bFound = TRUE;
					break;
				}

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("CurrentTemperature"), 0, &vtProp, 0, 0);
				if (SUCCEEDED(hRes)) {
					break;

				}

				// release the current result object
				VariantClear(&vtProp);
				pclsObj->Release();
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
Check ProcessId from Win32_Processor using WMI
KVM, XEN anv VMWare seems to return something, VBOX return NULL
*/
BOOL process_id_processor_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc, _T("ROOT\\CIMV2"));

	if (bStatus)
	{
		// If success, execute the desired query
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_Processor"));
		if (bStatus)
		{
			// Get the data from the query
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				// Get the value of the Name property
				hRes = pclsObj->Get(_T("ProcessorId"), 0, &vtProp, 0, 0);

				// Do our comparaison
				if (vtProp.bstrVal== NULL)
				{
					bFound = TRUE;
					break;
				}

				// release the current result object
				VariantClear(&vtProp);
				pclsObj->Release();
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
Check what power states are enabled.
Most VMs don't support S1-S4 power states whereas most hardware does, and thermal control is usually not found either.
This has been tested on VirtualBox and Hyper-V, as well as a physical desktop and laptop.
*/
BOOL power_capabilities()
{
	SYSTEM_POWER_CAPABILITIES powerCaps;
	BOOL bFound = FALSE;
	if (GetPwrCapabilities(&powerCaps) == TRUE)
	{
		if ((powerCaps.SystemS1 | powerCaps.SystemS2 | powerCaps.SystemS3 | powerCaps.SystemS4) == FALSE)
		{
			bFound = (powerCaps.ThermalControl == FALSE);
		}
	}

	return bFound;
}