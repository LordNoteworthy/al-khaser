#include "Generic.h"

/*
Check of following dll are loaded
 - sbiedll.dll (Sandboxie)
 - dbghelp.dll (vmware)
 - api_log.dll (SunBelt SandBox)
 - dir_watch.dll (SunBelt SandBox)
 - pstorec.dll (SunBelt Sandbox)
 - vmcheck.dll (Virtual PC)
 - wpespy.dll (WPE Pro)
*/
VOID loaded_dlls()
{
	/* Some vars */
	HMODULE hDll;

	/* Array of strings of blacklisted dlls */
	TCHAR* szDlls[] = {
		_T("sbiedll.dll"),
		_T("dbghelp.dll"),
		_T("api_log.dll"),
		_T("dir_watch.dll"),
		_T("pstorec.dll"),
		_T("vmcheck.dll"),
		_T("wpespy.dll"),

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
	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x30) + 0xB8);

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
	bStatus = InitWMI(&pSvc, &pLoc);
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
	INT64 minHardDiskSize = (80LL * (1024LL * (1024LL * (1024LL))));

	// Init WMI
	bStatus = InitWMI(&pSvc, &pLoc);
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
				hRes = pclsObj->Get(_T("Size"), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					// Do our comparaison
					if (vtProp.llVal < minHardDiskSize) { // Less than 80GB
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

	// This technique required admin priviliege starting from Vira Windows Vista
	if (!IsElevated() && IsWindowsVistaOrGreater())
		return FALSE;
	
	hDevice = CreateFile(_T("\\\\.\\PhysicalDrive0"),
		GENERIC_READ,                // no access to the drive
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

	if (bResult != NULL) {
		if (size.Length.QuadPart < minHardDiskSize) // 80GB
			bResult = TRUE;
		else
			bResult = FALSE;
	}

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
