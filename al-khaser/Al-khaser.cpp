// al-khaser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"


int main(void)
{
	/* enable functions */
	BOOL	ENABLE_TLS_CHECKS = TRUE;
	BOOL	ENABLE_DEBUG_CHECKS = TRUE;
	BOOL	ENABLE_INJECTION_CHECKS = TRUE;
	BOOL	ENABLE_GEN_SANDBOX_CHECKS = TRUE;
	BOOL	ENABLE_VBOX_CHECKS = TRUE;
	BOOL	ENABLE_VMWARE_CHECKS = TRUE;
	BOOL	ENABLE_VPC_CHECKS = TRUE;
	BOOL	ENABLE_QEMU_CHECKS = TRUE;
	BOOL	ENABLE_XEN_CHECKS = TRUE;
	BOOL	ENABLE_WINE_CHECKS = TRUE;
	BOOL	ENABLE_PARALLELS_CHECKS = TRUE;
	BOOL	ENABLE_CODE_INJECTIONS = FALSE;
	BOOL	ENABLE_TIMING_ATTACKS = TRUE;
	BOOL	ENABLE_DUMPING_CHECK = TRUE;
	BOOL	ENABLE_ANALYSIS_TOOLS_CHECK = TRUE;
	BOOL	ENABLE_ANTI_DISASSM_CHECKS = TRUE;
	
	/* Resize the console window for better visibility */
	resize_console_window();

	/* Display general informations */
	_tprintf(_T("[al-khaser version 0.80]"));

	print_category(TEXT("Initialisation"));
	API::Init();
	print_os();
	API::PrintAvailabilityReport();

	/* Are we running under WoW64 */
	if (IsWoW64())
		_tprintf(_T("Process is running under WOW64\n\n"));

	if (ENABLE_DEBUG_CHECKS) PageExceptionInitialEnum();

	/* TLS checks */
	if (ENABLE_TLS_CHECKS) {
		print_category(TEXT("TLS Callbacks"));
		exec_check(&TLSCallbackProcess, TEXT("TLS process attach callback "));
		exec_check(&TLSCallbackThread, TEXT("TLS thread attach callback "));
	}

	/* Debugger Detection */
	if (ENABLE_DEBUG_CHECKS) {
		print_category(TEXT("Debugger Detection"));
		exec_check(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API "));
		exec_check(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged "));
		exec_check(&CheckRemoteDebuggerPresentAPI, TEXT("Checking CheckRemoteDebuggerPresent API "));
		exec_check(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag "));
		exec_check(&HeapFlags, TEXT("Checking ProcessHeap.Flags "));
		exec_check(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags "));
		exec_check(&LowFragmentationHeap, TEXT("Checking Low Fragmentation Heap"));
		exec_check(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort "));
		exec_check(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags "));
		exec_check(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject "));
		exec_check(&WUDF_IsAnyDebuggerPresent, TEXT("Checking WudfIsAnyDebuggerPresent API "));
		exec_check(&WUDF_IsKernelDebuggerPresent, TEXT("Checking WudfIsKernelDebuggerPresent API "));
		exec_check(&WUDF_IsUserDebuggerPresent, TEXT("Checking WudfIsUserDebuggerPresent API "));
		exec_check(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger "));
		exec_check(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
		exec_check(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest "));
		exec_check(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
		exec_check(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
		exec_check(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));
		exec_check(&Interrupt_0x2d, TEXT("Checking Interupt 0x2d "));
		exec_check(&Interrupt_3, TEXT("Checking Interupt 1 "));
		exec_check(&TrapFlag, TEXT("Checking trap flag"));
		exec_check(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD "));
		exec_check(&IsParentExplorerExe, TEXT("Checking If Parent Process is explorer.exe "));
		exec_check(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege "));
		exec_check(&NtQueryObject_ObjectTypeInformation, TEXT("Checking NtQueryObject with ObjectTypeInformation "));
		exec_check(&NtQueryObject_ObjectAllTypesInformation, TEXT("Checking NtQueryObject with ObjectAllTypesInformation "));
		exec_check(&NtYieldExecutionAPI, TEXT("Checking NtYieldExecution "));
		exec_check(&SetHandleInformatiom_ProtectedHandle, TEXT("Checking CloseHandle protected handle trick  "));
		exec_check(&NtQuerySystemInformation_SystemKernelDebuggerInformation, TEXT("Checking NtQuerySystemInformation with SystemKernelDebuggerInformation  "));
		exec_check(&SharedUserData_KernelDebugger, TEXT("Checking SharedUserData->KdDebuggerEnabled  "));
		exec_check(&ProcessJob, TEXT("Checking if process is in a job  "));
		exec_check(&VirtualAlloc_WriteWatch_BufferOnly, TEXT("Checking VirtualAlloc write watch (buffer only) "));
		exec_check(&VirtualAlloc_WriteWatch_APICalls, TEXT("Checking VirtualAlloc write watch (API calls) "));
		exec_check(&VirtualAlloc_WriteWatch_IsDebuggerPresent, TEXT("Checking VirtualAlloc write watch (IsDebuggerPresent) "));
		exec_check(&VirtualAlloc_WriteWatch_CodeWrite, TEXT("Checking VirtualAlloc write watch (code write) "));
		exec_check(&PageExceptionBreakpointCheck, TEXT("Checking for page exception breakpoints "));
		exec_check(&ModuleBoundsHookCheck, TEXT("Checking for API hooks outside module bounds "));
	}

	if (ENABLE_INJECTION_CHECKS) {
		print_category(TEXT("DLL Injection Detection"));
		exec_check(&ScanForModules_EnumProcessModulesEx_32bit, TEXT("Enumerating modules with EnumProcessModulesEx [32-bit] "));
		exec_check(&ScanForModules_EnumProcessModulesEx_64bit, TEXT("Enumerating modules with EnumProcessModulesEx [64-bit] "));
		exec_check(&ScanForModules_EnumProcessModulesEx_All, TEXT("Enumerating modules with EnumProcessModulesEx [ALL] "));
		exec_check(&ScanForModules_ToolHelp32, TEXT("Enumerating modules with ToolHelp32 "));
		exec_check(&ScanForModules_LdrEnumerateLoadedModules, TEXT("Enumerating the process LDR via LdrEnumerateLoadedModules "));
		exec_check(&ScanForModules_LDR_Direct, TEXT("Enumerating the process LDR directly "));
		exec_check(&ScanForModules_MemoryWalk_GMI, TEXT("Walking process memory with GetModuleInformation "));
		exec_check(&ScanForModules_MemoryWalk_Hidden, TEXT("Walking process memory for hidden modules "));
	}

	/* Generic sandbox detection */
	if (ENABLE_GEN_SANDBOX_CHECKS) {
		print_category(TEXT("Generic Sandboxe/VM Detection"));
		loaded_dlls();
		known_file_names();
		known_usernames();
		known_hostnames();
		other_known_sandbox_environment_checks();
		exec_check(&NumberOfProcessors, TEXT("Checking Number of processors in machine "));
		exec_check(&idt_trick, TEXT("Checking Interupt Descriptor Table location "));
		exec_check(&ldt_trick, TEXT("Checking Local Descriptor Table location "));
		exec_check(&gdt_trick, TEXT("Checking Global Descriptor Table location "));
		exec_check(&str_trick, TEXT("Checking Store Task Register "));
		exec_check(&number_cores_wmi, TEXT("Checking Number of cores in machine using WMI "));
		exec_check(&disk_size_wmi, TEXT("Checking hard disk size using WMI "));
		exec_check(&dizk_size_deviceiocontrol, TEXT("Checking hard disk size using DeviceIoControl "));
		exec_check(&setupdi_diskdrive, TEXT("Checking SetupDi_diskdrive "));
		exec_check(&mouse_movement, TEXT("Checking mouse movement "));
		exec_check(&lack_user_input, TEXT("Checking lack of user input "));
		exec_check(&memory_space, TEXT("Checking memory space using GlobalMemoryStatusEx "));
		exec_check(&disk_size_getdiskfreespace, TEXT("Checking disk size using GetDiskFreeSpaceEx "));
		exec_check(&cpuid_is_hypervisor, TEXT("Checking if CPU hypervisor field is set using cpuid(0x1)"));
		exec_check(&cpuid_hypervisor_vendor, TEXT("Checking hypervisor vendor using cpuid(0x40000000)"));
		exec_check(&accelerated_sleep, TEXT("Check if time has been accelerated "));
		exec_check(&VMDriverServices, TEXT("VM Driver Services  "));
		exec_check(&serial_number_bios_wmi, TEXT("Checking SerialNumber from BIOS using WMI "));
		exec_check(&model_computer_system_wmi, TEXT("Checking Model from ComputerSystem using WMI "));
		exec_check(&manufacturer_computer_system_wmi, TEXT("Checking Manufacturer from ComputerSystem using WMI "));
		exec_check(&current_temperature_acpi_wmi, TEXT("Checking Current Temperature using WMI "));
		exec_check(&process_id_processor_wmi, TEXT("Checking ProcessId using WMI "));
		exec_check(&power_capabilities, TEXT("Checking power capabilities "));
		exec_check(&cpu_fan_wmi, TEXT("Checking CPU fan using WMI "));
		exec_check(&query_license_value, TEXT("Checking NtQueryLicenseValue with Kernel-VMDetection-Private "));
		exec_check(&cachememory_wmi, TEXT("Checking Win32_CacheMemory with WMI "));
		exec_check(&physicalmemory_wmi, TEXT("Checking Win32_PhysicalMemory with WMI "));
		exec_check(&memorydevice_wmi, TEXT("Checking Win32_MemoryDevice with WMI "));
		exec_check(&memoryarray_wmi, TEXT("Checking Win32_MemoryArray with WMI "));
		exec_check(&voltageprobe_wmi, TEXT("Checking Win32_VoltageProbe with WMI "));
		exec_check(&portconnector_wmi, TEXT("Checking Win32_PortConnector with WMI "));
		exec_check(&smbiosmemory_wmi, TEXT("Checking Win32_SMBIOSMemory with WMI "));
		exec_check(&perfctrs_thermalzoneinfo_wmi, TEXT("Checking ThermalZoneInfo performance counters with WMI "));
		exec_check(&cim_memory_wmi, TEXT("Checking CIM_Memory with WMI "));
		exec_check(&cim_sensor_wmi, TEXT("Checking CIM_Sensor with WMI "));
		exec_check(&cim_numericsensor_wmi, TEXT("Checking CIM_NumericSensor with WMI "));
		exec_check(&cim_temperaturesensor_wmi, TEXT("Checking CIM_TemperatureSensor with WMI "));
		exec_check(&cim_voltagesensor_wmi, TEXT("Checking CIM_VoltageSensor with WMI "));
		exec_check(&cim_physicalconnector_wmi, TEXT("Checking CIM_PhysicalConnector with WMI "));
		exec_check(&cim_slot_wmi, TEXT("Checking CIM_Slot with WMI "));
		exec_check(&pirated_windows, TEXT("Checking if Windows is Genuine "));
		exec_check(&registry_services_disk_enum, TEXT("Checking Services\\Disk\\Enum entries for VM strings "));
		exec_check(&registry_disk_enum, TEXT("Checking Enum\\IDE and Enum\\SCSI entries for VM strings "));
	}

	/* VirtualBox Detection */
	if (ENABLE_VBOX_CHECKS) {
		print_category(TEXT("VirtualBox Detection"));
		vbox_reg_key_value();
		exec_check(&vbox_dir, TEXT("Checking VirtualBox Guest Additions directory "));
		vbox_files();
		vbox_reg_keys();
		exec_check(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27 "));
		exec_check(&hybridanalysismacdetect, TEXT("Checking MAC address (Hybrid Analysis) "));
		vbox_devices();
		exec_check(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd "));
		exec_check(&vbox_network_share, TEXT("Checking VirtualBox Shared Folders network provider "));
		vbox_processes();
		exec_check(&vbox_pnpentity_pcideviceid_wmi, TEXT("Checking Win32_PnPDevice DeviceId from WMI for VBox PCI device "));
		exec_check(&vbox_pnpentity_controllers_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBox controller hardware "));
		exec_check(&vbox_pnpentity_vboxname_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBOX names "));
		exec_check(&vbox_bus_wmi, TEXT("Checking Win32_Bus from WMI "));
		exec_check(&vbox_baseboard_wmi, TEXT("Checking Win32_BaseBoard from WMI "));
		exec_check(&vbox_mac_wmi, TEXT("Checking MAC address from WMI "));
		exec_check(&vbox_eventlogfile_wmi, TEXT("Checking NTEventLog from WMI "));
		exec_check(&vbox_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
		exec_check(&vbox_firmware_ACPI, TEXT("Checking ACPI tables  "));
	}

	/* VMWare Detection */
	if (ENABLE_VMWARE_CHECKS) {
		print_category(TEXT("VMWare Detection"));
		vmware_reg_key_value();
		vmware_reg_keys();
		vmware_files();
		vmware_mac();
		exec_check(&vmware_adapter_name, TEXT("Checking VMWare network adapter name "));
		vmware_devices();
		exec_check(&vmware_dir, TEXT("Checking VMWare directory "));
		exec_check(&vmware_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
		exec_check(&vmware_firmware_ACPI, TEXT("Checking ACPI tables  "));
	}

	/* Virtual PC Detection */
	if (ENABLE_VPC_CHECKS) {
		print_category(TEXT("Virtual PC Detection"));
		virtual_pc_process();
		virtual_pc_reg_keys();
	}

	/* QEMU Detection */
	if (ENABLE_QEMU_CHECKS) {
		print_category(TEXT("QEMU Detection"));
		qemu_reg_key_value();
		qemu_processes();
		exec_check(&qemu_firmware_SMBIOS, TEXT("Checking SMBIOS firmware  "));
		exec_check(&qemu_firmware_ACPI, TEXT("Checking ACPI tables  "));
	}

	/* Xen Detection */
	if (ENABLE_XEN_CHECKS) {
		print_category(TEXT("Xen Detection"));
		xen_process();
		exec_check(&xen_check_mac, TEXT("Checking Mac Address start with 08:16:3E "));

	}

	/* Wine Detection */
	if (ENABLE_WINE_CHECKS) {
		print_category(TEXT("Wine Detection"));
		exec_check(&wine_exports, TEXT("Checking Wine via dll exports "));
		wine_reg_keys();
	}

	/* Paralles Detection */
	if (ENABLE_PARALLELS_CHECKS) {
		print_category(TEXT("Paralles Detection"));
		parallels_process();
		exec_check(&parallels_check_mac, TEXT("Checking Mac Address start with 08:1C:42 "));
	}

	/* Code injections techniques */
	if (ENABLE_CODE_INJECTIONS) {
		CreateRemoteThread_Injection();
		SetWindowsHooksEx_Injection();
		NtCreateThreadEx_Injection();
		RtlCreateUserThread_Injection();
		QueueUserAPC_Injection();
		GetSetThreadContext_Injection();
	}

	/* Timing Attacks */
	if (ENABLE_TIMING_ATTACKS) {
		print_category(TEXT("Timing-attacks"));
		UINT delayInSeconds = 600U;
		UINT delayInMillis = delayInSeconds * 1000U;
		printf("\n[*] Delay value is set to %u minutes ...\n", delayInSeconds / 60);

		exec_check(timing_NtDelayexecution, delayInMillis, TEXT("Performing a sleep using NtDelayExecution ..."));
		exec_check(timing_sleep_loop, delayInMillis, TEXT("Performing a sleep() in a loop ..."));
		exec_check(timing_SetTimer, delayInMillis, TEXT("Delaying execution using SetTimer ..."));
		exec_check(timing_timeSetEvent, delayInMillis, TEXT("Delaying execution using timeSetEvent ..."));
		exec_check(timing_WaitForSingleObject, delayInMillis, TEXT("Delaying execution using WaitForSingleObject ..."));
		exec_check(timing_IcmpSendEcho, delayInMillis, TEXT("Delaying execution using IcmpSendEcho ..."));
		exec_check(timing_CreateWaitableTimer, delayInMillis, TEXT("Delaying execution using CreateWaitableTimer ..."));
		exec_check(timing_CreateTimerQueueTimer, delayInMillis, TEXT("Delaying execution using CreateTimerQueueTimer ..."));

		exec_check(&rdtsc_diff_locky, TEXT("Checking RDTSC Locky trick "));
		exec_check(&rdtsc_diff_vmexit, TEXT("Checking RDTSC which force a VM Exit (cpuid) "));
	}

	/* Malware analysis tools */
	if (ENABLE_ANALYSIS_TOOLS_CHECK) {
		print_category(TEXT("Analysis-tools"));
		analysis_tools_process();
	}

	/* Anti disassembler tricks */
	if (ENABLE_ANTI_DISASSM_CHECKS) {

		_tprintf(_T("Begin AntiDisassmConstantCondition\n"));
		AntiDisassmConstantCondition();
		_tprintf(_T("Begin AntiDisassmAsmJmpSameTarget\n"));
		AntiDisassmAsmJmpSameTarget();
		_tprintf(_T("Begin AntiDisassmImpossibleDiasassm\n"));
		AntiDisassmImpossibleDiasassm();
		_tprintf(_T("Begin AntiDisassmFunctionPointer\n"));
		AntiDisassmFunctionPointer();
		_tprintf(_T("Begin AntiDisassmReturnPointerAbuse\n"));
		AntiDisassmReturnPointerAbuse();
	}

	/* Anti Dumping */
	if (ENABLE_DUMPING_CHECK) {
		print_category(TEXT("Anti Dumping"));
		ErasePEHeaderFromMemory();
		SizeOfImage();
	}

	_tprintf(_T("\n\nAnalysis done, I hope you didn't get red flags :)"));

	getchar();
	return 0;
}

