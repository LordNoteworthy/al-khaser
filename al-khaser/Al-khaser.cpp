#include <stdio.h>
#include "Shared\Main.h"

int main(void)
{

	/* Resize the console window for better visibility */
	resize_console_window();

	/* Display general informations */
	_tprintf(_T("[al-khaser version 0.70]"));
	print_os();

	if (IsWoW64())
		_tprintf(_T("Process is running under WOW64\n\n"));

	/* Debugger Detection */
	print_category(TEXT("Debugger Detection"));
	exec_check(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API () "));
	exec_check(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged "));
	exec_check(&CheckRemoteDebuggerPresentAPI, TEXT("Checking CheckRemoteDebuggerPresentAPI () "));
	exec_check(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag "));
	exec_check(&HeapFlags, TEXT("Checking ProcessHeap.Flags "));
	exec_check(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags "));
	exec_check(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort "));
	exec_check(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags "));
	exec_check(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject "));
	exec_check(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger "));
	exec_check(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
	exec_check(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest "));
	exec_check(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
	exec_check(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
	exec_check(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));
	exec_check(&Interrupt_0x2d, TEXT("Checking Interupt 0x2d "));
	exec_check(&Interrupt_3, TEXT("Checking Interupt 1 "));
	exec_check(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD: "));
	exec_check(&IsParentExplorerExe, TEXT("Checking If Parent Process is explorer.exe: "));
	exec_check(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege : "));
	exec_check(&NtQueryObject_ObjectTypeInformation, TEXT("Checking NtQueryObject with ObjectTypeInformation : "));
	exec_check(&NtQueryObject_ObjectAllTypesInformation, TEXT("Checking NtQueryObject with ObjectAllTypesInformation : "));
	exec_check(&NtYieldExecutionAPI, TEXT("Checking NtYieldExecution : "));
	exec_check(&SetHandleInformatiom_ProtectedHandle, TEXT("Checking CloseHandle protected handle trick : "));

	/* Generic sandbox detection */
	print_category(TEXT("Generic Sandboxe/VM Detection"));
	loaded_dlls();
	exec_check(&NumberOfProcessors, TEXT("Checking Number of processors in machine: "));
	exec_check(&idt_trick, TEXT("Checking Interupt Descriptor Table location: "));
	exec_check(&ldt_trick, TEXT("Checking Local Descriptor Table location: "));
	exec_check(&gdt_trick, TEXT("Checking Global Descriptor Table location: "));
	exec_check(&str_trick, TEXT("Checking Global Descriptor Table location: "));
	exec_check(&number_cores_wmi, TEXT("Checking Number of cores in machine using WMI: "));
	exec_check(&disk_size_wmi, TEXT("Checking hard disk size using WMI: "));
	exec_check(&dizk_size_deviceiocontrol, TEXT("Checking hard disk size using DeviceIoControl: "));
	exec_check(&setupdi_diskdrive, TEXT("Checking SetupDi_diskdrive: "));
	exec_check(&mouse_movement, TEXT("Checking mouse movement: "));
	exec_check(&memory_space, TEXT("Checking memory space using GlobalMemoryStatusEx: "));
	exec_check(&disk_size_getdiskfreespace, TEXT("Checking disk size using GetDiskFreeSpaceEx: "));
	exec_check(&cpuid_is_hypervisor, TEXT("Checking if CPU hypervisor field is set using cpuid(0x1)"));
	exec_check(&cpuid_hypervisor_vendor, TEXT("Checking hypervisor vendor using cpuid(0x40000000)"));
	exec_check(&accelerated_sleep, TEXT("Check if time has been accelerated: "));

	/* VirtualBox Detection */
	print_category(TEXT("VirtualBox Detection"));
	vbox_reg_key_value();
	exec_check(&vbox_dir, TEXT("Checking dir oracle\\virtualbox guest additions\\: "));
	vbox_files();
	vbox_reg_keys();
	exec_check(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27: "));
	vbox_devices();
	exec_check(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd: "));
	exec_check(&vbox_network_share, TEXT("Checking VirtualBox Shared Folders network provider: "));
	vbox_processes();
	exec_check(&vbox_devices_wmi, TEXT("Checking DeviceId from WMI: "));
	exec_check(&vbox_mac_wmi, TEXT("Checking Mac address from WMI: "));
	exec_check(&vbox_eventlogfile_wmi, TEXT("Checking NTEventLog from WMI: "));

	/* VMWare Detection */
	print_category(TEXT("VMWare Detection"));
	vmware_reg_key_value();
	vmware_reg_keys();
	vmware_files();
	vmware_mac();
	exec_check(&vmware_adapter_name, TEXT("Checking VMWare network adapter name: "));
	vmware_devices();
	exec_check(&vmware_dir, TEXT("Checking VMWare directory: "));

	/* Virtual PC Detection */
	print_category(TEXT("Virtual PC Detection"));
	virtual_pc_process();

	/* QEMU Detection */
	print_category(TEXT("QEMU Detection"));
	qemu_reg_key_value();

	/* Xen Detection */
	print_category(TEXT("Xen Detection"));
	xen_process();

	/* Wine Detection */
	print_category(TEXT("Wine Detection"));
	exec_check(&wine_exports, TEXT("Checking Wine via dll exports: "));
	wine_reg_keys();

	/* Paralles Detection */
	print_category(TEXT("Paralles Detection"));
	parallels_process();

	/* Code injections techniques */
	//CreateRemoteThread_Injection();
	//SetWindowsHooksEx_Injection();
	//NtCreateThreadEx_Injection();
	//RtlCreateUserThread_Injection();
	//QueueUserAPC_Injection();
	//GetSetThreadContext_Injection();

	/* Timing Attacks */
	print_category(TEXT("Timing-attacks"));
	UINT delayInSeconds = 300U;
	UINT delayInMilliSeconds = delayInSeconds * 1000U;
	printf("\n[*] Delay value is set to %u minutes ...\n", delayInSeconds / 60);

	_tprintf(_T("[+] Performing a sleep using NtDelayexecution:\n"));
	timing_NtDelayexecution(delayInMilliSeconds);
	print_results(FALSE, _T("NtDelayexecution was bypassed ... "));

	_tprintf(_T("[+] Performing a sleep() in a loop:\n"));
	timing_sleep_loop(delayInMilliSeconds);
	print_results(FALSE, _T("Sleep in loop was bypassed ... "));

	_tprintf(_T("[*] Delaying execution using SetTimer():\n"));
	timing_SetTimer(delayInMilliSeconds);
	print_results(FALSE, _T("timing_SetTimer was bypassed ... "));

	_tprintf(_T("[*] Delaying execution using timeSetEvent():\n"));
	timing_timeSetEvent(delayInMilliSeconds);
	print_results(FALSE, _T("timeSetEvent was bypassed ... "));

	_tprintf(_T("[*] Delaying execution using WaitForSingleObject():\n"));
	timing_WaitForSingleObject(delayInMilliSeconds);
	print_results(FALSE, _T("WaitForSingleObject was bypassed ... "));

	_tprintf(_T("[*] Delaying execution using IcmpSendEcho():\n"));
	timing_IcmpSendEcho(delayInMilliSeconds);
	print_results(FALSE, _T("IcmpSendEcho was bypassed ... "));

	exec_check(&rdtsc_diff_locky, TEXT("Checking RDTSC Locky trick: "));
	exec_check(&rdtsc_diff_vmexit, TEXT("Checking RDTSC which force a VM Exit (cpuid): "));
	
	/* Malware analysis tools */
	print_category(TEXT("Analysis-tools"));
	analysis_tools_process();

	/* Anti Dumping */
	print_category(TEXT("Anti Dumping"));
	ErasePEHeaderFromMemory();
	SizeOfImage();

	_tprintf(_T("\n\nAnalysis done, I hope you didn't get red flags :)"));
	
	getchar();
	return 0;
}

