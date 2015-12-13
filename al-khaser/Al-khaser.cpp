#include <stdio.h>
#include "Shared\Main.h"

int main(void)
{
	/* Display OS details */
	print_os();

	/* Debugger Detection */
	print_category(TEXT("Debugger Detection"));
	//exec_check(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API () "));
	//exec_check(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged "));
	//exec_check(&IsDebuggerPresentPEB, TEXT("Checking CheckRemoteDebuggerPresentAPI () "));
	//exec_check(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag "));
	//exec_check(&HeapFlags, TEXT("Checking ProcessHeap.Flags "));
	//exec_check(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags "));
	//exec_check(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort "));
	//exec_check(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags "));
	//exec_check(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject "));
	//exec_check(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger "));
	//exec_check(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
	//exec_check(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest "));
	//exec_check(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
	//exec_check(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
	//exec_check(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));
	//exec_check(&Interrupt_0x2d, TEXT("Checking Interupt 0x2d "));
	//exec_check(&Interrupt_3, TEXT("Checking Interupt 1 "));
	//exec_check(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD: "));
	//exec_check(&IsParentExplorerExe, TEXT("Checking If Parent Process is explorer.exe: "));
	//exec_check(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege : "));
	//exec_check(&NtQueryObject_ObjectTypeInformation, TEXT("Checking NtQueryObject with ObjectTypeInformation : "));
	exec_check(&NtQueryObject_ObjectAllTypesInformation, TEXT("Checking NtQueryObject with ObjectAllTypesInformation : "));


	/* Anti Dumping */
	//print_category(TEXT("Anti Dumping"));
	//exec_check(&ErasePEHeaderFromMemory, TEXT("Checking SeDebugPrivilege : "));


	/* VirtualBox Detection */
	//print_category(TEXT("VirtualBox Detection"));
	//exec_check(&IsWoW64, TEXT("Checking if process is running under WOW64: "));
	//exec_check(&vbox_scsi, TEXT("Checking Reg key HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\...: "));
	//exec_check(&vbox_SystemBiosVersion, TEXT("Checking Reg key HARDWARE\\Description\\System - SystemBiosVersion: "));
	//exec_check(&vbox_VideoBiosVersion, TEXT("Checking Reg key HARDWARE\\Description\\System - VideoBiosVersion: "));
	//exec_check(&vbox_SystemBiosDate, TEXT("Checking Reg key HARDWARE\\Description\\System - SystemBiosDate: "));
	//exec_check(&vbox_check_dir, TEXT("Checking dir oracle\\virtualbox guest additions\\: "));
	//vbox_check_files();
	//vbox_check_registry_keys();
	//exec_check(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27: "));
	//vbox_devices();
	//exec_check(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd: "));
	//exec_check(&vbox_network_share, TEXT("Checking VirtualBox Shared Folders network provider: "));

	system("PAUSE");
	return 0;
}

