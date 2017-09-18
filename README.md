## Al-Khaser v0.70

![Logo](https://www.mindmeister.com/files/avatars/0035/8332/original/avatar.jpg)

## Content

- [Introduction](#introduction)
- [Possible uses](#uses)
- [Features](#features)
 - [Anti-debugging attacks](#antidebug)
 - [Anti-Dumping](#antidump)
 - [Timing Attacks](#timingattack)
 - [Human Interaction](#antidump)
 - [Anti-VM](#antivm)
- [Requirements](#requirements)
- [License](#license)


## Introduction

al-khaser is a PoC malware with good intentions that aimes to stress your anti-malware system.
It performs a bunch of nowadays malwares tricks and the goal is to see if you stay under the radar.

![Logo](https://i.imgur.com/jEFhsJT.png)


## Download

You can download the last release [here](https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser.exe?raw=true).


## Possible uses

- You are making an anti-debug plugin and you want to check its effectiveness.
- You want to ensure that your sandbox solution is hidden enough.
- Or you want to ensure that your malware analysis environement is well hidden.

Please, if you encounter any of the anti-analysis tricks which you have seen in a malware, don't hesitate to contribute.


## Features
### Anti-debugging attacks
- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- Process Environement Block (BeingDebugged)
- Process Environement Block (NtGlobalFlag)
- ProcessHeap (Flags)
- ProcessHeap (ForceFlags)
- NtQueryInformationProcess (ProcessDebugPort)
- NtQueryInformationProcess (ProcessDebugFlags)
- NtQueryInformationProcess (ProcessDebugObject)
- NtSetInformationThread (HideThreadFromDebugger)
- NtQueryObject (ObjectTypeInformation)
- NtQueryObject (ObjectAllTypesInformation)
- CloseHanlde (NtClose) Invalide Handle
- SetHandleInformation (Protected Handle)
- UnhandledExceptionFilter
- OutputDebugString (GetLastError())
- Hardware Breakpoints (SEH / GetThreadContext)
- Software Breakpoints (INT3 / 0xCC)
- Memory Breakpoints (PAGE_GUARD)
- Interrupt 0x2d
- Interrupt 1
- Parent Process (Explorer.exe)
- SeDebugPrivilege (Csrss.exe)
- NtYieldExecution / SwitchToThread
- TLS callbacks

### Anti-Dumping
- Erase PE header from memory
- SizeOfImage

### Timing Attacks [Anti-Sandbox]
- RDTSC (with CPUID to force a VM Exit)
- RDTSC (Locky version with GetProcessHeap & CloseHandle)
- Sleep -> SleepEx -> NtDelayExecution
- Sleep (in a loop a small delay)
- Sleep and check if time was accelerated (GetTickCount)
- SetTimer (Standard Windows Timers)
- timeSetEvent (Multimedia Timers)
- WaitForSingleObject -> WaitForSingleObjectEx -> NtWaitForSingleObject
- WaitForMultipleObjects -> WaitForMultipleObjectsEx -> NtWaitForMultipleObjects (todo)
- IcmpSendEcho (CCleaner Malware)
- CreateWaitableTimer (todo)
- CreateTimerQueueTimer (todo)
- Big crypto loops (todo)

### Human Interaction / Generic [Anti-Sandbox]
- Mouse movement
- Total Physical memory (GlobalMemoryStatusEx)
- Disk size using DeviceIoControl (IOCTL_DISK_GET_LENGTH_INFO)
- Disk size using GetDiskFreeSpaceEx (TotalNumberOfBytes)
- Mouse (Single click / Double click) (todo)
- DialogBox (todo)
- Scrolling (todo)
- Execution after reboot (todo)
- Count of processors (Win32/Tinba - Win32/Dyre)
- Sandbox known product IDs (todo)
- Color of background pixel (todo)
- Keyboard layout (Win32/Banload) (todo)

### Anti-Virtualization / Full-System Emulation
- **Registry key value artifacts**
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VBOX)
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (QEMU)
	- HARDWARE\\Description\\System (SystemBiosVersion) (VBOX)
	- HARDWARE\\Description\\System (SystemBiosVersion) (QEMU)
	- HARDWARE\\Description\\System (VideoBiosVersion) (VIRTUALBOX)
	- HARDWARE\\Description\\System (SystemBiosDate) (06/23/99)
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VMWARE)
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VMWARE)
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VMWARE)

- **Registry Keys artifacts**
	- "HARDWARE\\ACPI\\DSDT\\VBOX__"
	- "HARDWARE\\ACPI\\FADT\\VBOX__"
	- "HARDWARE\\ACPI\\RSDT\\VBOX__"
	- "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
	- "SYSTEM\\ControlSet001\\Services\\VBoxGuest"
	- "SYSTEM\\ControlSet001\\Services\\VBoxMouse"
	- "SYSTEM\\ControlSet001\\Services\\VBoxService"
	- "SYSTEM\\ControlSet001\\Services\\VBoxSF"
	- "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
	- SOFTWARE\\VMware, Inc.\\VMware Tools
	- SOFTWARE\\Wine

- **File system artifacts**
	- "system32\\drivers\\VBoxMouse.sys"
	- "system32\\drivers\\VBoxGuest.sys"
	- "system32\\drivers\\VBoxSF.sys"
	- "system32\\drivers\\VBoxVideo.sys"
	- "system32\\vboxdisp.dll"
	- "system32\\vboxhook.dll"
	- "system32\\vboxmrxnp.dll"
	- "system32\\vboxogl.dll"
	- "system32\\vboxoglarrayspu.dll"
	- "system32\\vboxoglcrutil.dll"
	- "system32\\vboxoglerrorspu.dll"
	- "system32\\vboxoglfeedbackspu.dll"
	- "system32\\vboxoglpackspu.dll"
	- "system32\\vboxoglpassthroughspu.dll"
	- "system32\\vboxservice.exe"
	- "system32\\vboxtray.exe"
	- "system32\\VBoxControl.exe"
	- "system32\\drivers\\vmmouse.sys"
	- "system32\\drivers\\vmhgfs.sys"

- **Directories artifacts**
	- "%PROGRAMFILES%\\oracle\\virtualbox guest additions\\"
	- "%PROGRAMFILES%\\VMWare\\"

- **Memory artifacts**
	- Interupt Descriptor Table (IDT) location
	- Local Descriptor Table (LDT) location
	- Global Descriptor Table (GDT) location
	- Task state segment trick with STR

- **MAC Address**
	- "\x08\x00\x27" (VBOX)
	- "\x00\x05\x69" (VMWARE)
	- "\x00\x0C\x29" (VMWARE)
	- "\x00\x1C\x14" (VMWARE)
	- "\x00\x50\x56" (VMWARE)

- **Virtual devices**
	- "\\\\.\\VBoxMiniRdrDN"
	- "\\\\.\\VBoxGuest"
	- "\\\\.\\pipe\\VBoxMiniRdDN"
	- "\\\\.\\VBoxTrayIPC"
	- "\\\\.\\pipe\\VBoxTrayIPC")
	- "\\\\.\\HGFS"
	- "\\\\.\\vmci"

- **Hardware Device information**
	- SetupAPI SetupDiEnumDeviceInfo (GUID_DEVCLASS_DISKDRIVE) 
		- QEMU
		- VMWare
		- VBOX
		- VIRTUAL HD

- **Adapter name**
	- VMWare

- **Windows Class**
	- VBoxTrayToolWndClass
	- VBoxTrayToolWnd

- **Network shares**
	- VirtualBox Shared Folders

- **Processes**
	- vboxservice.exe	(VBOX)
	- vboxtray.exe		(VBOX)
	- vmtoolsd.exe		(VMWARE)
	- vmwaretray.exe	(VMWARE)
	- vmwareuser		(VMWARE)
	- vmsrvc.exe		(VirtualPC)
	- vmusrvc.exe		(VirtualPC)
	- prl_cc.exe		(Parallels)
	- prl_tools.exe		(Parallels)
	- xenservice.exe	(Citrix Xen)

- **WMI**
	- SELECT * FROM Win32_Bios (SerialNumber) (VMWARE)
	- SELECT * FROM Win32_PnPEntity (DeviceId) (VBOX)
	- SELECT * FROM Win32_NetworkAdapterConfiguration (MACAddress) (VBOX)
	- SELECT * FROM Win32_NTEventlogFile (VBOX)
	- SELECT * FROM Win32_Processor (NumberOfCores) (GENERIC)
	- SELECT * FROM Win32_LogicalDisk (Size) (GENERIC)

- **DLL Exports and Loaded DLLs**
	- kernel32.dll!wine_get_unix_file_nameWine (Wine)
	- sbiedll.dll (Sandboxie)
	- dbghelp.dll (MS debugging support routines)
	- api_log.dll (iDefense Labs)
	- dir_watch.dll (iDefense Labs)
	- pstorec.dll (SunBelt Sandbox)
	- vmcheck.dll (Virtual PC)
	- wpespy.dll (WPE Pro)

- **CPU**
	- Hypervisor presence using (EAX=0x1)
	- Hypervisor vendor using (EAX=0x40000000)
		- "KVMKVMKVM\0\0\0"	(KVM)
		- "Microsoft Hv"	(Microsoft Hyper-V or Windows Virtual PC)
		- "VMwareVMware"	(VMware)
		- "XenVMMXenVMM"	(Xen)
		- "prl hyperv  "	( Parallels)
		 -"VBoxVBoxVBox"	( VirtualBox)


### Anti-Analysis
- **Processes**
	- OllyDBG / ImmunityDebugger / WinDbg / IDA Pro
	- SysInternals Suite Tools (Process Explorer / Process Monitor / Regmon / Filemon, TCPView, Autoruns)
	- Wireshark / Dumpcap
	- ProcessHacker / SysAnalyzer / HookExplorer / SysInspector
	- ImportREC / PETools / LordPE
	- JoeBox Sandbox

### Macro malware attacks
- Document_Close / Auto_Close.
- Application.RecentFiles.Count 


### Code/DLL Injections techniques
- CreateRemoteThread 
- SetWindowsHooksEx
- NtCreateThreadEx
- RtlCreateUserThread
- APC (QueueUserAPC / NtQueueApcThread)
- RunPE (GetThreadContext / SetThreadContext)


## Contributors
- [mrexodia](http://mrexodia.cf): Main developer of [x64dbg](http://x64dbg.com/)
- [JoeSecurity](https://github.com/joesecurity/pafishmacro): PafishMacro

## References
- An Anti-Reverse Engineering Guide By Josh Jackson.
- Anti-Unpacker Tricks By Peter Ferrie.
- The Art Of Unpacking By Mark Vincent Yason.
- Walied Assar's blog http://waleedassar.blogspot.de/.
- Pafish tool: https://github.com/a0rtega/pafish.

