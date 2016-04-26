##Al-Khaser v0.3

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
It performs a bunch of nowadays malwares tricks and the goal is to see if you catch them all.

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

### Anti-Dumping
- Erase PE header from memory

### Timing Attacks [Anti-Sandbox]
- Sleep -> SleepEx -> NtDelayExecution
- Sleep (in a loop a small delay) (todo)
- Sleep and check if accelerated (todo)
- SetTimer (Standard Windows Timers)
- timeSetEvent (Multimedia Timers)
- WaitForSingleObject -> WaitForSingleObjectEx -> NtWaitForSingleObject
- WaitForMultipleObjects -> WaitForMultipleObjectsEx -> NtWaitForMultipleObjects (todo)
- CreateWaitableTimer (todo)
- CreateTimerQueueTimer (todo)
- Big crypto loops (todo)

### Human Interaction [Anti-Sandbox]
- Mouse (Single click / Double click) (todo)
- DialogBox (todo)
- Scrolling (todo)
- Execution after reboot (todo)
- CPU cores (todo) (Win32/Tinba)
- Sandbox known product IDs (todo)
- Color of background pixel
- Keyboard layout (Win32/Banload) (todo)

### Anti-Virtualization
- **Registry key value artifacts**
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VBOX)
	- HARDWARE\\Description\\System (SystemBiosVersion) (VBOX)
	- HARDWARE\\Description\\System (VideoBiosVersion) (VIRTUALBOX)
	- HARDWARE\\Description\\System (SystemBiosDate) (06/23/99)
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VMWARE)
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VMWARE)
	- HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier) (VMWARE)

- **Registry Keys artifacts**
	- "HARDWARE\\ACPI\\RSDT\\VBOX__"
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

- **Adapter name**
	- VMWare

- **Windows Class**
	- VBoxTrayToolWndClass
	- VBoxTrayToolWnd

- **Network shares**
	- VirtualBox Shared Folders

- **Processes**
	- vboxservice.exe
	- vboxtray.exe
	- vmtoolsd.exe

- **WMI**
	- SELECT * FROM Win32_Bios (SerialNumber) (VMWARE)
	- SELECT * FROM Win32_PnPEntity (DeviceId) (VBOX)
	- SELECT * FROM Win32_NetworkAdapterConfiguration (VBOX)

- **DLL Exports and Loaded DLLs**
	- kernel32.dll!wine_get_unix_file_nameWine (Wine)
	- sbiedll.dll (Sandboxie)
	- dbghelp.dll (MS debugging support routines)
	- api_log.dll (SunBelt SandBox)
	- dir_watch.dll (SunBelt SandBox)
	- pstorec.dll (SunBelt Sandbox)
	- vmcheck.dll (Virtual PC)
	- wpespy.dll (WPE Pro)

### Code/DLL Injections techniques
- CreateRemoteThread 
- SetWindowsHooksEx
- NtCreateThreadEx
- RtlCreateUserThread
- APC (QueueUserAPC / NtQueueApcThread)
- RunPE (GetThreadContext / SetThreadContext)


## References

- An Anti-Reverse Engineering Guide By Josh Jackson.
- Anti-Unpacker Tricks By Peter Ferrie.
- The Art Of Unpacking By Mark Vincent Yason.
- Walied Assar's blog http://waleedassar.blogspot.de/
- Pafish tool: https://github.com/a0rtega/pafish
