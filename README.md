##Al-Khaser v0.3

![Logo](https://www.mindmeister.com/files/avatars/0035/8332/original/avatar.jpg)

## Content

- [Introduction](#introduction)
- [Possible uses](#uses)
- [Features](#features)
 - [Anti-debugging attacks](#antidebug)
 - [Anti-virtualization attacks](#antivm)
 - [Anti-Dumping attacks](#antivm)
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
# Anti-debugging attacks
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

# Anti-virtualization
- Registry key values
  - "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier)
  - HARDWARE\\Description\\System (SystemBiosVersion)
  - HARDWARE\\Description\\System (VideoBiosVersion)
  - HARDWARE\\Description\\System (SystemBiosDate)
 - Registry Keys:
	- "HARDWARE\\ACPI\\RSDT\\VBOX__"
	- "HARDWARE\\ACPI\\FADT\\VBOX__"
	- "HARDWARE\\ACPI\\RSDT\\VBOX__"
	- "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
	- "SYSTEM\\ControlSet001\\Services\\VBoxGuest"
	- "SYSTEM\\ControlSet001\\Services\\VBoxMouse"
	- "SYSTEM\\ControlSet001\\Services\\VBoxService"
	- "SYSTEM\\ControlSet001\\Services\\VBoxSF"
	- "SYSTEM\\ControlSet001\\Services\\VBoxVideo"


# Anti Dumping
- Erase PE header from memory


# Code Injections techniques
- CreateRemoteThread (DLL Injection)
- CreateRemoteThread (ShellCode)
- SetWindowsHooksEx


