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
- Virtualbox registry key values artifacts:
	- "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 (Identifier)
	- HARDWARE\\Description\\System (SystemBiosVersion)
	- HARDWARE\\Description\\System (VideoBiosVersion)
	- HARDWARE\\Description\\System (SystemBiosDate)
- Virtualbox registry Keys artifacts
	- "HARDWARE\\ACPI\\RSDT\\VBOX__"
	- "HARDWARE\\ACPI\\FADT\\VBOX__"
	- "HARDWARE\\ACPI\\RSDT\\VBOX__"
	- "SOFTWARE\\Oracle\\VirtualBox Guest Additions"
	- "SYSTEM\\ControlSet001\\Services\\VBoxGuest"
	- "SYSTEM\\ControlSet001\\Services\\VBoxMouse"
	- "SYSTEM\\ControlSet001\\Services\\VBoxService"
	- "SYSTEM\\ControlSet001\\Services\\VBoxSF"
	- "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
- Virtualbox file system artifacts:
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
- Virtualbox directories artifacts:
	- "oracle\\virtualbox guest additions\\"
- Virtualbox MAC Address:
	- "\x08\x00\x27"
- Virtualbox virtual devices:
	- "\\\\.\\VBoxMiniRdrDN"
	- "\\\\.\\VBoxGuest"
	- "\\\\.\\pipe\\VBoxMiniRdDN"
	- "\\\\.\\VBoxTrayIPC"
	- "\\\\.\\pipe\\VBoxTrayIPC")
- Virtualbox Windows Class
	- VBoxTrayToolWndClass
	- VBoxTrayToolWnd
- Virtualbox network share
	- VirtualBox Shared Folders
- Virtualbox process list
	- vboxservice.exe
	- vboxtray.exe

# Anti Dumping
- Erase PE header from memory


# Code/DLL Injections techniques
- CreateRemoteThread 
- SetWindowsHooksEx
- NtCreateThreadEx
- RtlCreateUserThread
- APC (QueueUserAPC / NtQueueApcThread)
- RunPE (GetThreadContext / SetThreadContext)

# Timing Attacks
- Sleep -> SleepEx -> NtDelayExecution
- SetTimer (Standard Windows Timers)
- timeSetEvent (Multimedia Timers)
- WaitForSingleObject -> WaitForSingleObjectEx -> NtWaitForSingleObject
- WaitForMultipleObjects -> WaitForMultipleObjectsEx -> NtWaitForMultipleObjects (todo)
- CreateWaitableTimer (todo)
- CreateTimerQueueTimer (todo)
- Sleep (in a loop a small delay) (todo)
- Sleep and check if sit was not accelerated (todo)


# Human Interaction
- Mouse (Single click / Double click) (todo)
- DialogBox (todo)
- Scrolling (todo)
- Execution after reboot (todo)
- CPU cores (todo) (Win32/Tinba)
- Sandbox known product IDs (todo)
- Color of background pixel
- Keyboard layout (Win32/Banload) (todo)



