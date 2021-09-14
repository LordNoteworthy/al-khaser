#### 0.81

- Add anti-debug trick: Low Fragmentation Heap.
- Add known hostname / username checks from malware thanks to @recvfrom.
- Add Anti-VM disk enum registry checks thanks to @recvfrom.
- Fix Patching int2d check.
- Fix wrong comment in CheckRemoteDebuggerPresent check thanks to @SpriteOvO.
- Bug fixes and new checks in ThreadHideFromDebugger.
- Improve parent process check to avoid false positives.
- Fix ScanForModules_MemoryWalk_Hidden and add new .NET structure scan.
- Add github action to build and upload binaries thanks to @graysuit.
- Add Hyper-V object checks.
- Add QEMU directory check (guest agent and SPICE tools).
- Add KVM checks (virtio reg keys, files and directory).

#### 0.80

- Add Windows Genuine check. 
- Improve GetOSDisplayString by adding Windows Server 2019.
- Fixed the encoding of some files thanks to @not-matthias.
- Add Missing manifest makes version checks return incorrect values.
- Fix EnumProcessModulesEx crash on XP and some versions of Win7.
- Fixed path names in vmware_files() and vbox_files() due to wow64 fs redirection.
- Fixed string comparaison in check_adapter_name().
- Anti anti-debug trick: trap flag.
- Add check for well known names used by malware sandboxes.
- Improve ProcessDebugObject anti-debug check thanks to @Mattiwatti


#### 0.79
- Add anti-disassembly trick: Jump with constant condition
- Add anti-disassembly trick: Jump instruction with same target
- Add anti-disassembly trick: Impossible disassembly
- Add anti-disassembly trick: Function Pointers
- Add anti-disassembly trick: Return Pointer Abuse
- Add additional tools thanks to @darianvaughanm.


#### 0.78
- Fix anti-dump SizeOfImage() thanks to @Mattiwatti
- Fix Virtualbox vartype flag check of VARIANT properties from WMI thanks to @Mattiwatti
- Fix crash for Wow64 binaries in ScanForModules_LDR_Direct thanks to @dvarshavsky
- Fix IsBadLibrary() FP's for Wow64 binaries thanks to @dvarshavsky
- Added checks for Win32_PnPDevice for VBOX entries thanks to @gsuberland
- Added checks for Win32_BaseBoard thanks to @gsuberland
- Added checks for Win32_Bus to see if only ACPIBus_BUS_0, PCI_BUS_0, PNP_BUS_0 are present thanks to @gsuberland
- Added checks for Win32_PnPEntity for known VirtualBox hardware thanks to @gsuberland
- Added checks for vbox devices (PCI\\VEN_80EE&DEV_CAFE) using WMI thanks to @gsuberland
- Added ATAIdentifyDump and StructDumpCodegen tools to the repo thanks to @gsuberland
- Add README and CHANGELOG to VS solution file.
- Delete compiled binaries from repository.
- Ignores NuGet packages directory from git.
- Fix false positive in VirtualBox BIOS serial number WMI check thanks to @gsuberland


#### 0.77
- Add a gitattributes to normalize line endings.
- Update VMDriverServices routine thanks to @hfiref0x
- Add virtual machine detect by license thanks to @hfiref0x
- Fix for HardwareBreakpoints routine thanks to @hfiref0x
- Fix memory leak in check_mac_addr routine thanks to @hfiref0x
- Update MemoryBreakpoints_PageGuard.cpp thanks to @hfiref0x
- Fix number of bugs in get_system_firmware thanks to @hfiref0x
- Fix InitWMI routine and multiple bugs in WMI related routines thanks to @hfiref0x
- Remove incorrect result checks and wrong printf specifiers in ScanForModules.cpp thanks to @hfiref0x
- Fix null pointer dereference in qemu_firmware_ACPI routine thanks to @hfiref0x
- Fix null pointer dereferences in VirtualBox.cpp & VMWare.cpp thanks to @hfiref0x
- Fix QueueUserAPC_Injection routine by rewrite thanks to @hfiref0x
- Fix null pointer dereference in setupdi_diskdrive routine thanks to @hfiref0x
- Add error handling in log_print thanks to @hfiref0x
- Fix null pointer dereference in print_last_error routine, add more error handling thanks to @hfiref0x
- Fix signed/unsigned mismatch for specifiers in various *printf calls thanks to @hfiref0x
- Fix resource leak in timing_IcmpSendEcho routine thanks to @hfiref0x
- Fix missing VirtualAlloc checks in WriteWatch.cpp thanks to @hfiref0x
- Remove incorrect return value checks thanks to @hfiref0x
- Fixed multiple bugs in check_adapter_name & ascii_to_wide_str thanks to @hfiref0x
- Update and add typecast in IsBadLibrary thanks to @hfiref0x
- Fix handle leak in GetProccessIDByName routine thanks to @hfiref0x
- Fix invalid return value check in attempt_to_read_memory_wow64 routine thanks to @hfiref0x
- Remove double call of SetDebugPrivileges in CreateRemoteThread_Injection thanks to @hfiref0x
- Fix multiple bugs in SetPrivilege routine thanks to @hfiref0x
- Fix unexpected behavior in SetHandleInformatiom_ProtectedHandle thanks to @hfiref0x
- Fix null pointer dereference in get_system_firmware routine thanks to @hfiref0x
- Fix multiple bugs in {Services, log, Generic, timing, process, ScanForModules cpp files}  thanks to @hfiref0x
- Fix null pointer derefence in {vmware,vbox,qemu}_firmware_ACPI thanks to @hfiref0x
- Fix resource leak in ScanForModules_ToolHelp32 routine thanks to @hfiref0x
- Fix multiple bugs in ProcessJob routine thanks to @hfiref0x

#### 0.76
- Renamed PEB_BeingDebugged.cpp to BeingDebugged.cpp
- Renamed CheckRemoteDebuggerPresentAPI.cpp to CheckRemoteDebuggerPresent.cpp
- Renamed ProcessHeap_NtGlobalFlag.cpp to NtGlobalFlag.cpp
- Fix expression is always true in ScanForModules_LDR_Direct routine thanks to @hfiref0x
- Fix multiple bugs in GetSetThreadContext_Injection routine thanks to @hfiref0x
- Fix multiple bugs in CreateRemoteThread_Injection thanks to @hfiref0x
- Fix invalid return value check in QueueUserAPC_Injection routine thanks to @hfiref0x
- Fix multiple bugs in NtCreateThreadEx_Injection and actually make it work thanks to @hfiref0x
- Fix multiple bugs in RtlCreateUserThread_Injection routine thanks to @hfiref0x
- Rearrange a bit RtlCreateUserThread_Injection routine thanks to @hfiref0x
- Fix multiple bugs in GetMainThreadId thanks to @hfiref0x
- Fix always true expression in PrintAvailabilityReport routine thanks to @hfiref0x
- Fix resource leak in vmware_devices routine thanks to @hfiref0x
- Fix resource leak in vbox_devices routine thanks to @hfiref0x
- Fix invalid comparison in IsBadLibrary routine thanks to @hfiref0x
- Fix invalid memory allocation size in HardwareBreakpoints routine thanks to @hfiref0x
- Update print_os routine thanks to @hfiref0x
- Moved the project to Visual Studio 2017
- Add AppVeyor CI to build the project and check for errors.
- Add WMI Win32_Fan anti-vm trick
- Add DLL injection detection #148 (thanks to @gsuberland):
    - Enumerate modules with EnumProcessModulesEx (32-bit, 64-bit, and all options)
    - Enumerate modules with ToolHelp32
    - Enumerate the process LDR structures
    - Walk memory with GetModuleInformation
    - Walk memory for hidden modules
    - Patch issue with IsWin10OrGreater() due to missing compatibility GUIDs in application manifest
    - Add support for detecting presence of APIs that were removed in a later OS version
    - Add some WoW64 memory read/query utility functions for reading the 64-bit address space
- Added enumerate_memory function for finding all memory allocations in the process thanks to @gsuberland

#### 0.75
- Fixed a typo in API data structure and move print_os() after API initialization thanks to @hzqst
- Added page exception breakpoint anti-debug check (mainly focused on Cheat Engine)
- Added checks for power capabilities (GetPwrCapabilities)
- Added CreateWaitableTimer and CreateTimerQueueTimer timing attack checks
- Added Comodo sandbox checks thanks to @kaganisildak
- Added Hybrid Analysis sandbox checks thanks to @kaganisildak
- Improved TLS callback checks (no longer requires user interaction)
- Improved check text output so that it displays the it before the check completes
- Improved ThreadHideFromDebugger check
- Improved disk size IOCTL checks
- Improved reporting of timing checks
- Overhauled the code to use precompiled headers
- Added a standardised way to load and check APIs that aren't always available
- Fixed a bug that caused TLS callbacks to not always work
- Fixed a bug which resulted in a crash when RtlGetVersion was not available
- Fixed a string formatting bug in the Xen VM checks
- Fixed a bug where disk size was not read properly in the disk size WMI check
- Fixed a bug where the locky timer trick never worked

#### 0.74
- Added qemu process check (qemu-ga.exe) thanks to @kaganisildak.
- Added checks for system firmware tables (SMBIOS and ACPI for QEMU).
- Added checks for Hyper-V/Virtual-PC anti-VM (HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters)
- Added checks for multiple virtualization vendors using WMI (Select SerialNumber from Win32_BIOS).
- Added checks for multiple virtualization vendors using WMI (Select Model/Manufacturer from Win32_ComputerSystem).
- Added checks for MAC address for Xen, Parallels.
- Added checks for ProcessorId using WMI (Select ProcessorId from Win32_Process).
- Added checks for current CPU temperature using WMI (Select CurrentTemperature from MSAcpi_ThermalZoneTemperature).

#### 0.73
- Bug fix: GetSystemFirmwareTable should take `resultBufferSize` as an argument for the second call.
- Bug fix: nullref exception in timing.cpp.
- New: Add more checks for VMware related processes.
- New: Add more checks for VMware related files.
- New: Add more checks for VMWare related registry: SYSTEM\\ControlSet001\\Control\\SystemInformation.
- New: Add more checks for system firmware tables (SMBIOS and ACPI for VMware).
- New: Add more loaded dlls check inside process context:  avghookx.dll, avghooka.dll, snxhk.dll.
- New: Add write watch debugger detection.
- New: Add service anti-VM checks.
- New: Add checks for VM related services.
- Enhancement: add some macros to enable/disable a particular category of checks to easy debugging.

#### 0.72
- Bug fix: PEB offset in NumberOfProcessors() thanks to @Nxgr.
- Bug fix: array with duplicate strings in process_tools check thanks to @stxletto.
- Bug fix: ascii_to_wide_str() wrong argument thanks to @stxletto.

#### 0.71
- New: Add kernel debugger check using the KUSER_SHARED_DATA struct.
- New: Add kernel debugger check using NtQuerySystemInformation with SystemKernelDebuggerInformation.
- New: Added process job anti-debug check.
- New: Added system firmware tables with GetSystemFirmwareTable (SMBIOS and ACPI for VirtualBox).