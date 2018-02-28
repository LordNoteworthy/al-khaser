#### 0.73
- New: Add more checks for VMware related processes.
- New: Add more checks for VMware related files.
- New: Add Anti-VM checks for VMWare: SYSTEM\\ControlSet001\\Control\\SystemInformation.
- New: Add more loaded dlls check inside process context:  avghookx.dll, avghooka.dll, snxhk.dll.
- New: Add write watch debugger detection.
- New: Add service anti-VM checks.
- New: Add checks for VM related services.
- Bug fix nullref exception in timing.cpp.

#### 0.72
- Bug fix: PEB offset in NumberOfProcessors() thanks to @Nxgr.
- Bug fix: array with duplicate strings in process_tools check thanks to @stxletto.
- Bug fix: ascii_to_wide_str() wrong argument thanks to @stxletto.

### 0.71
- New: Add kernel debugger check using the KUSER_SHARED_DATA struct 
- New: Add kernel debugger check using NtQuerySystemInformation with SystemKernelDebuggerInformation.
- New: Added process job anti-debug check.
- New: Added system firmware tables with GetSystemFirmwareTable (SMBIOS and ACPI for VirtualBox).