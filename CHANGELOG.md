#### 0.72
- Bug fix: PEB offset in NumberOfProcessors() thanks to @Nxgr.
- Bug fix: array with duplicate strings in process_tools check thanks to @stxletto.
- Bug fix: ascii_to_wide_str() wrong argument thanks to @stxletto.

### 0.71
- New: Add kernel debugger check using the KUSER_SHARED_DATA struct 
- New: Add kernel debugger check using NtQuerySystemInformation with SystemKernelDebuggerInformation.
- New: Added process job anti-debug check.
- New: Added system firmware tables with GetSystemFirmwareTable (SMBIOS and ACPI for VirtualBox).