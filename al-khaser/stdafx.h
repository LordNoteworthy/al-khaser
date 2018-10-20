//#pragma once

#include <string>
#include <vector>

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <IPTypes.h>
#include <Iphlpapi.h>
#include <icmpapi.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <ShlObj.h>
#include <stdarg.h>
#include <strsafe.h>
#include <tchar.h>
#include <time.h>
#include <TlHelp32.h>
#include <Wbemidl.h>
#include <devguid.h>    // Device guids
#include <winioctl.h>	// IOCTL
#include <intrin.h>		// cpuid()
#include <locale.h>		// 64-bit wchar atoi
#include <powrprof.h>	// check_power_modes()
#include <SetupAPI.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "powrprof.lib")

#include "Shared\Common.h"
#include "Shared\VersionHelpers.h"
#include "Shared\log.h"
#include "Shared\Utils.h"
#include "Shared\WinStructs.h"
#include "Shared\ApiTypeDefs.h"
#include "Shared\APIs.h"
#include "Shared\winapifamily.h"

/* Anti debugs headers */
#include "Anti Debug\CheckRemoteDebuggerPresentAPI.h"
#include "Anti Debug\IsDebuggerPresent.h"
#include "Anti Debug\PEB_BeingDebugged.h"
#include "Anti Debug\ProcessHeap_Flags.h"
#include "Anti Debug\ProcessHeap_ForceFlags.h"
#include "Anti Debug\ProcessHeap_NtGlobalFlag.h"
#include "Anti Debug\NtQueryInformationProcess_ProcessDebugPort.h"
#include "Anti Debug\NtQueryInformationProcess_ProcessDebugFlags.h"
#include "Anti Debug\NtQueryInformationProcess_ProcessDebugObject.h"
#include "Anti Debug\NtSetInformationThread_ThreadHideFromDebugger.h"
#include "Anti Debug\CloseHandle_InvalidHandle.h"
#include "Anti Debug\UnhandledExceptionFilter_Handler.h"
#include "Anti Debug\OutputDebugStringAPI.h"
#include "Anti Debug\HardwareBreakpoints.h"
#include "Anti Debug\SoftwareBreakpoints.h"
#include "Anti Debug\Interrupt_0x2d.h"
#include "Anti Debug\Interrupt_3.h"
#include "Anti Debug\MemoryBreakpoints_PageGuard.h"
#include "Anti Debug\ParentProcess.h"
#include "Anti Debug\SeDebugPrivilege.h"
#include "Anti Debug\NtQueryObject_ObjectInformation.h"
#include "Anti Debug\NtYieldExecution.h"
#include "Anti Debug\SetHandleInformation_API.h"
#include "Anti Debug\TLS_callbacks.h"
#include "Anti Debug\NtQuerySystemInformation_SystemKernelDebuggerInformation.h"
#include "Anti Debug\SharedUserData_KernelDebugger.h"
#include "Anti Debug\ProcessJob.h"
#include "Anti Debug\WriteWatch.h"
#include "Anti Debug\PageExceptionBreakpointCheck.h"
#include "Anti Debug\ModuleBoundsHookCheck.h"
#include "Anti Debug\ScanForModules.h"
#include "Anti Debug\WUDF_IsDebuggerPresent.h"

/* Anti dumping headers */
#include "Anti Dump\ErasePEHeaderFromMemory.h"
#include "Anti Dump\SizeOfImage.h"

/* Anti VM headers */
#include "Anti VM\VirtualBox.h"
#include "Anti VM\VMware.h"
#include "Anti VM\Wine.h"
#include "Anti VM\Generic.h"
#include "Anti VM\VirtualPC.h"
#include "Anti VM\QEMU.h"
#include "Anti VM\Xen.h"
#include "Anti VM\Parallels.h"
#include "Anti VM\Services.h"

/* Code Injections Headers */
#include "Code Injections\CreateRemoteThread.h"
#include "Code Injections\SetWindowsHooksEx.h"
#include "Code Injections\NtCreateThreadEx.h"
#include "Code Injections\RtlCreateUserThread.h"
#include "Code Injections\QueueUserAPC.h"
#include "Code Injections\GetSetThreadContext.h"

/* Delay Execution */
#include "timing-attacks\timing.h"

/* Anti-Analysis */
#include "Anti Analysis\process.h"
