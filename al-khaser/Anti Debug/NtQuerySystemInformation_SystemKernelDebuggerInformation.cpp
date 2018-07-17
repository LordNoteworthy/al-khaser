#include "stdafx.h"

#include "NtQuerySystemInformation_SystemKernelDebuggerInformation.h"

/*
When NtQuerySystemInformation is called with the SystemKernelDebuggerInformation class, the function will return
a SYSTEM_KERNEL_DEBUGGER_INFORMATION struct which will reveal the presence of a kernel debugger.
*/

BOOL NtQuerySystemInformation_SystemKernelDebuggerInformation()
{
   	// SystemKernelDebuggerInformation
	const int SystemKernelDebuggerInformation = 0x23;

	// The debugger information struct
	SYSTEM_KERNEL_DEBUGGER_INFORMATION KdDebuggerInfo;

	HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
	if(hNtDll == NULL)
		DbgRaiseAssertionFailure();
 
	// Get the function address
	pNtQuerySystemInformation NtQuerySystemInfo = (pNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
	if(NtQuerySystemInfo == NULL)
		DbgRaiseAssertionFailure();
	
	// Call NtQuerySystemInformation
	NTSTATUS Status = NtQuerySystemInfo(SystemKernelDebuggerInformation, &KdDebuggerInfo, sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION), NULL);
	if (Status >= 0)
	{
		// KernelDebuggerEnabled almost always implies !KernelDebuggerNotPresent. KernelDebuggerNotPresent can sometimes
		// change if the debugger is temporarily disconnected, but either of these means a debugger is enabled.
		if (KdDebuggerInfo.KernelDebuggerEnabled || !KdDebuggerInfo.KernelDebuggerNotPresent)
			return TRUE;
	}
	return FALSE;
}
