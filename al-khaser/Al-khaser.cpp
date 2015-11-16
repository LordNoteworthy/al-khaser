#include <stdio.h>
#include "Shared\Main.h"

int main(void)
{
	/* Display OS details */
	print_os();

	/* Debugger Detection */
	print_category(TEXT("Debugger Detection"));
	exec_check(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API () "));
	exec_check(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged "));
	exec_check(&IsDebuggerPresentPEB, TEXT("Checking CheckRemoteDebuggerPresentAPI () "));
	exec_check(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag "));
	exec_check(&HeapFlags, TEXT("Checking ProcessHeap.Flags "));
	exec_check(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags "));
	exec_check(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort "));
	exec_check(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags "));
	exec_check(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject "));
	exec_check(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger "));
	exec_check(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle "));
	exec_check(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest "));
	exec_check(&OutputDebugStringAPI, TEXT("Checking OutputDebugString "));
	exec_check(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints "));
	exec_check(&SoftwareBreakpoints, TEXT("Checking Software Breakpoints "));

	system("PAUSE");
	return 0;
}

