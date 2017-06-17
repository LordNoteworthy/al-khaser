#include "Common.h"
#include "Utils.h"

/* Anti debugs headers */
#include "..\Anti Debug\CheckRemoteDebuggerPresentAPI.h"
#include "..\Anti Debug\IsDebuggerPresent.h"
#include "..\Anti Debug\PEB_BeingDebugged.h"
#include "..\Anti Debug\ProcessHeap_Flags.h"
#include "..\Anti Debug\ProcessHeap_ForceFlags.h"
#include "..\Anti Debug\ProcessHeap_NtGlobalFlag.h"
#include "..\Anti Debug\NtQueryInformationProcess_ProcessDebugPort.h"
#include "..\Anti Debug\NtQueryInformationProcess_ProcessDebugFlags.h"
#include "..\Anti Debug\NtQueryInformationProcess_ProcessDebugObject.h"
#include "..\Anti Debug\NtSetInformationThread_ThreadHideFromDebugger.h"
#include "..\Anti Debug\CloseHandle_InvalidHandle.h"
#include "..\Anti Debug\UnhandledExceptionFilter_Handler.h"
#include "..\Anti Debug\OutputDebugStringAPI.h"
#include "..\Anti Debug\HardwareBreakpoints.h"
#include "..\Anti Debug\SoftwareBreakpoints.h"
#include "..\Anti Debug\Interrupt_0x2d.h"
#include "..\Anti Debug\Interrupt_3.h"
#include "..\Anti Debug\MemoryBreakpoints_PageGuard.h"
#include "..\Anti Debug\ParentProcess.h"
#include "..\Anti Debug\SeDebugPrivilege.h"
#include "..\Anti Debug\NtQueryObject_ObjectInformation.h"
#include "..\Anti Debug\NtYieldExecution.h"
#include "..\Anti Debug\SetHandleInformation_API.h"
#include "..\Anti Debug\TLS_callbacks.h"

/* Anti dumping headers */
#include "..\Anti Dump\ErasePEHeaderFromMemory.h"
#include "..\Anti Dump\SizeOfImage.h"

/* Anti VM headers */
#include "..\Anti VM\VirtualBox.h"
#include "..\Anti VM\VMware.h"
#include "..\Anti VM\Wine.h"
#include "..\Anti VM\Generic.h"
#include "..\Anti VM\VirtualPC.h"
#include "..\Anti VM\QEMU.h"
#include "..\Anti VM\Xen.h"
#include "..\Anti VM\Parallels.h"

/* Code Injections Headers */
#include "..\Code Injections\CreateRemoteThread.h"
#include "..\Code Injections\SetWindowsHooksEx.h"
#include "..\Code Injections\NtCreateThreadEx.h"
#include "..\Code Injections\RtlCreateUserThread.h"
#include "..\Code Injections\QueueUserAPC.h"
#include "..\Code Injections\GetSetThreadContext.h"

/* Delay Execution */
#include "..\timing-attacks\timing.h"

/* Anti-Analysis */
#include "..\Anti Analysis\process.h"





