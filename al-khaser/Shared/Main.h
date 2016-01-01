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

/* Anti dumping headers */
#include "..\Anti Dump\ErasePEHeaderFromMemory.h"

/* Anti VM headers */
#include "..\Anti VM\VirtualBox.h"

/* Code Injections Headers */
#include "..\Code Injections\CreateRemoteThread_LoadLibrary.h"
#include "..\Code Injections\SetWindowsHooksEx.h"







