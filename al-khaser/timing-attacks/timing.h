#include <windows.h>
#include <tchar.h>
#include <Mmsystem.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#pragma comment(lib, "Winmm.lib")

#include "..\Shared\Common.h"

VOID timing_SetTimer(UINT delayInMilliSeconds);
VOID timing_NtDelayexecution(UINT delayInMilliSeconds);
VOID timing_timeSetEvent(UINT delayInMilliSeconds);
VOID timing_WaitForSingleObject(UINT delayInMilliSeconds);
VOID timing_sleep_loop(UINT delayInMilliSeconds);
BOOL rdtsc_diff_locky();
BOOL rdtsc_diff_vmexit();
VOID timing_IcmpSendEcho(UINT delayInMilliSeconds);

