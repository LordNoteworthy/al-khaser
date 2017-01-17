#include <windows.h>
#include <tchar.h>
#include <Mmsystem.h>
#include <intrin.h>

#pragma comment(lib, "Winmm.lib")

#include "..\Shared\Common.h"

VOID timing_SetTimer(UINT delayInSeconds);
VOID timing_NtDelayexecution(UINT delayInSeconds);
VOID timing_timeSetEvent(UINT delayInSeconds);
VOID timing_WaitForSingleObject(UINT delayInSeconds);
VOID timing_sleep_loop(UINT delayInSeconds);
BOOL rdtsc_diff_locky();
BOOL rdtsc_diff_vmexit();



