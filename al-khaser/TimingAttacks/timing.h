#pragma once

BOOL timing_SetTimer(UINT delayInMillis);
BOOL timing_NtDelayexecution(UINT delayInMillis);
BOOL timing_timeSetEvent(UINT delayInMillis);
BOOL timing_WaitForSingleObject(UINT delayInMillis);
BOOL timing_sleep_loop(UINT delayInMillis);
BOOL rdtsc_diff_locky();
BOOL rdtsc_diff_vmexit();
BOOL timing_IcmpSendEcho(UINT delayInMillis);
BOOL timing_CreateWaitableTimer(UINT delayInMillis);
BOOL timing_CreateTimerQueueTimer(UINT delayInMillis);
VOID CALLBACK CallbackCTQT(PVOID lParam, BOOLEAN TimerOrWaitFired);
