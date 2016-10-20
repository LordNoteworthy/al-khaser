#include "timing.h"

/* Timing attacks or sleepy malwares are used to bypass sandboxed in general
Every system which run in a timeout is vulmerable to this types of attacks */


VOID timing_NtDelayexecution(UINT delayInSeconds)
{
	// In this example, I will demonstrate NtDelayExecution because it is the lowest user mode
	// api to delay execution Sleep -> SleepEx -> NtDelayExecution.
	LARGE_INTEGER DelayInterval;
	LONGLONG llDelay = delayInSeconds * 10000LL;
	DelayInterval.QuadPart = -llDelay;

	// Function pointer Typedef for NtDelayExecution
	typedef NTSTATUS(WINAPI *pNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);

	// We have to import the function
	pNtDelayExecution NtDelayExecution = NULL;

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}

	NtDelayExecution = (pNtDelayExecution)GetProcAddress(hNtdll, "NtDelayExecution");
	if (NtDelayExecution == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	// Time to finally make the call
	NtDelayExecution(FALSE, &DelayInterval);
}

BOOL bProcessed = FALSE;

VOID CALLBACK TimerProc(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTime)
{
	// Malicious code is place here ....
	bProcessed = TRUE;
}


VOID timing_SetTimer(UINT delayInSeconds)
{
	MSG Msg;
	UINT_PTR iTimerID;
	
	// Set our timer without window handle
	iTimerID = SetTimer(NULL, 0, delayInSeconds, TimerProc);
	
	// Because we are running in a console app, we should get the messages from
	// the queue and check if msg is WM_TIMER
	while (GetMessage(&Msg, NULL, 0, 0) & !bProcessed) 
	{
		TranslateMessage(&Msg); 
		DispatchMessage(&Msg);
	}

	// Kill the timer
	KillTimer(NULL, iTimerID);

}


VOID CALLBACK TimerFunction(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2)
{
	bProcessed = TRUE;
}

VOID timing_timeSetEvent(UINT delayInSeconds)
{

	// Some vars
	UINT uResolution;
	TIMECAPS tc;
	MMRESULT idEvent;

	// We can obtain this minimum value by calling
	timeGetDevCaps(&tc, sizeof(TIMECAPS));
	uResolution = min(max(tc.wPeriodMin, 0), tc.wPeriodMax);

	// Create the timer
	idEvent = timeSetEvent(
		delayInSeconds,
		uResolution,
		TimerFunction,
		0,
		TIME_ONESHOT);

	while (!bProcessed){
		// wait until uor function finish
	}

	// destroy the timer
	timeKillEvent(idEvent);

	// reset the timer
	timeEndPeriod(uResolution);
}


VOID timing_WaitForSingleObject(UINT delayInSeconds)
{
	HANDLE hEvent;

	// Create a nonsignaled event
	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hEvent == NULL)
		print_last_error(_T("CreateEvent"));

	// Wait until timeout 
	DWORD x = WaitForSingleObject(hEvent, delayInSeconds);

	// Malicious code goes here

}


VOID timing_sleep_loop (UINT delayInSeconds)
{
	/* 
	This trick is about performing a low number of seconds to sleep but in a loop,
	the reason behind that sandboxes tries to avoid patching such sleeps because it
	could lead to race conditions and also because it is just negliable. However,
	when you do it in a loop, you can make it efficiant to cuz the sandboxe to reach
	its timeout.
	*/

	int delayInSeconds_divided  = delayInSeconds / 1000;

	/* Example: we want to sleep 300 seeconds, then we can sleep
	0.3s for 1000 times which is like: 300 seconds = 5 minues */
	for (int i = 0; i < 1000; i++) {
		Sleep(delayInSeconds_divided);
	}

	// Malicious code goes here
}




/*
RDSTC is a famous x86 instruction to count the number of cycle since reset.
This can be used to detect the VM. Thanks to Forcepoint for blog article.
*/

#define LODWORD(_qw)    ((DWORD)(_qw))
BOOL rdtsc_diff()
{
	ULONGLONG tsc1;
	ULONGLONG tsc2;
	ULONGLONG tsc3;
	DWORD i = 0;

	// Try this 10 times in case of small fluctuations
	for (i = 0; i < 10; i++)
	{
		tsc1 = __rdtsc();

		// Waste some cycles - should be faster than CloseHandle on bare metal
		GetProcessHeap();

		tsc2 = __rdtsc();

		// Waste some cycles - slightly longer than GetProcessHeap() on bare metal
		CloseHandle(0);

		tsc3 = __rdtsc();

		// Did it take at least 10 times more CPU cycles to perform CloseHandle than it took to perform GetProcessHeap()?
		if ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10)
			return TRUE;
	}

	// We consistently saw a small ratio of difference between GetProcessHeap and CloseHandle execution times
	// so we're probably in a VM!
	return FALSE;
}