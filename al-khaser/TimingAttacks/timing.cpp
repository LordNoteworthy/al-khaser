#include "pch.h"
#include "timing.h"

/* Timing attacks or sleepy malwares are used to bypass sandboxed in general
Every system which run in a timeout is vulmerable to this types of attacks */

BOOL timing_NtDelayexecution(UINT delayInMillis)
{
	// In this example, I will demonstrate NtDelayExecution because it is the lowest user mode
	// api to delay execution Sleep -> SleepEx -> NtDelayExecution.
	LARGE_INTEGER DelayInterval;
	LONGLONG llDelay = delayInMillis * 10000LL;
	DelayInterval.QuadPart = -llDelay;

	if (!API::IsAvailable(API_IDENTIFIER::API_NtDelayExecution))
		return TRUE; // TODO: make this a warning (NtDelayExecution should always exist)

	auto NtDelayExecution = static_cast<pNtDelayExecution>(API::GetAPI(API_IDENTIFIER::API_NtDelayExecution));
	NtDelayExecution(FALSE, &DelayInterval);

	return FALSE;
}

BOOL bProcessed = FALSE;

VOID CALLBACK TimerProc(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTime)
{
	// Malicious code is place here ....
	bProcessed = TRUE;
}


BOOL timing_SetTimer(UINT delayInMillis)
{
	MSG Msg;
	UINT_PTR iTimerID;
	
	// Set our timer without window handle
	iTimerID = SetTimer(NULL, 0, delayInMillis, TimerProc);

	if (iTimerID == NULL)
		return TRUE;
	
	// Because we are running in a console app, we should get the messages from
	// the queue and check if msg is WM_TIMER
	while (GetMessage(&Msg, NULL, 0, 0) & !bProcessed) 
	{
		TranslateMessage(&Msg); 
		DispatchMessage(&Msg);
	}

	// Kill the timer
	KillTimer(NULL, iTimerID);

	return FALSE;
}


VOID CALLBACK TimerFunction(UINT uTimerID, UINT uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2)
{
	bProcessed = TRUE;
}

BOOL timing_timeSetEvent(UINT delayInMillis)
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
		delayInMillis,
		uResolution,
		TimerFunction,
		0,
		TIME_ONESHOT);

	if (idEvent == NULL)
		return TRUE;

	while (!bProcessed){
		// wait until uor function finish
	}

	// destroy the timer
	timeKillEvent(idEvent);

	// reset the timer
	timeEndPeriod(uResolution);

	return FALSE;
}


BOOL timing_WaitForSingleObject(UINT delayInMillis)
{
	HANDLE hEvent;

	// Create a nonsignaled event
	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hEvent == NULL)
	{
		print_last_error(_T("CreateEvent"));
		return TRUE;
	}

	// Wait until timeout 
	DWORD x = WaitForSingleObject(hEvent, delayInMillis);

	// Malicious code goes here

	return FALSE;
}


BOOL timing_sleep_loop (UINT delayInMillis)
{
	/* 
	This trick is about performing a low number of seconds to sleep but in a loop,
	the reason behind that sandboxes tries to avoid patching such sleeps because it
	could lead to race conditions and also because it is just negliable. However,
	when you do it in a loop, you can make it efficiant to cuz the sandboxe to reach
	its timeout.
	*/

	int delayInMillis_divided  = delayInMillis / 1000;

	/* Example: we want to sleep 300 seeconds, then we can sleep
	0.3s for 1000 times which is like: 300 seconds = 5 minues */
	for (int i = 0; i < 1000; i++) {
		Sleep(delayInMillis_divided);
	}

	// Malicious code goes here

	return FALSE;
}


/*
RDSTC is a famous x86 instruction to count the number of cycle since reset.
This can be used to detect the VM. Thanks to Forcepoint for blog article.
*/

#define LODWORD(_qw)    ((DWORD)(_qw))
BOOL rdtsc_diff_locky()
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
			return FALSE;
	}

	// We consistently saw a small ratio of difference between GetProcessHeap and CloseHandle execution times
	// so we're probably in a VM!
	return TRUE;
}


/*
CPUID is an instruction which cauz a VM Exit to the VMM, 
this little overhead can show the presence of a hypervisor
*/

BOOL rdtsc_diff_vmexit()
{
	ULONGLONG tsc1 = 0;
	ULONGLONG tsc2 = 0;
	ULONGLONG avg = 0;
	INT cpuInfo[4] = {};

	// Try this 10 times in case of small fluctuations
	for (INT i = 0; i < 10; i++)
	{
		tsc1 = __rdtsc();
		__cpuid(cpuInfo, 0);
		tsc2 = __rdtsc();

		// Get the delta of the two RDTSC
		avg += (tsc2 - tsc1);
	}

	// We repeated the process 10 times so we make sure our check is as much reliable as we can
	avg = avg / 10;
	return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}


/*
Another timinig attack using the API IcmpSendEcho which takes a TimeOut 
in milliseconds as a parameter, to wait for IPv4 ICMP packets replies.
First time observed: http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html
*/
BOOL timing_IcmpSendEcho(UINT delayInMillis)
{

	HANDLE hIcmpFile;
	unsigned long DestinationAddress = INADDR_NONE;
	char SendData[32] = "Data Buffer";
	LPVOID ReplyBuffer = NULL;
	DWORD ReplySize = 0;
	const char ipaddr[] = "224.0.0.0";

	hIcmpFile = IcmpCreateFile();
	if (hIcmpFile == INVALID_HANDLE_VALUE) {
		printf("\tUnable to open handle.\n");
		printf("IcmpCreatefile returned error: %u\n", GetLastError());
		return TRUE;
	}

	//
	// Size of ICMP_ECHO_REPLY + size of send data + 8 extra bytes for ICMP error message
	//
	ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData) + 8;
	ReplyBuffer = (VOID*)malloc(ReplySize);
	if (ReplyBuffer == NULL) {
		IcmpCloseHandle(hIcmpFile);
		printf("\tUnable to allocate memory\n");
		return TRUE;
	}

	IcmpSendEcho(hIcmpFile, DestinationAddress, SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, delayInMillis);
	IcmpCloseHandle(hIcmpFile);
	free(ReplyBuffer);

	return FALSE;
}

/*
Timing attack using waitable timers. Test fails if any of the calls return an error state.
*/
BOOL timing_CreateWaitableTimer(UINT delayInMillis)
{
	HANDLE hTimer;
	LARGE_INTEGER dueTime;

	BOOL bResult = FALSE;

	dueTime.QuadPart = delayInMillis * -10000LL;
	
	hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
	
	if (hTimer == NULL)
	{
		return TRUE;
	}

	if (SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE) == FALSE)
	{
		bResult = TRUE;
	}
	else {
		if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0)
		{
			bResult = TRUE;
		}
	}

	CancelWaitableTimer(hTimer);
	CloseHandle(hTimer);
	return bResult;
}

HANDLE g_hEventCTQT = NULL;

/*
Timing attack using CreateTimerQueueTimer. Test fails if any of the calls return an error state.
*/
BOOL timing_CreateTimerQueueTimer(UINT delayInMillis)
{
	HANDLE hTimerQueue;
	HANDLE hTimerQueueTimer = NULL;
	BOOL bResult = FALSE;

	g_hEventCTQT = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (g_hEventCTQT == NULL)
		return FALSE;

	hTimerQueue = CreateTimerQueue();
	if (hTimerQueue == NULL)
	{
		return TRUE;
	}

	if (CreateTimerQueueTimer(
		&hTimerQueueTimer,
		hTimerQueue,
		&CallbackCTQT,
		reinterpret_cast<PVOID>(0xDEADBEEFULL),
		delayInMillis,
		0,
		WT_EXECUTEDEFAULT) == FALSE)
	{
		bResult = TRUE;
	}
	else {

		// idea here is to wait only 10x the expected delay time
		// if the wait expires before the timer comes back, we fail the test
		if (WaitForSingleObject(g_hEventCTQT, delayInMillis * 10) != WAIT_OBJECT_0)
		{
			bResult = FALSE;
		}

	}

	// Delete all timers in the timer queue.
	DeleteTimerQueueEx(hTimerQueue, NULL);

	CloseHandle(g_hEventCTQT);

	return bResult;
}

VOID CALLBACK CallbackCTQT(PVOID lParam, BOOLEAN TimerOrWaitFired)
{
	if (TimerOrWaitFired == TRUE && lParam == reinterpret_cast<PVOID>(0xDEADBEEFULL))
	{
		SetEvent(g_hEventCTQT);
	}
}
