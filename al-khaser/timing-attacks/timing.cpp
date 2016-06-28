#include "timing.h"

/* Timing attacks or sleepy malwares are used to bypass sandboxed in general
Every system which run in a timeout is vulmerable to this types of attacks */


VOID timing_NtDelayexecution()
{
	// In this example, I will demonstrate NtDelayExecution because it is the lowest user mode
	// api to delay execution Sleep -> SleepEx -> NtDelayExecution.

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
	NtDelayExecution(FALSE, (PLARGE_INTEGER)10000);
}

BOOL bProcessed = FALSE;

VOID CALLBACK TimerProc(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTime)
{
	// Malicious code is place here ....
	_tprintf(_T("SetTimer sleepy malware ..."));

	bProcessed = TRUE;
}


VOID timing_SetTimer()
{
	MSG Msg;
	UINT_PTR iTimerID;
	
	// Set our timer without window handle
	iTimerID = SetTimer(NULL, 0, 5000, TimerProc);
	
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
	_tprintf(_T("calling from timeSetEvent"));
	bProcessed = TRUE;
}

VOID timing_timeSetEvent()
{

	// Some vars
	UINT uDelay = 5000;
	UINT uResolution;
	TIMECAPS tc;
	MMRESULT idEvent;

	// We can obtain this minimum value by calling
	timeGetDevCaps(&tc, sizeof(TIMECAPS));
	uResolution = min(max(tc.wPeriodMin, 0), tc.wPeriodMax);

	// Create the timer
	idEvent = timeSetEvent(
		uDelay,
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


VOID timing_WaitForSingleObject()
{
	HANDLE hEvent;

	// Create a nonsignaled event
	hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (hEvent == NULL)
		print_last_error(_T("CreateEvent"));

	// Wait until timeout 
	DWORD x = WaitForSingleObject(hEvent, 5000);

	// Malicious code goes here

}


