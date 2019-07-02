#include "pch.h"

#include "OutputDebugStringAPI.h"

/*
OutputDebugString() is typically used to output a string value to the debugging data stream.
This string is then displayed in the debugger. Due to this fact, the function OutputDebugString()
acts differently based on the existence of a debugger on the running process. If a debugger is
attached to the process, the function will execute normally and no error state will be registered;
however if there is no debugger attached, LastError will be set by the process letting us know that
we are debugger free. To execute this method we set LastError to an arbitrary value of our choosing
and then call OutputDebugString(). We then check GetLastError() and if our error code remains,
we know we are debugger free. This Works only in Windows XP/2000 
*/

BOOL OutputDebugStringAPI()
{

	BOOL IsDbgPresent = FALSE;
	DWORD Val = 0x29A;

	// This is working only in Windows XP/2000
	if (IsWindowsXPOr2k())
	{
		SetLastError(Val);
		OutputDebugString(_T("random"));

		if (GetLastError() == Val)
			IsDbgPresent = TRUE;
	}
		
	return IsDbgPresent;
}

