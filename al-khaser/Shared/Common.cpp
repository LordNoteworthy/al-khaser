#include "pch.h"
#include "Common.h"

VOID print_detected()
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
	SecureZeroMemory(&ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	/* Save the original console color */
	GetConsoleScreenBufferInfo(nStdHandle, &ConsoleScreenBufferInfo);
	WORD OriginalColors = *(&ConsoleScreenBufferInfo.wAttributes);

	SetConsoleTextAttribute(nStdHandle, 12);
	_tprintf(TEXT("[ BAD  ]\n"));
	SetConsoleTextAttribute(nStdHandle, OriginalColors);
}

VOID print_not_detected()
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
	SecureZeroMemory(&ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	/* Save the original console color */
	GetConsoleScreenBufferInfo(nStdHandle, &ConsoleScreenBufferInfo);
	WORD OriginalColors = *(&ConsoleScreenBufferInfo.wAttributes);

	SetConsoleTextAttribute(nStdHandle, 10);
	_tprintf(TEXT("[ GOOD ]\n"));
	SetConsoleTextAttribute(nStdHandle, OriginalColors);
}

VOID print_category(const TCHAR* text)
{
	/* Get handle to standard output */
	HANDLE nStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);  
	CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;
	SecureZeroMemory(&ConsoleScreenBufferInfo, sizeof(CONSOLE_SCREEN_BUFFER_INFO));

	/* Save the original console color */
	GetConsoleScreenBufferInfo(nStdHandle, &ConsoleScreenBufferInfo);
	WORD OriginalColors = *(&ConsoleScreenBufferInfo.wAttributes);

	SetConsoleTextAttribute(nStdHandle, 13);
	_tprintf(TEXT("\n-------------------------[%s]-------------------------\n"), text);
	SetConsoleTextAttribute(nStdHandle, OriginalColors);
}

VOID _print_check_text(const TCHAR* szMsg)
{
	_tprintf(TEXT("[*] %s"), szMsg);

	/* align the result according to the length of the text */
	size_t spaces_to_padd = 95 - _tcslen(szMsg);
	while (spaces_to_padd > 0) {
		_tprintf(TEXT(" "));
		spaces_to_padd--;
	}
}

VOID _print_check_result(int result, const TCHAR* szMsg)
{
	if (result == TRUE)
		print_detected();
	else
		print_not_detected();

	/* log to file*/
	TCHAR buffer[256] = _T("");
	_stprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("[*] %s -> %d"), szMsg, result);
	LOG_PRINT(buffer);
}

VOID print_results(int result, TCHAR* szMsg)
{
	_print_check_text(szMsg);
	_print_check_result(result, szMsg);
}

// note: templated version of this function is in Common.h
VOID exec_check(int(*callback)(), const TCHAR* szMsg)
{
	/* Print the text to screen so we can see what's currently running */
	_print_check_text(szMsg);

	/* Call our check */
	int result = callback();

	/* Print / Log the result */
	if (szMsg)
		_print_check_result(result, szMsg);
}

VOID resize_console_window()
{
	// Change the window title:
	SetConsoleTitle(_T("Al-Khaser - by Lord Noteworthy"));

	// Get console window handle
	HWND wh = GetConsoleWindow();

	// Move window to required position
	MoveWindow(wh, 100, 100, 900, 900, TRUE);
}


VOID print_os()
{
	TCHAR szOS[MAX_PATH] = _T("");
	if (GetOSDisplayString(szOS))
	{
		//_tcscpy_s(szOS, MAX_PATH, szOS);
		_tprintf(_T("\n[*] You are running: %s\n"), szOS);
	}
}

VOID print_last_error(LPCTSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	if (FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL) == 0)
	{
		//FormatMessage failed, return
		return;
	}

	// Display the error message and exit the process

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));

	if (lpDisplayBuf) {

		StringCchPrintf((LPTSTR)lpDisplayBuf,
			LocalSize(lpDisplayBuf) / sizeof(TCHAR),
			TEXT("%s failed with error %u: %s"),
			lpszFunction, dw, lpMsgBuf);

		_tprintf((LPCTSTR)lpDisplayBuf);

		LocalFree(lpDisplayBuf);
	}
	LocalFree(lpMsgBuf);
}

WCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr)
{

	/* Get the required size */
	INT iNumChars = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, NULL, 0);

	/* Allocate new wide string */

	SIZE_T Size = (1 + iNumChars) * sizeof(WCHAR);
	
	WCHAR *lpWideCharStr = reinterpret_cast<WCHAR*>(malloc(Size));

	if (lpWideCharStr) {
		SecureZeroMemory(lpWideCharStr, Size);
		/* Do the conversion */
		iNumChars = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, lpWideCharStr, iNumChars);
	}
	return lpWideCharStr;
}

CHAR* wide_str_to_multibyte (TCHAR* lpWideStr)
{
	errno_t status;
	int *pRetValue = NULL;
	CHAR *mbchar = NULL;
	size_t sizeInBytes = 0;
	
	status = wctomb_s(pRetValue, mbchar, sizeInBytes, *lpWideStr);
	return mbchar;
}
