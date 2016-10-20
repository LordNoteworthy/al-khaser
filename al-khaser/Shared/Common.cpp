#include "Common.h"
#include "Utils.h"
#include "log.h"

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
	_tprintf(TEXT("[ BAD ].\n"));
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

VOID print_category(TCHAR* text)
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

VOID print_results(int result, TCHAR* szMsg)
{
	_tprintf(TEXT("[*] %s"), szMsg);

	/* align the result according to the length of the text */
	size_t len = _tcslen(szMsg);
	//for (int=0; i<l)

	if (result == TRUE)
		print_detected();
	else
		print_not_detected();

	/* log to file*/
	TCHAR buffer[256] = _T("");
	_stprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("[*] % s"), szMsg);
	LOG_PRINT(buffer);
}

VOID exec_check(int(*callback)(), TCHAR* szMsg) 
{
	
	/* Call our check */
	int result = callback();

	/* Print / Log the result */
	print_results(result, szMsg);
}

VOID resize_console_window()
{
	HANDLE wHnd;    // Handle to write to the console.
	HANDLE rHnd;    // Handle to read from the console.
	wHnd = GetStdHandle(STD_OUTPUT_HANDLE);
	rHnd = GetStdHandle(STD_INPUT_HANDLE);

	// Change the window title:
	SetConsoleTitle(_T("Al-Khaser - by Lord Noteworthy"));

	// Set up the required window size:
	SMALL_RECT windowSize = { 0, 0, 100, 30 };
	SetConsoleWindowInfo(wHnd, 1, &windowSize);

	// Change the console window size:
	// Create a COORD to hold the buffer size:
	COORD bufferSize = { 10, 10 };
	SetConsoleScreenBufferSize(wHnd, bufferSize);
}

VOID print_os()
{
	TCHAR szOS[MAX_PATH] = _T("");
	if (GetOSDisplayString(szOS))
	{
		_tcscpy_s(szOS, MAX_PATH, szOS);
		_tprintf(_T("\nOS: %s\n"), szOS);
	}
}

VOID print_last_error(LPTSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(			
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 

    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 

	_tprintf((LPCTSTR)lpDisplayBuf); 


    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
}

TCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr)
{

	/* Get the required size */
	CONST INT iSizeRequired = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, NULL, 0);

	TCHAR *lpWideCharStr = (TCHAR*)MALLOC(12 * sizeof(TCHAR));

	/* Do the conversion */
	INT iNumChars =  MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, lpWideCharStr, iSizeRequired);

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
