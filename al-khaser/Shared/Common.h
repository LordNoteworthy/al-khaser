#pragma once

VOID print_detected() ;
VOID print_not_detected() ;
VOID print_category(TCHAR* text);
VOID print_last_error(LPTSTR lpszFunction);
VOID print_os();
TCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr);
CHAR* wide_str_to_multibyte(TCHAR* lpWideStr);
VOID resize_console_window();
VOID print_results(int result, TCHAR* szMsg);
VOID _print_check_text(TCHAR* szMsg);
VOID _print_check_result(int result, TCHAR* szMsg);

VOID exec_check(int(*callback)(), TCHAR* szMsg);

bool attempt_to_read_memory(void* addr, void* buf, int size);
bool attempt_to_read_memory_wow64(PVOID buffer, DWORD size, PVOID64 address);
bool attempt_to_read_memory_wow64(PVOID buffer, DWORD size, ULONGLONG address);

// this must be defined in this header file
// see: https://stackoverflow.com/questions/495021/why-can-templates-only-be-implemented-in-the-header-file
template <typename T>
VOID exec_check(int(*callback)(T param), T param, TCHAR* szMsg)
{
	/* Print the text to screen so we can see what's currently running */
	_print_check_text(szMsg);

	/* Call our check */
	int result = callback(param);

	/* Print / Log the result */
	if (szMsg)
		_print_check_result(result, szMsg);
}