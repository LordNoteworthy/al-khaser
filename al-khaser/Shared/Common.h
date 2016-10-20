#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>


VOID print_detected() ;
VOID print_not_detected() ;
VOID print_category(TCHAR* text);
VOID print_last_error(LPTSTR lpszFunction);
VOID exec_check(int(*callback)(), TCHAR* text_log);
VOID print_os();
TCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr);
CHAR* wide_str_to_multibyte(TCHAR* lpWideStr);
VOID resize_console_window();
VOID print_results(int result, TCHAR* szMsg);





