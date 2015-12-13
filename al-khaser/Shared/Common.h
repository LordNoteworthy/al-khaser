#include <Windows.h>

VOID print_detected() ;
VOID print_not_detected() ;
VOID print_category(TCHAR* text);
VOID print_last_error(LPTSTR lpszFunction);
VOID exec_check(int(*callback)(), TCHAR* text_log);
VOID print_os();






