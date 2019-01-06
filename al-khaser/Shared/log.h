#pragma once

#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)
#define __WFILE__ WIDEN(__FILE__)

#ifdef UNICODE
#define __TFILE__ __WFILE__
#else
#define __TFILE__ __FILE__
#endif

void log_print(const TCHAR* filename, const TCHAR *fmt, ...);

#define LOG_PRINT(...) log_print(__TFILE__, __VA_ARGS__ )




