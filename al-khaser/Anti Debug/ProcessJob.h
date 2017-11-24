#include <Windows.h>
#include <Winternl.h>
#include <Psapi.h>
#include <string>

#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

BOOL ProcessJob();