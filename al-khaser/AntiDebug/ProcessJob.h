#pragma once

#ifndef UNICODE  
typedef std::string String;
#else
typedef std::wstring String;
#endif

BOOL ProcessJob();