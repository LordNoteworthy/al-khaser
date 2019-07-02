#include "pch.h"

#ifdef _DEBUG
#define OutputDebugStringDbgOnly(S) OutputDebugString(S)
#else
#define OutputDebugStringDbgOnly(S) do {} while(0);
#endif

std::vector<PVOID> executablePages = {};

void PageExceptionInitialEnum()
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	size_t pageSize = sysInfo.dwPageSize;

	HMODULE hMainModule;
	MODULEINFO moduleInfo;

	MEMORY_BASIC_INFORMATION memInfo = { 0 };

	// Get the main module handle from an address stored within it (pointer to this method)
	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)PageExceptionBreakpointCheck, &hMainModule))
	{
		// Get information about the main module (we want to know the size of it)
		if (GetModuleInformation(GetCurrentProcess(), hMainModule, &moduleInfo, sizeof(MODULEINFO)))
		{
			// cast the module to a pointer
			unsigned char* module = static_cast<unsigned char*>(moduleInfo.lpBaseOfDll);
			for (size_t ofs = 0; ofs < moduleInfo.SizeOfImage; ofs += pageSize)
			{
				if (VirtualQuery(module + ofs, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
				{
					if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
						(memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
						(memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
						(memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
					{
						executablePages.push_back(module + ofs);
					}
				}
			}
		}
	}
}

BOOL PageExceptionBreakpointCheck()
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	size_t pageSize = sysInfo.dwPageSize;

	HMODULE hMainModule;
	MODULEINFO moduleInfo;

	MEMORY_BASIC_INFORMATION memInfo = { 0 };

	wchar_t buffer[512];

	// first we check if any of the pages are executable+guard or noaccess

	// Get the main module handle from an address stored within it (pointer to this method)
	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)PageExceptionBreakpointCheck, &hMainModule))
	{
		// Get information about the main module (we want to know the size of it)
		if (GetModuleInformation(GetCurrentProcess(), hMainModule, &moduleInfo, sizeof(MODULEINFO)))
		{
			// cast the module to a pointer
			unsigned char* module = static_cast<unsigned char*>(moduleInfo.lpBaseOfDll);
			for (size_t ofs = 0; ofs < moduleInfo.SizeOfImage; ofs += pageSize)
			{
				SecureZeroMemory(buffer, 512);
				wsprintf(buffer, L"Scanning %p... ", module + ofs);
				OutputDebugStringDbgOnly(buffer);
				if (VirtualQuery(module + ofs, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
				{
					if (memInfo.AllocationProtect == 0)
						OutputDebugStringDbgOnly(L"^ AllocationProtect is zero. Potential shenanigans.");
					if (memInfo.Protect == 0)
						OutputDebugStringDbgOnly(L"^ Protect is zero. Potential shenanigans.");

					if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
						(memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
						(memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
						(memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
					{
						// this is an executable page
						OutputDebugStringDbgOnly(L"^ is executable.");

						if ((memInfo.Protect & PAGE_GUARD) == PAGE_GUARD ||
							(memInfo.AllocationProtect & PAGE_GUARD) == PAGE_GUARD)
						{
							// this is an executable guard page, page exception debugging detected
							OutputDebugStringDbgOnly(L"^ is guard page !!!!!!");
							return TRUE;
						}
					}

					if ((memInfo.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
					{
						// this is a NOACCESS page, which shouldn't exist here (alternative way to set page exception BPs)
						OutputDebugStringDbgOnly(L"^ is NOACCESS !!!!!!!");
						return TRUE;
					}
				}
				else OutputDebugStringDbgOnly(L"^ FAILED!");
			}
		}

		OutputDebugStringDbgOnly(L"Moving on to delta check...");

		for (PVOID page : executablePages)
		{
			SecureZeroMemory(buffer, 512);
			wsprintf(buffer, L"Scanning delta for %p... ", page);
			OutputDebugStringDbgOnly(buffer);

			if (VirtualQuery(page, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
			{
				if (memInfo.AllocationProtect == 0)
					OutputDebugStringDbgOnly(L"^ AllocationProtect is zero. Potential shenanigans.");
				if (memInfo.Protect == 0)
					OutputDebugStringDbgOnly(L"^ Protect is zero. Potential shenanigans.");

				if (!((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
					(memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
					(memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
					(memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE))
				{
					// page was executable, now isn't!
					OutputDebugStringDbgOnly(L"^ was executable, now isn't !!!!!!");
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}