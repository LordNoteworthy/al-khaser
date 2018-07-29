#include "stdafx.h"

#define NUMCHARS(a) (sizeof(a)/sizeof(*a))

static HRESULT NormalizeNTPathOld(wchar_t* pszPath, size_t nMax)
// Normalizes the path returned by GetProcessImageFileName
{
	wchar_t* pszSlash = wcschr(&pszPath[1], '\\');
	if (pszSlash) pszSlash = wcschr(pszSlash + 1, '\\');
	if (!pszSlash)
		return E_FAIL;
	wchar_t cSave = *pszSlash;
	*pszSlash = 0;

	wchar_t szNTPath[_MAX_PATH];
	wchar_t szDrive[_MAX_PATH] = L"A:";
	// We'll need to query the NT device names for the drives to find a match with pszPath
	for (wchar_t cDrive = 'A'; cDrive < 'Z'; ++cDrive)
	{
		szDrive[0] = cDrive;
		szNTPath[0] = 0;
		if (0 != QueryDosDevice(szDrive, szNTPath, NUMCHARS(szNTPath)) &&
			0 == _wcsicmp(szNTPath, pszPath))
		{
			// Match
			wcscat_s(szDrive, NUMCHARS(szDrive), L"\\");
			wcscat_s(szDrive, NUMCHARS(szDrive), pszSlash + 1);
			wcscpy_s(pszPath, nMax, szDrive);
			return S_OK;
		}
	}
	*pszSlash = cSave;
	return E_FAIL;
}

static HRESULT NormalizeNTPath(TCHAR* pszPath, size_t nMax)
// Normalizes the path returned by GetProcessImageFileName
{
	TCHAR* pszSlash = StrChr(&pszPath[1], '\\');
	if (pszSlash) pszSlash = StrChr(pszSlash + 1, '\\');
	if (!pszSlash)
		return E_FAIL;
	TCHAR cSave = *pszSlash;
	*pszSlash = 0;

	TCHAR szNTPath[_MAX_PATH];
	TCHAR szDrive[_MAX_PATH] = L"A:";
	// We'll need to query the NT device names for the drives to find a match with pszPath
	for (TCHAR cDrive = 'A'; cDrive < 'Z'; ++cDrive)
	{
		szDrive[0] = cDrive;
		szNTPath[0] = 0;
		if (0 != QueryDosDevice(szDrive, szNTPath, NUMCHARS(szNTPath)) &&
			0 == StrCmpI(szNTPath, pszPath))
		{
			// Match
			StringCbCat(szDrive, NUMCHARS(szDrive), _T("\\"));
			StringCbCat(szDrive, NUMCHARS(szDrive), pszSlash + 1);
			StringCbCopy(pszPath, nMax, szDrive);
			return S_OK;
		}
	}
	*pszSlash = cSave;
	return E_FAIL;
}

bool IsBadLibrary(TCHAR* filename, DWORD filenameLength)
{
	TCHAR systemDrive[MAX_PATH];
	TCHAR systemDriveDevice[MAX_PATH];
	TCHAR systemRootPath[MAX_PATH];
	TCHAR exePath[MAX_PATH];
	TCHAR normalisedPath[MAX_PATH];

	StringCbCopy(normalisedPath, MAX_PATH, filename);
	NormalizeNTPath(filename, MAX_PATH);
	size_t normalisedPathLength = 0;
	StringCbLength(normalisedPath, MAX_PATH, &normalisedPathLength);

	if (filenameLength < 0)
	{
		size_t filenameActualLength = 0;
		StringCbLength(filename, MAX_PATH, &filenameActualLength);
		filenameLength = filenameActualLength;
	}

	GetSystemDirectory(systemRootPath, MAX_PATH);

	size_t exePathLength = GetProcessImageFileName(GetCurrentProcess(), exePath, MAX_PATH);
	NormalizeNTPath(exePath, MAX_PATH);
	StringCbLength(exePath, MAX_PATH, &exePathLength);


	if (GetEnvironmentVariable(_T("SystemDrive"), systemDrive, MAX_PATH) > 0)
	{
		if (QueryDosDeviceW(systemDrive, systemDriveDevice, MAX_PATH) > 0)
		{
			StringCbCat(systemDriveDevice, MAX_PATH, _T("\\Windows\\System32\\"));
			size_t systemDriveDevicelength = 0;
			StringCbLength(systemDriveDevice, MAX_PATH, &systemDriveDevicelength);

			//printf("systemDriveDevice: %S (%d)\n", systemDriveDevice, systemDriveDevicelength);

			if (StrNCmpI(systemDriveDevice, filename, min(systemDriveDevicelength, filenameLength) / sizeof(TCHAR)) == 0)
			{
				// path matched the NT file path
				return false;
			}

			StringCbCat(systemRootPath, MAX_PATH, _T("\\"));
			size_t systemRootPathLength = 0;
			StringCbLength(systemRootPath, MAX_PATH, &systemRootPathLength);

			//printf("systemRootPath: %S (%d)\n", systemRootPath, systemRootPathLength);

			if (StrNCmpI(systemRootPath, normalisedPath, min(systemRootPathLength, normalisedPathLength) / sizeof(TCHAR)) == 0)
			{
				// path matched the regular system path
				return false;
			}

			if (StrCmpI(exePath, normalisedPath) == 0)
			{
				// path matched the executable path
				return false;
			}
		}
	}
	return true;
}

bool ScanForModules_EnumProcessModulesEx()
{
	//printf("EnumProcessModulesEx()\n");
	auto moduleList = static_cast<HMODULE*>(calloc(1024, sizeof(HMODULE)));
	DWORD currentSize = 1024 * sizeof(HMODULE);
	DWORD requiredSize = 0;
	bool anyBadLibs = false;
	if (EnumProcessModulesEx(GetCurrentProcess(), moduleList, currentSize, &requiredSize, LIST_MODULES_ALL) == TRUE)
	{
		bool success = true;
		if (requiredSize > currentSize)
		{
			currentSize = requiredSize;
			moduleList = static_cast<HMODULE*>(realloc(moduleList, currentSize));
			if (EnumProcessModulesEx(GetCurrentProcess(), moduleList, currentSize, &requiredSize, LIST_MODULES_ALL) == FALSE)
			{
				success = false;
			}
		}
		if (success)
		{
			DWORD count = requiredSize / sizeof(HMODULE);
			TCHAR moduleName[MAX_PATH];
			for (DWORD i = 0; i < count; i++)
			{
				if (DWORD len = GetModuleFileNameEx(GetCurrentProcess(), moduleList[i], moduleName, MAX_PATH) > 0)
				{
					bool isBad = IsBadLibrary(moduleName, len);
					if (isBad)
						printf(" [!] Injected library: %S\n", moduleName);
					anyBadLibs |= isBad;
				}
			}
		}
	}

	return anyBadLibs;
}

bool ScanForModules_EnumProcessModulesEx_64bit()
{
	//printf("EnumProcessModulesEx_64bit()\n");
	auto moduleList = static_cast<HMODULE*>(calloc(1024, sizeof(HMODULE)));
	DWORD currentSize = 1024 * sizeof(HMODULE);
	DWORD requiredSize = 0;
	bool anyBadLibs = false;
	if (EnumProcessModulesEx(GetCurrentProcess(), moduleList, currentSize, &requiredSize, LIST_MODULES_32BIT) == TRUE)
	{
		bool success = true;
		if (requiredSize > currentSize)
		{
			currentSize = requiredSize;
			moduleList = static_cast<HMODULE*>(realloc(moduleList, currentSize));
			if (EnumProcessModulesEx(GetCurrentProcess(), moduleList, currentSize, &requiredSize, LIST_MODULES_32BIT) == FALSE)
			{
				success = false;
			}
		}
		if (success)
		{
			DWORD count = requiredSize / sizeof(HMODULE);
			TCHAR moduleName[MAX_PATH];
			for (DWORD i = 0; i < count; i++)
			{
				if (DWORD len = GetModuleFileNameEx(GetCurrentProcess(), moduleList[i], moduleName, MAX_PATH) > 0)
				{
					bool isBad = IsBadLibrary(moduleName, len);
					if (isBad)
						printf(" [!] Injected library: %S\n", moduleName);
					anyBadLibs |= isBad;
				}
			}
		}
	}
	return anyBadLibs;
}

bool ScanForModules_MemoryWalk_GMI()
{
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	HMODULE moduleHandle = 0;
	TCHAR moduleName[MAX_PATH];
	MODULEINFO moduleInfo = { 0 };

	//printf("Memory walking with GetModuleHandleEx...\n");

	size_t maxPage = 0x7FFFFFFF;
	size_t addr = 0;
	bool anyBadLibs = false;
	while(addr < maxPage)
	{
		bool skippedForward = false;
		if (VirtualQuery((PVOID)addr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
		{
			if (memInfo.State != MEM_FREE)
			{
				if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (TCHAR*)addr, &moduleHandle) == TRUE)
				{
					SecureZeroMemory(moduleName, MAX_PATH * sizeof(TCHAR));
					DWORD len = GetModuleFileName(moduleHandle, moduleName, MAX_PATH);
					//printf(" [!] %p: %S\n", addr, moduleName);
					bool isBad = IsBadLibrary(moduleName, len);
					if (isBad)
						printf(" [!] Injected library: %S\n", moduleName);
					anyBadLibs |= isBad;

					if (GetModuleInformation(GetCurrentProcess(), moduleHandle, &moduleInfo, sizeof(MODULEINFO)) == TRUE)
					{
						size_t moduleSizeRoundedUp = (moduleInfo.SizeOfImage + 1);
						moduleSizeRoundedUp += 4096 - (moduleSizeRoundedUp % 4096);
						size_t nextPos = reinterpret_cast<size_t>(static_cast<unsigned char*>(moduleInfo.lpBaseOfDll) + moduleSizeRoundedUp);
						if (nextPos > addr)
						{
							//printf(" -> Moving from %x to %x\n", addr, nextPos);
							addr = nextPos;
							skippedForward = true;
						}
					}
				}
			}
		}
		if (!skippedForward)
			addr += 4096;
	}

	return anyBadLibs;
}

bool ScanForModules_MemoryWalk_Hidden()
{
	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	HMODULE moduleHandle = 0;
	TCHAR moduleName[MAX_PATH];

	//printf("Memory walking for hidden modules...\n");

	size_t maxPage = 0x7FFFFFFF;
	size_t addr = 0;
	bool anyBadLibs = false;
	while (addr < maxPage)
	{
		bool skippedForward = false;
		if (VirtualQuery((PVOID)addr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) >= sizeof(MEMORY_BASIC_INFORMATION))
		{
			if (memInfo.State != MEM_FREE)
			{
				if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (TCHAR*)addr, &moduleHandle) == FALSE)
				{
					// not a known module
					if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE ||
						(memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
						(memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY ||
						(memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
					{
						auto moduleData = static_cast<unsigned char*>(memInfo.AllocationBase);
						if (moduleData[0] == 'M' && moduleData[1] == 'Z')
						{
							printf(" [!] Executable at %p\n", memInfo.AllocationBase);
						}
					}
				}

				SecureZeroMemory(moduleName, sizeof(TCHAR)*MAX_PATH);
				if (DWORD len = GetMappedFileName(GetCurrentProcess(), memInfo.AllocationBase, moduleName, MAX_PATH) > 0)
				{
					bool isBad = IsBadLibrary(moduleName, len);
					if (isBad)
						printf(" [!] Injected library: %S\n", moduleName);
					anyBadLibs |= isBad;
				}

				size_t nextPos = reinterpret_cast<size_t>(static_cast<unsigned char*>(memInfo.AllocationBase) + memInfo.RegionSize);
				nextPos += 4096 - (nextPos % 4096);
				if (nextPos > addr)
				{
					//printf(" -> Moving from %x to %x\n", addr, nextPos);
					addr = nextPos;
					skippedForward = true;
				}
			}
		}
		if (!skippedForward)
			addr += 4096;
	}

	return anyBadLibs;
}

std::vector<LDR_DATA_TABLE_ENTRY*>* WalkLDR(PPEB_LDR_DATA ldrData)
{
	auto entryList = new std::vector<LDR_DATA_TABLE_ENTRY*>();

	LIST_ENTRY* head = ldrData->InMemoryOrderModuleList.Flink;
	LIST_ENTRY* node = head;

	do
	{
		LDR_DATA_TABLE_ENTRY ldrEntry = { 0 };
		LDR_DATA_TABLE_ENTRY* pLdrEntry = CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		if (attempt_to_read_memory(pLdrEntry, &ldrEntry, sizeof(ldrEntry)))
		{
			entryList->push_back(new LDR_DATA_TABLE_ENTRY(ldrEntry));

			node = ldrEntry.InMemoryOrderLinks.Flink;
		}
		else
		{
			printf(" [!] Error reading entry.\n");
			break;
		}
	}
	while (node != head);

	entryList->pop_back();

	return entryList;
}

std::vector<LDR_DATA_TABLE_ENTRY64*>* WalkLDR(PPEB_LDR_DATA64 ldrData)
{
	auto entryList = new std::vector<LDR_DATA_TABLE_ENTRY64*>();

	LIST_ENTRY64 head;
	if (!attempt_to_read_memory_wow64(&head, sizeof(LIST_ENTRY64), ldrData->InMemoryOrderModuleList.Flink))
	{
		printf(" [!] Error reading list head.\n");
	}
	ULONGLONG nodeAddr = ldrData->InMemoryOrderModuleList.Flink;
	LIST_ENTRY64 node = head;
	LDR_DATA_TABLE_ENTRY64 ldrEntry = { 0 };

	do
	{
		if (attempt_to_read_memory_wow64(&ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY64), nodeAddr - sizeof(LIST_ENTRY64)))
		{
			entryList->push_back(new LDR_DATA_TABLE_ENTRY64(ldrEntry));

			if (!attempt_to_read_memory_wow64(&node, sizeof(LIST_ENTRY64), ldrEntry.InMemoryOrderLinks.Flink))
			{
				break;
			}

			nodeAddr = ldrEntry.InMemoryOrderLinks.Flink;
		}
		else
		{
			break;
		}
	} while (nodeAddr != ldrData->InMemoryOrderModuleList.Flink);

	entryList->pop_back();

	return entryList;
}

bool ScanForModules_LDR()
{
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	THREAD_BASIC_INFORMATION tbi = { 0 };

	//printf("MemoryWalk_LDR()\n");

	bool anyBadLibs = false;

	auto NtQueryInformationProcess = static_cast<pNtQueryInformationProcess>(API::GetAPI(API_IDENTIFIER::API_NtQueryInformationProcess));
	NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
	if (status != 0)
	{
		printf("Failed to get process information. Status: %d\n", status);
	}
	else
	{
		if (pbi.PebBaseAddress != nullptr)
		{
			PPEB peb = pbi.PebBaseAddress;
			if (peb->Ldr != nullptr)
			{
				PPEB_LDR_DATA ldrData = peb->Ldr;

				auto ldrEntries = WalkLDR(ldrData);
				for (LDR_DATA_TABLE_ENTRY* ldrEntry : *ldrEntries)
				{
					//printf(" -> %S\n", ldrEntry->FullDllName.Buffer);
					bool isBad = IsBadLibrary(ldrEntry->FullDllName.Buffer, ldrEntry->FullDllName.Length);
					if (isBad)
						printf(" [!] Injected library: %S\n", ldrEntry->FullDllName.Buffer);
					anyBadLibs |= isBad;
					delete ldrEntry;
				}
				delete ldrEntries;
			}

			if (pbi.PebBaseAddress != nullptr)
			{
				PPEB64 peb = reinterpret_cast<PPEB64>(reinterpret_cast<UCHAR*>(pbi.PebBaseAddress) - 0x1000);
				PEB_LDR_DATA64 ldrData = { 0 };

				if (attempt_to_read_memory_wow64(&ldrData, sizeof(PEB_LDR_DATA64), peb->Ldr))
				{
					auto ldrEntries = WalkLDR(&ldrData);
					for (LDR_DATA_TABLE_ENTRY64* ldrEntry : *ldrEntries)
					{
						WCHAR* dllNameBuffer = new WCHAR[ldrEntry->FullDllName.Length + 1];
						SecureZeroMemory(dllNameBuffer, (ldrEntry->FullDllName.Length + 1) * sizeof(WCHAR));
						if (attempt_to_read_memory_wow64(dllNameBuffer, ldrEntry->FullDllName.Length * sizeof(WCHAR), ldrEntry->FullDllName.Buffer))
						{
							//printf(" -> %S\n", dllNameBuffer);
							bool isBad = IsBadLibrary(dllNameBuffer, ldrEntry->FullDllName.Length);
							if (isBad)
								printf(" [!] Injected library (WOW64): %S\n", dllNameBuffer);
							anyBadLibs |= isBad;
						}
						else
						{
							printf(" [!] Failed to read module name at %llx.\n", reinterpret_cast<ULONGLONG>(ldrEntry->FullDllName.Buffer));
						}
						delete dllNameBuffer;
						delete ldrEntry;
					}
					delete ldrEntries;
				}
			}
		}
	}

	return anyBadLibs;
}

bool ScanForModules_ToolHelp32()
{
	//printf("MemoryWalk_ToolHelp32()\n");

	bool anyBadLibs = false;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
	//printf("Snapshot: %p\n", snapshot);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		printf("Failed to get snapshot. Last error: %d\n", GetLastError());
	}
	else
	{
		MODULEENTRY32 module = { 0 };
		module.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(snapshot, &module) != FALSE)
		{
			do
			{
				bool isBad = IsBadLibrary(module.szExePath, -1);
				if (isBad)
					printf(" [!] Injected library: %S\n", module.szExePath);
				anyBadLibs |= isBad;
				//printf(" [!] %S\n", module.szModule);

			} while (Module32Next(snapshot, &module) != FALSE);
		}
		else
		{
			printf("Failed to get first module. Last error: %d\n", GetLastError());
		}
	}

	return anyBadLibs;
}

BOOL ScanForModules()
{
	bool badModules = false;
	badModules |= ScanForModules_ToolHelp32();
	badModules |= ScanForModules_EnumProcessModulesEx();
	badModules |= ScanForModules_EnumProcessModulesEx_64bit();
	badModules |= ScanForModules_LDR();
#ifdef ENV32BIT
	// these tests would work for 64-bit but the scan time is waaaaaaaaay too long

	badModules |= ScanForModules_MemoryWalk_GMI();

	// only run this on non-WoW64 as it'll throw false positives if we run both.
	BOOL isWow64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &isWow64);
	if (isWow64 == FALSE)
	{
		badModules |= ScanForModules_MemoryWalk_Hidden();
	}
#endif

	return badModules ? TRUE : FALSE;
}