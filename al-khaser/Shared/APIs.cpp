#include "stdafx.h"
#include "APIs.h"

#define API_COUNT (sizeof(ApiData)/sizeof(*ApiData))

API_DATA ApiData[] = {
	{ API_IDENTIFIER::API_CsrGetProcessId,				"ntdll.dll",		"CsrGetProcessId",				API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_EnumSystemFirmwareTables,		"kernel32.dll",		"EnumSystemFirmwareTables",		API_MIN_OS_VERSION::WIN_VISTA },
	{ API_IDENTIFIER::API_GetNativeSystemInfo,			"kernel32.dll",		"GetNativeSystemInfo",			API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_GetProductInfo,				"kernel32.dll",		"GetProductInfo",				API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_GetSystemFirmwareTable,		"kernel32.dll",		"GetSystemFirmwareTable",		API_MIN_OS_VERSION::WIN_VISTA },
	{ API_IDENTIFIER::API_IsWow64Process,				"kernel32.dll",		"IsWow64Process",				API_MIN_OS_VERSION::WIN_XP_SP2 },
	{ API_IDENTIFIER::API_NtClose,						"ntdll.dll",		"NtClose",						API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtCreateDebugObject,			"ntdll.dll",		"NtCreateDebugObject",			API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtDelayExecution,				"ntdll.dll",		"NtDelayExecution",				API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtQueryInformationThread,		"ntdll.dll",		"NtQueryInformationThread",		API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtQueryInformationProcess,	"ntdll.dll",		"NtQueryInformationProcess",	API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtQueryObject,				"ntdll.dll",		"NtQueryObject",				API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtQuerySystemInformation,		"ntdll.dll",		"NtQuerySystemInformation",		API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtSetInformationThread,		"ntdll.dll",		"NtSetInformationThread",		API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtWow64ReadVirtualMemory64,	"ntdll.dll",		"NtWow64ReadVirtualMemory64",	API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_NtYieldExecution,				"ntdll.dll",		"NtYieldExecution",				API_MIN_OS_VERSION::WIN_XP },
	{ API_IDENTIFIER::API_RtlGetVersion,				"ntdll.dll",		"RtlGetVersion",				API_MIN_OS_VERSION::WIN_XP },
};

void API::Init()
{
	for (int i = 0; i < API_COUNT; i++)
	{
		ApiData[i].ExpectedAvailable = ShouldFunctionExistOnCurrentPlatform(ApiData[i].Identifier);

		HMODULE hLib = LoadLibraryA(ApiData[i].Library);
		if (hLib == NULL)
		{
			ApiData[i].Available = false;
			continue;
		}
		ApiData[i].Pointer = GetProcAddress(hLib, ApiData[i].EntryName);
		if (ApiData[i].Pointer == NULL)
		{
			ApiData[i].Available = false;
			continue;
		}
		else
		{
			ApiData[i].Available = true;
		}
	}
}

bool API::ShouldFunctionExistOnCurrentPlatform(API_IDENTIFIER api)
{
	for (int i = 0; i < API_MIN_OS_VERSION::VERSION_MAX; i++)
	{
		if (VersionFunctionMap[i].Version == api)
			return VersionFunctionMap[i].Function();
	}
	// this should never occur as long as this function is called with a proper API_IDENTIFIER value and the VersionFunctionMap is properly populated
	assert(false);
	// satisfy compiler warnings
	return false;
}

void API::PrintAvailabilityReport()
{
	int warningCount = 0;
	for (int i = 0; i < API_COUNT; i++)
	{
		if (ApiData[i].ExpectedAvailable && !ApiData[i].Available)
		{
			printf("[*] Warning: API %s!%s was expected to exist but was not found.\n", ApiData[i].Library, ApiData[i].EntryName);
		}
	}
	if (warningCount == 0)
	{
		printf("[*] All APIs present and accounted for.\n");
	}
}

bool API::IsAvailable(API_IDENTIFIER api)
{
	for (int i = 0; i < API_COUNT; i++)
	{
		if (ApiData[i].Identifier == api)
		{
			return ApiData[i].Available;
		}
	}
	assert(false);
	return false;
}

void* API::GetAPI(API_IDENTIFIER api)
{
	for (int i = 0; i < API_COUNT; i++)
	{
		if (ApiData[i].Identifier == api)
		{
			if (ApiData[i].Available)
			{
				return ApiData[i].Pointer;
			}
			else
			{
				return nullptr;
			}
		}
	}
	assert(false);
	return nullptr;
}
