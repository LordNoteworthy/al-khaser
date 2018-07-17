#pragma once

enum API_IDENTIFIER
{
	API_CsrGetProcessId,
	API_EnumSystemFirmwareTables,
	API_GetSystemFirmwareTable,
	API_GetNativeSystemInfo,
	API_GetProductInfo,
	API_IsWow64Process,
	API_NtClose,
	API_NtCreateDebugObject,
	API_NtDelayExecution,
	API_NtQueryInformationThread,
	API_NtQueryInformationProcess,
	API_NtQueryObject,
	API_NtQuerySystemInformation,
	API_NtSetInformationThread,
	API_NtYieldExecution,
	API_RtlGetVersion,
};

enum API_MIN_OS_VERSION
{
	WIN_XP,
	WIN_XP_SP1,
	WIN_XP_SP2,
	WIN_XP_SP3,
	WIN_VISTA,
	WIN_VISTA_SP1,
	WIN_VISTA_SP2,
	WIN_7,
	WIN_7_SP1,
	WIN_80,
	WIN_81,
	WIN_10,
	VERSION_MAX
};

struct VERSION_FUNCTION_MAP
{
	API_MIN_OS_VERSION Version;
	bool(__stdcall *Function)();

	VERSION_FUNCTION_MAP(API_MIN_OS_VERSION version, bool(__stdcall *function)())
	{
		Version = version;
		Function = function;
	}
};

struct API_DATA
{
	API_IDENTIFIER Identifier;
	char* Library;
	char* EntryName;
	API_MIN_OS_VERSION MinVersion;
	bool Available;
	bool ExpectedAvailable;
	void* Pointer;

	API_DATA(API_IDENTIFIER identifier, char* lib, char* name, API_MIN_OS_VERSION minVersion)
	{
		Identifier = identifier;
		Library = lib;
		EntryName = name;
		MinVersion = minVersion;
		Available = false;
		ExpectedAvailable = false;
		Pointer = nullptr;
	}
};

const VERSION_FUNCTION_MAP VersionFunctionMap[] = {
	{ API_MIN_OS_VERSION::WIN_XP, IsWindowsXPOrGreater },
	{ API_MIN_OS_VERSION::WIN_XP_SP1, IsWindowsXPSP1OrGreater },
	{ API_MIN_OS_VERSION::WIN_XP_SP2, IsWindowsXPSP2OrGreater },
	{ API_MIN_OS_VERSION::WIN_XP_SP3, IsWindowsXPSP3OrGreater },
	{ API_MIN_OS_VERSION::WIN_VISTA, IsWindowsVistaOrGreater },
	{ API_MIN_OS_VERSION::WIN_VISTA_SP1, IsWindowsVistaSP1OrGreater },
	{ API_MIN_OS_VERSION::WIN_VISTA_SP2, IsWindowsVistaSP2OrGreater },
	{ API_MIN_OS_VERSION::WIN_7, IsWindows7OrGreater },
	{ API_MIN_OS_VERSION::WIN_7_SP1, IsWindows7SP1OrGreater },
	{ API_MIN_OS_VERSION::WIN_80, IsWindows8OrGreater },
	{ API_MIN_OS_VERSION::WIN_81, IsWindows8Point1OrGreater },
	{ API_MIN_OS_VERSION::WIN_10, IsWindows10OrGreater },
};

class API
{
private:
	static bool ShouldFunctionExistOnCurrentPlatform(API_IDENTIFIER api);
public:
	static void Init();
	static void PrintAvailabilityReport();
	static bool IsAvailable(API_IDENTIFIER api);
	static void* GetAPI(API_IDENTIFIER api);
};