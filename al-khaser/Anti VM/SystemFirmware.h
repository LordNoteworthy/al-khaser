#include <Windows.h>
#include "../Shared/Utils.h"


BOOL FirmwareSMBIOS();
BOOL FirmwareACPI();
BOOL find_str_in_data(PBYTE needle, size_t needleLen, PBYTE haystack, size_t haystackLen);
PBYTE get_system_firmware(_In_ DWORD signature, _In_ DWORD table, _Out_ PDWORD pBufferSize);