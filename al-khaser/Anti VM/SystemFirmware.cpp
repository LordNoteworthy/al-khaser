#include "SystemFirmware.h"


BOOL FirmwareSMBIOS()
{
	BOOL result = FALSE;

	DWORD smbiosSize = 0;
	PBYTE smbios = get_system_firmware(static_cast<DWORD>('RSMB'), 0x0000, &smbiosSize);
	if (smbios != NULL)
	{
		// TODO: Add string checks for VMs other than VirtualBox
		PBYTE virtualBoxString = (PBYTE)"VirtualBox";
		size_t virtualBoxStringLen = 10;
		PBYTE vboxLowerString = (PBYTE)"vbox";
		size_t vboxLowerStringLen = 4;
		PBYTE vboxUpperString = (PBYTE)"VBOX";
		size_t vboxUpperStringLen = 4;

		if (find_str_in_data(virtualBoxString, virtualBoxStringLen, smbios, smbiosSize) ||
			find_str_in_data(vboxLowerString, vboxLowerStringLen, smbios, smbiosSize) ||
			find_str_in_data(vboxUpperString, vboxUpperStringLen, smbios, smbiosSize))
		{
			result = TRUE;
		}

		free(smbios);
	}

	return result;
}

BOOL FirmwareACPI()
{
	BOOL result = FALSE;

	PDWORD tableNames = static_cast<PDWORD>(malloc(4096));
	SecureZeroMemory(tableNames, 4096);
	DWORD tableSize = EnumSystemFirmwareTables(static_cast<DWORD>('ACPI'), tableNames, 4096);
	DWORD tableCount = tableSize / 4;
	if (tableSize < 4 || tableCount == 0)
		result = TRUE;
	else
	{
		for (DWORD i = 0; i < tableCount; i++)
		{
			DWORD tableSize = 0;
			PBYTE table = get_system_firmware(static_cast<DWORD>('ACPI'), tableNames[i], &tableSize);

			// TODO: Add string checks for VMs other than VirtualBox
			PBYTE virtualBoxString = (PBYTE)"VirtualBox";
			size_t virtualBoxStringLen = 10;
			PBYTE vboxLowerString = (PBYTE)"vbox";
			size_t vboxLowerStringLen = 4;
			PBYTE vboxUpperString = (PBYTE)"VBOX";
			size_t vboxUpperStringLen = 4;

			if (find_str_in_data(virtualBoxString, virtualBoxStringLen, table, tableSize) ||
				find_str_in_data(vboxLowerString, vboxLowerStringLen, table, tableSize) ||
				find_str_in_data(vboxUpperString, vboxUpperStringLen, table, tableSize))
			{
				result = TRUE;
			}

			free(table);
		}
	}

	free(tableNames);
	return result;
}

BOOL find_str_in_data(PBYTE needle, size_t needleLen, PBYTE haystack, size_t haystackLen)
{
	for (size_t i = 0; i < haystackLen - needleLen; i++)
	{
		if (memcmp(&haystack[i], needle, needleLen) == 0)
		{
			return TRUE;
		}
	}
	return FALSE;
}

PBYTE get_system_firmware(_In_ DWORD signature, _In_ DWORD table, _Out_ PDWORD pBufferSize)
{
	DWORD bufferSize = 4096;
	PBYTE firmwareTable = static_cast<PBYTE>(malloc(bufferSize));
	SecureZeroMemory(firmwareTable, bufferSize);
	DWORD resultBufferSize = GetSystemFirmwareTable(signature, table, firmwareTable, bufferSize);
	if (resultBufferSize == 0)
	{
		printf("First call failed :(\n");
		free(firmwareTable);
		return NULL;
	}

	// if the buffer was too small, realloc and try again
	if (resultBufferSize > bufferSize)
	{
		firmwareTable = static_cast<BYTE*>(realloc(firmwareTable, resultBufferSize));
		SecureZeroMemory(firmwareTable, resultBufferSize);
		if (GetSystemFirmwareTable(signature, table, firmwareTable, resultBufferSize) == 0)
		{
			printf("Second call failed :(\n");
			free(firmwareTable);
			return NULL;
		}
	}

	*pBufferSize = resultBufferSize;
	return firmwareTable;
}