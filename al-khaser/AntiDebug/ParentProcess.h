#pragma once

typedef struct _ALK_PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	void* PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} ALK_PROCESS_BASIC_INFORMATION;

BOOL IsParentExplorerExe();