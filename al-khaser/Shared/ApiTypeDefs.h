#pragma once

typedef DWORD(NTAPI* pCsrGetId)(VOID);
typedef UINT(WINAPI* pEnumSystemFirmwareTables)(DWORD, PVOID, DWORD);
typedef UINT(WINAPI* pGetSystemFirmwareTable)(DWORD, DWORD, PVOID, DWORD); 
typedef void (WINAPI *pGetNativeSystemInfo)(LPSYSTEM_INFO);
typedef BOOL(WINAPI *pGetProductInfo)(DWORD, DWORD, DWORD, DWORD, PDWORD);
typedef BOOL(WINAPI *pIsWow64Process) (HANDLE, PBOOL);
typedef DWORD(WINAPI * pRtlCreateUserThread)(
	IN HANDLE 					ProcessHandle,
	IN PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	IN BOOL 					CreateSuspended,
	IN ULONG					StackZeroBits,
	IN OUT PULONG				StackReserved,
	IN OUT PULONG				StackCommit,
	IN LPVOID					StartAddress,
	IN LPVOID					StartParameter,
	OUT HANDLE 					ThreadHandle,
	OUT LPVOID					ClientID
	);
typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);
typedef NTSTATUS(WINAPI *pNtCreateDebugObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG);
typedef NTSTATUS(WINAPI *pNtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN LPVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN LPTHREAD_START_ROUTINE lpStartAddress,
	IN LPVOID lpParameter,
	IN BOOL CreateSuspended,
	IN DWORD StackZeroBits,
	IN DWORD SizeOfStackCommit,
	IN DWORD SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer
	);
typedef NTSTATUS(WINAPI *pNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *pNtQueryInformationThread)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI *pNtQueryObject)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *pNtQuerySystemInformation)(IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
typedef NTSTATUS(WINAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(WINAPI* pNtYieldExecution)();
typedef NTSTATUS(WINAPI* pRtlGetVersion)(RTL_OSVERSIONINFOEXW*);
typedef NTSTATUS(WINAPI *pNtWow64ReadVirtualMemory64)(
	HANDLE ProcessHandle,
	PVOID64 BaseAddress,
	PVOID Buffer,
	ULONGLONG BufferSize,
	PULONGLONG NumberOfBytesRead
);
typedef NTSTATUS(NTAPI *pNtWow64QueryVirtualMemory64)(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress,
	IN DWORD MemoryInformationClass,
	OUT PMEMORY_BASIC_INFORMATION64 MemoryInformation,
	IN ULONG64 Size,
	OUT PULONG64 ReturnLength OPTIONAL);