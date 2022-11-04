#pragma once

typedef DWORD(NTAPI* pCsrGetId)(VOID);
typedef BOOL(WINAPI* pEnumProcessModulesEx)(
	HANDLE hProcess,
	HMODULE *lphModule,
	DWORD cb,
	LPDWORD lpcbNeeded,
	DWORD dwFilterFlag);
typedef UINT(WINAPI* pEnumSystemFirmwareTables)(DWORD, PVOID, DWORD);
typedef DWORD(WINAPI* pGetActiveProcessorCount)(WORD);
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
typedef enum _SYSDBG_COMMAND {
	SysDbgQueryModuleInformation,
	SysDbgQueryTraceInformation,
	SysDbgSetTracepoint,
	SysDbgSetSpecialCall,
	SysDbgClearSpecialCalls,
	SysDbgQuerySpecialCalls,
	SysDbgBreakPoint,
	SysDbgQueryVersion,
	SysDbgReadVirtual,
	SysDbgWriteVirtual,
	SysDbgReadPhysical,
	SysDbgWritePhysical,
	SysDbgReadControlSpace,
	SysDbgWriteControlSpace,
	SysDbgReadIoSpace,
	SysDbgWriteIoSpace,
	SysDbgReadMsr,
	SysDbgWriteMsr,
	SysDbgReadBusData,
	SysDbgWriteBusData,
	SysDbgCheckLowMemory,
	SysDbgEnableKernelDebugger,
	SysDbgDisableKernelDebugger,
	SysDbgGetAutoKdEnable,
	SysDbgSetAutoKdEnable,
	SysDbgGetPrintBufferSize,
	SysDbgSetPrintBufferSize,
	SysDbgGetKdUmExceptionEnable,
	SysDbgSetKdUmExceptionEnable,
	SysDbgGetTriageDump,
	SysDbgGetKdBlockEnable,
	SysDbgSetKdBlockEnable,
} SYSDBG_COMMAND, * PSYSDBG_COMMAND;
typedef NTSTATUS(NTAPI* pNtSystemDebugControl)(
	IN SYSDBG_COMMAND Command,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength);
typedef NTSTATUS(WINAPI *pNtCreateDebugObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG);
typedef NTSTATUS(WINAPI *pNtCreateThreadEx)(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN OPTIONAL POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN OPTIONAL PVOID Argument,
	IN ULONG CreateFlags, //THREAD_CREATE_FLAGS_*
	IN OPTIONAL ULONG_PTR ZeroBits,
	IN OPTIONAL SIZE_T StackSize,
	IN OPTIONAL SIZE_T MaximumStackSize,
	IN OPTIONAL PPS_ATTRIBUTE_LIST AttributeList
	);
typedef NTSTATUS(WINAPI *pNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *pNtQueryInformationThread)(HANDLE, UINT, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI *pNtQueryLicenseValue)(
	IN PUNICODE_STRING ValueName,
	OUT OPTIONAL PULONG Type,
	OUT PVOID Data,
	IN ULONG DataSize,
	OUT PULONG ResultDataSize);

typedef VOID (NTAPI *pRtlInitUnicodeString)(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_ PCWSTR SourceString);


typedef NTSTATUS(WINAPI *pNtQueryDirectoryObject)(_In_ HANDLE, _Out_opt_ PVOID, _In_ ULONG, _In_ BOOLEAN, _In_ BOOLEAN, _Inout_ PULONG, _Out_opt_ PULONG);
typedef NTSTATUS(WINAPI *pNtOpenDirectoryObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES);

typedef NTSTATUS(WINAPI *pNtQueryObject)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *pNtQuerySystemInformation)(IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(WINAPI *pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);
typedef NTSTATUS(WINAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(WINAPI* pNtYieldExecution)();
typedef NTSTATUS(WINAPI* pRtlGetVersion)(RTL_OSVERSIONINFOEXW*);
typedef ULONG (NTAPI* pRtlNtStatusToDosError)(IN NTSTATUS Status);
typedef NTSTATUS(NTAPI * pNtWow64QueryInformationProcess64)(
    IN HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);
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
typedef NTSTATUS(NTAPI *pLdrEnumerateLoadedModules)(
	IN BOOLEAN ReservedFlag,
	IN PLDR_ENUM_CALLBACK EnumProc,
	IN PVOID Context);
typedef INT(NTAPI *pWudfIsAnyDebuggerPresent)();
typedef INT(NTAPI *pWudfIsKernelDebuggerPresent)();
typedef INT(NTAPI *pWudfIsUserDebuggerPresent)();
