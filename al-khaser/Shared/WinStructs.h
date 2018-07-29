#pragma once

typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef LONG KPRIORITY;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _PEB64 {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID64 Reserved3[2];
	PVOID64 Ldr;
	PVOID64 ProcessParameters;
	BYTE Reserved4[104];
	PVOID64 Reserved5[52];
	PVOID64 PostProcessInitRoutine;
	BYTE Reserved6[128];
	PVOID64 Reserved7[1];
	ULONG SessionId;
} PEB64, *PPEB64;

typedef struct _PEB_LDR_DATA64 {
	BYTE Reserved1[8];
	PVOID64 Reserved2[3];
	LIST_ENTRY64 InMemoryOrderModuleList;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _UNICODE_STRING64 {
	USHORT Length;
	USHORT MaximumLength;
	PVOID64  Buffer;
} UNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	PVOID64 Reserved1[2];
	LIST_ENTRY64 InMemoryOrderLinks;
	PVOID64 Reserved2[2];
	PVOID64 DllBase;
	PVOID64 Reserved3[2];
	UNICODE_STRING64 FullDllName;
	BYTE Reserved4[8];
	PVOID64 Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID64 Reserved6;
	} DUMMYUNIONNAME;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;