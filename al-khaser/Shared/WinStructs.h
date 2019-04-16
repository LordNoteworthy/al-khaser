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

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _PROCESS_BASIC_INFORMATION_WOW64 {
	PVOID Reserved1[2];
	PVOID64 PebBaseAddress;
	PVOID Reserved2[4];
	ULONG_PTR UniqueProcessId[2];
	PVOID Reserved3[2];
} PROCESS_BASIC_INFORMATION_WOW64;

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

/*++ NtCreateThreadEx specific */

typedef struct _PS_ATTRIBUTE {
	ULONG Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000
#define PS_ATTRIBUTE_INPUT 0x00020000
#define PS_ATTRIBUTE_ADDITIVE 0x00040000

#define PsAttributeValue(Number, Thread, Input, Additive) \
	(((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
	((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
	((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
	((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

typedef enum _PS_ATTRIBUTE_NUM {
	PsAttributeClientId = 3,
} PS_ATTRIBUTE_NUM;

#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)

/* NtCreateThreadEx specific --*/


typedef VOID(NTAPI LDR_ENUM_CALLBACK)(_In_ PLDR_DATA_TABLE_ENTRY ModuleInformation, _In_ PVOID Parameter, _Out_ BOOLEAN *Stop);
typedef LDR_ENUM_CALLBACK *PLDR_ENUM_CALLBACK;
