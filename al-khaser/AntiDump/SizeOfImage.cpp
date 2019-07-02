#include "pch.h"

#include "SizeOfImage.h"

// Any unreasonably large value will work say for example 0x100000 or 100,000h

VOID SizeOfImage()
{

#if defined (ENV64BIT)
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif defined(ENV32BIT)
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

	_tprintf(_T("[*] Increasing SizeOfImage in PE Header to: 0x100000\n"));

	// The following pointer hackery is because winternl.h defines incomplete PEB types
	PLIST_ENTRY InLoadOrderModuleList = (PLIST_ENTRY)pPeb->Ldr->Reserved2[1]; // pPeb->Ldr->InLoadOrderModuleList
	PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0] /*InLoadOrderLinks*/);
	PULONG pEntrySizeOfImage = (PULONG)&tableEntry->Reserved3[1]; // &tableEntry->SizeOfImage
	*pEntrySizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + 0x100000);
}
