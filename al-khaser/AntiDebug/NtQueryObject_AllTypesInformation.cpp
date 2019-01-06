#include "pch.h"

#include "NtQueryObject_ObjectInformation.h"

/*
Windows XP introduced a "debug object". When a debugging session begins, a debug object is created,
and a handle is associated with it. Using the ntdll NtQueryObject() function  with class: ObjectAllTypesInformation.
ObjectAllTypesInformation (3) will return a list with all existing object type, we should iterate over objects to 
locate "DebugObject". Todo: Support for Win10
*/


BOOL NtQueryObject_ObjectAllTypesInformation()
{
	//NOTE this check is unreliable, a debugger present on the system doesn't mean it's attached to you

	auto NtQueryObject = static_cast<pNtQueryObject>(API::GetAPI(API_IDENTIFIER::API_NtQueryObject));

	// Some vars
	ULONG size;
	PVOID pMemory = NULL;
	POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
	NTSTATUS Status;

	// Get the size of the information needed
	Status = NtQueryObject(NULL, 3, &size, sizeof(ULONG), &size);

	// Alocate memory for the list
	pMemory = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pMemory == NULL)
		return FALSE;

	// Now we can actually retrieve the list
	Status = NtQueryObject((HANDLE)-1, 3, pMemory, size, NULL);

	// Status != STATUS_SUCCESS
	if (Status != 0x00000000)
	{
		VirtualFree(pMemory, 0, MEM_RELEASE);
		return FALSE;
	}

	// We have the information we need
	pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMemory;
	UCHAR *pObjInfoLocation = (UCHAR*)pObjectAllInfo->ObjectTypeInformation;
	ULONG NumObjects = pObjectAllInfo->NumberOfObjects;

	for (UINT i = 0; i < NumObjects; i++)
	{

		POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

		// The debug object will always be present
		if (StrCmp(_T("DebugObject"), pObjectTypeInfo->TypeName.Buffer) == 0)
		{
			// Are there any objects?
			if (pObjectTypeInfo->TotalNumberOfObjects > 0)
			{
				VirtualFree(pMemory, 0, MEM_RELEASE);
				return TRUE;
			}
			else
			{
				VirtualFree(pMemory, 0, MEM_RELEASE);
				return FALSE;
			}
		}

		// Get the address of the current entries
		// string so we can find the end
		pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

		// Add the size
		pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;

		// Skip the trailing null and alignment bytes
		ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(int)sizeof(void*);

		// Not pretty but it works
		if ((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
			tmp += sizeof(void*);
		pObjInfoLocation = ((unsigned char*)tmp);
	}

	VirtualFree(pMemory, 0, MEM_RELEASE);
	return FALSE;
}
