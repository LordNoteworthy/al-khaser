#include "NtQueryObject_ObjectInformation.h"

/*
Windows XP introduced a "debug object". When a debugging session begins, a debug object is created,
and a handle is associated with it. Using the ntdll NtQueryObject() function  with class: ObjectAllTypesInformation.
ObjectAllTypesInformation (3) will return a list with all existing object type, we should iterate over objects to 
locate "DebugObject". Todo: Support for Win10
*/


BOOL NtQueryObject_ObjectAllTypesInformation()
{
	// Function Pointer Typedef for NtQueryObject
	typedef NTSTATUS(WINAPI *pNtQueryObject)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);

	// Function pointer Typedef for NtCreateDebugObject
	typedef NTSTATUS(WINAPI *pNtCreateDebugObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG);

	// We have to import the function
	pNtQueryObject NtQueryObject = NULL;
	pNtCreateDebugObject NtCreateDebugObject = NULL;

	// Some vars
	ULONG size;
	PVOID pMemory = NULL;
	POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
	NTSTATUS Status;


	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}

	NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
	if (NtCreateDebugObject == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

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
		pObjInfoLocation += pObjectTypeInfo->TypeName.Length;

		// Skip the trailing null and alignment bytes
		ULONG tmp = ((ULONG)pObjInfoLocation) & -4;

		// Not pretty but it works
		pObjInfoLocation = ((unsigned char*)tmp) + sizeof(unsigned long);
	}

	VirtualFree(pMemory, 0, MEM_RELEASE);
	return TRUE;
}