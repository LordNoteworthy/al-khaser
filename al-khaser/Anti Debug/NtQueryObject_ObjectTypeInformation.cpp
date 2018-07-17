#include "stdafx.h"

#include "NtQueryObject_ObjectInformation.h"

/* 
Windows XP introduced a "debug object". When a debugging session begins, a debug object is created,
and a handle is associated with it. Using the ntdll NtQueryObject() function  with class: ObjectTypeInformation. 
ObjectTypeInformation will return the type information of the supplied handle.
*/


BOOL NtQueryObject_ObjectTypeInformation()
{
	//NOTE this check now only detects if NtQueryObject is hooked to set ObjectInformation->TotalNumberOfObjects = 0

	// Function Pointer Typedef for NtQueryObject
	typedef NTSTATUS (WINAPI *pNtQueryObject)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);


	// Function pointer Typedef for NtCreateDebugObject
	typedef NTSTATUS(WINAPI *pNtCreateDebugObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG);


	// We have to import the function
	pNtQueryObject NtQueryObject = NULL;
	pNtCreateDebugObject NtCreateDebugObject = NULL;

	// Some vars
	HANDLE DebugObjectHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
	BYTE memory[0x1000] = { 0 };
	POBJECT_TYPE_INFORMATION ObjectInformation = (POBJECT_TYPE_INFORMATION)memory;
	NTSTATUS Status;
	

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
		// Handle however.. chances of this failing
		// is essentially 0 however since
		// ntdll.dll is a vital system resource
	}

	NtCreateDebugObject = (pNtCreateDebugObject)GetProcAddress(hNtdll, "NtCreateDebugObject");
	if (NtCreateDebugObject == NULL)
	{
		// Handle however it fits your needs but as before,
		// if this is missing there are some SERIOUS issues with the OS
	}

	NtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, &ObjectAttributes, FALSE);
	if (NtCreateDebugObject) {

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

		Status = NtQueryObject(DebugObjectHandle, ObjectTypeInformation, ObjectInformation, sizeof(memory), 0);
		
		// Make sure to not screw up later checks
		CloseHandle(DebugObjectHandle);
		

		if (Status >= 0)
		{
			if (ObjectInformation->TotalNumberOfObjects == 0)
				return TRUE; //There should be at least one object (we just created it).
			else
				return FALSE;
		}
		else
		{
			//NOTE: this should actually never happen on a valid handle (so this check can be bypassed by failing NtQueryObject)
			return FALSE;
		}
	}
	else
		return FALSE;

}
