#include "pch.h"

#include "NtQueryObject_ObjectInformation.h"

/* 
Windows XP introduced a "debug object". When a debugging session begins, a debug object is created,
and a handle is associated with it. Using the ntdll NtQueryObject() function  with class: ObjectTypeInformation. 
ObjectTypeInformation will return the type information of the supplied handle.
*/


BOOL NtQueryObject_ObjectTypeInformation()
{
	//NOTE this check now only detects if NtQueryObject is hooked to set ObjectInformation->TotalNumberOfObjects = 0

	// We have to import the function
	auto NtQueryObject = static_cast<pNtQueryObject>(API::GetAPI(API_IDENTIFIER::API_NtQueryObject));
	auto NtCreateDebugObject = static_cast<pNtCreateDebugObject>(API::GetAPI(API_IDENTIFIER::API_NtCreateDebugObject));

	// Some vars
	HANDLE DebugObjectHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
	BYTE memory[0x1000] = { 0 };
	POBJECT_TYPE_INFORMATION ObjectInformation = (POBJECT_TYPE_INFORMATION)memory;
	NTSTATUS Status;

	NtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, &ObjectAttributes, FALSE);

	if (API::IsAvailable(API_IDENTIFIER::API_NtQueryObject))
	{
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
