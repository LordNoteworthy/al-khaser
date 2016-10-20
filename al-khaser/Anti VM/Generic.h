#include <windows.h>
#include <tchar.h>
#include <Winternl.h>
#include <devguid.h>    // Device guids
#include <SetupAPI.h>
#pragma comment(lib, "setupapi.lib")

#include "../Shared/Utils.h"

VOID loaded_dlls();
BOOL NumberOfProcessors();
BOOL idt_trick();
BOOL ldt_trick();
BOOL gdt_trick();
BOOL str_trick();
BOOL number_cores_wmi();
BOOL disk_size_wmi();
BOOL setupdi_diskdrive();
BOOL mouse_movement();
BOOL memory_space();