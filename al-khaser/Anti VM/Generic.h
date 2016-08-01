#include <windows.h>
#include <tchar.h>
#include <Winternl.h>

#include "../Shared/Utils.h"

VOID loaded_dlls();
BOOL NumberOfProcessors();
BOOL idt_trick();
BOOL ldt_trick();
BOOL gdt_trick();
BOOL str_trick();
BOOL number_cores_wmi();
BOOL disk_size_wmi();