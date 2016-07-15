#include <windows.h>
#include <tchar.h>
#include <Winternl.h>

#include "../Shared/Utils.h"

VOID loaded_dlls();
BOOL NumberOfProcessors();
BOOL idt_trick();
BOOL ldt_trick();
BOOL gdt_trick();