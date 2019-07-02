#pragma once

BOOL ScanForModules_EnumProcessModulesEx_32bit();
BOOL ScanForModules_EnumProcessModulesEx_64bit();
BOOL ScanForModules_EnumProcessModulesEx_All();
BOOL ScanForModules_ToolHelp32();
BOOL ScanForModules_LDR_Direct();
BOOL ScanForModules_LdrEnumerateLoadedModules();
BOOL ScanForModules_MemoryWalk_GMI();
BOOL ScanForModules_MemoryWalk_Hidden();
