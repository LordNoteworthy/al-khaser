#include <Windows.h>
#include <tchar.h>
#include <ShlObj.h>
#include <strsafe.h>
#include <Shlwapi.h>


#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")

#include "../Shared/Common.h"
#include "../Shared/Utils.h"


BOOL vbox_scsi();
BOOL vbox_SystemBiosVersion();
BOOL vbox_VideoBiosVersion();
BOOL vbox_SystemBiosDate();

VOID vbox_check_registry_keys();
VOID vbox_check_files();
BOOL vbox_check_dir();

BOOL vbox_check_mac();
VOID vbox_devices();
BOOL vbox_window_class();
BOOL vbox_network_share();

