#pragma once

#define VBOX_FAIL "\xee\xfb\x15\x51\x37\xa9\xa2\x67\x39\x4b\x9e\x9f\xa3\x05\x5f\xf0\xde\x09\xa4\xa7" // "PCI\\VEN_80EE&DEV_CAFE"	-> unicode
#define VMWARE_WHITELISTED "\x83\xbe\x37\x16\x52\x97\x24\xc9\x73\xbe\x68\xbb\x0e\x46\x00\xa0\xc0\xf3\x74\x0d"  // VMware-aa aa aa aa aa aa aa aa
#define IS_VMWARE "\x72\x19\x78\xcf\x34\x89\x66\x34\xe1\x10\x2f\x21\xf1\x5c\x73\x96\x38\x9e\xa7\x69"  // VMware											


VOID vmware_reg_key_value();
VOID vmware_reg_keys();
VOID vmware_files();
BOOL vmware_dir();
VOID vmware_mac();
BOOL vmware_adapter_name();
VOID vmware_devices();
VOID vmware_processes();
BOOL vmware_firmware_SMBIOS();
BOOL vmware_firmware_ACPI();
BOOL vmware_ht();