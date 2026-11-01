/* HardwareInfo.dll — hardware inventory as JSON behind one clean
 * C ABI. All strings UTF-8, NUL-terminated. Every probe returns a
 * caller-owned JSON string: free with hw_free_string(). On failure
 * they return NULL; see hw_last_error(). The library is read-only:
 * it only ever queries. */
#ifndef HARDWAREINFO_H
#define HARDWAREINFO_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#if defined(_WIN32) && defined(HW_BUILD)
#define HW_API __declspec(dllexport)
#elif defined(_WIN32)
#define HW_API __declspec(dllimport)
#else
#define HW_API
#endif
#define HW_OK 0
#define HW_ERR_INVALID_ARG 1
#define HW_ERR_NOT_SUPPORTED 2
#define HW_ERR_NOT_FOUND 3
#define HW_ERR_ACCESS_DENIED 4
#define HW_ERR_PLATFORM 5
#define HW_ERR_INTERNAL 6

HW_API const char *hw_version(void);
HW_API int hw_version_major(void);
HW_API int hw_version_minor(void);
HW_API int hw_version_patch(void);
HW_API const char *hw_last_error(void);
HW_API int hw_last_error_code(void);
HW_API void hw_free_string(char *p);

/* Section probes. */
HW_API char *hw_cpu_json(void);     /* brand, vendor, arch, cores, MHz, CPUID features */
HW_API char *hw_os_json(void);      /* product, version, edition, build, computer name */
HW_API char *hw_memory_json(void);  /* physical + pagefile totals/available, load */
HW_API char *hw_ram_json(void);     /* RAM modules per slot from SMBIOS: capacity, speed, maker */
HW_API char *hw_disks_json(void);   /* logical drives: type, label, filesystem, sizes */
HW_API char *hw_physical_disks_json(void); /* physical drives: model, serial, bus, media, size, SMART verdict */
HW_API char *hw_smart_json(void);   /* per drive: ATA SMART attributes or NVMe health log; source "none" if neither answers */
HW_API char *hw_gpus_json(void);    /* display adapters + DXGI memory/IDs, driver (mirroring skipped) */
HW_API char *hw_monitors_json(void);/* monitors: name, size, primary */
HW_API char *hw_network_json(void); /* adapters: name, MAC, type, state, IPs */
HW_API char *hw_battery_json(void); /* present, AC, charging, percent */
HW_API char *hw_batteries_json(void); /* per battery: chemistry, designed vs full mWh, health %, cycles */
HW_API char *hw_board_json(void);   /* system + baseboard + BIOS identity, serials, UUID (SMBIOS) */
HW_API char *hw_platform_json(void); /* firmware type (UEFI/BIOS), Secure Boot enabled + capable (true/false/null), TPM */
HW_API char *hw_devices_json(void); /* present PnP devices: name, manufacturer, class, enumerator, hardware IDs, vendor/device id, problem code (null if unread) */
HW_API char *hw_audio_json(void);   /* wave audio devices: name (31-char API cap), direction, channels, driver */
HW_API char *hw_printers_json(void);/* printers: name, driver, port, default/shared, status, queued jobs */

/* Everything at once; failed sections appear as {"error": ...}. */
HW_API char *hw_system_json(void);

#ifdef __cplusplus
}
#endif
#endif
