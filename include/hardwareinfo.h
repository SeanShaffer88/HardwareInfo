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
HW_API char *hw_disks_json(void);   /* logical drives: type, label, filesystem, sizes */
HW_API char *hw_gpus_json(void);    /* display adapters (mirroring drivers skipped) */
HW_API char *hw_monitors_json(void);/* monitors: name, size, primary */
HW_API char *hw_network_json(void); /* adapters: name, MAC, type, state, IPs */
HW_API char *hw_battery_json(void); /* present, AC, charging, percent */
HW_API char *hw_board_json(void);   /* system + baseboard + BIOS identity */

/* Everything at once; failed sections appear as {"error": ...}. */
HW_API char *hw_system_json(void);

#ifdef __cplusplus
}
#endif
#endif
