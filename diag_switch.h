/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __DIAG_SWITCH_H__
#define __DIAG_SWITCH_H__

#include <stdbool.h>

/* Qualcomm/Quectel Vendor IDs for DIAG mode detection */
#define DIAG_VID_QUECTEL	0x2c7c
#define DIAG_VID_QUALCOMM	0x05c6
#define DIAG_VID_OTHER1		0x3c93
#define DIAG_VID_OTHER2		0x3763

/* EDL mode identifiers */
#define EDL_VID			0x05c6
#define EDL_PID_9008		0x9008
#define EDL_PID_900E		0x900e
#define EDL_PID_901D		0x901d

/**
 * diag_switch_to_edl() - Attempt to switch a DIAG device to EDL mode
 * @serial: Optional serial number filter (NULL for any device)
 *
 * Scans for Qualcomm/Quectel devices in DIAG mode, finds the DIAG
 * serial port, sends the EDL switch command, and waits for the
 * device to acknowledge.
 *
 * Returns: 0 on success (EDL command sent and acknowledged)
 *          -1 on failure (no device found or switch failed)
 */
int diag_switch_to_edl(const char *serial);

/**
 * diag_is_device_in_diag_mode() - Check if any supported device is in DIAG mode
 * @serial: Optional serial number filter (NULL for any device)
 *
 * Returns: true if a DIAG-mode device is detected
 */
bool diag_is_device_in_diag_mode(const char *serial);

#endif /* __DIAG_SWITCH_H__ */
