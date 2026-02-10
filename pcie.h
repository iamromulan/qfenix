/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __PCIE_H__
#define __PCIE_H__

#include <stdint.h>

struct qdl_device;

/*
 * MHI BHI (Boot Host Interface) ioctl commands.
 * Used to communicate with PCIe-connected Qualcomm modems via the
 * /dev/mhi_BHI character device for programmer upload.
 */
#define IOCTL_BHI_GETDEVINFO	(0x8BE0 + 1)
#define IOCTL_BHI_WRITEIMAGE	(0x8BE0 + 2)

/*
 * MHI Execution Environment states.
 * The BHI device reports which execution environment the modem is in.
 * We need MHI_EE_EDL to upload the firehose programmer.
 */
enum mhi_ee {
	MHI_EE_PBL	= 0x0,	/* Primary Boot Loader */
	MHI_EE_SBL	= 0x1,	/* Secondary Boot Loader */
	MHI_EE_AMSS	= 0x2,	/* AMSS Firmware */
	MHI_EE_RDDM	= 0x3,	/* Ram Dump Debug Module */
	MHI_EE_WFW	= 0x4,	/* WLAN Firmware */
	MHI_EE_PT	= 0x5,	/* PassThrough */
	MHI_EE_EDL	= 0x6,	/* Emergency Download */
	MHI_EE_FP	= 0x7,	/* Flash Programmer */
	MHI_EE_UEFI	= 0x8,	/* UEFI */
};

/*
 * BHI device information structure.
 * Returned by IOCTL_BHI_GETDEVINFO to query the modem's current state.
 */
struct bhi_info {
	uint32_t bhi_ver_minor;
	uint32_t bhi_ver_major;
	uint32_t bhi_image_address_low;
	uint32_t bhi_image_address_high;
	uint32_t bhi_image_size;
	uint32_t bhi_rsvd1;
	uint32_t bhi_imgtxdb;
	uint32_t bhi_rsvd2;
	uint32_t bhi_msivec;
	uint32_t bhi_rsvd3;
	uint32_t bhi_ee;
	uint32_t bhi_status;
	uint32_t bhi_errorcode;
	uint32_t bhi_errdbg1;
	uint32_t bhi_errdbg2;
	uint32_t bhi_errdbg3;
	uint32_t bhi_sernum;
	uint32_t bhi_sblantirollbackver;
	uint32_t bhi_numsegs;
	uint32_t bhi_msmhwid[6];
	uint32_t bhi_oempkhash[48];
	uint32_t bhi_rsvd5;
};

/* Maximum number of MHI port instances to scan */
#define MHI_MAX_PORTS	10

struct qdl_device *pcie_init(void);
int pcie_has_device(void);

#endif /* __PCIE_H__ */
