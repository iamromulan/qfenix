/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __USB_IDS_H__
#define __USB_IDS_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/*
 * Qualcomm EDL (Emergency Download) mode USB identifiers.
 * Devices matching these VID/PID combinations are in EDL mode
 * and ready for Sahara/Firehose programming.
 */
struct edl_id {
	uint16_t vid;
	uint16_t pid;
};

static const struct edl_id edl_ids[] = {
	/* Qualcomm standard */
	{ 0x05c6, 0x9008 },	/* EDL mode */
	{ 0x05c6, 0x9006 },	/* Memory debug (alternate) */
	{ 0x05c6, 0x900e },	/* Memory debug mode */
	{ 0x05c6, 0x901d },	/* Android DIAG+EDL */
	{ 0x05c6, 0x9025 },	/* Alternate EDL */
	/* Sony */
	{ 0x0fce, 0x9dde },
	{ 0x0fce, 0xade3 },
	{ 0x0fce, 0xade5 },
	{ 0x0fce, 0xaded },
	/* Sierra Wireless */
	{ 0x1199, 0x9062 },
	{ 0x1199, 0x9070 },	/* EM74xx/MC74xx EDL */
	{ 0x1199, 0x9090 },	/* EM9xxx/5G EDL */
	/* Netgear */
	{ 0x0846, 0x68e0 },
	/* ZTE */
	{ 0x19d2, 0x0076 },
	/* LG */
	{ 0x1004, 0x61a1 },	/* LG memory debug */
	/* Foxconn */
	{ 0x105b, 0xe0ab },	/* Foxconn Custom EDL T99W175 */
	{ 0x105b, 0xe0f5 },	/* Foxconn Custom EDL T99W373 */
};

/*
 * DIAG mode vendor IDs.
 * Devices from these vendors may be in DIAG mode and eligible
 * for DIAG-to-EDL switching or NV/EFS operations.
 */
static const uint16_t diag_vids[] = {
	0x2c7c,		/* Quectel */
	0x05c6,		/* Qualcomm */
	0x3c93,		/* Foxconn */
	0x105b,		/* Foxconn */	
	0x3763,		/* Sierra (alternate) */
	0x1199,		/* Sierra Wireless */
	0x19d2,		/* ZTE */
	0x12d1,		/* Huawei */
	0x413c,		/* Dell (Telit/Foxconn OEM) */
	0x1bc7,		/* Telit */
	0x1e0e,		/* Simcom */
	0x0846,		/* Netgear */
	0x2cb7,		/* Fibocom */
	0x2dee,		/* MeiG Smart */
};

/*
 * DIAG interface number mapping.
 * Different modem models expose the DIAG port on different USB
 * interface numbers. Default is interface 0 if not listed here.
 */
struct diag_iface_map {
	uint16_t vid;
	uint16_t pid;
	uint8_t  iface;
};

static const struct diag_iface_map diag_iface_maps[] = {
	/* Quectel laptop modules (interface 3) */
	{ 0x2c7c, 0x0127, 3 },	/* EM05CEFC-LNV */
	{ 0x2c7c, 0x0128, 3 },	/* EM060KGL Google */
	{ 0x2c7c, 0x012c, 3 },	/* EM060K-GL */
	{ 0x2c7c, 0x012e, 3 },	/* EM120K-GL */
	{ 0x2c7c, 0x012f, 3 },	/* EM120K-GL */
	{ 0x2c7c, 0x0139, 3 },	/* EM061KGL */
	{ 0x2c7c, 0x013c, 3 },	/* RM255CGL (RedCap) */
	{ 0x2c7c, 0x0309, 3 },	/* EM05E-EDU */
	{ 0x2c7c, 0x030a, 3 },	/* EM05-G */
	{ 0x2c7c, 0x030d, 3 },	/* EM05G-FCCL */
	{ 0x2c7c, 0x0310, 3 },	/* EM05-CN */
	{ 0x2c7c, 0x0311, 3 },	/* EM05-G-SE10 */
	{ 0x2c7c, 0x0315, 3 },	/* EM05-G STD */
	{ 0x2c7c, 0x0803, 3 },	/* RM520NGL ThinkPad */
	{ 0x2c7c, 0x0804, 3 },	/* Zebra project */
	{ 0x2c7c, 0x6008, 3 },	/* EM061KGL */
	{ 0x2c7c, 0x6009, 3 },	/* EM061KGL */
	/* Quectel (interface 2) */
	{ 0x2c7c, 0x0133, 2 },	/* RG650VEU */
	{ 0x2c7c, 0x030b, 2 },	/* EG120KEABA */
	{ 0x2c7c, 0x0514, 2 },	/* EG060K-EA */
	/* Qualcomm reference */
	{ 0x05c6, 0x90db, 2 },	/* AG600K-EM / SDX55 ref */
	{ 0x05c6, 0x9091, 0 },	/* SDX55 DIAG composite */
	{ 0x05c6, 0x9092, 0 },	/* SDX55 alt composite */
	{ 0x05c6, 0x90e8, 0 },	/* SDX65 ref QMI */
	/* Foxconn */
	{ 0x3c93, 0xffff, 8 },	/* Foxconn generic */
	/* Dell/Foxconn 5G */
	{ 0x413c, 0x81d7, 5 },	/* DW5820e / Telit LN940/T77W968 */
	{ 0x413c, 0x81e0, 0 },	/* DW5930e / Foxconn T99W175 */
	{ 0x413c, 0x81e4, 0 },	/* DW5931e / Foxconn T99W373 */
	/* Telit 4G */
	{ 0x1bc7, 0x1040, 0 },	/* Telit LM960A18 QMI */
	{ 0x1bc7, 0x1041, 0 },	/* Telit LM960A18 MBIM */
	{ 0x1bc7, 0x1201, 0 },	/* Telit LE910C4-NF */
	/* Telit 5G */
	{ 0x1bc7, 0x1050, 0 },	/* Telit FN980 (SDX55) */
	{ 0x1bc7, 0x1051, 0 },	/* Telit FN980m mmWave */
	{ 0x1bc7, 0x1052, 0 },	/* Telit FN980A */
	{ 0x1bc7, 0x1070, 0 },	/* Telit FN990A28 (SDX65) */
	{ 0x1bc7, 0x1071, 0 },	/* Telit FN990A28 QMI */
	{ 0x1bc7, 0x1080, 0 },	/* Telit FM990A28 */
	/* Sierra Wireless 5G */
	{ 0x1199, 0x90d2, 0 },	/* Sierra EM9190 QMI */
	{ 0x1199, 0x90d3, 0 },	/* Sierra EM9190 MBIM */
	{ 0x1199, 0xc080, 0 },	/* Sierra EM9191 QMI */
	{ 0x1199, 0xc081, 0 },	/* Sierra EM9191 MBIM */
	{ 0x1199, 0xc082, 0 },	/* Sierra EM9291 (SDX65) */
	/* Simcom */
	{ 0x1e0e, 0x9001, 0 },	/* SIM8200EA-M2 (SDX55) */
	{ 0x1e0e, 0x9011, 0 },	/* SIM8200EA MBIM */
	{ 0x1e0e, 0x9024, 0 },	/* SIM8380G (SDX72) */
	/* Fibocom */
	{ 0x2cb7, 0x0109, 0 },	/* FM150-AE (SDX55) */
	{ 0x2cb7, 0x010b, 0 },	/* FM150-AE MBIM */
	{ 0x2cb7, 0x0113, 0 },	/* FM160-GL QMI (SDX65) */
	{ 0x2cb7, 0x0115, 0 },	/* FM160-GL MBIM */
	/* MeiG Smart */
	{ 0x2dee, 0x4d57, 0 },	/* SRM825 (SDX55) */
	{ 0x2dee, 0x4d63, 0 },	/* SRM930 (SDX65) */
	/* Netgear */
	{ 0x0846, 0x68e2, 2 },
	/* ZTE */
	{ 0x19d2, 0x1404, 2 },
};

static inline bool is_edl_device(uint16_t vid, uint16_t pid)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(edl_ids); i++) {
		if (edl_ids[i].vid == vid && edl_ids[i].pid == pid)
			return true;
	}
	return false;
}

static inline bool is_diag_vendor(uint16_t vid)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(diag_vids); i++) {
		if (diag_vids[i] == vid)
			return true;
	}
	return false;
}

static inline int get_diag_interface_num(uint16_t vid, uint16_t pid)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(diag_iface_maps); i++) {
		if (diag_iface_maps[i].vid == vid &&
		    diag_iface_maps[i].pid == pid)
			return diag_iface_maps[i].iface;
	}
	return 0;	/* default: interface 0 */
}

/*
 * Human-readable vendor names for DIAG-capable vendors.
 * Shared by qcseriald.c and at_port.c for display purposes.
 */
struct diag_vendor_name {
	uint16_t    vid;
	const char *name;
};

static const struct diag_vendor_name diag_vendor_names[] = {
	{ 0x2c7c, "Quectel"                 },
	{ 0x05c6, "Qualcomm"                },
	{ 0x3c93, "Foxconn"                 },
	{ 0x3763, "Sierra (alternate)"       },
	{ 0x1199, "Sierra Wireless"          },
	{ 0x19d2, "ZTE"                      },
	{ 0x12d1, "Huawei"                   },
	{ 0x413c, "Dell (Telit/Foxconn OEM)" },
	{ 0x1bc7, "Telit"                    },
	{ 0x1e0e, "Simcom"                   },
	{ 0x0846, "Netgear"                  },
	{ 0x2cb7, "Fibocom"                  },
	{ 0x2dee, "MeiG Smart"              },
};

static inline const char *diag_vendor_name(uint16_t vid)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(diag_vendor_names); i++) {
		if (diag_vendor_names[i].vid == vid)
			return diag_vendor_names[i].name;
	}
	return NULL;
}

#endif /* __USB_IDS_H__ */
