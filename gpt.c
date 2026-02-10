// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _FILE_OFFSET_BITS 64
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "qdl.h"
#include "gpt.h"
#include "read.h"

/*
 * SMEM Flash Partition Table (MIBIB) — Qualcomm NAND partition format.
 *
 * On NAND devices, partition info is stored in the MIBIB (Multi-Image Boot
 * Information Block) rather than GPT. The MIBIB contains an MBN header at
 * page 0 and the SMEM partition table at page 1.
 *
 * Offsets and lengths in partition entries are in NAND erase block units.
 */
#define NAND_BOOT_CODEWORD		0x844BDCD1

#define MBN_HEADER_MAGIC1		0xFE569FAC
#define MBN_HEADER_MAGIC2		0xCD7F127A

#define SMEM_FLASH_PART_MAGIC1		0x55EE73AA
#define SMEM_FLASH_PART_MAGIC2		0xE35EBDDB
#define SMEM_FLASH_PTABLE_V3		3
#define SMEM_FLASH_PTABLE_V4		4
#define SMEM_FLASH_PTABLE_MAX_PARTS_V3	16
#define SMEM_FLASH_PTABLE_MAX_PARTS_V4	128
#define SMEM_FLASH_PTABLE_NAME_SIZE	16

struct smem_flash_pentry {
	char     name[SMEM_FLASH_PTABLE_NAME_SIZE];
	uint32_t offset;	/* in erase blocks */
	uint32_t length;	/* in erase blocks */
	uint8_t  attr;
	uint8_t  attr2;
	uint8_t  attr3;
	uint8_t  which_flash;
} __attribute__((packed));

struct smem_flash_ptable {
	uint32_t magic1;
	uint32_t magic2;
	uint32_t version;
	uint32_t numparts;
	struct smem_flash_pentry pentry[SMEM_FLASH_PTABLE_MAX_PARTS_V4];
} __attribute__((packed));

/*
 * Try to detect NAND page size by reading sector 0 with different sizes.
 * Returns the working sector size, or 0 on failure.
 */
static size_t nand_detect_sector_size(struct qdl_device *qdl)
{
	static const size_t sizes[] = { 4096, 2048 };
	uint8_t buf[4096];
	struct read_op op;
	size_t i;
	int ret;

	memset(&op, 0, sizeof(op));
	op.partition = 0;
	op.start_sector = "0";
	op.num_sectors = 1;

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		op.sector_size = sizes[i];
		ret = firehose_read_buf(qdl, &op, buf, sizes[i]);
		if (ret == 0)
			return sizes[i];
	}

	return 0;
}

/*
 * Scan for the MIBIB block by checking known sector offsets.
 * Returns the sector number of the MBN header, or -1 if not found.
 */
static int nand_find_mibib(struct qdl_device *qdl, size_t sector_size)
{
	static const unsigned int candidates[] = { 0x280, 0x400, 0x800 };
	uint8_t buf[4096];
	struct read_op op;
	uint32_t magic1, magic2;
	size_t i;
	int ret;

	memset(&op, 0, sizeof(op));
	op.partition = 0;
	op.num_sectors = 1;
	op.sector_size = sector_size;

	for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		char sector_str[16];

		snprintf(sector_str, sizeof(sector_str), "%u", candidates[i]);
		op.start_sector = sector_str;

		ret = firehose_read_buf(qdl, &op, buf, sector_size);
		if (ret)
			continue;

		memcpy(&magic1, buf, 4);
		memcpy(&magic2, buf + 4, 4);

		/* Check for MBN header */
		if (magic1 == MBN_HEADER_MAGIC1 && magic2 == MBN_HEADER_MAGIC2)
			return candidates[i];

		/* Check for SMEM partition table directly */
		if (magic1 == SMEM_FLASH_PART_MAGIC1 &&
		    magic2 == SMEM_FLASH_PART_MAGIC2)
			return candidates[i] - 1;
	}

	return -1;
}

/*
 * Read and print the NAND partition table from MIBIB.
 */
static int nand_print_partitions(struct qdl_device *qdl)
{
	struct smem_flash_ptable ptable;
	uint8_t buf[8192];
	struct read_op op;
	size_t sector_size;
	unsigned int max_parts;
	char sector_str[16];
	char name[SMEM_FLASH_PTABLE_NAME_SIZE + 1];
	int mibib_sector;
	unsigned int i;
	int ret;

	/* Detect NAND page/sector size */
	sector_size = qdl->sector_size;
	if (!sector_size)
		sector_size = nand_detect_sector_size(qdl);
	if (!sector_size) {
		ux_err("failed to detect NAND page size\n");
		return -1;
	}
	qdl->sector_size = sector_size;

	/* Find MIBIB block */
	mibib_sector = nand_find_mibib(qdl, sector_size);
	if (mibib_sector < 0) {
		ux_err("MIBIB partition table not found\n");
		return -1;
	}

	ux_debug("found MIBIB at sector %d\n", mibib_sector);

	/* Read partition table (page after MBN header) */
	memset(&op, 0, sizeof(op));
	op.partition = 0;
	op.num_sectors = 2;
	op.sector_size = sector_size;
	snprintf(sector_str, sizeof(sector_str), "%u", mibib_sector + 1);
	op.start_sector = sector_str;

	memset(buf, 0, sizeof(buf));
	ret = firehose_read_buf(qdl, &op, buf, sector_size * 2);
	if (ret) {
		ux_err("failed to read MIBIB partition table\n");
		return -1;
	}

	/* Parse SMEM header */
	memcpy(&ptable, buf, sizeof(ptable));

	if (ptable.magic1 != SMEM_FLASH_PART_MAGIC1 ||
	    ptable.magic2 != SMEM_FLASH_PART_MAGIC2) {
		ux_err("invalid SMEM partition table magic "
		       "(got 0x%08x 0x%08x, expected 0x%08x 0x%08x)\n",
		       ptable.magic1, ptable.magic2,
		       SMEM_FLASH_PART_MAGIC1, SMEM_FLASH_PART_MAGIC2);
		return -1;
	}

	if (ptable.version == SMEM_FLASH_PTABLE_V3)
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V3;
	else
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V4;

	if (ptable.numparts > max_parts) {
		ux_err("SMEM table has %u entries, capping at %u\n",
		       ptable.numparts, max_parts);
		ptable.numparts = max_parts;
	}

	printf("\n=== NAND Partition Table (MIBIB/SMEM v%u) ===\n",
	       ptable.version);
	printf("Page size: %zu bytes\n", sector_size);
	printf("Partitions: %u\n\n", ptable.numparts);
	printf("%-4s %-24s %12s %12s %6s\n",
	       "#", "Name", "Offset(blk)", "Length(blk)", "Attr");
	printf("%-4s %-24s %12s %12s %6s\n",
	       "---", "------------------------",
	       "------------", "------------", "------");

	for (i = 0; i < ptable.numparts; i++) {
		struct smem_flash_pentry *e = &ptable.pentry[i];

		/* Copy name and null-terminate */
		memcpy(name, e->name, SMEM_FLASH_PTABLE_NAME_SIZE);
		name[SMEM_FLASH_PTABLE_NAME_SIZE] = '\0';

		/* Strip "0:" prefix if present */
		const char *display_name = name;
		if (name[0] == '0' && name[1] == ':')
			display_name = name + 2;

		printf("%-4u %-24s %12u %12u  0x%02x\n",
		       i, display_name, e->offset, e->length, e->attr);
	}

	printf("\nNote: offsets and lengths are in NAND erase blocks\n");
	return 0;
}

/* GPT structures for eMMC/UFS/NVMe block devices */

struct gpt_guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t  data4[8];
} __attribute__((packed));

static const struct gpt_guid gpt_zero_guid = {0};

struct gpt_header {
	uint8_t signature[8];
	uint32_t revision;
	uint32_t header_size;
	uint32_t header_crc32;
	uint32_t reserved;
	uint64_t current_lba;
	uint64_t backup_lba;
	uint64_t first_usable_lba;
	uint64_t last_usable_lba;
	struct gpt_guid disk_guid;
	uint64_t part_entry_lba;
	uint32_t num_part_entries;
	uint32_t part_entry_size;
	uint32_t part_array_crc32;
	uint8_t reserved2[420];
} __attribute__((packed));

struct gpt_entry {
	struct gpt_guid type_guid;
	struct gpt_guid unique_guid;
	uint64_t first_lba;
	uint64_t last_lba;
	uint64_t attrs;
	uint16_t name_utf16le[36];
} __attribute__((packed));

struct gpt_partition {
	const char *name;
	unsigned int partition;
	unsigned int start_sector;
	unsigned int num_sectors;
	uint64_t attrs;

	struct gpt_partition *next;
};

static struct gpt_partition *gpt_partitions;
static struct gpt_partition *gpt_partitions_last;

static void utf16le_to_utf8(uint16_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
	uint32_t codepoint;
	uint16_t high;
	uint16_t low;
	uint16_t w;
	size_t i;
	size_t j = 0;

	for (i = 0; i < in_len; i++) {
		w = in[i];

		if (w >= 0xd800 && w <= 0xdbff) {
			high = w - 0xd800;

			if (i < in_len) {
				w = in[++i];
				if (w >= 0xdc00 && w <= 0xdfff) {
					low = w - 0xdc00;
					codepoint = (((uint32_t)high << 10) | low) + 0x10000;
				} else {
					/* Surrogate without low surrogate */
					codepoint = 0xfffd;
				}
			} else {
				/* Lone high surrogate at end of string */
				codepoint = 0xfffd;
			}
		} else if (w >= 0xdc00 && w <= 0xdfff) {
			/* Low surrogate without high */
			codepoint = 0xfffd;
		} else {
			codepoint = w;
		}

		if (codepoint == 0)
			break;

		if (codepoint <= 0x7f) {
			if (j + 1 >= out_len)
				break;
			out[j++] = (uint8_t)codepoint;
		} else if (codepoint <= 0x7ff) {
			if (j + 2 >= out_len)
				break;
			out[j++] = 0xc0 | ((codepoint >> 6) & 0x1f);
			out[j++] = 0x80 | (codepoint & 0x3f);
		} else if (codepoint <= 0xffff) {
			if (j + 3 >= out_len)
				break;
			out[j++] = 0xe0 | ((codepoint >> 12) & 0x0f);
			out[j++] = 0x80 | ((codepoint >> 6) & 0x3f);
			out[j++] = 0x80 | (codepoint & 0x3f);
		} else if (codepoint <= 0x10ffff) {
			if (j + 4 >= out_len)
				break;
			out[j++] = 0xf0 | ((codepoint >> 18) & 0x07);
			out[j++] = 0x80 | ((codepoint >> 12) & 0x3f);
			out[j++] = 0x80 | ((codepoint >> 6) & 0x3f);
			out[j++] = 0x80 | (codepoint & 0x3f);
		}
	}

	out[j] = '\0';
}

static int gpt_load_table_from_partition(struct qdl_device *qdl, unsigned int phys_partition, bool *eof)
{
	struct gpt_partition *partition;
	struct gpt_entry *entry;
	struct gpt_header gpt;
	uint8_t buf[4096];
	struct read_op op;
	unsigned int offset;
	unsigned int lba;
	char lba_buf[10];
	uint16_t name_utf16le[36];
	char name[36 * 4];
	int ret;
	unsigned int i;

	memset(&op, 0, sizeof(op));

	op.sector_size = qdl->sector_size;
	op.start_sector = "1";
	op.num_sectors = 1;
	op.partition = phys_partition;

	memset(&buf, 0, sizeof(buf));
	ret = firehose_read_buf(qdl, &op, &gpt, sizeof(gpt));
	if (ret) {
		/* Assume that we're beyond the last partition */
		*eof = true;
		return -1;
	}

	if (memcmp(gpt.signature, "EFI PART", 8)) {
		ux_err("partition %d has not GPT header\n", phys_partition);
		return 0;
	}

	if (gpt.part_entry_size > qdl->sector_size || gpt.num_part_entries > 1024) {
		ux_debug("partition %d has invalid GPT header\n", phys_partition);
		return -1;
	}

	ux_debug("Loading GPT table from physical partition %d\n", phys_partition);
	for (i = 0; i < gpt.num_part_entries; i++) {
		offset = (i * gpt.part_entry_size) % qdl->sector_size;

		if (offset == 0) {
			lba = gpt.part_entry_lba + i * gpt.part_entry_size / qdl->sector_size;
			sprintf(lba_buf, "%u", lba);
			op.start_sector = lba_buf;

			memset(buf, 0, sizeof(buf));
			ret = firehose_read_buf(qdl, &op, buf, sizeof(buf));
			if (ret) {
				ux_err("failed to read GPT partition entries from %d:%u\n", phys_partition, lba);
				return -1;
			}
		}

		entry = (struct gpt_entry *)(buf + offset);

		if (!memcmp(&entry->type_guid, &gpt_zero_guid, sizeof(struct gpt_guid)))
			continue;

		memcpy(name_utf16le, entry->name_utf16le, sizeof(name_utf16le));
		utf16le_to_utf8(name_utf16le, 36, (uint8_t *)name, sizeof(name));

		partition = calloc(1, sizeof(*partition));
		partition->name = strdup(name);
		partition->partition = phys_partition;
		partition->start_sector = entry->first_lba;
		/* if first_lba == last_lba there is 1 sector worth of data (IE: add 1 below) */
		partition->num_sectors = entry->last_lba - entry->first_lba + 1;
		partition->attrs = entry->attrs;

		ux_debug("  %3d: %s start sector %u, num sectors %u\n", i, partition->name,
			 partition->start_sector, partition->num_sectors);

		if (gpt_partitions) {
			gpt_partitions_last->next = partition;
			gpt_partitions_last = partition;
		} else {
			gpt_partitions = partition;
			gpt_partitions_last = partition;
		}
	}

	return 0;
}

static int gpt_load_tables(struct qdl_device *qdl)
{
	unsigned int i;
	bool eof = false;
	int ret = 0;

	if (gpt_partitions)
		return 0;

	for (i = 0; ; i++) {
		ret = gpt_load_table_from_partition(qdl, i, &eof);
		if (ret)
			break;
	}

	return eof ? 0 : ret;
}

int gpt_find_by_name(struct qdl_device *qdl, const char *name, int *phys_partition,
		     unsigned int *start_sector, unsigned int *num_sectors)
{
	struct gpt_partition *gpt_part;
	bool found = false;
	int ret;

	if (qdl->dev_type == QDL_DEVICE_SIM)
		return 0;

	ret = gpt_load_tables(qdl);
	if (ret < 0)
		return -1;

	for (gpt_part = gpt_partitions; gpt_part; gpt_part = gpt_part->next) {
		if (*phys_partition >= 0 && gpt_part->partition != (unsigned int)(*phys_partition))
			continue;

		if (strcmp(gpt_part->name, name))
			continue;

		if (found) {
			ux_err("duplicate candidates for partition \"%s\" found\n", name);
			return -1;
		}

		*phys_partition = gpt_part->partition;
		*start_sector = gpt_part->start_sector;
		*num_sectors = gpt_part->num_sectors;

		found = true;
	}

	if (!found) {
		if (*phys_partition >= 0)
			ux_err("no partition \"%s\" found on physical partition %d\n", name, *phys_partition);
		else
			ux_err("no partition \"%s\" found\n", name);
		return -1;
	}

	return 0;
}

static void guid_to_string(const struct gpt_guid *guid, char *out, size_t len)
{
	snprintf(out, len,
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 guid->data1, guid->data2, guid->data3,
		 guid->data4[0], guid->data4[1],
		 guid->data4[2], guid->data4[3],
		 guid->data4[4], guid->data4[5],
		 guid->data4[6], guid->data4[7]);
}

static void print_size_human(uint64_t bytes, char *out, size_t len)
{
	if (bytes >= (uint64_t)1024 * 1024 * 1024)
		snprintf(out, len, "%.1f GiB",
			 (double)bytes / (1024.0 * 1024.0 * 1024.0));
	else if (bytes >= 1024 * 1024)
		snprintf(out, len, "%.1f MiB",
			 (double)bytes / (1024.0 * 1024.0));
	else if (bytes >= 1024)
		snprintf(out, len, "%.1f KiB", (double)bytes / 1024.0);
	else
		snprintf(out, len, "%llu B", (unsigned long long)bytes);
}

static int gpt_print_table_from_partition(struct qdl_device *qdl,
					  unsigned int phys_partition,
					  bool *eof)
{
	struct gpt_entry *entry;
	struct gpt_header gpt;
	uint8_t buf[4096];
	struct read_op op;
	unsigned int offset;
	unsigned int lba;
	char lba_buf[10];
	uint16_t name_utf16le[36];
	char name[36 * 4];
	char type_str[40];
	char unique_str[40];
	char size_str[32];
	char disk_guid_str[40];
	int ret;
	unsigned int i;
	int count = 0;

	memset(&op, 0, sizeof(op));

	op.sector_size = qdl->sector_size;
	op.start_sector = "1";
	op.num_sectors = 1;
	op.partition = phys_partition;

	memset(&buf, 0, sizeof(buf));
	ret = firehose_read_buf(qdl, &op, &gpt, sizeof(gpt));
	if (ret) {
		*eof = true;
		return -1;
	}

	if (memcmp(gpt.signature, "EFI PART", 8)) {
		ux_err("partition %d has no GPT header\n", phys_partition);
		return 0;
	}

	if (gpt.part_entry_size > qdl->sector_size ||
	    gpt.num_part_entries > 1024) {
		ux_debug("partition %d has invalid GPT header\n",
			 phys_partition);
		return -1;
	}

	guid_to_string(&gpt.disk_guid, disk_guid_str,
		       sizeof(disk_guid_str));

	printf("\n=== Physical Partition %d ===\n", phys_partition);
	printf("Disk GUID:        %s\n", disk_guid_str);
	printf("First usable LBA: %llu\n",
	       (unsigned long long)gpt.first_usable_lba);
	printf("Last usable LBA:  %llu\n",
	       (unsigned long long)gpt.last_usable_lba);
	printf("Partition entries: %u (size: %u bytes each)\n",
	       gpt.num_part_entries, gpt.part_entry_size);
	printf("\n");
	printf("%-4s %-32s %12s %12s %10s  %-36s  Attrs\n",
	       "#", "Name", "Start LBA", "End LBA", "Size", "Type GUID");
	printf("%-4s %-32s %12s %12s %10s  %-36s  -----\n",
	       "---", "--------------------------------",
	       "------------", "------------", "----------",
	       "------------------------------------");

	for (i = 0; i < gpt.num_part_entries; i++) {
		offset = (i * gpt.part_entry_size) % qdl->sector_size;

		if (offset == 0) {
			lba = gpt.part_entry_lba +
			      i * gpt.part_entry_size / qdl->sector_size;
			sprintf(lba_buf, "%u", lba);
			op.start_sector = lba_buf;

			memset(buf, 0, sizeof(buf));
			ret = firehose_read_buf(qdl, &op, buf, sizeof(buf));
			if (ret) {
				ux_err("failed to read GPT entries from %d:%u\n",
				       phys_partition, lba);
				return -1;
			}
		}

		entry = (struct gpt_entry *)(buf + offset);

		if (!memcmp(&entry->type_guid, &gpt_zero_guid,
			    sizeof(struct gpt_guid)))
			continue;

		memcpy(name_utf16le, entry->name_utf16le,
		       sizeof(name_utf16le));
		utf16le_to_utf8(name_utf16le, 36, (uint8_t *)name,
				sizeof(name));

		guid_to_string(&entry->type_guid, type_str,
			       sizeof(type_str));
		guid_to_string(&entry->unique_guid, unique_str,
			       sizeof(unique_str));
		print_size_human((entry->last_lba - entry->first_lba + 1) *
				 qdl->sector_size,
				 size_str, sizeof(size_str));

		printf("%-4u %-32s %12llu %12llu %10s  %s  0x%016llx\n",
		       count, name,
		       (unsigned long long)entry->first_lba,
		       (unsigned long long)entry->last_lba,
		       size_str, type_str,
		       (unsigned long long)entry->attrs);
		count++;
	}

	return 0;
}

int gpt_print_table(struct qdl_device *qdl)
{
	unsigned int i;
	bool eof = false;
	int ret = 0;

	if (qdl->storage_type == QDL_STORAGE_NAND)
		return nand_print_partitions(qdl);

	for (i = 0; ; i++) {
		ret = gpt_print_table_from_partition(qdl, i, &eof);
		if (ret)
			break;
	}

	return eof ? 0 : ret;
}

#define AB_FLAG_OFFSET 6
#define AB_PARTITION_ATTR_SLOT_ACTIVE (1 << 2)

int gpt_get_active_slot(struct qdl_device *qdl)
{
	struct gpt_partition *part;
	uint8_t flags_byte;
	int ret;

	ret = gpt_load_tables(qdl);
	if (ret < 0)
		return -1;

	for (part = gpt_partitions; part; part = part->next) {
		if (strcmp(part->name, "boot_a") == 0) {
			flags_byte = (part->attrs >> (AB_FLAG_OFFSET * 8)) &
				     0xFF;
			if (flags_byte & AB_PARTITION_ATTR_SLOT_ACTIVE)
				return 'a';
		}
	}

	for (part = gpt_partitions; part; part = part->next) {
		if (strcmp(part->name, "boot_b") == 0) {
			flags_byte = (part->attrs >> (AB_FLAG_OFFSET * 8)) &
				     0xFF;
			if (flags_byte & AB_PARTITION_ATTR_SLOT_ACTIVE)
				return 'b';
		}
	}

	ux_err("no active A/B slot found (no boot_a or boot_b partitions)\n");
	return -1;
}

int gpt_set_active_slot(struct qdl_device *qdl, char slot)
{
	(void)qdl;
	(void)slot;
	ux_err("setslot is not yet implemented\n");
	return -1;
}

/*
 * Detect a file extension from the first bytes of partition data.
 * Returns a string like ".ubi", ".img", ".elf", etc., or ".bin"
 * if the magic is unrecognized.
 */
static const char *detect_partition_ext(const uint8_t *data, size_t len)
{
	/* Android boot image */
	if (len >= 8 && memcmp(data, "ANDROID!", 8) == 0)
		return ".img";

	/* Android vendor boot image (boot header v3+) */
	if (len >= 13 && memcmp(data, "ANDROID-BOOT!", 13) == 0)
		return ".img";

	if (len < 4)
		return ".bin";

	/* UBI filesystem */
	if (data[0] == 'U' && data[1] == 'B' && data[2] == 'I' && data[3] == '#')
		return ".ubi";

	/* ELF binary (SBL, TZ, QHEE, etc.) */
	if (data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F')
		return ".elf";

	/* SquashFS (little-endian) */
	if (data[0] == 'h' && data[1] == 's' && data[2] == 'q' && data[3] == 's')
		return ".squashfs";

	/* SquashFS (big-endian) */
	if (data[0] == 's' && data[1] == 'q' && data[2] == 's' && data[3] == 'h')
		return ".squashfs";

	/* Device tree blob */
	if (data[0] == 0xd0 && data[1] == 0x0d &&
	    data[2] == 0xfe && data[3] == 0xed)
		return ".dtb";

	/* gzip */
	if (data[0] == 0x1f && data[1] == 0x8b)
		return ".gz";

	/* XZ */
	if (len >= 6 && data[0] == 0xfd && data[1] == '7' &&
	    data[2] == 'z' && data[3] == 'X' &&
	    data[4] == 'Z' && data[5] == 0x00)
		return ".xz";

	return ".bin";
}

/*
 * Read the first sector of a partition and detect its file extension
 * from magic bytes.  Returns ".bin" on any failure.
 */
static const char *probe_partition_ext(struct qdl_device *qdl,
				       unsigned int partition,
				       unsigned int start_sector,
				       unsigned int sector_size,
				       unsigned int pages_per_block)
{
	struct read_op op = {0};
	uint8_t probe[4096];
	char sec_str[20];

	op.partition = partition;
	op.sector_size = sector_size;
	op.num_sectors = 1;
	op.pages_per_block = pages_per_block;
	snprintf(sec_str, sizeof(sec_str), "%u", start_sector);
	op.start_sector = sec_str;

	if (firehose_read_buf(qdl, &op, probe, sector_size) != 0)
		return ".bin";

	return detect_partition_ext(probe, sector_size);
}

static int nand_read_all_partitions(struct qdl_device *qdl, const char *outdir)
{
	struct smem_flash_ptable ptable;
	struct storage_info sinfo;
	uint8_t buf[8192];
	struct read_op op;
	size_t sector_size;
	unsigned int max_parts;
	unsigned int pages_per_block;
	char sector_str[16];
	char filepath[4096];
	char name[SMEM_FLASH_PTABLE_NAME_SIZE + 1];
	int mibib_sector;
	unsigned int i;
	int ret;
	int count = 0;
	int failed = 0;

	/* Detect NAND page/sector size */
	sector_size = qdl->sector_size;
	if (!sector_size)
		sector_size = nand_detect_sector_size(qdl);
	if (!sector_size) {
		ux_err("failed to detect NAND page size\n");
		return -1;
	}
	qdl->sector_size = sector_size;

	/* Find MIBIB block */
	mibib_sector = nand_find_mibib(qdl, sector_size);
	if (mibib_sector < 0) {
		ux_err("MIBIB partition table not found\n");
		return -1;
	}

	/* Read partition table (page after MBN header) */
	memset(&op, 0, sizeof(op));
	op.partition = 0;
	op.num_sectors = 2;
	op.sector_size = sector_size;
	snprintf(sector_str, sizeof(sector_str), "%u", mibib_sector + 1);
	op.start_sector = sector_str;

	memset(buf, 0, sizeof(buf));
	ret = firehose_read_buf(qdl, &op, buf, sector_size * 2);
	if (ret) {
		ux_err("failed to read MIBIB partition table\n");
		return -1;
	}

	/* Parse SMEM header */
	memcpy(&ptable, buf, sizeof(ptable));

	if (ptable.magic1 != SMEM_FLASH_PART_MAGIC1 ||
	    ptable.magic2 != SMEM_FLASH_PART_MAGIC2) {
		ux_err("invalid SMEM partition table magic\n");
		return -1;
	}

	if (ptable.version == SMEM_FLASH_PTABLE_V3)
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V3;
	else
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V4;

	if (ptable.numparts > max_parts) {
		ux_err("SMEM table has %u entries, capping at %u\n",
		       ptable.numparts, max_parts);
		ptable.numparts = max_parts;
	}

	/* Get block size from storage info for erase-block-to-page conversion */
	ret = firehose_getstorageinfo(qdl, 0, &sinfo);
	if (ret || !sinfo.block_size) {
		ux_err("failed to get NAND block size from storage info\n");
		return -1;
	}

	pages_per_block = sinfo.block_size / sector_size;
	if (!pages_per_block) {
		ux_err("invalid block_size/page_size ratio\n");
		return -1;
	}

	/* Create output directory if needed */
#ifdef _WIN32
	ret = mkdir(outdir);
#else
	ret = mkdir(outdir, 0755);
#endif
	if (ret < 0 && errno != EEXIST) {
		ux_err("failed to create output directory %s: %s\n",
		       outdir, strerror(errno));
		return -1;
	}

	for (i = 0; i < ptable.numparts; i++) {
		struct smem_flash_pentry *e = &ptable.pentry[i];
		unsigned int start_pages = e->offset * pages_per_block;
		unsigned int num_pages = e->length * pages_per_block;
		const char *ext;

		memcpy(name, e->name, SMEM_FLASH_PTABLE_NAME_SIZE);
		name[SMEM_FLASH_PTABLE_NAME_SIZE] = '\0';

		/* Strip "0:" prefix if present */
		const char *display_name = name;
		if (name[0] == '0' && name[1] == ':')
			display_name = name + 2;

		ext = probe_partition_ext(qdl, 0, start_pages,
					 sector_size, pages_per_block);
		snprintf(filepath, sizeof(filepath), "%s/%s%s",
			 outdir, display_name, ext);

		ux_info("reading partition '%s' (%u pages) to %s\n",
			display_name, num_pages, filepath);

		ret = firehose_read_to_file(qdl, 0, start_pages,
					    num_pages, sector_size,
					    pages_per_block, filepath);
		if (ret < 0) {
			ux_err("failed to read partition '%s'\n", display_name);
			failed++;
		} else {
			count++;
		}
	}

	ux_info("read %d partitions (%d failed) to %s\n",
		count, failed, outdir);
	return failed ? -1 : 0;
}

int gpt_read_all_partitions(struct qdl_device *qdl, const char *outdir)
{
	struct gpt_partition *part;
	char filepath[4096];
	int ret;
	int count = 0;
	int failed = 0;

	if (qdl->storage_type == QDL_STORAGE_NAND)
		return nand_read_all_partitions(qdl, outdir);

	ret = gpt_load_tables(qdl);
	if (ret < 0)
		return -1;

	/* Create output directory if needed */
#ifdef _WIN32
	ret = mkdir(outdir);
#else
	ret = mkdir(outdir, 0755);
#endif
	if (ret < 0 && errno != EEXIST) {
		ux_err("failed to create output directory %s: %s\n",
		       outdir, strerror(errno));
		return -1;
	}

	for (part = gpt_partitions; part; part = part->next) {
		const char *ext;

		ext = probe_partition_ext(qdl, part->partition,
					 part->start_sector,
					 qdl->sector_size, 0);
		snprintf(filepath, sizeof(filepath), "%s/lun%u_%s%s",
			 outdir, part->partition, part->name, ext);

		ux_info("reading partition '%s' (%u sectors) to %s\n",
			part->name, part->num_sectors, filepath);

		ret = firehose_read_to_file(qdl, part->partition,
					    part->start_sector,
					    part->num_sectors,
					    qdl->sector_size, 0, filepath);
		if (ret < 0) {
			ux_err("failed to read partition '%s'\n", part->name);
			failed++;
		} else {
			count++;
		}
	}

	ux_info("read %d partitions (%d failed) to %s\n",
		count, failed, outdir);
	return failed ? -1 : 0;
}

static int nand_read_partition(struct qdl_device *qdl, const char *label,
			      const char *outfile)
{
	struct smem_flash_ptable ptable;
	struct storage_info sinfo;
	uint8_t buf[8192];
	struct read_op op;
	size_t sector_size;
	unsigned int max_parts;
	unsigned int pages_per_block;
	char sector_str[16];
	char name[SMEM_FLASH_PTABLE_NAME_SIZE + 1];
	int mibib_sector;
	unsigned int i;
	int ret;

	sector_size = qdl->sector_size;
	if (!sector_size)
		sector_size = nand_detect_sector_size(qdl);
	if (!sector_size) {
		ux_err("failed to detect NAND page size\n");
		return -1;
	}
	qdl->sector_size = sector_size;

	mibib_sector = nand_find_mibib(qdl, sector_size);
	if (mibib_sector < 0) {
		ux_err("MIBIB partition table not found\n");
		return -1;
	}

	memset(&op, 0, sizeof(op));
	op.partition = 0;
	op.num_sectors = 2;
	op.sector_size = sector_size;
	snprintf(sector_str, sizeof(sector_str), "%u", mibib_sector + 1);
	op.start_sector = sector_str;

	memset(buf, 0, sizeof(buf));
	ret = firehose_read_buf(qdl, &op, buf, sector_size * 2);
	if (ret) {
		ux_err("failed to read MIBIB partition table\n");
		return -1;
	}

	memcpy(&ptable, buf, sizeof(ptable));

	if (ptable.magic1 != SMEM_FLASH_PART_MAGIC1 ||
	    ptable.magic2 != SMEM_FLASH_PART_MAGIC2) {
		ux_err("invalid SMEM partition table magic\n");
		return -1;
	}

	if (ptable.version == SMEM_FLASH_PTABLE_V3)
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V3;
	else
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V4;

	if (ptable.numparts > max_parts) {
		ux_err("SMEM table has %u entries, capping at %u\n",
		       ptable.numparts, max_parts);
		ptable.numparts = max_parts;
	}

	ret = firehose_getstorageinfo(qdl, 0, &sinfo);
	if (ret || !sinfo.block_size) {
		ux_err("failed to get NAND block size from storage info\n");
		return -1;
	}

	pages_per_block = sinfo.block_size / sector_size;
	if (!pages_per_block) {
		ux_err("invalid block_size/page_size ratio\n");
		return -1;
	}

	for (i = 0; i < ptable.numparts; i++) {
		struct smem_flash_pentry *e = &ptable.pentry[i];
		unsigned int start_pages = e->offset * pages_per_block;
		unsigned int num_pages = e->length * pages_per_block;

		memcpy(name, e->name, SMEM_FLASH_PTABLE_NAME_SIZE);
		name[SMEM_FLASH_PTABLE_NAME_SIZE] = '\0';

		const char *display_name = name;
		if (name[0] == '0' && name[1] == ':')
			display_name = name + 2;

		if (strcmp(display_name, label) != 0)
			continue;

		ux_info("reading partition '%s' (%u pages) to %s\n",
			display_name, num_pages, outfile);

		return firehose_read_to_file(qdl, 0, start_pages,
					     num_pages, sector_size,
					     pages_per_block, outfile);
	}

	ux_err("no partition '%s' found in NAND partition table\n", label);
	return -1;
}

int gpt_read_partition(struct qdl_device *qdl, const char *label,
		       const char *outfile)
{
	int phys_partition = -1;
	unsigned int start_sector;
	unsigned int num_sectors;
	int ret;

	if (qdl->storage_type == QDL_STORAGE_NAND)
		return nand_read_partition(qdl, label, outfile);

	ret = gpt_find_by_name(qdl, label, &phys_partition,
			       &start_sector, &num_sectors);
	if (ret < 0)
		return -1;

	ux_info("reading partition '%s' (%u sectors) to %s\n",
		label, num_sectors, outfile);

	return firehose_read_to_file(qdl, phys_partition,
				     start_sector, num_sectors,
				     qdl->sector_size, 0, outfile);
}

static int nand_read_partition_to_dir(struct qdl_device *qdl,
				     const char *label, const char *outdir)
{
	struct smem_flash_ptable ptable;
	struct storage_info sinfo;
	uint8_t buf[8192];
	struct read_op op;
	size_t sector_size;
	unsigned int max_parts;
	unsigned int pages_per_block;
	char sector_str[16];
	char name[SMEM_FLASH_PTABLE_NAME_SIZE + 1];
	char filepath[4096];
	int mibib_sector;
	unsigned int i;
	int ret;

	sector_size = qdl->sector_size;
	if (!sector_size)
		sector_size = nand_detect_sector_size(qdl);
	if (!sector_size) {
		ux_err("failed to detect NAND page size\n");
		return -1;
	}
	qdl->sector_size = sector_size;

	mibib_sector = nand_find_mibib(qdl, sector_size);
	if (mibib_sector < 0) {
		ux_err("MIBIB partition table not found\n");
		return -1;
	}

	memset(&op, 0, sizeof(op));
	op.partition = 0;
	op.num_sectors = 2;
	op.sector_size = sector_size;
	snprintf(sector_str, sizeof(sector_str), "%u", mibib_sector + 1);
	op.start_sector = sector_str;

	memset(buf, 0, sizeof(buf));
	ret = firehose_read_buf(qdl, &op, buf, sector_size * 2);
	if (ret) {
		ux_err("failed to read MIBIB partition table\n");
		return -1;
	}

	memcpy(&ptable, buf, sizeof(ptable));

	if (ptable.magic1 != SMEM_FLASH_PART_MAGIC1 ||
	    ptable.magic2 != SMEM_FLASH_PART_MAGIC2) {
		ux_err("invalid SMEM partition table magic\n");
		return -1;
	}

	if (ptable.version == SMEM_FLASH_PTABLE_V3)
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V3;
	else
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V4;

	if (ptable.numparts > max_parts)
		ptable.numparts = max_parts;

	ret = firehose_getstorageinfo(qdl, 0, &sinfo);
	if (ret || !sinfo.block_size) {
		ux_err("failed to get NAND block size from storage info\n");
		return -1;
	}

	pages_per_block = sinfo.block_size / sector_size;
	if (!pages_per_block) {
		ux_err("invalid block_size/page_size ratio\n");
		return -1;
	}

	for (i = 0; i < ptable.numparts; i++) {
		struct smem_flash_pentry *e = &ptable.pentry[i];
		unsigned int start_pages = e->offset * pages_per_block;
		unsigned int num_pages = e->length * pages_per_block;
		const char *ext;

		memcpy(name, e->name, SMEM_FLASH_PTABLE_NAME_SIZE);
		name[SMEM_FLASH_PTABLE_NAME_SIZE] = '\0';

		const char *display_name = name;

		if (name[0] == '0' && name[1] == ':')
			display_name = name + 2;

		if (strcmp(display_name, label) != 0)
			continue;

		ext = probe_partition_ext(qdl, 0, start_pages,
					  sector_size, pages_per_block);
		snprintf(filepath, sizeof(filepath), "%s/%s%s",
			 outdir, display_name, ext);

		ux_info("reading partition '%s' (%u pages) to %s\n",
			display_name, num_pages, filepath);

		return firehose_read_to_file(qdl, 0, start_pages,
					      num_pages, sector_size,
					      pages_per_block, filepath);
	}

	ux_err("no partition '%s' found in NAND partition table\n", label);
	return -1;
}

int gpt_read_partition_to_dir(struct qdl_device *qdl, const char *label,
			      const char *outdir)
{
	int phys_partition = -1;
	unsigned int start_sector;
	unsigned int num_sectors;
	char filepath[4096];
	const char *ext;
	int ret;

	if (qdl->storage_type == QDL_STORAGE_NAND)
		return nand_read_partition_to_dir(qdl, label, outdir);

	ret = gpt_find_by_name(qdl, label, &phys_partition,
			       &start_sector, &num_sectors);
	if (ret < 0)
		return -1;

	ext = probe_partition_ext(qdl, phys_partition, start_sector,
				  qdl->sector_size, 0);
	snprintf(filepath, sizeof(filepath), "%s/%s%s", outdir, label, ext);

	ux_info("reading partition '%s' (%u sectors) to %s\n",
		label, num_sectors, filepath);

	return firehose_read_to_file(qdl, phys_partition,
				     start_sector, num_sectors,
				     qdl->sector_size, 0, filepath);
}

static int nand_read_full_storage(struct qdl_device *qdl, const char *outfile)
{
	struct storage_info sinfo;
	size_t sector_size;
	unsigned int pages_per_block;
	unsigned int total_pages;
	int ret;

	sector_size = qdl->sector_size;
	if (!sector_size)
		sector_size = nand_detect_sector_size(qdl);
	if (!sector_size) {
		ux_err("failed to detect NAND page size\n");
		return -1;
	}
	qdl->sector_size = sector_size;

	ret = firehose_getstorageinfo(qdl, 0, &sinfo);
	if (ret || !sinfo.block_size || !sinfo.total_blocks) {
		ux_err("failed to get NAND storage info\n");
		return -1;
	}

	pages_per_block = sinfo.block_size / sector_size;
	total_pages = sinfo.total_blocks * pages_per_block;

	ux_info("reading full NAND storage (%lu blocks, %u pages) to %s\n",
		sinfo.total_blocks, total_pages, outfile);

	return firehose_read_to_file(qdl, 0, 0, total_pages,
				     sector_size, pages_per_block, outfile);
}

int gpt_read_full_storage(struct qdl_device *qdl, const char *outfile)
{
	struct storage_info sinfo;
	unsigned int i;
	char filepath[4096];
	int ret = 0;
	int count = 0;

	if (qdl->storage_type == QDL_STORAGE_NAND)
		return nand_read_full_storage(qdl, outfile);

	/* For GPT (UFS/eMMC), dump each LUN as a separate file */
	ret = firehose_getstorageinfo(qdl, 0, &sinfo);
	if (ret) {
		ux_err("failed to get storage info\n");
		return -1;
	}

	for (i = 0; i < sinfo.num_physical; i++) {
		struct storage_info lun_info;

		ret = firehose_getstorageinfo(qdl, i, &lun_info);
		if (ret || !lun_info.total_blocks)
			continue;

		if (sinfo.num_physical == 1) {
			snprintf(filepath, sizeof(filepath), "%s", outfile);
		} else {
			/* Insert LUN number before extension */
			const char *dot = strrchr(outfile, '.');
			if (dot) {
				snprintf(filepath, sizeof(filepath),
					 "%.*s_lun%u%s",
					 (int)(dot - outfile), outfile,
					 i, dot);
			} else {
				snprintf(filepath, sizeof(filepath),
					 "%s_lun%u", outfile, i);
			}
		}

		ux_info("reading LUN %u (%lu sectors) to %s\n",
			i, lun_info.total_blocks, filepath);

		ret = firehose_read_to_file(qdl, i, 0,
					    lun_info.total_blocks,
					    qdl->sector_size, 0,
					    filepath);
		if (ret < 0) {
			ux_err("failed to read LUN %u\n", i);
		} else {
			count++;
		}
	}

	return count > 0 ? 0 : -1;
}

static const char *storage_type_str(enum qdl_storage_type t)
{
	switch (t) {
	case QDL_STORAGE_NAND:  return "nand";
	case QDL_STORAGE_EMMC:  return "emmc";
	case QDL_STORAGE_UFS:   return "ufs";
	case QDL_STORAGE_NVME:  return "nvme";
	case QDL_STORAGE_SPINOR: return "spinor";
	default:                return "unknown";
	}
}

static int nand_make_xml(struct qdl_device *qdl, const char *outdir,
			 bool make_read, bool make_program)
{
	struct smem_flash_ptable ptable;
	struct storage_info sinfo;
	uint8_t buf[8192];
	struct read_op op;
	size_t sector_size;
	unsigned int max_parts;
	unsigned int pages_per_block;
	char sector_str[16];
	char filepath[4096];
	char name[SMEM_FLASH_PTABLE_NAME_SIZE + 1];
	int mibib_sector;
	unsigned int i;
	FILE *fp;
	int ret;

	/* Detect NAND page/sector size */
	sector_size = qdl->sector_size;
	if (!sector_size)
		sector_size = nand_detect_sector_size(qdl);
	if (!sector_size) {
		ux_err("failed to detect NAND page size\n");
		return -1;
	}
	qdl->sector_size = sector_size;

	/* Find MIBIB block */
	mibib_sector = nand_find_mibib(qdl, sector_size);
	if (mibib_sector < 0) {
		ux_err("MIBIB partition table not found\n");
		return -1;
	}

	/* Read partition table */
	memset(&op, 0, sizeof(op));
	op.partition = 0;
	op.num_sectors = 2;
	op.sector_size = sector_size;
	snprintf(sector_str, sizeof(sector_str), "%u", mibib_sector + 1);
	op.start_sector = sector_str;

	memset(buf, 0, sizeof(buf));
	ret = firehose_read_buf(qdl, &op, buf, sector_size * 2);
	if (ret) {
		ux_err("failed to read MIBIB partition table\n");
		return -1;
	}

	memcpy(&ptable, buf, sizeof(ptable));

	if (ptable.magic1 != SMEM_FLASH_PART_MAGIC1 ||
	    ptable.magic2 != SMEM_FLASH_PART_MAGIC2) {
		ux_err("invalid SMEM partition table magic\n");
		return -1;
	}

	if (ptable.version == SMEM_FLASH_PTABLE_V3)
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V3;
	else
		max_parts = SMEM_FLASH_PTABLE_MAX_PARTS_V4;

	if (ptable.numparts > max_parts) {
		ux_err("SMEM table has %u entries, capping at %u\n",
		       ptable.numparts, max_parts);
		ptable.numparts = max_parts;
	}

	/* Get block size for conversion */
	ret = firehose_getstorageinfo(qdl, 0, &sinfo);
	if (ret || !sinfo.block_size) {
		ux_err("failed to get NAND block size from storage info\n");
		return -1;
	}

	pages_per_block = sinfo.block_size / sector_size;
	if (!pages_per_block) {
		ux_err("invalid block_size/page_size ratio\n");
		return -1;
	}

	/* Probe each partition for file extension detection */
	const char **exts = calloc(ptable.numparts, sizeof(char *));
	if (exts) {
		for (i = 0; i < ptable.numparts; i++) {
			struct smem_flash_pentry *e = &ptable.pentry[i];
			unsigned int start_pages = e->offset * pages_per_block;

			exts[i] = probe_partition_ext(qdl, 0, start_pages,
						      sector_size,
						      pages_per_block);
		}
	}

	if (make_read) {
		snprintf(filepath, sizeof(filepath), "%s/rawread_nand.xml", outdir);
		fp = fopen(filepath, "w");
		if (!fp) {
			ux_err("failed to create %s: %s\n", filepath, strerror(errno));
			free(exts);
			return -1;
		}

		fprintf(fp, "<?xml version=\"1.0\" ?>\n");
		fprintf(fp, "<data>\n");
		fprintf(fp, "  <!-- Generated by qfenix from device partition table -->\n");

		for (i = 0; i < ptable.numparts; i++) {
			struct smem_flash_pentry *e = &ptable.pentry[i];
			unsigned int start_pages = e->offset * pages_per_block;
			unsigned int num_pages = e->length * pages_per_block;
			const char *ext = exts ? exts[i] : ".bin";

			memcpy(name, e->name, SMEM_FLASH_PTABLE_NAME_SIZE);
			name[SMEM_FLASH_PTABLE_NAME_SIZE] = '\0';
			const char *dname = name;
			if (name[0] == '0' && name[1] == ':')
				dname = name + 2;

			fprintf(fp, "  <read PAGES_PER_BLOCK=\"%u\" SECTOR_SIZE_IN_BYTES=\"%zu\""
				" filename=\"%s%s\" label=\"%s\""
				" num_partition_sectors=\"%u\" physical_partition_number=\"0\""
				" start_sector=\"%u\"/>\n",
				pages_per_block, sector_size, dname, ext, dname,
				num_pages, start_pages);
		}

		fprintf(fp, "</data>\n");
		fclose(fp);
		ux_info("wrote %s (%u partitions)\n", filepath, ptable.numparts);
	}

	if (make_program) {
		snprintf(filepath, sizeof(filepath), "%s/rawprogram_nand.xml", outdir);
		fp = fopen(filepath, "w");
		if (!fp) {
			ux_err("failed to create %s: %s\n", filepath, strerror(errno));
			free(exts);
			return -1;
		}

		fprintf(fp, "<?xml version=\"1.0\" ?>\n");
		fprintf(fp, "<data>\n");
		fprintf(fp, "  <!-- Generated by qfenix from device partition table -->\n");

		for (i = 0; i < ptable.numparts; i++) {
			struct smem_flash_pentry *e = &ptable.pentry[i];
			unsigned int start_pages = e->offset * pages_per_block;
			unsigned int num_pages = e->length * pages_per_block;
			const char *ext = exts ? exts[i] : ".bin";

			memcpy(name, e->name, SMEM_FLASH_PTABLE_NAME_SIZE);
			name[SMEM_FLASH_PTABLE_NAME_SIZE] = '\0';
			const char *dname = name;
			if (name[0] == '0' && name[1] == ':')
				dname = name + 2;

			fprintf(fp, "  <erase PAGES_PER_BLOCK=\"%u\" SECTOR_SIZE_IN_BYTES=\"%zu\""
				" num_partition_sectors=\"%u\" physical_partition_number=\"0\""
				" start_sector=\"%u\"/>\n",
				pages_per_block, sector_size, num_pages, start_pages);
			fprintf(fp, "  <program PAGES_PER_BLOCK=\"%u\" SECTOR_SIZE_IN_BYTES=\"%zu\""
				" filename=\"%s%s\" label=\"%s\""
				" num_partition_sectors=\"%u\" physical_partition_number=\"0\""
				" start_sector=\"%u\"/>\n",
				pages_per_block, sector_size, dname, ext, dname,
				num_pages, start_pages);
		}

		fprintf(fp, "</data>\n");
		fclose(fp);
		ux_info("wrote %s (%u partitions)\n", filepath, ptable.numparts);
	}

	free(exts);

	return 0;
}

static int gpt_make_xml_from_table(struct qdl_device *qdl, const char *outdir,
				   bool make_read, bool make_program)
{
	struct gpt_partition *part;
	char filepath[4096];
	const char *stype;
	const char **exts = NULL;
	FILE *fp;
	int ret;
	int count = 0;
	int i;

	ret = gpt_load_tables(qdl);
	if (ret < 0)
		return -1;

	stype = storage_type_str(qdl->storage_type);

	/* Probe each partition for file extension detection */
	for (part = gpt_partitions; part; part = part->next)
		count++;

	if (count > 0) {
		exts = calloc(count, sizeof(char *));
		if (exts) {
			i = 0;
			for (part = gpt_partitions; part; part = part->next)
				exts[i++] = probe_partition_ext(qdl,
					part->partition, part->start_sector,
					qdl->sector_size, 0);
		}
	}

	if (make_read) {
		snprintf(filepath, sizeof(filepath), "%s/rawread_%s.xml", outdir, stype);
		fp = fopen(filepath, "w");
		if (!fp) {
			ux_err("failed to create %s: %s\n", filepath, strerror(errno));
			free(exts);
			return -1;
		}

		fprintf(fp, "<?xml version=\"1.0\" ?>\n");
		fprintf(fp, "<data>\n");
		fprintf(fp, "  <!-- Generated by qfenix from device partition table -->\n");

		i = 0;
		for (part = gpt_partitions; part; part = part->next) {
			const char *ext = exts ? exts[i] : ".bin";

			fprintf(fp, "  <read SECTOR_SIZE_IN_BYTES=\"%zu\""
				" filename=\"lun%u_%s%s\" label=\"%s\""
				" num_partition_sectors=\"%u\" physical_partition_number=\"%u\""
				" start_sector=\"%u\"/>\n",
				qdl->sector_size, part->partition, part->name, ext,
				part->name, part->num_sectors, part->partition,
				part->start_sector);
			i++;
		}

		fprintf(fp, "</data>\n");
		fclose(fp);
		ux_info("wrote %s (%d partitions)\n", filepath, count);
	}

	if (make_program) {
		snprintf(filepath, sizeof(filepath), "%s/rawprogram_%s.xml", outdir, stype);
		fp = fopen(filepath, "w");
		if (!fp) {
			ux_err("failed to create %s: %s\n", filepath, strerror(errno));
			free(exts);
			return -1;
		}

		fprintf(fp, "<?xml version=\"1.0\" ?>\n");
		fprintf(fp, "<data>\n");
		fprintf(fp, "  <!-- Generated by qfenix from device partition table -->\n");

		i = 0;
		for (part = gpt_partitions; part; part = part->next) {
			const char *ext = exts ? exts[i] : ".bin";

			fprintf(fp, "  <erase SECTOR_SIZE_IN_BYTES=\"%zu\""
				" num_partition_sectors=\"%u\" physical_partition_number=\"%u\""
				" start_sector=\"%u\"/>\n",
				qdl->sector_size, part->num_sectors,
				part->partition, part->start_sector);
			fprintf(fp, "  <program SECTOR_SIZE_IN_BYTES=\"%zu\""
				" filename=\"lun%u_%s%s\" label=\"%s\""
				" num_partition_sectors=\"%u\" physical_partition_number=\"%u\""
				" start_sector=\"%u\"/>\n",
				qdl->sector_size, part->partition, part->name, ext,
				part->name, part->num_sectors, part->partition,
				part->start_sector);
			i++;
		}

		fprintf(fp, "</data>\n");
		fclose(fp);
		ux_info("wrote %s (%d partitions)\n", filepath, count);
	}

	free(exts);

	return 0;
}

int gpt_make_xml(struct qdl_device *qdl, const char *outdir,
		 bool make_read, bool make_program)
{
	if (qdl->storage_type == QDL_STORAGE_NAND)
		return nand_make_xml(qdl, outdir, make_read, make_program);

	return gpt_make_xml_from_table(qdl, outdir, make_read, make_program);
}
