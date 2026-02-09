/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __READ_H__
#define __READ_H__

#include <stdbool.h>
#include <libxml/tree.h>

#include "list.h"

struct qdl_device;

struct read_op {
	unsigned int sector_size;
	unsigned int pages_per_block;
	const char *filename;
	int partition;
	unsigned int num_sectors;
	const char *start_sector;
	const char *gpt_partition;

	struct list_head node;
};

int read_op_load_tag(xmlNode *node, const char *incdir);
int read_op_load(const char *read_op_file, const char *incdir);
int read_op_execute(struct qdl_device *qdl,
		    int (*apply)(struct qdl_device *qdl, struct read_op *read_op, int fd));
int read_cmd_add(const char *source, const char *filename);
int read_resolve_gpt_deferrals(struct qdl_device *qdl);

#endif
