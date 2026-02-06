// SPDX-License-Identifier: BSD-3-Clause
/*
 * Unified firehose operation queue for document-order execution.
 *
 * All erase, program, read, and patch operations are registered here
 * in the order they appear in the XML files, and executed in that same
 * order by firehose_op_execute().
 */
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qdl.h"
#include "oscompat.h"

static struct list_head firehose_ops = LIST_INIT(firehose_ops);

void firehose_op_add_program(struct program *program)
{
	struct firehose_op *op = calloc(1, sizeof(*op));

	op->type = program->is_erase ? OP_ERASE : OP_PROGRAM;
	op->program = program;
	list_add(&firehose_ops, &op->node);
}

void firehose_op_add_read(struct read_op *read_op)
{
	struct firehose_op *op = calloc(1, sizeof(*op));

	op->type = OP_READ;
	op->read_op = read_op;
	list_add(&firehose_ops, &op->node);
}

void firehose_op_add_patch(struct patch *patch)
{
	struct firehose_op *op = calloc(1, sizeof(*op));

	op->type = OP_PATCH;
	op->patch = patch;
	list_add(&firehose_ops, &op->node);
}

int firehose_op_execute(struct qdl_device *qdl,
			int (*apply_erase)(struct qdl_device *, struct program *),
			int (*apply_program)(struct qdl_device *, struct program *, int),
			int (*apply_read)(struct qdl_device *, struct read_op *, int),
			int (*apply_patch)(struct qdl_device *, struct patch *))
{
	unsigned int patch_count = 0;
	unsigned int patch_idx = 0;
	struct firehose_op *op;
	int ret;
	int fd;

	/* Pre-count patches for progress reporting */
	list_for_each_entry(op, &firehose_ops, node) {
		if (op->type == OP_PATCH && op->patch->filename &&
		    !strcmp(op->patch->filename, "DISK"))
			patch_count++;
	}

	list_for_each_entry(op, &firehose_ops, node) {
		switch (op->type) {
		case OP_ERASE:
			ret = apply_erase(qdl, op->program);
			if (ret)
				return ret;
			break;
		case OP_PROGRAM:
			if (!op->program->filename)
				continue;
			fd = open(op->program->filename, O_RDONLY | O_BINARY);
			if (fd < 0) {
				ux_err("unable to open %s\n", op->program->filename);
				return -1;
			}
			ret = apply_program(qdl, op->program, fd);
			close(fd);
			if (ret)
				return ret;
			break;
		case OP_READ:
			mkpath(op->read_op->filename);
			fd = open(op->read_op->filename,
				  O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
			if (fd < 0) {
				ux_err("unable to open %s\n", op->read_op->filename);
				return -1;
			}
			ret = apply_read(qdl, op->read_op, fd);
			close(fd);
			if (ret)
				return ret;
			break;
		case OP_PATCH:
			if (!op->patch->filename)
				continue;
			if (strcmp(op->patch->filename, "DISK"))
				continue;
			ret = apply_patch(qdl, op->patch);
			if (ret)
				return ret;
			ux_progress("Applying patches", patch_idx++, patch_count);
			break;
		}
	}

	if (patch_count)
		ux_info("%d patches applied\n", patch_idx);

	return 0;
}

void free_firehose_ops(void)
{
	struct firehose_op *op;
	struct firehose_op *next;

	list_for_each_entry_safe(op, next, &firehose_ops, node) {
		free(op);
	}
	list_init(&firehose_ops);
}
