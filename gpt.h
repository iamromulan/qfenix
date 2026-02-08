/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __GPT_H__
#define __GPT_H__

#include <stdbool.h>

struct qdl_device;

int gpt_find_by_name(struct qdl_device *qdl, const char *name, int *partition,
		     unsigned int *start_sector, unsigned int *num_sectors);
int gpt_print_table(struct qdl_device *qdl);
int gpt_get_active_slot(struct qdl_device *qdl);
int gpt_set_active_slot(struct qdl_device *qdl, char slot);
int gpt_read_all_partitions(struct qdl_device *qdl, const char *outdir);
int gpt_make_xml(struct qdl_device *qdl, const char *outdir,
		 bool make_read, bool make_program);

#endif
