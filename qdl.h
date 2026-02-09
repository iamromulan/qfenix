/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __QDL_H__
#define __QDL_H__

#include <stdbool.h>

#include "list.h"
#include "patch.h"
#include "program.h"
#include "read.h"
#include <libxml/tree.h>
#include "vip.h"

#define container_of(ptr, typecast, member) ({                  \
	void *_ptr = (void *)(ptr);		                \
	((typeof(typecast) *)(_ptr - offsetof(typecast, member))); })

#define MIN(x, y) ({		\
	__typeof__(x) _x = (x);	\
	__typeof__(y) _y = (y);	\
	_x < _y ? _x : _y;	\
})

#define ROUND_UP(x, a) ({		\
	__typeof__(x) _x = (x);		\
	__typeof__(a) _a = (a);		\
	(_x + _a - 1) & ~(_a - 1);	\
})

#define __unused __attribute__((__unused__))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGN_UP(p, size) ({						\
		__typeof__(size) _mask = (size) - 1;			\
		(__typeof__(p))(((uintptr_t)(p) + _mask) & ~_mask);	\
})

#define MAPPING_SZ 64

#define SAHARA_ID_EHOSTDL_IMG	13

enum QDL_DEVICE_TYPE {
	QDL_DEVICE_USB,
	QDL_DEVICE_SIM,
	QDL_DEVICE_PCIE,
};

enum qdl_storage_type {
	QDL_STORAGE_UNKNOWN,
	QDL_STORAGE_EMMC,
	QDL_STORAGE_NAND,
	QDL_STORAGE_UFS,
	QDL_STORAGE_NVME,
	QDL_STORAGE_SPINOR,
};

struct qdl_device {
	enum QDL_DEVICE_TYPE dev_type;
	int fd;
	size_t max_payload_size;
	size_t sector_size;
	enum qdl_storage_type storage_type;
	unsigned int slot;

	int (*open)(struct qdl_device *qdl, const char *serial);
	int (*read)(struct qdl_device *qdl, void *buf, size_t len, unsigned int timeout);
	int (*write)(struct qdl_device *qdl, const void *buf, size_t nbytes, unsigned int timeout);
	void (*close)(struct qdl_device *qdl);
	void (*set_out_chunk_size)(struct qdl_device *qdl, long size);
	void (*set_vip_transfer)(struct qdl_device *qdl, const char *signed_table,
				 const char *chained_table);

	struct vip_transfer_data vip_data;
};

struct sahara_image {
	const char *name;
	void *ptr;
	size_t len;
};

struct libusb_device_handle;

struct qdl_device *qdl_init(enum QDL_DEVICE_TYPE type);
void qdl_deinit(struct qdl_device *qdl);
int qdl_open(struct qdl_device *qdl, const char *serial);
void qdl_close(struct qdl_device *qdl);
int qdl_read(struct qdl_device *qdl, void *buf, size_t len, unsigned int timeout);
int qdl_write(struct qdl_device *qdl, const void *buf, size_t len, unsigned int timeout);
void qdl_set_out_chunk_size(struct qdl_device *qdl, long size);
int qdl_vip_transfer_enable(struct qdl_device *qdl, const char *vip_table_path);

struct qdl_device *usb_init(void);
struct qdl_device *sim_init(void);
struct qdl_device *pcie_init(void);
int pcie_prepare(struct qdl_device *qdl, const char *programmer_path);

struct qdl_device_desc {
	int vid;
	int pid;
	char serial[16];
};

struct qdl_device_desc *usb_list(unsigned int *devices_found);

int firehose_run(struct qdl_device *qdl);
int firehose_provision(struct qdl_device *qdl);
int firehose_read_buf(struct qdl_device *qdl, struct read_op *read_op, void *out_buf, size_t out_size);
int firehose_detect_and_configure(struct qdl_device *qdl,
				  bool skip_storage_init,
				  enum qdl_storage_type storage,
				  unsigned int timeout_s);
int firehose_power(struct qdl_device *qdl, const char *mode, int delay);
int firehose_read_to_file(struct qdl_device *qdl, unsigned int partition,
			  unsigned int start_sector, unsigned int num_sectors,
			  unsigned int sector_size, unsigned int pages_per_block,
			  const char *filename);

struct storage_info {
	unsigned long total_blocks;
	unsigned int block_size;
	unsigned int page_size;
	unsigned int num_physical;
	unsigned int sector_size;
	char mem_type[32];
	char prod_name[64];
};

int firehose_getstorageinfo(struct qdl_device *qdl,
			    unsigned int phys_partition,
			    struct storage_info *info);
int sahara_run(struct qdl_device *qdl, const struct sahara_image *images,
	       const char *ramdump_path,
	       const char *ramdump_filter);
int load_sahara_image(const char *filename, struct sahara_image *image);
int decode_programmer(char *s, struct sahara_image *images);
void print_hex_dump(const char *prefix, const void *buf, size_t len);
unsigned int attr_as_unsigned(xmlNode *node, const char *attr, int *errors);
const char *attr_as_string(xmlNode *node, const char *attr, int *errors);
bool attr_as_bool(xmlNode *node, const char *attr, int *errors);

void ux_init(void);
void ux_err(const char *fmt, ...);
void ux_info(const char *fmt, ...);
void ux_log(const char *fmt, ...);
void ux_debug(const char *fmt, ...);
void ux_progress(const char *fmt, unsigned int value, unsigned int size, ...);

void normalize_path(char *path);
int mkpath(const char *file_path);
void print_version(void);

int parse_storage_address(const char *address, int *physical_partition,
			  unsigned int *start_sector, unsigned int *num_sectors,
			  char **gpt_partition);

extern bool qdl_debug;
extern bool qdl_auto_edl;

enum firehose_op_type {
	OP_ERASE,
	OP_PROGRAM,
	OP_READ,
	OP_PATCH,
};

struct firehose_op {
	enum firehose_op_type type;
	union {
		struct program *program;
		struct read_op *read_op;
		struct patch *patch;
	};
	struct list_head node;
};

void firehose_op_add_program(struct program *program);
void firehose_op_add_read(struct read_op *read_op);
void firehose_op_add_patch(struct patch *patch);
int firehose_op_execute(struct qdl_device *qdl,
			int (*apply_erase)(struct qdl_device *, struct program *),
			int (*apply_program)(struct qdl_device *, struct program *, int),
			int (*apply_read)(struct qdl_device *, struct read_op *, int),
			int (*apply_patch)(struct qdl_device *, struct patch *));
void free_firehose_ops(void);

#endif
