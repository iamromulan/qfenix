/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __DIAG_H__
#define __DIAG_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* DIAG command codes */
#define DIAG_CONTROL_F		0x29
#define DIAG_NV_READ_F		0x26
#define DIAG_NV_WRITE_F		0x27
#define DIAG_SPC_F		0x41
#define DIAG_PASSWORD_F		0x46
#define DIAG_SUBSYS_CMD_F	0x4B

/* DIAG_CONTROL_F mode values */
#define DIAG_MODE_OFFLINE_D	1
#define DIAG_MODE_RESET		2
#define DIAG_MODE_FTM		3
#define DIAG_MODE_ONLINE	4
#define DIAG_MODE_LPM		5

/* NV subsystem ID for indexed reads/writes */
#define DIAG_SUBSYS_NV		0x30
#define DIAG_SUBSYS_NV_READ	0x01
#define DIAG_SUBSYS_NV_WRITE	0x02

/* EFS subsystem IDs */
#define DIAG_SUBSYS_EFS_STD	0x13
#define DIAG_SUBSYS_EFS_ALT	0x3E

/* EFS command codes */
#define EFS2_DIAG_HELLO		0
#define EFS2_DIAG_QUERY		1
#define EFS2_DIAG_OPEN		2
#define EFS2_DIAG_CLOSE		3
#define EFS2_DIAG_READ		4
#define EFS2_DIAG_OPENDIR	11
#define EFS2_DIAG_READDIR	12
#define EFS2_DIAG_CLOSEDIR	13
#define EFS2_DIAG_STAT		15
#define EFS2_DIAG_FSTAT		17

/* EFS write/modify commands */
#define EFS2_DIAG_WRITE		5
#define EFS2_DIAG_SYMLINK	6
#define EFS2_DIAG_UNLINK	7
#define EFS2_DIAG_RMDIR		8
#define EFS2_DIAG_MKDIR		9
#define EFS2_DIAG_READLINK	14
#define EFS2_DIAG_CHMOD		18

/* EFS item interface commands (bypass file-level ACLs) */
#define EFS2_DIAG_PUT		26
#define EFS2_DIAG_GET		27

/* EFS factory image commands */
#define EFS2_DIAG_PREP_FACT_IMAGE	25
#define EFS2_DIAG_FACT_IMAGE_START	22
#define EFS2_DIAG_FACT_IMAGE_READ	23
#define EFS2_DIAG_FACT_IMAGE_END	24

/* EFS filesystem image (TAR/ZIP) commands */
#define EFS2_DIAG_FS_IMAGE_OPEN		54
#define EFS2_DIAG_FS_IMAGE_READ		55
#define EFS2_DIAG_FS_IMAGE_CLOSE	56

/* NV item sizes */
#define NV_ITEM_DATA_SIZE	128
#define NV_ITEM_PKT_SIZE	(1 + 2 + NV_ITEM_DATA_SIZE + 2)

/* EFS read/write chunk size */
#define EFS_MAX_READ_REQ	1024
#define EFS_MAX_WRITE_REQ	1024

/* NV item status codes */
#define NV_DONE_S	0
#define NV_BUSY_S	1
#define NV_BADCMD_S	2
#define NV_FULL_S	3
#define NV_FAIL_S	4
#define NV_NOTACTIVE_S	5
#define NV_BADPARM_S	6
#define NV_READONLY_S	7
#define NV_NOTDEF_S	8

struct diag_session {
#ifdef _WIN32
	intptr_t fd;	/* Windows HANDLE for serial port */
#else
	int fd;
#endif
	uint8_t efs_method;
	bool efs_detected;
};

struct nv_item {
	uint16_t item;
	uint8_t data[NV_ITEM_DATA_SIZE];
	uint16_t status;
};

struct efs_dirent {
	int32_t entry_type;
	int32_t mode;
	int32_t size;
	int32_t atime;
	int32_t mtime;
	int32_t ctime;
	char name[256];
};

struct efs_stat {
	int32_t mode;
	int32_t size;
	int32_t nlink;
	int32_t atime;
	int32_t mtime;
	int32_t ctime;
};

/* Session management */
struct diag_session *diag_open(const char *serial);
void diag_close(struct diag_session *sess);

/* Mode control */
int diag_offline(struct diag_session *sess);
int diag_online(struct diag_session *sess);

/* Low-level send/receive */
int diag_send(struct diag_session *sess, const uint8_t *cmd, size_t cmd_len,
	      uint8_t *resp, size_t resp_size);

/* NV item operations */
int diag_nv_read(struct diag_session *sess, uint16_t item,
		 struct nv_item *out);
int diag_nv_write(struct diag_session *sess, uint16_t item,
		  const uint8_t *data, size_t data_len);
int diag_nv_read_sub(struct diag_session *sess, uint16_t item,
		     uint16_t index, struct nv_item *out);
int diag_nv_write_sub(struct diag_session *sess, uint16_t item,
		      uint16_t index, const uint8_t *data, size_t data_len);
const char *diag_nv_status_str(uint16_t status);

/* EFS operations */
int diag_efs_detect(struct diag_session *sess);
int diag_efs_listdir(struct diag_session *sess, const char *path,
		     void (*callback)(const struct efs_dirent *entry,
				      void *ctx),
		     void *ctx);
int diag_efs_readfile(struct diag_session *sess, const char *src_path,
		      const char *dst_path);
int diag_efs_dump(struct diag_session *sess, const char *output_file);
int diag_efs_backup(struct diag_session *sess, const char *path,
		    const char *output_file, bool manual);
int diag_efs_restore(struct diag_session *sess, const char *tar_file);
int diag_efs_put(struct diag_session *sess, const char *local_path,
		 const char *efs_path);
int diag_efs_rm(struct diag_session *sess, const char *path, bool recursive);
int diag_efs_stat_path(struct diag_session *sess, const char *path,
		       struct efs_stat *st);
int diag_efs_mkdir_path(struct diag_session *sess, const char *path,
			int16_t mode);
int diag_efs_chmod_path(struct diag_session *sess, const char *path,
			int16_t mode);
int diag_efs_ln(struct diag_session *sess, const char *target,
		const char *linkpath);
int diag_efs_readlink_path(struct diag_session *sess, const char *path,
			   char *buf, size_t buf_size);

/* EFS item interface (GET/PUT) — more permissive than file interface */
int diag_efs_get_item(struct diag_session *sess, const char *path,
		      uint8_t *buf, size_t buf_size, int32_t *data_len_out);
int diag_efs_put_item(struct diag_session *sess, const char *path,
		      const uint8_t *data, int32_t data_len,
		      int32_t flags, int32_t mode);

/* Enhanced backup with probe walk */
int diag_efs_backup_enhanced(struct diag_session *sess, const char *path,
			     const char *output_file, bool quick);

/* NV numbered item scanning */
struct nv_scan_result {
	struct nv_item *items;
	int count;
	int capacity;
};

int diag_nv_scan(struct diag_session *sess,
		 struct nv_scan_result *def_items,
		 struct nv_scan_result *sim1_items);
void nv_scan_result_free(struct nv_scan_result *r);

/* XQCN backup/restore */
int diag_efs_backup_xqcn(struct diag_session *sess, const char *output_file);
int diag_efs_restore_xqcn(struct diag_session *sess, const char *xqcn_file);

/* Offline XQCN <-> TAR conversion (no device needed) */
int diag_xqcn_to_tar(const char *xqcn_file, const char *tar_file);
int diag_tar_to_xqcn(const char *tar_file, const char *xqcn_file);

/* DIAG feature query */
int diag_feature_query(struct diag_session *sess, uint8_t *mask,
		       size_t mask_size, size_t *mask_len);

/* DIAG extended build ID */
int diag_ext_build_id(struct diag_session *sess, char *model,
		      size_t model_size);

#endif
