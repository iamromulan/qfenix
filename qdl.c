// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2016-2017, Linaro Ltd.
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * All rights reserved.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "qdl.h"
#include "patch.h"
#include "program.h"
#include "ufs.h"
#include "diag.h"
#include "diag_switch.h"
#include "gpt.h"
#include "oscompat.h"
#include "vip.h"
#include "version.h"
#include "atcmd.h"
#include "at_port.h"

#ifdef HAVE_QCSERIALD
#include "qcseriald.h"
#endif

#ifdef _WIN32
const char *__progname = "qfenix";
#endif

#define MAX_USBFS_BULK_SIZE	(16 * 1024)

enum {
	QDL_FILE_UNKNOWN,
	QDL_FILE_PATCH,
	QDL_FILE_PROGRAM,
	QDL_FILE_READ,
	QDL_FILE_UFS,
	QDL_FILE_CONTENTS,
	QDL_CMD_READ,
	QDL_CMD_WRITE,
};

bool qdl_debug;
FILE *qdl_log_file;

static int sahara_run_with_retry(struct qdl_device *qdl,
				 const struct sahara_image *images,
				 const char *ramdump_path,
				 const char *ramdump_filter,
				 const char *serial);
static void print_all_help(FILE *out);

static int detect_type(const char *verb)
{
	xmlNode *root;
	xmlDoc *doc;
	xmlNode *node;
	int type = QDL_FILE_UNKNOWN;

	if (!strcmp(verb, "read"))
		return QDL_CMD_READ;
	if (!strcmp(verb, "write"))
		return QDL_CMD_WRITE;

	if (access(verb, F_OK)) {
		ux_err("%s is not a verb and not a XML file\n", verb);
		return -EINVAL;
	}

	doc = xmlReadFile(verb, NULL, 0);
	if (!doc) {
		ux_err("failed to parse XML file \"%s\"\n", verb);
		return -EINVAL;
	}

	root = xmlDocGetRootElement(doc);
	if (!xmlStrcmp(root->name, (xmlChar *)"patches")) {
		type = QDL_FILE_PATCH;
	} else if (!xmlStrcmp(root->name, (xmlChar *)"data")) {
		for (node = root->children; node ; node = node->next) {
			if (node->type != XML_ELEMENT_NODE)
				continue;
			if (!xmlStrcmp(node->name, (xmlChar *)"program")) {
				type = QDL_FILE_PROGRAM;
				break;
			}
			if (!xmlStrcmp(node->name, (xmlChar *)"read")) {
				type = QDL_FILE_READ;
				break;
			}
			if (!xmlStrcmp(node->name, (xmlChar *)"ufs")) {
				type = QDL_FILE_UFS;
				break;
			}
		}
	} else if (!xmlStrcmp(root->name, (xmlChar *)"contents")) {
		type = QDL_FILE_CONTENTS;
	}

	xmlFreeDoc(doc);

	return type;
}

static enum qdl_storage_type decode_storage(const char *storage)
{

	if (!strcmp(storage, "emmc"))
		return QDL_STORAGE_EMMC;
	if (!strcmp(storage, "nand"))
		return QDL_STORAGE_NAND;
	if (!strcmp(storage, "nvme"))
		return QDL_STORAGE_NVME;
	if (!strcmp(storage, "spinor"))
		return QDL_STORAGE_SPINOR;
	if (!strcmp(storage, "ufs"))
		return QDL_STORAGE_UFS;

	fprintf(stderr, "Unknown storage type \"%s\"\n", storage);
	exit(1);
}

#define CPIO_MAGIC "070701"
struct cpio_newc_header {
	char c_magic[6];       /* "070701" */
	char c_ino[8];
	char c_mode[8];
	char c_uid[8];
	char c_gid[8];
	char c_nlink[8];
	char c_mtime[8];
	char c_filesize[8];
	char c_devmajor[8];
	char c_devminor[8];
	char c_rdevmajor[8];
	char c_rdevminor[8];
	char c_namesize[8];
	char c_check[8];
};

static uint32_t parse_ascii_hex32(const char *s)
{
	uint32_t x = 0;

	for (int i = 0; i < 8; i++) {
		if (!isxdigit(s[i]))
			err(1, "non-hex-digit found in archive header");

		if (s[i] <= '9')
			x = (x << 4) | (s[i] - '0');
		else
			x = (x << 4) | (10 + (s[i] | 32) - 'a');
	}

	return x;
}

/**
 * decode_programmer_archive() - Attempt to decode a programmer CPIO archive
 * @blob: Loaded image to be decoded as archive
 * @images: List of Sahara images to populate
 *
 * The blob might be a CPIO archive containing Sahara images, in files with
 * names in the format "<id>:<filename>". Load each such Sahara image into the
 * relevant spot in the @images array.
 *
 * The blob is always consumed (freed) on both success and error paths.
 * On error, any partially-populated @images entries are also freed.
 *
 * Returns: 0 if no archive was found, 1 if archive was decoded, -1 on error
 */
static int decode_programmer_archive(struct sahara_image *blob, struct sahara_image *images)
{
	struct cpio_newc_header *hdr;
	size_t filesize;
	size_t namesize;
	char name[128];
	char *save;
	char *tok;
	void *ptr = blob->ptr;
	void *end = blob->ptr + blob->len;
	long id;

	if (blob->len < sizeof(*hdr) || memcmp(ptr, CPIO_MAGIC, 6))
		return 0;

	for (;;) {
		if (ptr + sizeof(*hdr) > end) {
			ux_err("programmer archive is truncated\n");
			goto err;
		}
		hdr = ptr;

		if (memcmp(hdr->c_magic, "070701", 6)) {
			ux_err("expected cpio header in programmer archive\n");
			goto err;
		}

		filesize = parse_ascii_hex32(hdr->c_filesize);
		namesize = parse_ascii_hex32(hdr->c_namesize);

		ptr += sizeof(*hdr);
		if (ptr + namesize > end || ptr + filesize + namesize > end) {
			ux_err("programmer archive is truncated\n");
			goto err;
		}

		if (namesize > sizeof(name)) {
			ux_err("unexpected filename length in progammer archive\n");
			goto err;
		}
		memcpy(name, ptr, namesize);

		if (!memcmp(name, "TRAILER!!!", 11))
			break;

		tok = strtok_r(name, ":", &save);
		id = strtoul(tok, NULL, 0);
		if (id == 0 || id >= MAPPING_SZ) {
			ux_err("invalid image id \"%s\" in programmer archive\n", tok);
			goto err;
		}

		ptr += namesize;
		ptr = ALIGN_UP(ptr, 4);

		tok = strtok_r(NULL, ":", &save);
		if (tok)
			images[id].name = strdup(tok);
		images[id].len = filesize;
		images[id].ptr = malloc(filesize);
		memcpy(images[id].ptr, ptr, filesize);

		ptr += filesize;
		ptr = ALIGN_UP(ptr, 4);
	}

	free(blob->ptr);
	blob->ptr = NULL;
	blob->len = 0;

	return 1;

err:
	sahara_images_free(images, MAPPING_SZ);
	free(blob->ptr);
	blob->ptr = NULL;
	blob->len = 0;
	return -1;
}

/**
 * decode_sahara_config() - Attempt to decode a Sahara config XML document
 * @blob: Loaded image to be decoded as Sahara config
 * @images: List of Sahara images, with @images[0] populated
 *
 * The single blob provided in @images[0] might be a XML blob containing
 * a sahara_config document with definitions of the various Sahara images that
 * will be loaded. Attempt to parse this and if possible load each referenced
 * Sahara image into the @images array.
 *
 * The original blob (in @images[0]) is freed once it has been consumed.
 *
 * Returns: 0 if no archive was found, 1 if archive was decoded, -1 on error
 */
static int decode_sahara_config(struct sahara_image *blob, struct sahara_image *images)
{
	char image_path_full[PATH_MAX];
	const char *image_path;
	unsigned int image_id;
	size_t image_path_len;
	xmlNode *images_node;
	xmlNode *image_node;
	char *blob_name_buf;
	size_t base_path_len;
	char *base_path;
	xmlNode *root;
	xmlDoc *doc;
	int errors = 0;
	int ret;

	if (blob->len < 5 || memcmp(blob->ptr, "<?xml", 5))
		return 0;

	doc = xmlReadMemory(blob->ptr, blob->len, blob->name, NULL, 0);
	if (!doc) {
		ux_err("failed to parse sahara_config in \"%s\"\n", blob->name);
		return -1;
	}

	blob_name_buf = strdup(blob->name);
	base_path = dirname(blob_name_buf);
	base_path_len = strlen(base_path);

	root = xmlDocGetRootElement(doc);
	if (xmlStrcmp(root->name, (xmlChar *)"sahara_config")) {
		ux_err("specified sahara_config \"%s\" is not a Sahara config\n", blob->name);
		goto err_free_doc;
	}

	for (images_node = root->children; images_node; images_node = images_node->next) {
		if (images_node->type == XML_ELEMENT_NODE &&
		    !xmlStrcmp(images_node->name, (xmlChar *)"images"))
			break;
	}

	if (!images_node) {
		ux_err("no images definitions found in sahara_config \"%s\"\n", blob->name);
		goto err_free_doc;
	}

	for (image_node = images_node->children; image_node; image_node = image_node->next) {
		if (image_node->type != XML_ELEMENT_NODE ||
		    xmlStrcmp(image_node->name, (xmlChar *)"image"))
			continue;

		image_id = attr_as_unsigned(image_node, "image_id", &errors);
		image_path = attr_as_string(image_node, "image_path", &errors);

		if (image_id == 0 || image_id >= MAPPING_SZ || errors) {
			ux_err("invalid sahara_config image in \"%s\"\n", blob->name);
			free((void *)image_path);
			goto err_free_doc;
		}

		image_path_len = strlen(image_path);
		if (base_path_len + 1 + image_path_len + 1 > PATH_MAX) {
			free((void *)image_path);
			goto err_free_doc;
		}

		memcpy(image_path_full, base_path, base_path_len);
		image_path_full[base_path_len] = '/';
		memcpy(image_path_full + base_path_len + 1, image_path, image_path_len);
		image_path_full[base_path_len + 1 + image_path_len] = '\0';

		free((void *)image_path);

		ret = load_sahara_image(image_path_full, &images[image_id]);
		if (ret < 0)
			goto err_free_doc;
	}

	xmlFreeDoc(doc);
	free(blob_name_buf);

	free(blob->ptr);
	blob->ptr = NULL;
	blob->len = 0;

	return 1;

err_free_doc:
	sahara_images_free(images, MAPPING_SZ);
	free(blob->ptr);
	blob->ptr = NULL;
	blob->len = 0;
	xmlFreeDoc(doc);
	free(blob_name_buf);
	return -1;
}

/**
 * decode_programmer() - decodes the programmer specifier
 * @s: programmer specifier, from the user
 * @images: array of images to populate
 *
 * This parses the progammer specifier @s, which can either be a single
 * filename, or a comma-separated series of <id>:<filename> entries.
 *
 * In the first case an attempt will be made to decode the Sahara archive and
 * each programmer part will be loaded into their requestd @images entry. If
 * the file isn't an archive @images[SAHARA_ID_EHOSTDL_IMG] is assigned. In the
 * second case, each comma-separated entry will be split on ':' and the given
 * <filename> will be assigned to the @image entry indicated by the given <id>.
 *
 * Memory is not allocated for the various strings, instead @s will be modified
 * by the tokenizer and pointers to the individual parts will be stored in the
 * @images array.
 *
 * Returns: 0 on success, -1 otherwise.
 */
int decode_programmer(char *s, struct sahara_image *images)
{
	struct sahara_image archive;
	char *filename;
	char *save1;
	char *pair;
	char *tail;
	long id;
	int ret;

	strtoul(s, &tail, 0);
	if (tail != s && tail[0] == ':') {
		for (pair = strtok_r(s, ",", &save1); pair; pair = strtok_r(NULL, ",", &save1)) {
			id = strtoul(pair, &tail, 0);
			if (tail == pair) {
				ux_err("invalid programmer specifier\n");
				return -1;
			}

			if (id == 0 || id >= MAPPING_SZ) {
				ux_err("invalid image id \"%s\"\n", pair);
				return -1;
			}

			filename = &tail[1];
			ret = load_sahara_image(filename, &images[id]);
			if (ret < 0)
				return -1;
		}
	} else {
		ret = load_sahara_image(s, &archive);
		if (ret < 0)
			return -1;

		ret = decode_programmer_archive(&archive, images);
		if (ret < 0 || ret == 1)
			return ret;

		ret = decode_sahara_config(&archive, images);
		if (ret < 0 || ret == 1)
			return ret;

		images[SAHARA_ID_EHOSTDL_IMG] = archive;
	}

	return 0;
}

/*
 * Firmware directory auto-detection
 */
struct firmware_files {
	char *programmer;
	char **rawprogram;
	int rawprogram_count;
	char **patch;
	int patch_count;
	char **rawread;
	int rawread_count;
	enum qdl_storage_type storage_type;
	char *firehose_dir;
};

static int match_file(const char *name, const char *prefix, const char *suffix)
{
	size_t name_len = strlen(name);
	size_t prefix_len = strlen(prefix);
	size_t suffix_len = strlen(suffix);

	if (name_len < prefix_len + suffix_len)
		return 0;

	if (strncasecmp(name, prefix, prefix_len) != 0)
		return 0;

	if (strcasecmp(name + name_len - suffix_len, suffix) != 0)
		return 0;

	return 1;
}

static char *find_file_recursive_impl(const char *dir, const char *prefix,
				      const char *suffix, int depth)
{
	struct dirent *entry;
	char path[PATH_MAX];
	char *result = NULL;
	struct stat st;
	DIR *d;

	if (depth > 10)
		return NULL;

	d = opendir(dir);
	if (!d)
		return NULL;

	/* First pass: check files in current directory */
	while ((entry = readdir(d)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		if (match_file(entry->d_name, prefix, suffix)) {
			snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
			result = strdup(path);
			break;
		}
	}

	/* Second pass: recurse into subdirectories */
	if (!result) {
		rewinddir(d);
		while ((entry = readdir(d)) != NULL) {
			if (entry->d_name[0] == '.')
				continue;

			snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
			if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
				result = find_file_recursive_impl(path, prefix, suffix, depth + 1);
				if (result)
					break;
			}
		}
	}

	closedir(d);
	return result;
}

static char *find_file_recursive(const char *dir, const char *prefix, const char *suffix)
{
	return find_file_recursive_impl(dir, prefix, suffix, 0);
}

static int find_files_recursive_impl(const char *dir, const char *prefix,
				      const char *suffix, char ***files_out,
				      int *count_out, int *capacity, int depth)
{
	struct dirent *entry;
	char path[PATH_MAX];
	struct stat st;
	DIR *d;

	if (depth > 10)
		return 0;

	d = opendir(dir);
	if (!d)
		return 0;

	while ((entry = readdir(d)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);

		if (match_file(entry->d_name, prefix, suffix)) {
			if (*count_out >= *capacity) {
				*capacity = *capacity ? *capacity * 2 : 8;
				*files_out = realloc(*files_out, *capacity * sizeof(char *));
			}
			(*files_out)[(*count_out)++] = strdup(path);
		}

		if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
			find_files_recursive_impl(path, prefix, suffix,
						  files_out, count_out, capacity, depth + 1);
	}

	closedir(d);
	return 0;
}

static int cmp_strings(const void *a, const void *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}

static int find_files_recursive(const char *dir, const char *prefix, const char *suffix,
				char ***files_out, int *count_out)
{
	int capacity = 0;

	*files_out = NULL;
	*count_out = 0;
	find_files_recursive_impl(dir, prefix, suffix,
				  files_out, count_out, &capacity, 0);

	if (*count_out > 1)
		qsort(*files_out, *count_out, sizeof(char *), cmp_strings);

	return 0;
}

static enum qdl_storage_type detect_storage_from_filename(const char *filename)
{
	if (strcasestr(filename, "_nand") || strcasestr(filename, "nand_"))
		return QDL_STORAGE_NAND;
	if (strcasestr(filename, "_emmc") || strcasestr(filename, "emmc_"))
		return QDL_STORAGE_EMMC;
	if (strcasestr(filename, "_ufs") || strcasestr(filename, "ufs_"))
		return QDL_STORAGE_UFS;

	return QDL_STORAGE_NAND; /* default */
}

/*
 * Recursively search a directory for a Firehose programmer file.
 * Tries multiple known naming patterns in priority order.
 * Returns malloc'd path on success, NULL on failure.
 */
static char *find_programmer_recursive(const char *base_dir)
{
	static const struct {
		const char *prefix;
		const char *suffix;
	} patterns[] = {
		{ "prog_firehose_",      ".elf"  },
		{ "prog_firehose_",      ".mbn"  },
		{ "prog_nand_firehose_", ".mbn"  },
		{ "prog_emmc_firehose_", ".mbn"  },
		{ "prog_ufs_firehose_",  ".mbn"  },
		{ "firehose-prog",       ".mbn"  },
		{ "prog_",               ".mbn"  },
		{ "prog_",               ".elf"  },
		{ "xbl_s_devprg_",       ".melf" },
	};
	char *result;
	size_t i;

	for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
		result = find_file_recursive(base_dir, patterns[i].prefix,
					     patterns[i].suffix);
		if (result)
			return result;
	}

	return NULL;
}

/*
 * Detect storage type from rawprogram XMLs in a directory.
 * Returns detected type, or QDL_STORAGE_NAND as default.
 */
static enum qdl_storage_type detect_storage_from_directory(const char *base_dir)
{
	enum qdl_storage_type storage;
	char **rawprogram = NULL;
	int count = 0;

	find_files_recursive(base_dir, "rawprogram", ".xml",
			     &rawprogram, &count);
	if (count > 0) {
		storage = detect_storage_from_filename(rawprogram[0]);
		while (count > 0)
			free(rawprogram[--count]);
		free(rawprogram);
		return storage;
	}

	free(rawprogram);
	return QDL_STORAGE_NAND;
}

static int firmware_detect(const char *base_dir, struct firmware_files *fw)
{
	char *dir_buf;
	int i;

	memset(fw, 0, sizeof(*fw));
	fw->storage_type = QDL_STORAGE_NAND;

	/* Find programmer file by searching recursively from base directory */
	fw->programmer = find_programmer_recursive(base_dir);

	if (!fw->programmer) {
		ux_err("no programmer file found under %s\n", base_dir);
		return -1;
	}

	/*
	 * Use the directory containing the programmer as the firehose
	 * directory. Binary files referenced in XMLs are typically
	 * co-located with the programmer.
	 */
	dir_buf = strdup(fw->programmer);
	fw->firehose_dir = strdup(dirname(dir_buf));
	free(dir_buf);

	/* Find rawprogram XML files recursively */
	find_files_recursive(base_dir, "rawprogram", ".xml",
			     &fw->rawprogram, &fw->rawprogram_count);

	/* Find rawread XML files recursively */
	find_files_recursive(base_dir, "rawread", ".xml",
			     &fw->rawread, &fw->rawread_count);

	if (fw->rawprogram_count == 0 && fw->rawread_count == 0) {
		ux_err("no rawprogram or rawread XML files found under %s\n", base_dir);
		return -1;
	}

	/* Detect storage type from first rawprogram or rawread filename */
	if (fw->rawprogram_count > 0)
		fw->storage_type = detect_storage_from_filename(fw->rawprogram[0]);
	else
		fw->storage_type = detect_storage_from_filename(fw->rawread[0]);

	/* Find patch XML files recursively */
	find_files_recursive(base_dir, "patch", ".xml",
			     &fw->patch, &fw->patch_count);

	ux_info("Firmware directory: %s\n", base_dir);
	ux_info("  Programmer: %s\n", fw->programmer);
	ux_info("  Firehose dir: %s\n", fw->firehose_dir);
	ux_info("  Storage type: %s\n",
		fw->storage_type == QDL_STORAGE_NAND ? "nand" :
		fw->storage_type == QDL_STORAGE_EMMC ? "emmc" :
		fw->storage_type == QDL_STORAGE_UFS ? "ufs" : "unknown");
	ux_info("  Program files: %d\n", fw->rawprogram_count);
	for (i = 0; i < fw->rawprogram_count; i++)
		ux_info("    %s\n", fw->rawprogram[i]);
	ux_info("  Patch files: %d\n", fw->patch_count);
	for (i = 0; i < fw->patch_count; i++)
		ux_info("    %s\n", fw->patch[i]);
	if (fw->rawread_count > 0) {
		ux_info("  Read files: %d\n", fw->rawread_count);
		for (i = 0; i < fw->rawread_count; i++)
			ux_info("    %s\n", fw->rawread[i]);
	}

	return 0;
}

static void firmware_free(struct firmware_files *fw)
{
	int i;

	free(fw->programmer);
	free(fw->firehose_dir);

	for (i = 0; i < fw->rawprogram_count; i++)
		free(fw->rawprogram[i]);
	free(fw->rawprogram);

	for (i = 0; i < fw->patch_count; i++)
		free(fw->patch[i]);
	free(fw->patch);

	for (i = 0; i < fw->rawread_count; i++)
		free(fw->rawread[i]);
	free(fw->rawread);
}

static void print_usage(FILE *out)
{
	extern const char *__progname;

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "qfenix");
	fprintf(out, " - A Qualcomm Firehose / DIAG multi-tool by iamromulan\n");
	fprintf(out, "A Custom fork of https://github.com/linux-msm/qdl\n");
#ifdef BUILD_STATIC
	fprintf(out, "%s, %s %s, static binary\n", VERSION, __DATE__, __TIME__);
#else
	fprintf(out, "%s, %s %s, dynamically linked\n", VERSION, __DATE__, __TIME__);
#endif
	fprintf(out, "\nCheck for new updates here: https://github.com/iamromulan/qfenix/releases\n");

	fprintf(out, "\nUsage: %s [options] -F <firmware-dir>\n", __progname);
	fprintf(out, "       %s [options] <prog.mbn> <read-xml|patch-xml|program-xml>...\n", __progname);
	fprintf(out, "       %s [options] <prog.mbn> (read|write) <address> <binary>...\n", __progname);
	fprintf(out, "       %s <subcommand> [options]\n", __progname);

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nEDL Commands");
	fprintf(out, " (require a firehose programmer/loader):\n");
	fprintf(out, "\n  The loader/programmer can be provided 3 ways:\n");
	fprintf(out, "    1. Auto-detected from current directory (or subdirectory)\n");
	fprintf(out, "    2. -L <dir> to specify a search directory\n");
	fprintf(out, "    3. Exact programmer path as a positional argument\n");
	fprintf(out, "\n  flash         Flash firmware (same as -F)\n");
	fprintf(out, "  printgpt      Print GPT/NAND partition tables\n");
	fprintf(out, "  storageinfo   Query storage hardware information\n");
	fprintf(out, "  partinfo      Storage info + partition table (single session)\n");
	fprintf(out, "  reset         Reset, power-off, or EDL-reboot a device\n");
	fprintf(out, "  getslot       Show the active A/B slot\n");
	fprintf(out, "  setslot       Set the active A/B slot (a or b)\n");
	fprintf(out, "  read          Read partition(s) by label\n");
	fprintf(out, "  readall       Dump all partitions to files\n");
	fprintf(out, "  write         Erase + write a raw image to a partition\n");
	fprintf(out, "  erase         Erase partition(s) by label or raw sectors\n");
	fprintf(out, "  eraseall      Erase all partitions on device\n");

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nDIAG Commands");
	fprintf(out, " (work directly on DIAG port, no programmer needed):\n");
	fprintf(out, "  diag2edl      Switch a device from DIAG to EDL mode\n");
	fprintf(out, "  nvread        Read an NV item via DIAG\n");
	fprintf(out, "  nvwrite       Write an NV item via DIAG\n");

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nEFS Commands");
	fprintf(out, " (EFS filesystem over DIAG, no programmer needed):\n");
	fprintf(out, "  efsbackup     Backup EFS filesystem to TAR or XQCN format\n");
	fprintf(out, "  efsrestore    Restore EFS filesystem from TAR or XQCN file\n");
	fprintf(out, "  efspull       Download a file from EFS\n");
	fprintf(out, "  efspush       Upload a file to EFS\n");
	fprintf(out, "  efsls         List an EFS directory\n");
	fprintf(out, "  efsrm         Delete a file or directory from EFS (-r for recursive)\n");
	fprintf(out, "  efsstat       Show EFS file/directory information\n");
	fprintf(out, "  efsmkdir      Create a directory on EFS\n");
	fprintf(out, "  efschmod      Change EFS file/directory permissions\n");
	fprintf(out, "  efsln         Create a symlink on EFS\n");
	fprintf(out, "  efsrl         Read a symlink target on EFS\n");
	fprintf(out, "  efsdump       Dump the EFS factory image\n");

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nConversion Commands");
	fprintf(out, " (offline, no device needed):\n");
	fprintf(out, "  xqcn2tar      Convert XQCN backup to TAR archive\n");
	fprintf(out, "  tar2xqcn      Convert TAR archive to XQCN format\n");

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nAT/SMS Operations");
	fprintf(out, " (AT command port, no programmer needed):\n");
	fprintf(out, "  smssend       Send an SMS message\n");
	fprintf(out, "  smsread       Receive/list SMS messages\n");
	fprintf(out, "  smsrm         Delete SMS message(s)\n");
	fprintf(out, "  smsstatus     Query SMS storage status\n");
	fprintf(out, "  ussd          Send USSD/USSI query\n");
	fprintf(out, "  atcmd         Send a raw AT command\n");
	fprintf(out, "  atconsole     Interactive AT command console\n");

#ifdef HAVE_QCSERIALD
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nmacOS Serial Port Daemon");
	fprintf(out, ":\n");
	fprintf(out, "  qcseriald     Manage the USB-to-serial bridge daemon\n");
#endif

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nOther Commands");
	fprintf(out, ":\n");
	fprintf(out, "  list          List connected EDL, DIAG, and PCIe devices\n");
	fprintf(out, "  ramdump       Extract RAM dumps via Sahara\n");
	fprintf(out, "  ks            Keystore/Sahara over serial device nodes\n");

	fprintf(out, "\nUse '%s <subcommand> --help' for detailed subcommand usage.\n", __progname);
	fprintf(out, "Use '%s --help-all' to show help for all subcommands at once.\n", __progname);

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nGlobal Options");
	fprintf(out, " (work with all subcommands):\n");
	fprintf(out, "      --log=FILE            Write debug-level log to FILE\n");

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nFlash Options");
	fprintf(out, ":\n");
	fprintf(out, "  -d, --debug               Print detailed debug info\n");
	fprintf(out, "  -n, --dry-run             Dry run, no device reading or flashing\n");
	fprintf(out, "  -e, --erase-all           Erase all partitions before programming\n");
	fprintf(out, "  -f, --allow-missing       Allow skipping of missing files\n");
	fprintf(out, "  -s, --storage=T           Set storage type: emmc|nand|nvme|spinor|ufs (default: nand)\n");
	fprintf(out, "  -l, --finalize-provisioning  Provision the target storage\n");
	fprintf(out, "  -i, --include=T           Set folder T to search for files\n");
	fprintf(out, "  -S, --serial=T            Target by serial number or COM port name\n");
	fprintf(out, "  -u, --out-chunk-size=T    Override chunk size for transactions\n");
	fprintf(out, "  -t, --create-digests=T    Generate VIP digest table in folder T\n");
	fprintf(out, "  -T, --slot=T              Set slot number for multiple storage devices\n");
	fprintf(out, "  -D, --vip-table-path=T    Use VIP digest tables from folder T\n");
	fprintf(out, "  -E, --no-auto-edl         Disable automatic DIAG to EDL switching\n");
	fprintf(out, "  -M, --skip-md5            Skip MD5 verification of firmware files\n");
	fprintf(out, "  -F, --firmware-dir=T      Auto-detect firmware from directory T\n");
	fprintf(out, "  -L, --find-loader=T       Auto-detect programmer/loader from directory T\n");
	fprintf(out, "  -P, --pcie                Use PCIe/MHI transport instead of USB\n");
	fprintf(out, "  -v, --version             Print version and exit\n");
	fprintf(out, "  -h, --help                Print this usage info\n");
	fprintf(out, "      --help-all            Print help for all subcommands\n");

	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nExamples");
	fprintf(out, ":\n");
	fprintf(out, "  %s flash /path/to/firmware/       Auto-detect and flash\n", __progname);
	fprintf(out, "  %s -F /path/to/firmware/          Auto-detect and flash\n", __progname);
	fprintf(out, "  %s prog_firehose_ddr.elf rawprogram*.xml patch*.xml\n", __progname);
	fprintf(out, "  %s printgpt                       Print partitions (with loader in current dir)\n", __progname);
	fprintf(out, "  %s readall -o backup/             Dump all partitions to backup/\n", __progname);
	fprintf(out, "  %s list                           List connected devices\n", __progname);
	fprintf(out, "  %s efsbackup                      Backup EFS + NV items to XQCN\n", __progname);
	fprintf(out, "  %s efsrestore backup.xqcn         Restore from XQCN file\n", __progname);
	fprintf(out, "  %s nvread 550                     Read NV item 550\n", __progname);
}

/*
 * List USB EDL devices via libusb.
 * Returns number of devices found.
 */
static int list_usb_edl(FILE *out)
{
	struct qdl_device_desc *devices;
	unsigned int count;
	unsigned int i;
	int printed_header = 0;

	devices = usb_list(&count);
	if (!devices || count == 0) {
		free(devices);
		return 0;
	}

	fprintf(out, "EDL devices (USB):\n");
	printed_header = 1;

	for (i = 0; i < count; i++)
		fprintf(out, "  %04x:%04x  SN:%s\n",
			devices[i].vid, devices[i].pid, devices[i].serial);

	free(devices);

	return printed_header ? (int)count : 0;
}

/*
 * List USB devices with an ADB interface via libusb.
 * ADB: class 0xFF, subclass 0x42, protocol 0x01.
 * Returns number of devices found.
 */
static int list_usb_adb(FILE *out)
{
	struct usb_adb_desc *devices;
	unsigned int count;
	unsigned int i;

	devices = usb_list_adb(&count);
	if (!devices || count == 0) {
		free(devices);
		return 0;
	}

	fprintf(out, "ADB devices:\n");

	for (i = 0; i < count; i++)
		fprintf(out, "  %04x:%04x  iface %d\n",
			devices[i].vid, devices[i].pid, devices[i].iface);

	free(devices);
	return (int)count;
}

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>

static const GUID GUID_DEVCLASS_PORTS_LIST = {
	0x4d36e978, 0xe325, 0x11ce,
	{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
};

static int is_qc_modem_name_list(const char *name)
{
	if (strstr(name, "Qualcomm") || strstr(name, "Snapdragon") ||
	    strstr(name, "QDLoader") || strstr(name, "Sahara") ||
	    strstr(name, "QCOM") || strstr(name, "SDX") ||
	    strstr(name, "DW59") || strstr(name, "DW58") ||
	    strstr(name, "Quectel") || strstr(name, "Sierra") ||
	    strstr(name, "Fibocom") || strstr(name, "Telit") ||
	    strstr(name, "Foxconn") || strstr(name, "T99W") ||
	    strstr(name, "EM91") || strstr(name, "EM92") ||
	    strstr(name, "FM150") || strstr(name, "FM160") ||
	    strstr(name, "SIM82") || strstr(name, "SIM83") ||
	    strstr(name, "RM5") || strstr(name, "RM2"))
		return 1;
	return 0;
}

static int is_diag_name_list(const char *name)
{
	if (strstr(name, "DIAG") || strstr(name, "DM Port") ||
	    strstr(name, "QDLoader") || strstr(name, "Diagnostic") ||
	    strstr(name, "Sahara"))
		return 1;
	return 0;
}

static int is_edl_name_list(const char *name)
{
	if (strstr(name, "EDL"))
		return 1;
	return 0;
}

static int is_at_name_list(const char *name)
{
	if (strstr(name, "AT Port") || strstr(name, "AT Interface") ||
	    strstr(name, "Modem"))
		return 1;
	return 0;
}

static int is_skip_name_list(const char *name)
{
	if (is_at_name_list(name) ||
	    strstr(name, "NMEA") || strstr(name, "GPS") ||
	    strstr(name, "Audio"))
		return 1;
	return 0;
}

/*
 * Scan all Windows COM ports and list Qualcomm EDL and DIAG devices.
 * Returns total number of devices found.
 */
static int list_com_ports(FILE *out)
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA devInfoData;
	DWORD i;
	int edl_count = 0, diag_count = 0, at_count = 0;
	int edl_header = 0, diag_header = 0, at_header = 0;

	/* Collect ports in two passes: first EDL, then DIAG */
	hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_PORTS_LIST, NULL, NULL,
					DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
		return 0;

	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	/* Pass 1: EDL ports */
	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
		char hwid[512] = {0};
		char friendlyName[256] = {0};
		char portName[32] = {0};
		char *vidStr, *pidStr;
		HKEY hKey;
		DWORD size;
		int vid = 0, pid = 0;
		int is_edl = 0;
		const char *bus;

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_HARDWAREID, NULL, (PBYTE)hwid,
			sizeof(hwid), NULL);

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName,
			sizeof(friendlyName), NULL);

		vidStr = strstr(hwid, "VID_");
		pidStr = strstr(hwid, "PID_");

		if (vidStr)
			vid = strtol(vidStr + 4, NULL, 16);
		if (pidStr)
			pid = strtol(pidStr + 4, NULL, 16);

		if (vidStr) {
			/* USB device */
			if (is_edl_device(vid, pid)) {
				is_edl = 1;
				bus = "USB";
			}
		} else {
			/* PCIe/MHI device — check friendly name */
			if (is_edl_name_list(friendlyName) &&
			    is_qc_modem_name_list(friendlyName)) {
				is_edl = 1;
				bus = "PCIe";
			}
		}

		if (!is_edl)
			continue;

		hKey = SetupDiOpenDevRegKey(hDevInfo, &devInfoData,
					    DICS_FLAG_GLOBAL, 0, DIREG_DEV,
					    KEY_READ);
		if (hKey == INVALID_HANDLE_VALUE)
			continue;

		size = sizeof(portName);
		if (RegQueryValueExA(hKey, "PortName", NULL, NULL,
				     (LPBYTE)portName, &size) != ERROR_SUCCESS ||
		    strncmp(portName, "COM", 3) != 0) {
			RegCloseKey(hKey);
			continue;
		}
		RegCloseKey(hKey);

		if (!edl_header) {
			fprintf(out, "EDL devices (COM):\n");
			edl_header = 1;
		}

		if (vid)
			fprintf(out, "  %-8s  %04x:%04x  %s  %s\n",
				portName, vid, pid, friendlyName, bus);
		else
			fprintf(out, "  %-8s  %s  %s\n",
				portName, friendlyName, bus);
		edl_count++;
	}

	/* Pass 2: DIAG ports */
	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
		char hwid[512] = {0};
		char friendlyName[256] = {0};
		char portName[32] = {0};
		char *vidStr, *pidStr;
		HKEY hKey;
		DWORD size;
		int vid = 0, pid = 0;
		int is_diag = 0;
		const char *bus;

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_HARDWAREID, NULL, (PBYTE)hwid,
			sizeof(hwid), NULL);

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName,
			sizeof(friendlyName), NULL);

		vidStr = strstr(hwid, "VID_");
		pidStr = strstr(hwid, "PID_");

		if (vidStr)
			vid = strtol(vidStr + 4, NULL, 16);
		if (pidStr)
			pid = strtol(pidStr + 4, NULL, 16);

		if (vidStr) {
			/* USB device — check DIAG vendor, skip EDL */
			if (!is_diag_vendor(vid))
				continue;
			if (is_edl_device(vid, pid))
				continue;
			bus = "USB";
		} else {
			/* PCIe/MHI device — check friendly name */
			if (!is_qc_modem_name_list(friendlyName))
				continue;
			/* Skip EDL ports (already listed above) */
			if (is_edl_name_list(friendlyName))
				continue;
			bus = "PCIe";
		}

		/* Skip non-DIAG ports (AT, NMEA, GPS, etc.) */
		if (is_skip_name_list(friendlyName))
			continue;

		hKey = SetupDiOpenDevRegKey(hDevInfo, &devInfoData,
					    DICS_FLAG_GLOBAL, 0, DIREG_DEV,
					    KEY_READ);
		if (hKey == INVALID_HANDLE_VALUE)
			continue;

		size = sizeof(portName);
		if (RegQueryValueExA(hKey, "PortName", NULL, NULL,
				     (LPBYTE)portName, &size) != ERROR_SUCCESS ||
		    strncmp(portName, "COM", 3) != 0) {
			RegCloseKey(hKey);
			continue;
		}
		RegCloseKey(hKey);

		if (!diag_header) {
			if (edl_count > 0)
				fprintf(out, "\n");
			fprintf(out, "DIAG devices (COM):\n");
			diag_header = 1;
		}

		if (vid) {
			int iface = get_diag_interface_num(vid, pid);

			fprintf(out, "  %-8s  %04x:%04x  iface %d  %s  %s\n",
				portName, vid, pid, iface, friendlyName, bus);
		} else {
			is_diag = is_diag_name_list(friendlyName);
			fprintf(out, "  %-8s  %s%s  %s\n",
				portName, friendlyName,
				is_diag ? "" : "  (unknown role)",
				bus);
		}
		diag_count++;
	}

	/* Pass 3: AT ports */
	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
		char hwid[512] = {0};
		char friendlyName[256] = {0};
		char portName[32] = {0};
		char *vidStr, *pidStr;
		HKEY hKey;
		DWORD size;
		int vid = 0, pid = 0;
		const char *bus;

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_HARDWAREID, NULL, (PBYTE)hwid,
			sizeof(hwid), NULL);

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName,
			sizeof(friendlyName), NULL);

		vidStr = strstr(hwid, "VID_");
		pidStr = strstr(hwid, "PID_");

		if (vidStr)
			vid = strtol(vidStr + 4, NULL, 16);
		if (pidStr)
			pid = strtol(pidStr + 4, NULL, 16);

		if (vidStr) {
			if (!is_diag_vendor(vid))
				continue;
			if (is_edl_device(vid, pid))
				continue;
			bus = "USB";
		} else {
			if (!is_qc_modem_name_list(friendlyName))
				continue;
			if (is_edl_name_list(friendlyName))
				continue;
			bus = "PCIe";
		}

		if (!is_at_name_list(friendlyName))
			continue;

		hKey = SetupDiOpenDevRegKey(hDevInfo, &devInfoData,
					    DICS_FLAG_GLOBAL, 0, DIREG_DEV,
					    KEY_READ);
		if (hKey == INVALID_HANDLE_VALUE)
			continue;

		size = sizeof(portName);
		if (RegQueryValueExA(hKey, "PortName", NULL, NULL,
				     (LPBYTE)portName, &size) != ERROR_SUCCESS ||
		    strncmp(portName, "COM", 3) != 0) {
			RegCloseKey(hKey);
			continue;
		}
		RegCloseKey(hKey);

		if (!at_header) {
			if (edl_count + diag_count > 0)
				fprintf(out, "\n");
			fprintf(out, "AT devices (COM):\n");
			at_header = 1;
		}

		if (vid)
			fprintf(out, "  %-8s  %04x:%04x  %s  %s\n",
				portName, vid, pid, friendlyName, bus);
		else
			fprintf(out, "  %-8s  %s  %s\n",
				portName, friendlyName, bus);
		at_count++;
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);

	return edl_count + diag_count + at_count;
}

#elif defined(__linux__)

#include <termios.h>
#include <poll.h>

static int list_diag_ports(FILE *out)
{
	const char *base = "/sys/bus/usb/devices";
	DIR *busdir, *infdir;
	struct dirent *de, *de2;
	char path[512], line[256];
	FILE *fp;
	int count = 0;
	int printed_header = 0;

	busdir = opendir(base);
	if (!busdir)
		return 0;

	while ((de = readdir(busdir)) != NULL) {
		int major = 0, vid = 0, pid = 0;
		char devtype[64] = {0};
		char product[64] = {0};
		int diag_iface;

		if (!isdigit(de->d_name[0]))
			continue;

		snprintf(path, sizeof(path), "%s/%s/uevent",
			 base, de->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		while (fgets(line, sizeof(line), fp)) {
			line[strcspn(line, "\r\n")] = 0;
			if (strncmp(line, "MAJOR=", 6) == 0)
				major = atoi(line + 6);
			else if (strncmp(line, "DEVTYPE=", 8) == 0)
				snprintf(devtype, sizeof(devtype),
					 "%.63s", line + 8);
			else if (strncmp(line, "PRODUCT=", 8) == 0)
				snprintf(product, sizeof(product),
					 "%.63s", line + 8);
		}
		fclose(fp);

		if (major != 189 || strncmp(devtype, "usb_device", 10) != 0)
			continue;

		sscanf(product, "%x/%x", &vid, &pid);

		if (!is_diag_vendor(vid))
			continue;

		/* Skip EDL-mode devices (already shown by usb_list) */
		if (is_edl_device(vid, pid))
			continue;

		diag_iface = get_diag_interface_num(vid, pid);

		/* Look for tty port under the DIAG interface */
		snprintf(path, sizeof(path), "%s/%s:1.%d",
			 base, de->d_name, diag_iface);
		infdir = opendir(path);
		if (!infdir) {
			/* Try interface 0 as fallback */
			snprintf(path, sizeof(path), "%s/%s:1.0",
				 base, de->d_name);
			infdir = opendir(path);
		}
		if (!infdir)
			continue;

		while ((de2 = readdir(infdir)) != NULL) {
			char ttypath[520];
			DIR *ttydir;
			struct dirent *de3;

			if (strncmp(de2->d_name, "ttyUSB", 6) == 0 ||
			    strncmp(de2->d_name, "ttyACM", 6) == 0) {
				if (!printed_header) {
					fprintf(out, "DIAG devices:\n");
					printed_header = 1;
				}
				fprintf(out, "  /dev/%-12s  %04x:%04x  iface %d  USB\n",
					de2->d_name, vid, pid, diag_iface);
				count++;
				break;
			}

			if (strncmp(de2->d_name, "tty", 3) == 0 &&
			    strlen(de2->d_name) == 3) {
				snprintf(ttypath, sizeof(ttypath),
					 "%.511s/tty", path);
				ttydir = opendir(ttypath);
				if (!ttydir)
					continue;

				while ((de3 = readdir(ttydir)) != NULL) {
					if (strncmp(de3->d_name, "ttyUSB", 6) == 0 ||
					    strncmp(de3->d_name, "ttyACM", 6) == 0) {
						if (!printed_header) {
							fprintf(out, "DIAG devices:\n");
							printed_header = 1;
						}
						fprintf(out, "  /dev/%-12s  %04x:%04x  iface %d  USB\n",
							de3->d_name, vid, pid,
							diag_iface);
						count++;
						break;
					}
				}
				closedir(ttydir);
				if (count > 0)
					break;
			}
		}
		closedir(infdir);
	}

	closedir(busdir);
	return count;
}

/*
 * Probe a serial port with AT command.
 * Returns 1 if port responds to AT (OK or ERROR), 0 otherwise (NMEA etc).
 */
static int probe_at_port(const char *port_path)
{
	int fd;
	struct termios tio;
	struct pollfd pfd;
	char resp[128] = {0};
	int ret;

	fd = open(port_path, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0)
		return -1;

	memset(&tio, 0, sizeof(tio));
	cfmakeraw(&tio);
	cfsetspeed(&tio, B115200);
	tio.c_cflag |= CLOCAL | CREAD | CS8;
	tio.c_cflag &= ~(PARENB | CSTOPB | CRTSCTS);
	tcsetattr(fd, TCSANOW, &tio);
	tcflush(fd, TCIOFLUSH);

	write(fd, "AT\r", 3);

	pfd.fd = fd;
	pfd.events = POLLIN;

	/* Read in a loop — first poll may only return the AT echo */
	int resp_len = 0;

	while (resp_len < (int)sizeof(resp) - 1) {
		ret = poll(&pfd, 1, 500);
		if (ret <= 0 || !(pfd.revents & POLLIN))
			break;
		ret = read(fd, resp + resp_len,
			   sizeof(resp) - 1 - resp_len);
		if (ret <= 0)
			break;
		resp_len += ret;
		resp[resp_len] = '\0';
		if (strstr(resp, "OK") || strstr(resp, "ERROR"))
			break;
	}

	close(fd);

	if (strstr(resp, "OK") || strstr(resp, "ERROR"))
		return 1;
	return 0;
}

/*
 * List non-DIAG serial ports from Qualcomm USB devices on Linux.
 * Probes each port to classify as AT or NMEA.
 */
static int list_at_ports(FILE *out)
{
	const char *base = "/sys/bus/usb/devices";
	DIR *busdir, *infdir;
	struct dirent *de, *de2;
	char path[512], line[256];
	FILE *fp;
	int at_count = 0, nmea_count = 0;
	int at_header = 0, nmea_header = 0;
	/* Collect ports first, then print (AT before NMEA) */
	struct {
		char path[300];
		int vid, pid, iface;
		int is_at;	/* 1=AT, 0=NMEA/other, -1=cant open */
	} ports[32];
	int port_count = 0;

	busdir = opendir(base);
	if (!busdir)
		return 0;

	while ((de = readdir(busdir)) != NULL) {
		int major = 0, vid = 0, pid = 0;
		char devtype[64] = {0};
		char product[64] = {0};
		int diag_iface, iface_num;

		if (!isdigit(de->d_name[0]))
			continue;

		snprintf(path, sizeof(path), "%s/%s/uevent",
			 base, de->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		while (fgets(line, sizeof(line), fp)) {
			line[strcspn(line, "\r\n")] = 0;
			if (strncmp(line, "MAJOR=", 6) == 0)
				major = atoi(line + 6);
			else if (strncmp(line, "DEVTYPE=", 8) == 0)
				snprintf(devtype, sizeof(devtype),
					 "%.63s", line + 8);
			else if (strncmp(line, "PRODUCT=", 8) == 0)
				snprintf(product, sizeof(product),
					 "%.63s", line + 8);
		}
		fclose(fp);

		if (major != 189 || strncmp(devtype, "usb_device", 10) != 0)
			continue;

		sscanf(product, "%x/%x", &vid, &pid);

		if (!is_diag_vendor(vid))
			continue;
		if (is_edl_device(vid, pid))
			continue;

		diag_iface = get_diag_interface_num(vid, pid);

		/* Scan all interfaces EXCEPT the DIAG interface */
		for (iface_num = 0; iface_num < 16; iface_num++) {
			char port_path[300];

			if (iface_num == diag_iface)
				continue;

			snprintf(path, sizeof(path), "%s/%s:1.%d",
				 base, de->d_name, iface_num);
			infdir = opendir(path);
			if (!infdir)
				continue;

			port_path[0] = '\0';
			while ((de2 = readdir(infdir)) != NULL) {
				char ttypath[520];
				DIR *ttydir;
				struct dirent *de3;

				if (strncmp(de2->d_name, "ttyUSB", 6) == 0 ||
				    strncmp(de2->d_name, "ttyACM", 6) == 0) {
					snprintf(port_path, sizeof(port_path),
						 "/dev/%s", de2->d_name);
					break;
				}

				if (strncmp(de2->d_name, "tty", 3) == 0 &&
				    strlen(de2->d_name) == 3) {
					snprintf(ttypath, sizeof(ttypath),
						 "%.511s/tty", path);
					ttydir = opendir(ttypath);
					if (!ttydir)
						continue;

					while ((de3 = readdir(ttydir)) != NULL) {
						if (strncmp(de3->d_name, "ttyUSB", 6) == 0 ||
						    strncmp(de3->d_name, "ttyACM", 6) == 0) {
							snprintf(port_path,
								 sizeof(port_path),
								 "/dev/%s",
								 de3->d_name);
							break;
						}
					}
					closedir(ttydir);
					if (port_path[0])
						break;
				}
			}
			closedir(infdir);

			if (port_path[0] && port_count < 32) {
				snprintf(ports[port_count].path,
					 sizeof(ports[port_count].path),
					 "%s", port_path);
				ports[port_count].vid = vid;
				ports[port_count].pid = pid;
				ports[port_count].iface = iface_num;
				ports[port_count].is_at =
					probe_at_port(port_path);
				port_count++;
			}
		}
	}

	closedir(busdir);

	/* Print AT ports first */
	for (int i = 0; i < port_count; i++) {
		if (ports[i].is_at != 1)
			continue;
		if (!at_header) {
			fprintf(out, "AT devices:\n");
			at_header = 1;
		}
		fprintf(out, "  %-18s  %04x:%04x  iface %d  USB\n",
			ports[i].path, ports[i].vid, ports[i].pid,
			ports[i].iface);
		at_count++;
	}

	/* Then NMEA/other ports */
	for (int i = 0; i < port_count; i++) {
		if (ports[i].is_at != 0)
			continue;
		if (!nmea_header) {
			if (at_count > 0)
				fprintf(out, "\n");
			fprintf(out, "NMEA/other devices:\n");
			nmea_header = 1;
		}
		fprintf(out, "  %-18s  %04x:%04x  iface %d  USB\n",
			ports[i].path, ports[i].vid, ports[i].pid,
			ports[i].iface);
		nmea_count++;
	}

	return at_count + nmea_count;
}

static int list_edl_ports(FILE *out)
{
	char path[64];
	int count = 0;
	int printed_header = 0;
	int i;
	const char *types[] = {"BHI", "DIAG", "EDL"};
	int t;

	for (t = 0; t < 3; t++) {
		for (i = 0; i < 10; i++) {
			if (i == 0)
				snprintf(path, sizeof(path),
					 "/dev/mhi_%s", types[t]);
			else
				snprintf(path, sizeof(path),
					 "/dev/mhi_%s%d", types[t], i);

			if (access(path, F_OK) != 0)
				continue;

			if (!printed_header) {
				fprintf(out, "PCIe MHI devices:\n");
				printed_header = 1;
			}

			fprintf(out, "  %-20s  port %d\n", path, i);
			count++;
		}
	}

	return count;
}

#endif /* _WIN32 / __linux__ */

static void print_list_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s list\n", __progname);
	fprintf(out, "\nList connected EDL, DIAG, AT, and ADB devices.\n");
	fprintf(out, "\nScans USB (libusb) for EDL and ADB devices.\n");
#ifdef _WIN32
	fprintf(out, "Scans Windows COM ports for EDL, DIAG, and AT devices.\n");
#elif defined(__APPLE__)
	fprintf(out, "Queries qcseriald for DIAG and AT ports (macOS).\n");
#else
	fprintf(out, "Scans Linux sysfs/MHI for DIAG, AT, and PCIe devices.\n");
#endif
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s list\n", __progname);
}

static int qdl_list(FILE *out)
{
	int found = 0;
	int prev, n;

	/* EDL devices via libusb (all platforms) */
	n = list_usb_edl(out);
	found += n;

#ifdef _WIN32
	prev = found;
	n = list_com_ports(out);
	if (n > 0 && prev > 0)
		fprintf(out, "\n");
	found += n;
#elif defined(__APPLE__)
#ifdef HAVE_QCSERIALD
	prev = found;
	n = qcseriald_list_ports(out);
	if (n > 0 && prev > 0)
		fprintf(out, "\n");
	found += n;
#endif
#else /* Linux */
	prev = found;
	n = list_edl_ports(out);
	if (n > 0 && prev > 0)
		fprintf(out, "\n");
	found += n;

	prev = found;
	n = list_diag_ports(out);
	if (n > 0 && prev > 0)
		fprintf(out, "\n");
	found += n;

	prev = found;
	n = list_at_ports(out);
	if (n > 0 && prev > 0)
		fprintf(out, "\n");
	found += n;
#endif

	/* ADB devices via libusb (all platforms) */
	prev = found;
	n = list_usb_adb(out);
	if (n > 0 && prev > 0)
		fprintf(out, "\n");
	found += n;

	if (!found)
		fprintf(out, "No devices found\n");

	return found ? 0 : 1;
}

static void print_ramdump_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s ramdump [options] [filter]\n", __progname);
	fprintf(out, "\nExtract RAM dumps from a device via Sahara protocol.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -o, --output=DIR      Output directory for dumps (default: .)\n");
	fprintf(out, "  -S, --serial=T        Target by serial number or COM port name\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -v, --version         Print version and exit\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nIf [filter] is given, only dump regions matching the filter.\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s ramdump -o dumps/\n", __progname);
	fprintf(out, "  %s ramdump -o dumps/ CODERAM\n", __progname);
}

static int qdl_ramdump(int argc, char **argv)
{
	struct qdl_device *qdl;
	char *ramdump_path = ".";
	char *filter = NULL;
	char *serial = NULL;
	int ret = 0;
	int opt;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"output", required_argument, 0, 'o'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvo:S:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'o':
			ramdump_path = optarg;
			break;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_ramdump_help(stdout);
			return 0;
		default:
			print_ramdump_help(stderr);
			return 1;
		}
	}

	if (optind < argc)
		filter = argv[optind++];

	if (optind != argc) {
		print_ramdump_help(stderr);
		return 1;
	}

	ux_init();

	qdl = qdl_init(QDL_DEVICE_USB);
	if (!qdl)
		return 1;

	if (qdl_debug)
		print_version();

	ret = qdl_open(qdl, serial);
#ifdef _WIN32
	if (ret == -2) {
		qdl_deinit(qdl);
		qdl = qdl_init(QDL_DEVICE_PCIE);
		if (!qdl)
			return 1;
		ret = qdl_open(qdl, serial);
	}
#endif
	if (ret) {
		ret = 1;
		goto out_cleanup;
	}

	ret = sahara_run_with_retry(qdl, NULL, ramdump_path, filter, serial);
	if (ret < 0) {
		ret = 1;
		goto out_cleanup;
	}

out_cleanup:
	qdl_close(qdl);
	qdl_deinit(qdl);

	return ret;
}

static int ks_read(struct qdl_device *qdl, void *buf, size_t len,
		   unsigned int timeout __unused)
{
	return read(qdl->fd, buf, len);
}

static int ks_write(struct qdl_device *qdl, const void *buf, size_t len,
		    unsigned int timeout __unused)
{
	return write(qdl->fd, buf, len);
}

static void print_ks_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s ks -p <device_node> -s <id:filepath> [...] [options]\n", __progname);
	fprintf(out, "\nKeystore/Sahara utility for serial device nodes.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -p, --port=NODE       Sahara device node (required)\n");
	fprintf(out, "  -s, --sahara=ID:FILE  File mapping for Sahara protocol (one or more)\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nOne -p instance is required.  One or more -s instances are required.\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s ks -p /dev/mhi0_QAIC_SAHARA -s 1:fw1.bin -s 2:fw2.bin\n", __progname);
}

static int qdl_ks(int argc, char **argv)
{
	struct sahara_image mappings[MAPPING_SZ] = {};
	struct qdl_device qdl = {};
	const char *filename;
	bool found_mapping = false;
	char *dev_node = NULL;
	long file_id;
	char *colon;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"version", no_argument, 0, 'v'},
		{"port", required_argument, 0, 'p'},
		{"sahara", required_argument, 0, 's'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvp:s:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'p':
			dev_node = optarg;
			printf("Using port - %s\n", dev_node);
			break;
		case 's':
			found_mapping = true;
			file_id = strtol(optarg, NULL, 10);
			if (file_id < 0) {
				print_ks_help(stderr);
				return 1;
			}
			if (file_id >= MAPPING_SZ) {
				fprintf(stderr,
					"ID:%ld exceeds the max value of %d\n",
					file_id,
					MAPPING_SZ - 1);
				return 1;
			}
			colon = strchr(optarg, ':');
			if (!colon) {
				print_ks_help(stderr);
				return 1;
			}
			filename = &optarg[colon - optarg + 1];
			ret = load_sahara_image(filename, &mappings[file_id]);
			if (ret < 0)
				return 1;

			printf("Created mapping ID:%ld File:%s\n",
			       file_id, filename);
			break;
		case 'h':
			print_ks_help(stdout);
			return 0;
		default:
			print_ks_help(stderr);
			return 1;
		}
	}

	if (!dev_node || !found_mapping) {
		print_ks_help(stderr);
		return 1;
	}

	if (qdl_debug)
		print_version();

	qdl.fd = open(dev_node, O_RDWR);
	if (qdl.fd < 0) {
		fprintf(stderr, "Unable to open %s\n", dev_node);
		return 1;
	}

	qdl.read = ks_read;
	qdl.write = ks_write;

	ret = sahara_run(&qdl, mappings, NULL, NULL);
	if (ret < 0)
		return 1;

	close(qdl.fd);

	return 0;
}

static void print_diag2edl_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s diag2edl [options]\n", __progname);
	fprintf(out, "\nSwitch a device from DIAG mode to EDL mode.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s diag2edl\n", __progname);
	fprintf(out, "  %s diag2edl -S /dev/ttyUSB0\n", __progname);
}

static int qdl_diag2edl(int argc, char **argv)
{
	char *serial = NULL;
	int opt;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_diag2edl_help(stdout);
			return 0;
		default:
			print_diag2edl_help(stderr);
			return 1;
		}
	}

	if (qdl_debug)
		print_version();

#ifdef __APPLE__
	if (!diag_is_device_in_diag_mode(serial)) {
		fprintf(stderr, "No device found in DIAG mode\n");
		return 1;
	}
#else
	{
		int printed = 0;
		time_t start = time(NULL);

		while (!diag_is_device_in_diag_mode(serial)) {
			int elapsed = (int)(time(NULL) - start);

			if (!printed)
				printed = 1;
			fprintf(stderr, "\rWaiting for DIAG port... "
				"(Ctrl+C to abort) [%ds]", elapsed);
			fflush(stderr);
			usleep(1000000);
		}
		if (printed)
			fprintf(stderr, "\n");
	}
#endif

	printf("Device in DIAG mode, switching to EDL...\n");
	if (diag_switch_to_edl(serial) < 0) {
		fprintf(stderr, "Failed to switch device to EDL mode\n");
		return 1;
	}

	printf("EDL switch command sent successfully\n");
	return 0;
}

/*
 * Wrapper around sahara_run() that retries with a COM port close/reopen
 * cycle when the initial handshake fails.
 *
 * On Windows COM port transport, the device's Sahara HELLO is often
 * sent before the port is opened and is lost.  The in-protocol reset
 * retries don't always recover because the PBL may ignore resets
 * after its initial HELLO times out.  Closing and reopening the port
 * (which re-asserts DTR) reliably triggers the PBL to re-send HELLO.
 */
static int sahara_run_with_retry(struct qdl_device *qdl,
				 const struct sahara_image *images,
				 const char *ramdump_path,
				 const char *ramdump_filter,
				 const char *serial)
{
	int attempts = 3;
	int ret;
	int i;

	for (i = 0; i < attempts; i++) {
		ret = sahara_run(qdl, images, ramdump_path, ramdump_filter);
		if (ret >= 0)
			return ret;

		if (i + 1 >= attempts)
			break;

		ux_info("retrying Sahara handshake (%d/%d)...\n",
			i + 2, attempts);
		qdl_close(qdl);
#ifdef _WIN32
		Sleep(500);
#else
		usleep(500000);
#endif
		ret = qdl_open(qdl, serial);
		if (ret)
			return -1;
	}

	return ret;
}

/*
 * Common Firehose session setup for interactive subcommands.
 * Opens device, uploads programmer via Sahara (USB) or BHI (PCIe),
 * configures Firehose.
 */
static int firehose_session_open(struct qdl_device **qdl_out, char *programmer,
				 enum qdl_storage_type storage,
				 const char *serial, bool use_pcie)
{
	struct sahara_image sahara_images[MAPPING_SZ] = {};
	struct qdl_device *qdl;
	int ret;

	ret = decode_programmer(programmer, sahara_images);
	if (ret < 0)
		return -1;

	/* Auto-detect PCIe if no transport explicitly chosen */
	if (!use_pcie && pcie_has_device()) {
		ux_info("PCIe MHI modem detected, using PCIe transport\n");
		use_pcie = true;
	}

	qdl = qdl_init(use_pcie ? QDL_DEVICE_PCIE : QDL_DEVICE_USB);
	if (!qdl)
		return -1;

	ux_init();

	if (qdl_debug)
		print_version();

	if (use_pcie) {
		/*
		 * PCIe: DIAG→EDL switch + programmer upload.
		 * Returns 0 if programmer uploaded via BHI (Linux),
		 * 1 if Sahara still needed (Windows), negative on error.
		 */
		int need_sahara;

		need_sahara = pcie_prepare(qdl, sahara_images[SAHARA_ID_EHOSTDL_IMG].name);
		if (need_sahara < 0) {
			qdl_deinit(qdl);
			return -1;
		}

		ret = qdl_open(qdl, serial);
		if (ret) {
			qdl_deinit(qdl);
			return -1;
		}

		if (need_sahara) {
			qdl->storage_type = storage;
			ret = sahara_run_with_retry(qdl, sahara_images,
						    NULL, NULL, serial);
			if (ret < 0) {
				qdl_close(qdl);
				qdl_deinit(qdl);
				return -1;
			}
		}
	} else {
		/* USB: standard Sahara handshake */
		ret = qdl_open(qdl, serial);
#ifdef _WIN32
		if (ret == -2) {
			/*
			 * USB driver not WinUSB-compatible (e.g. QDLoader).
			 * Fall back to COM port transport — the QDLoader
			 * driver exposes the same Sahara/Firehose protocol
			 * over a serial port.
			 */
			qdl_deinit(qdl);
			qdl = qdl_init(QDL_DEVICE_PCIE);
			if (!qdl)
				return -1;
			ret = qdl_open(qdl, serial);
		}
#endif
		if (ret) {
			qdl_deinit(qdl);
			return -1;
		}

		qdl->storage_type = storage;

		ret = sahara_run_with_retry(qdl, sahara_images,
					    NULL, NULL, serial);
		if (ret < 0) {
			qdl_close(qdl);
			qdl_deinit(qdl);
			return -1;
		}
	}

	qdl->storage_type = storage;

	ux_info("waiting for programmer...\n");
	ret = firehose_detect_and_configure(qdl, true, storage, 5);
	if (ret) {
		qdl_close(qdl);
		qdl_deinit(qdl);
		return -1;
	}

	*qdl_out = qdl;
	return 0;
}

static void firehose_session_close(struct qdl_device *qdl, bool do_reset)
{
	if (do_reset)
		firehose_power(qdl, "reset", 1);
	qdl_close(qdl);
	qdl_deinit(qdl);
}

static void print_printgpt_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s printgpt [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nPrint GPT or NAND partition tables from a live device.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  --make-xml=read       Generate rawread XML from partition table\n");
	fprintf(out, "  --make-xml=program    Generate rawprogram XML from partition table\n");
	fprintf(out, "  -o, --output=DIR      Output directory for generated XMLs (default: .)\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s printgpt\n", __progname);
	fprintf(out, "  %s printgpt -L /path/to/loader/\n", __progname);
	fprintf(out, "  %s printgpt --make-xml=read --make-xml=program -o xmls/\n", __progname);
}

static int qdl_printgpt(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	const char *outdir = ".";
	bool make_read = false;
	bool make_program = false;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"make-xml", required_argument, 0, 'X'},
		{"output", required_argument, 0, 'o'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:X:o:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'X':
			if (strcmp(optarg, "read") == 0)
				make_read = true;
			else if (strcmp(optarg, "program") == 0)
				make_program = true;
			else {
				fprintf(stderr, "Error: --make-xml must be 'read' or 'program'\n");
				return 1;
			}
			break;
		case 'o':
			outdir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_printgpt_help(stdout);
			return 0;
		default:
			print_printgpt_help(stderr);
			return 1;
		}
	}

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ret = gpt_print_table(qdl);

	if (!ret && (make_read || make_program))
		ret = gpt_make_xml(qdl, outdir, make_read, make_program);

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static void print_storageinfo_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s storageinfo [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nQuery storage hardware information from the device.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s storageinfo\n", __progname);
	fprintf(out, "  %s storageinfo -L /path/to/loader/\n", __progname);
}

static int qdl_storageinfo(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct storage_info info;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_storageinfo_help(stdout);
			return 0;
		default:
			print_storageinfo_help(stderr);
			return 1;
		}
	}

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ret = firehose_getstorageinfo(qdl, 0, &info);
	if (ret == 0) {
		printf("Storage Information:\n");
		if (info.mem_type[0])
			printf("  Memory type:    %s\n", info.mem_type);
		if (info.prod_name[0])
			printf("  Product name:   %s\n", info.prod_name);
		if (info.total_blocks)
			printf("  Total blocks:   %lu\n", info.total_blocks);
		if (info.block_size)
			printf("  Block size:     %u\n", info.block_size);
		if (info.page_size)
			printf("  Page size:      %u\n", info.page_size);
		if (info.sector_size)
			printf("  Sector size:    %u\n", info.sector_size);
		if (info.num_physical)
			printf("  Physical parts: %u\n", info.num_physical);
	} else {
		ux_err("failed to get storage info\n");
	}

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static void print_partinfo_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s partinfo [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nQuery storage info and partition table in a single session.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s partinfo\n", __progname);
	fprintf(out, "  %s partinfo -L /path/to/firmware/\n", __progname);
}

static int qdl_partinfo(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct storage_info info;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_partinfo_help(stdout);
			return 0;
		default:
			print_partinfo_help(stderr);
			return 1;
		}
	}

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	/* Storage info */
	ret = firehose_getstorageinfo(qdl, 0, &info);
	if (ret == 0) {
		printf("Storage Information:\n");
		if (info.mem_type[0])
			printf("  Memory type:    %s\n", info.mem_type);
		if (info.prod_name[0])
			printf("  Product name:   %s\n", info.prod_name);
		if (info.total_blocks)
			printf("  Total blocks:   %lu\n", info.total_blocks);
		if (info.block_size)
			printf("  Block size:     %u\n", info.block_size);
		if (info.page_size)
			printf("  Page size:      %u\n", info.page_size);
		if (info.sector_size)
			printf("  Sector size:    %u\n", info.sector_size);
		if (info.num_physical)
			printf("  Physical parts: %u\n", info.num_physical);
	} else {
		ux_warn("failed to get storage info (continuing with partition table)\n");
		ret = 0; /* Don't fail — still try partition table */
	}

	printf("\n");

	/* Partition table */
	if (gpt_print_table(qdl))
		ret = -1;

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static void print_reset_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s reset [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nReset, power-off, or EDL-reboot a device in EDL mode.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -m, --mode=MODE       reset|off|edl (default: reset)\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s reset\n", __progname);
	fprintf(out, "  %s reset --mode=off\n", __progname);
	fprintf(out, "  %s reset --mode=edl\n", __progname);
}

static int qdl_reset(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	const char *mode = "reset";
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"mode", required_argument, 0, 'm'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:m:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'm':
			mode = optarg;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_reset_help(stdout);
			return 0;
		default:
			print_reset_help(stderr);
			return 1;
		}
	}

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ux_info("sending power command: %s\n", mode);
	ret = firehose_power(qdl, mode, 1);

	qdl_close(qdl);
	qdl_deinit(qdl);
	free(programmer);
	return !!ret;
}

static void print_getslot_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s getslot [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nShow the active A/B slot on the device.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s getslot\n", __progname);
}

static int qdl_getslot(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	int opt;
	int ret;
	int slot;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_getslot_help(stdout);
			return 0;
		default:
			print_getslot_help(stderr);
			return 1;
		}
	}

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	slot = gpt_get_active_slot(qdl);
	if (slot > 0)
		printf("Active slot: %c\n", slot);
	else
		ux_err("failed to determine active slot\n");

	firehose_session_close(qdl, true);
	free(programmer);
	return slot > 0 ? 0 : 1;
}

static void print_setslot_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s setslot <a|b> [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nSet the active A/B slot on the device.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s setslot a\n", __progname);
	fprintf(out, "  %s setslot b\n", __progname);
}

static int qdl_setslot(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	char slot;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_setslot_help(stdout);
			return 0;
		default:
			print_setslot_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: slot (a or b) required\n");
		return 1;
	}

	slot = argv[optind][0];
	if (slot != 'a' && slot != 'b') {
		fprintf(stderr, "Error: slot must be 'a' or 'b'\n");
		return 1;
	}
	optind++;

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ret = gpt_set_active_slot(qdl, slot);
	if (ret == 0)
		printf("Active slot set to: %c\n", slot);

	firehose_session_close(qdl, ret == 0);
	free(programmer);
	return !!ret;
}

static void print_read_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s read <label> [label2 ...] [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nRead partitions by label from a device in EDL mode.\n");
	fprintf(out, "\nWith one label, -o is an output file path.\n");
	fprintf(out, "With multiple labels, -o is a directory (auto-named files).\n");
	fprintf(out, "If -o is omitted, output to the loader directory (or current directory).\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -o, --output=PATH     Output file or directory\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s read modem -o modem.bin\n", __progname);
	fprintf(out, "  %s read sbl1 tz modem -o backup/\n", __progname);
	fprintf(out, "  %s read system\n", __progname);
}

static int qdl_read_partition(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	const char *output = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	char auto_path[4096];
	const char **labels;
	int nlabels;
	int opt;
	int ret;
	int i;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"output", required_argument, 0, 'o'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:o:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'o':
			output = optarg;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_read_help(stdout);
			return 0;
		default:
			print_read_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: partition label required\n");
		return 1;
	}

	/* Collect labels — all positional args before programmer */
	labels = (const char **)&argv[optind];

	if (!loader_dir && (optind >= argc || argc - optind < 2)) {
		/* No -L and not enough args for label+programmer — default to cwd */
		loader_dir = ".";
	}

	if (loader_dir) {
		/* All remaining positional args are labels */
		nlabels = argc - optind;

		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	} else {
		/*
		 * Last positional arg is the programmer, rest are labels.
		 * Need at least 2 args: one label + one programmer.
		 */
		nlabels = argc - optind - 1;
	}

	if (nlabels < 1) {
		fprintf(stderr, "Error: at least one partition label is required\n");
		return 1;
	}

	/* Open firehose session */
	ret = firehose_session_open(&qdl,
				    programmer ? programmer : argv[optind + nlabels],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	if (nlabels == 1 && output) {
		/* Single label with explicit output file */
		ret = gpt_read_partition(qdl, labels[0], output);
	} else if (nlabels == 1) {
		/* Single label, auto-generate filename */
		const char *dir = loader_dir ? loader_dir : ".";

		snprintf(auto_path, sizeof(auto_path), "%s/%s.bin",
			 dir, labels[0]);
		ret = gpt_read_partition(qdl, labels[0], auto_path);
	} else {
		/* Multiple labels — output is a directory */
		const char *outdir = output ? output : (loader_dir ? loader_dir : ".");

#ifdef _WIN32
		mkdir(outdir);
#else
		mkdir(outdir, 0755);
#endif
		ret = 0;
		for (i = 0; i < nlabels; i++) {
			if (gpt_read_partition_to_dir(qdl, labels[i], outdir))
				ret = -1;
		}
	}

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static void print_readall_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s readall [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nDump all partitions to individual files.\n");
	fprintf(out, "Also generates a rawprogram XML file in the output directory.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -o, --output=DIR        Output directory (default: .)\n");
	fprintf(out, "      --single-file=FILE  Dump entire storage as one file\n");
	fprintf(out, "  -s, --storage=T         Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S          Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR   Find programmer in directory\n");
	fprintf(out, "  -P, --pcie              Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug             Print detailed debug info\n");
	fprintf(out, "  -h, --help              Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s readall -o backup/\n", __progname);
	fprintf(out, "  %s readall --single-file=full_dump.bin\n", __progname);
}

static int qdl_readall(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	const char *outdir = ".";
	const char *single_file = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"output", required_argument, 0, 'o'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"single-file", required_argument, 0, 'F'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:o:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'o':
			outdir = optarg;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'F':
			single_file = optarg;
			break;
		case 'h':
			print_readall_help(stdout);
			return 0;
		default:
			print_readall_help(stderr);
			return 1;
		}
	}

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	if (single_file) {
		ret = gpt_read_full_storage(qdl, single_file);
	} else {
		ret = gpt_read_all_partitions(qdl, outdir);
		if (!ret)
			gpt_make_xml(qdl, outdir, false, true);
	}

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static void print_nvread_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s nvread <item_id> [options]\n", __progname);
	fprintf(out, "\nRead an NV item from the device via DIAG protocol.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -I, --index=N         Subscription index for indexed NV items\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nThe <item_id> can be decimal or hex (0x prefix).\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s nvread 550\n", __progname);
	fprintf(out, "  %s nvread 0x226\n", __progname);
	fprintf(out, "  %s nvread 550 --index=1\n", __progname);
}

static int qdl_nvread(int argc, char **argv)
{
	struct diag_session *sess;
	struct nv_item nv;
	char *serial = NULL;
	int opt;
	int ret;
	uint16_t item_id;
	int index = -1;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"index", required_argument, 0, 'I'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:I:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'I':
			index = (int)strtol(optarg, NULL, 0);
			break;
		case 'h':
			print_nvread_help(stdout);
			return 0;
		default:
			print_nvread_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: NV item ID required\n");
		return 1;
	}

	item_id = (uint16_t)strtoul(argv[optind], NULL, 0);

	sess = diag_open(serial);
	if (!sess)
		return 1;

	if (index >= 0) {
		ret = diag_nv_read_sub(sess, item_id, (uint16_t)index, &nv);
	} else {
		ret = diag_nv_read(sess, item_id, &nv);
	}

	if (ret == 0) {
		if (nv.status != NV_DONE_S) {
			printf("NV item %u: %s (status=%u)\n",
			       item_id, diag_nv_status_str(nv.status),
			       nv.status);
		} else {
			printf("NV item %u:\n", item_id);
			print_hex_dump("  ", nv.data, NV_ITEM_DATA_SIZE);
		}
	}

	diag_close(sess);
	return !!ret;
}

static void print_nvwrite_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s nvwrite <item_id> <hex_data> [options]\n", __progname);
	fprintf(out, "\nWrite an NV item to the device via DIAG protocol.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -I, --index=N         Subscription index for indexed NV items\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nThe <hex_data> is a hex string (e.g. 01020304). Remaining bytes\n");
	fprintf(out, "are zero-padded to 128 bytes.\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s nvwrite 550 0102030405060708\n", __progname);
	fprintf(out, "  %s nvwrite 0x226 FF --index=1\n", __progname);
}

static int qdl_nvwrite(int argc, char **argv)
{
	struct diag_session *sess;
	uint8_t data[NV_ITEM_DATA_SIZE];
	char *serial = NULL;
	int opt;
	int ret;
	uint16_t item_id;
	int index = -1;
	size_t data_len = 0;
	const char *hex;
	size_t i;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"index", required_argument, 0, 'I'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:I:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'I':
			index = (int)strtol(optarg, NULL, 0);
			break;
		case 'h':
			print_nvwrite_help(stdout);
			return 0;
		default:
			print_nvwrite_help(stderr);
			return 1;
		}
	}

	if (optind + 1 >= argc) {
		fprintf(stderr, "Error: NV item ID and hex data required\n");
		return 1;
	}

	item_id = (uint16_t)strtoul(argv[optind], NULL, 0);

	/* Parse hex string to bytes */
	hex = argv[optind + 1];
	memset(data, 0, sizeof(data));
	for (i = 0; hex[i] && hex[i + 1] && data_len < NV_ITEM_DATA_SIZE; i += 2) {
		unsigned int byte;

		if (sscanf(&hex[i], "%2x", &byte) != 1) {
			fprintf(stderr, "Error: invalid hex data at position %zu\n", i);
			return 1;
		}
		data[data_len++] = (uint8_t)byte;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	if (index >= 0)
		ret = diag_nv_write_sub(sess, item_id, (uint16_t)index,
					data, data_len);
	else
		ret = diag_nv_write(sess, item_id, data, data_len);

	if (ret == 0) {
		printf("NV item %u written successfully\n", item_id);
		printf("Reboot modem for changes to take effect\n");
	} else if (ret > 0) {
		fprintf(stderr, "NV item %u: %s\n", item_id,
			diag_nv_status_str((uint16_t)ret));
	} else {
		fprintf(stderr, "NV item %u: protocol error\n", item_id);
	}

	diag_close(sess);
	return (ret != 0) ? 1 : 0;
}

static void efsls_print_entry(const struct efs_dirent *entry, void *ctx)
{
	const char *type_str;

	(void)ctx;

	if (entry->mode & 0040000)
		type_str = "dir";
	else if ((entry->mode & 0170000) == EFS_S_IFITM)
		type_str = "item";
	else if (entry->entry_type == 2)
		type_str = "link";
	else
		type_str = "file";

	printf("%-4s %8d  %04o  %s\n",
	       type_str, entry->size, entry->mode & 0777, entry->name);
}

static void print_efsls_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsls <path> [options]\n", __progname);
	fprintf(out, "\nList contents of an EFS directory.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsls /\n", __progname);
	fprintf(out, "  %s efsls /nv/item_files/modem/\n", __progname);
}

static int qdl_efsls(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	const char *path;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efsls_help(stdout);
			return 0;
		default:
			print_efsls_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: EFS path required\n");
		return 1;
	}

	path = argv[optind];

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	printf("%-4s %8s  %4s  %s\n", "Type", "Size", "Mode", "Name");
	printf("---- --------  ----  ----\n");

	ret = diag_efs_listdir(sess, path, efsls_print_entry, NULL);

	diag_online(sess);
	diag_close(sess);
	return !!ret;
}

static void print_efspull_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efspull <remote_path> <local_path> [options]\n", __progname);
	fprintf(out, "\nDownload a file from the device EFS filesystem.\n");
	fprintf(out, "\nAlso supports NV item paths (e.g. nv_items/550.bin).\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efspull /nv/item_files/rfnv/00024955 rfnv_24955.bin\n", __progname);
	fprintf(out, "  %s efspull nv_items/550.bin nv550.bin\n", __progname);
}

static int qdl_efspull(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	const char *src;
	const char *dst;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efspull_help(stdout);
			return 0;
		default:
			print_efspull_help(stderr);
			return 1;
		}
	}

	if (optind + 1 >= argc) {
		fprintf(stderr, "Error: remote path and local path required\n");
		return 1;
	}

	src = argv[optind];
	dst = argv[optind + 1];

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	{
		const char *nv_str = NULL;
		uint32_t nv_id;

		/* Detect nv_items/NNNNN.bin paths from TAR extraction */
		if (strncmp(src, "nv_items/", 9) == 0)
			nv_str = src + 9;
		else if (strncmp(src, "/nv_items/", 10) == 0)
			nv_str = src + 10;

		if (nv_str && sscanf(nv_str, "%u", &nv_id) == 1) {
			struct nv_item nv;
			int local_fd;

			ret = diag_nv_read(sess, (uint16_t)nv_id, &nv);
			if (ret != 0) {
				fprintf(stderr, "NV %u read: %s\n", nv_id,
					nv.status ?
					diag_nv_status_str(nv.status) :
					"failed");
				diag_online(sess);
				diag_close(sess);
				return 1;
			}

			local_fd = open(dst,
					O_WRONLY | O_CREAT | O_TRUNC |
					O_BINARY, 0644);
			if (local_fd < 0) {
				fprintf(stderr, "Error: cannot create %s: %s\n",
					dst, strerror(errno));
				diag_online(sess);
				diag_close(sess);
				return 1;
			}
			if (write(local_fd, nv.data, NV_ITEM_DATA_SIZE) !=
			    NV_ITEM_DATA_SIZE)
				fprintf(stderr, "warning: write to %s truncated\n",
					dst);
			close(local_fd);
			printf("NV item %u saved to %s (128 bytes)\n",
			       nv_id, dst);
			diag_online(sess);
			diag_close(sess);
			return 0;
		}
	}

	ret = diag_efs_readfile(sess, src, dst);

	diag_online(sess);
	diag_close(sess);
	return !!ret;
}

static void print_efsdump_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsdump <output_file> [options]\n", __progname);
	fprintf(out, "\nDump the EFS factory image via modem FS_IMAGE opcodes.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsdump efs_image.bin\n", __progname);
}

static int qdl_efsdump(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	const char *output;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efsdump_help(stdout);
			return 0;
		default:
			print_efsdump_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: output file required\n");
		return 1;
	}

	output = argv[optind];

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);
	ret = diag_efs_dump(sess, output);

	diag_online(sess);
	diag_close(sess);
	return !!ret;
}

static void print_efspush_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efspush <local_file> <efs_path> [options]\n", __progname);
	fprintf(out, "\nUpload a local file to the device EFS filesystem.\n");
	fprintf(out, "\nAlso supports NV item paths (e.g. nv_items/550.bin).\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efspush local.bin /nv/item_files/rfnv/00024955\n", __progname);
	fprintf(out, "  %s efspush nv550.bin nv_items/550.bin\n", __progname);
}

static int qdl_efspush(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efspush_help(stdout);
			return 0;
		default:
			print_efspush_help(stderr);
			return 1;
		}
	}

	if (optind + 1 >= argc) {
		fprintf(stderr, "Error: requires <local_file> and <efs_path>\n");
		return 1;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	{
		const char *efs_path = argv[optind + 1];
		const char *nv_str = NULL;
		uint32_t nv_id;

		/* Detect nv_items/NNNNN.bin paths from TAR extraction */
		if (strncmp(efs_path, "nv_items/", 9) == 0)
			nv_str = efs_path + 9;
		else if (strncmp(efs_path, "/nv_items/", 10) == 0)
			nv_str = efs_path + 10;

		if (nv_str && sscanf(nv_str, "%u", &nv_id) == 1) {
			uint8_t nv_data[NV_ITEM_DATA_SIZE];
			int local_fd = open(argv[optind],
					    O_RDONLY | O_BINARY);

			if (local_fd < 0) {
				fprintf(stderr, "Error: cannot open %s: %s\n",
					argv[optind], strerror(errno));
				diag_online(sess);
				diag_close(sess);
				return 1;
			}

			memset(nv_data, 0, sizeof(nv_data));
			if (read(local_fd, nv_data, NV_ITEM_DATA_SIZE) <= 0)
				fprintf(stderr, "warning: read from %s failed\n",
					argv[optind]);
			close(local_fd);

			ret = diag_nv_write(sess, (uint16_t)nv_id,
					    nv_data, NV_ITEM_DATA_SIZE);
			if (ret == 0) {
				printf("NV item %u written successfully\n",
				       nv_id);
				printf("Reboot modem for changes to take effect\n");
			} else if (ret > 0) {
				fprintf(stderr, "NV %u write: %s\n",
					nv_id,
					diag_nv_status_str((uint16_t)ret));
			} else {
				fprintf(stderr, "NV %u write failed\n", nv_id);
			}

			diag_online(sess);
			diag_close(sess);
			return ret != 0;
		}
	}

	ret = diag_efs_put(sess, argv[optind], argv[optind + 1]);
	if (ret == 0)
		printf("Reboot modem for changes to take effect\n");

	diag_online(sess);
	diag_close(sess);
	return !!ret;
}

static void print_efsrm_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsrm [-r] <path> [path2 ...] [options]\n", __progname);
	fprintf(out, "\nDelete file(s) or directories from EFS.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -r, --recursive       Recursively remove directories\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsrm /policyman/net_policy_info.xml\n", __progname);
	fprintf(out, "  %s efsrm -r /nv/item_files/ims/\n", __progname);
}

static int qdl_efsrm(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	bool recursive = false;
	int opt;
	int ret;
	int i;
	int failed = 0;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"recursive", no_argument, 0, 'r'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:rh", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'r':
			recursive = true;
			break;
		case 'h':
			print_efsrm_help(stdout);
			return 0;
		default:
			print_efsrm_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: no path(s) specified\n");
		return 1;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	for (i = optind; i < argc; i++) {
		ret = diag_efs_rm(sess, argv[i], recursive);
		if (ret)
			failed++;
	}

	if (failed < (argc - optind))
		printf("Reboot modem for changes to take effect\n");

	diag_online(sess);
	diag_close(sess);
	return !!failed;
}

static const char *mode_string(int32_t mode)
{
	static char buf[11];

	buf[0] = S_ISDIR(mode) ? 'd' :
		S_ISLNK(mode) ? 'l' :
		(mode & 0170000) == EFS_S_IFITM ? 'i' : '-';
	buf[1] = (mode & 0400) ? 'r' : '-';
	buf[2] = (mode & 0200) ? 'w' : '-';
	buf[3] = (mode & 0100) ? 'x' : '-';
	buf[4] = (mode & 040) ? 'r' : '-';
	buf[5] = (mode & 020) ? 'w' : '-';
	buf[6] = (mode & 010) ? 'x' : '-';
	buf[7] = (mode & 04) ? 'r' : '-';
	buf[8] = (mode & 02) ? 'w' : '-';
	buf[9] = (mode & 01) ? 'x' : '-';
	buf[10] = '\0';

	return buf;
}

static void print_efsstat_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsstat <path> [path2 ...] [options]\n", __progname);
	fprintf(out, "\nShow file/directory information from EFS.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsstat /nv/item_files/rfnv/00024955\n", __progname);
	fprintf(out, "  %s efsstat /policyman/ /nv/\n", __progname);
}

static int qdl_efsstat(int argc, char **argv)
{
	struct diag_session *sess;
	struct efs_stat st;
	char *serial = NULL;
	int opt;
	int ret;
	int i;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efsstat_help(stdout);
			return 0;
		default:
			print_efsstat_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: no path(s) specified\n");
		return 1;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	for (i = optind; i < argc; i++) {
		ret = diag_efs_stat_path(sess, argv[i], &st);
		if (ret) {
			ux_err("cannot stat '%s'\n", argv[i]);
			continue;
		}

		printf("  File: %s\n", argv[i]);
		printf("  Size: %-12d  Links: %d\n", st.size, st.nlink);
		printf("  Mode: %s (0%o)\n", mode_string(st.mode),
		       st.mode & 07777);
		printf("  Type: %s\n",
		       S_ISDIR(st.mode) ? "directory" :
		       S_ISLNK(st.mode) ? "symlink" :
		       (st.mode & 0170000) == EFS_S_IFITM ? "item file" :
		       S_ISREG(st.mode) ? "regular file" : "other");
		printf(" Atime: %d\n", st.atime);
		printf(" Mtime: %d\n", st.mtime);
		printf(" Ctime: %d\n", st.ctime);

		if (i + 1 < argc)
			printf("\n");
	}

	diag_online(sess);
	diag_close(sess);
	return 0;
}

static void print_efsmkdir_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsmkdir [-m mode] <path> [path2 ...] [options]\n", __progname);
	fprintf(out, "\nCreate directories on the EFS filesystem.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -m, --mode=MODE       Octal permission mode (default: 0755)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsmkdir /my_data/\n", __progname);
	fprintf(out, "  %s efsmkdir -m 0700 /my_data/private/\n", __progname);
}

static int qdl_efsmkdir(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	int16_t mode = 0755;
	int opt;
	int ret;
	int i;
	int failed = 0;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"mode", required_argument, 0, 'm'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:m:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'm':
			mode = (int16_t)strtol(optarg, NULL, 8);
			break;
		case 'h':
			print_efsmkdir_help(stdout);
			return 0;
		default:
			print_efsmkdir_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: no path(s) specified\n");
		return 1;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	for (i = optind; i < argc; i++) {
		ret = diag_efs_mkdir_path(sess, argv[i], mode);
		if (ret) {
			ux_err("failed to create '%s'\n", argv[i]);
			failed++;
		} else {
			ux_info("created directory '%s'\n", argv[i]);
		}
	}

	diag_online(sess);
	diag_close(sess);
	return !!failed;
}

static void print_efschmod_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efschmod <mode> <path> [path2 ...] [options]\n", __progname);
	fprintf(out, "\nChange EFS file/directory permissions.\n");
	fprintf(out, "\n  <mode> is an octal permission value (e.g. 0644, 0755).\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efschmod 0644 /nv/item_files/rfnv/00024955\n", __progname);
	fprintf(out, "  %s efschmod 0755 /policyman/\n", __progname);
}

static int qdl_efschmod(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	int16_t mode;
	int opt;
	int ret;
	int i;
	int failed = 0;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efschmod_help(stdout);
			return 0;
		default:
			print_efschmod_help(stderr);
			return 1;
		}
	}

	if (optind + 1 >= argc) {
		fprintf(stderr, "Error: requires <mode> and <path>\n");
		return 1;
	}

	mode = (int16_t)strtol(argv[optind], NULL, 8);

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	for (i = optind + 1; i < argc; i++) {
		ret = diag_efs_chmod_path(sess, argv[i], mode);
		if (ret) {
			ux_err("failed to chmod '%s'\n", argv[i]);
			failed++;
		} else {
			ux_info("chmod 0%o '%s'\n", mode & 07777, argv[i]);
		}
	}

	diag_online(sess);
	diag_close(sess);
	return !!failed;
}

static void print_efsln_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsln <target> <linkpath> [options]\n", __progname);
	fprintf(out, "\nCreate a symlink on the EFS filesystem.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsln /nv/item_files/data /data_link\n", __progname);
}

static int qdl_efsln(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efsln_help(stdout);
			return 0;
		default:
			print_efsln_help(stderr);
			return 1;
		}
	}

	if (optind + 1 >= argc) {
		fprintf(stderr, "Error: requires <target> and <linkpath>\n");
		return 1;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);
	ret = diag_efs_ln(sess, argv[optind], argv[optind + 1]);
	if (ret == 0)
		ux_info("symlink '%s' -> '%s'\n",
			argv[optind + 1], argv[optind]);

	diag_online(sess);
	diag_close(sess);
	return !!ret;
}

static void print_efsrl_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsrl <path> [path2 ...] [options]\n", __progname);
	fprintf(out, "\nRead symlink target(s) on the EFS filesystem.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsrl /data_link\n", __progname);
}

static int qdl_efsrl(int argc, char **argv)
{
	struct diag_session *sess;
	char buf[256];
	char *serial = NULL;
	int opt;
	int ret;
	int i;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efsrl_help(stdout);
			return 0;
		default:
			print_efsrl_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: no path(s) specified\n");
		return 1;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	for (i = optind; i < argc; i++) {
		ret = diag_efs_readlink_path(sess, argv[i], buf, sizeof(buf));
		if (ret) {
			ux_err("cannot read link '%s'\n", argv[i]);
		} else {
			printf("%s -> %s\n", argv[i], buf);
		}
	}

	diag_online(sess);
	diag_close(sess);
	return 0;
}

static void print_efsbackup_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsbackup [-o FILE] [-t] [--quick] [path] [options]\n", __progname);
	fprintf(out, "\nBackup EFS filesystem to XQCN or TAR format.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -o, --output=FILE     Output file (default: efs_backup.xqcn or .tar)\n");
	fprintf(out, "  -t, --tar            Generate TAR format instead of XQCN\n");
	fprintf(out, "  -q, --quick          Skip probe walk (tree walk only, faster)\n");
	fprintf(out, "  -m, --manual         Force manual tree walk (skip modem TAR generation)\n");
	fprintf(out, "  -S, --serial=S       Target device by serial/port\n");
	fprintf(out, "  -d, --debug          Print detailed debug info\n");
	fprintf(out, "  -h, --help           Print this help\n");
	fprintf(out, "\nDefault XQCN backup includes NV items for QPST-compatible restore.\n");
	fprintf(out, "Use -t for TAR format with probe-based path coverage.\n");
	fprintf(out, "Use --quick for fast tree-walk-only backup (TAR only).\n");
	fprintf(out, "\nIf [path] is given, only that EFS subtree is backed up (default: /).\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsbackup\n", __progname);
	fprintf(out, "  %s efsbackup -o my_backup.xqcn\n", __progname);
	fprintf(out, "  %s efsbackup -t -o backup.tar\n", __progname);
	fprintf(out, "  %s efsbackup -t --quick -o quick.tar\n", __progname);
}

static int qdl_efsbackup(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	const char *output = NULL;
	const char *path = "/";
	bool manual = false;
	bool tar = false;
	bool quick = false;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"output", required_argument, 0, 'o'},
		{"manual", no_argument, 0, 'm'},
		{"tar", no_argument, 0, 't'},
		{"quick", no_argument, 0, 'q'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:o:mtqh", options,
				  NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'o':
			output = optarg;
			break;
		case 'm':
			manual = true;
			break;
		case 't':
			tar = true;
			break;
		case 'q':
			quick = true;
			break;
		case 'h':
			print_efsbackup_help(stdout);
			return 0;
		default:
			print_efsbackup_help(stderr);
			return 1;
		}
	}

	if (optind < argc)
		path = argv[optind];

	if (!output)
		output = tar ? "efs_backup.tar" : "efs_backup.xqcn";

	sess = diag_open(serial);
	if (!sess)
		return 1;

	diag_offline(sess);

	if (tar && manual)
		ret = diag_efs_backup(sess, path, output, true);
	else if (tar)
		ret = diag_efs_backup_enhanced(sess, path, output, quick);
	else
		ret = diag_efs_backup_xqcn(sess, output);

	diag_online(sess);
	diag_close(sess);
	return !!ret;
}

static bool file_starts_with_xml(const char *path)
{
	char buf[8] = {0};
	int fd;
	ssize_t r;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return false;
	r = read(fd, buf, 5);
	close(fd);
	return r == 5 && memcmp(buf, "<?xml", 5) == 0;
}

static void print_efsrestore_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s efsrestore <input.tar|input.xqcn> [options]\n", __progname);
	fprintf(out, "\nRestore EFS filesystem from a TAR archive or XQCN file.\n");
	fprintf(out, "Format is auto-detected from file contents.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -d, --debug           Print detailed debug info (QPST-style per-item status)\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nXQCN restore phases: NV items -> sync -> Provisioning -> EFS_Backup\n");
	fprintf(out, "  -> NV_Items -> device reboot.\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s efsrestore efs_backup.tar\n", __progname);
	fprintf(out, "  %s efsrestore backup.xqcn\n", __progname);
	fprintf(out, "  %s efsrestore backup.xqcn -d\n", __progname);
}

static int qdl_efsrestore(int argc, char **argv)
{
	struct diag_session *sess;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:h", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 'h':
			print_efsrestore_help(stdout);
			return 0;
		default:
			print_efsrestore_help(stderr);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Error: input file required (TAR or XQCN)\n");
		return 1;
	}

	sess = diag_open(serial);
	if (!sess)
		return 1;

	if (file_starts_with_xml(argv[optind])) {
		/* XQCN restore manages offline/sync/reboot internally */
		ret = diag_efs_restore_xqcn(sess, argv[optind]);
	} else {
		diag_offline(sess);
		ret = diag_efs_restore(sess, argv[optind]);
	}

	diag_close(sess);
	return !!ret;
}

/*
 * Parse argv for a [-o <file>] flag pair plus a single positional input
 * argument.  Both subcommands xqcn2tar and tar2xqcn use this shape and
 * previously hit a parser quirk where `-o` was treated as a positional
 * output filename (e.g. `xqcn2tar in.xqcn -o out.tar` wrote to a file
 * literally named "-o" and silently ignored "out.tar").
 *
 * Accepts:
 *   <input>                       (output defaults to *default_output)
 *   <input> <output>              (legacy positional form)
 *   <input> -o <output>           (flag form, matches efsbackup/efsdump)
 *   -o <output> <input>           (flag-first form)
 *
 * On success, *input and *output point into argv (input is required;
 * output falls back to default_output if neither form supplied one).
 * Returns 0 on success, -1 on a parse error (e.g. duplicate -o, -o
 * without a value, multiple positional inputs).
 */
static int parse_in_out(int argc, char **argv, const char *default_output,
			const char **input, const char **output)
{
	const char *in = NULL;
	const char *out = NULL;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) {
			if (out) {
				fprintf(stderr,
					"error: -o specified more than once\n");
				return -1;
			}
			if (i + 1 >= argc) {
				fprintf(stderr,
					"error: -o requires a filename\n");
				return -1;
			}
			out = argv[++i];
		} else if (in) {
			fprintf(stderr,
				"error: unexpected extra positional argument "
				"'%s' (already have input '%s'). If you meant "
				"to set the output file, use -o.\n",
				argv[i], in);
			return -1;
		} else {
			in = argv[i];
		}
	}

	if (!in) {
		fprintf(stderr, "error: missing input filename\n");
		return -1;
	}

	*input = in;
	*output = out ? out : default_output;
	return 0;
}

static void print_xqcn2tar_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s xqcn2tar <input.xqcn> [-o <output.tar>]\n", __progname);
	fprintf(out, "\nConvert XQCN backup to TAR archive (offline, no device needed).\n");
	fprintf(out, "NV items are stored as nv_items/NNNNN.bin in the TAR.\n");
	fprintf(out, "\nIf -o is omitted, output defaults to 'output.tar'.\n");
	fprintf(out, "Legacy positional form `<input> <output>` is also accepted.\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s xqcn2tar backup.xqcn\n", __progname);
	fprintf(out, "  %s xqcn2tar backup.xqcn -o my_backup.tar\n", __progname);
	fprintf(out, "  %s xqcn2tar backup.xqcn my_backup.tar\n", __progname);
}

static int qdl_xqcn2tar(int argc, char **argv)
{
	const char *input;
	const char *output;

	if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0) {
		print_xqcn2tar_help(argc < 2 ? stderr : stdout);
		return argc < 2 ? 1 : 0;
	}

	if (parse_in_out(argc, argv, "output.tar", &input, &output) < 0) {
		print_xqcn2tar_help(stderr);
		return 1;
	}

	return !!diag_xqcn_to_tar(input, output);
}

static void print_tar2xqcn_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s tar2xqcn <input.tar> [-o <output.xqcn>]\n", __progname);
	fprintf(out, "\nConvert TAR archive to XQCN format (offline, no device needed).\n");
	fprintf(out, "TAR entries under nv_items/ are converted to NV_ITEM_ARRAY.\n");
	fprintf(out, "\nIf -o is omitted, output defaults to 'output.xqcn'.\n");
	fprintf(out, "Legacy positional form `<input> <output>` is also accepted.\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s tar2xqcn backup.tar\n", __progname);
	fprintf(out, "  %s tar2xqcn backup.tar -o my_backup.xqcn\n", __progname);
	fprintf(out, "  %s tar2xqcn backup.tar my_backup.xqcn\n", __progname);
}

static int qdl_tar2xqcn(int argc, char **argv)
{
	const char *input;
	const char *output;

	if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
	    strcmp(argv[1], "--help") == 0) {
		print_tar2xqcn_help(argc < 2 ? stderr : stdout);
		return argc < 2 ? 1 : 0;
	}

	if (parse_in_out(argc, argv, "output.xqcn", &input, &output) < 0) {
		print_tar2xqcn_help(stderr);
		return 1;
	}

	return !!diag_tar_to_xqcn(input, output);
}

static void print_erase_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s erase [-L dir | <programmer>] <label> [label2 ...] [options]\n", __progname);
	fprintf(out, "       %s erase [-L dir | <programmer>] --start-sector=N --num-sectors=N [options]\n", __progname);
	fprintf(out, "\nErase partitions by label, or erase raw sectors by address.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -a, --start-sector=N  Start sector for raw erase\n");
	fprintf(out, "  -n, --num-sectors=N   Number of sectors to erase\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s erase modem\n", __progname);
	fprintf(out, "  %s erase sbl1 tz rpm\n", __progname);
	fprintf(out, "  %s erase --start-sector=0 --num-sectors=1024\n", __progname);
}

static int qdl_erase(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	unsigned int start_sector = 0;
	unsigned int num_sectors = 0;
	bool raw_mode = false;
	int opt;
	int ret;
	int i;
	int failed = 0;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"start-sector", required_argument, 0, 'a'},
		{"num-sectors", required_argument, 0, 'n'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:Pa:n:h", options,
				  NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'a':
			start_sector = strtoul(optarg, NULL, 0);
			raw_mode = true;
			break;
		case 'n':
			num_sectors = strtoul(optarg, NULL, 0);
			raw_mode = true;
			break;
		case 'h':
			print_erase_help(stdout);
			return 0;
		default:
			print_erase_help(stderr);
			return 1;
		}
	}

	if (!raw_mode && optind >= argc) {
		fprintf(stderr,
			"Error: specify partition label(s) or"
			" --start-sector + --num-sectors\n");
		return 1;
	}

	if (raw_mode && !num_sectors) {
		fprintf(stderr, "Error: --num-sectors is required"
			" for raw sector erase\n");
		return 1;
	}

	if (!loader_dir && !raw_mode && optind + 1 >= argc) {
		/* Only labels, no programmer — try current dir */
		loader_dir = ".";
	}

	if (!loader_dir && raw_mode && optind >= argc) {
		loader_dir = ".";
	}

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n",
				loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl,
				    programmer ? programmer : argv[optind++],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	if (raw_mode) {
		ux_info("erasing %u sectors starting at sector %u\n",
			num_sectors, start_sector);
		ret = firehose_erase_partition(qdl, 0, start_sector,
					       num_sectors, 0);
		if (ret)
			failed++;
	} else {
		for (i = optind; i < argc; i++) {
			ret = gpt_erase_partition(qdl, argv[i]);
			if (ret)
				failed++;
		}
	}

	firehose_session_close(qdl, true);
	free(programmer);
	return !!failed;
}

static void print_write_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s write <label> <file> [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nErase a partition and write a raw image file to it.\n");
	fprintf(out, "\nArguments:\n");
	fprintf(out, "  <label>               Partition name (e.g. modem, sbl1, tz)\n");
	fprintf(out, "  <file>                Image file to write to the partition\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s write modem modem.bin\n", __progname);
	fprintf(out, "  %s write sbl1 sbl1_new.mbn -L /path/to/firmware/\n", __progname);
}

static int qdl_write_partition(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	const char *label;
	const char *filename;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:Ph", options,
				  NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_write_help(stdout);
			return 0;
		default:
			print_write_help(stderr);
			return 1;
		}
	}

	/*
	 * Positional args: <label> <file> [programmer]
	 * With -L: <label> <file>
	 * Without -L: <label> <file> <programmer>
	 */
	if (optind >= argc || argc - optind < 2) {
		fprintf(stderr, "Error: partition label and image file required\n");
		print_write_help(stderr);
		return 1;
	}

	label = argv[optind];
	filename = argv[optind + 1];

	if (!loader_dir && argc - optind < 3) {
		/* No -L and no programmer arg — try current dir */
		loader_dir = ".";
	}

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n",
				loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl,
				    programmer ? programmer : argv[optind + 2],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ret = gpt_write_partition(qdl, label, filename);

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static void print_eraseall_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s eraseall [-L dir | <programmer>] [options]\n", __progname);
	fprintf(out, "\nErase all partitions on the device.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "  -s, --storage=T       Storage type: emmc|nand|ufs (default: nand)\n");
	fprintf(out, "  -S, --serial=S        Target by serial number or COM port\n");
	fprintf(out, "  -L, --find-loader=DIR Find programmer in directory\n");
	fprintf(out, "  -P, --pcie            Use PCIe/MHI transport\n");
	fprintf(out, "  -d, --debug           Print detailed debug info\n");
	fprintf(out, "  -h, --help            Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s eraseall\n", __progname);
	fprintf(out, "  %s eraseall -L /path/to/loader/\n", __progname);
}

static int qdl_eraseall(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct qdl_device *qdl = NULL;
	char *loader_dir = NULL;
	char *programmer = NULL;
	bool storage_set = false;
	bool use_pcie = false;
	char *serial = NULL;
	int opt;
	int ret;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"serial", required_argument, 0, 'S'},
		{"storage", required_argument, 0, 's'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvS:s:L:Ph", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'v':
			print_version();
			return 0;
		case 'S':
			serial = optarg;
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_set = true;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			use_pcie = true;
			break;
		case 'h':
			print_eraseall_help(stdout);
			return 0;
		default:
			print_eraseall_help(stderr);
			return 1;
		}
	}

	if (!loader_dir && optind >= argc)
		loader_dir = ".";

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	}

	ret = firehose_session_open(&qdl,
				    programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ret = gpt_erase_all_partitions(qdl);

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static void print_flash_help(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s flash [options] [directory]\n", __progname);
	fprintf(out, "       %s [options] -F <firmware-dir>\n", __progname);
	fprintf(out, "       %s [options] <prog.mbn> <xml-files>...\n", __progname);
	fprintf(out, "\nFlash firmware from a directory or individual XML files.\n");
	fprintf(out, "If no directory is given, the current directory is searched.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, "      --log=FILE            Write debug-level log to FILE\n");
	fprintf(out, "  -d, --debug               Print detailed debug info\n");
	fprintf(out, "  -n, --dry-run             Dry run, no device reading or flashing\n");
	fprintf(out, "  -e, --erase-all           Erase all partitions before programming\n");
	fprintf(out, "  -f, --allow-missing       Allow skipping of missing files\n");
	fprintf(out, "  -s, --storage=T           Storage type: emmc|nand|nvme|spinor|ufs (default: nand)\n");
	fprintf(out, "  -l, --finalize-provisioning  Provision the target storage\n");
	fprintf(out, "  -i, --include=T           Set folder to search for files\n");
	fprintf(out, "  -S, --serial=T            Target by serial number or COM port\n");
	fprintf(out, "  -u, --out-chunk-size=T    Override chunk size for transactions\n");
	fprintf(out, "  -t, --create-digests=T    Generate VIP digest table in folder\n");
	fprintf(out, "  -T, --slot=T              Set slot number for multiple storage devices\n");
	fprintf(out, "  -D, --vip-table-path=T    Use VIP digest tables from folder\n");
	fprintf(out, "  -E, --no-auto-edl         Disable automatic DIAG to EDL switching\n");
	fprintf(out, "  -M, --skip-md5            Skip MD5 verification of firmware files\n");
	fprintf(out, "  -F, --firmware-dir=T      Auto-detect firmware from directory\n");
	fprintf(out, "  -L, --find-loader=T       Auto-detect programmer/loader from directory\n");
	fprintf(out, "  -P, --pcie                Use PCIe/MHI transport\n");
	fprintf(out, "  -h, --help                Print this help\n");
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s flash /path/to/firmware/\n", __progname);
	fprintf(out, "  %s flash -e /path/to/firmware/       Erase-all + flash\n", __progname);
	fprintf(out, "  %s -F /path/to/firmware/\n", __progname);
	fprintf(out, "  %s prog_firehose_ddr.elf rawprogram*.xml patch*.xml\n", __progname);
}

static int qdl_flash(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_NAND;
	struct sahara_image sahara_images[MAPPING_SZ] = {};
	struct firmware_files fw = {};
	char *incdir = NULL;
	char *serial = NULL;
	char *firmware_dir = NULL;
	char *loader_dir = NULL;
	char *loader_programmer = NULL;
	const char *vip_generate_dir = NULL;
	const char *vip_table_path = NULL;
	int type;
	int ret;
	int opt;
	int i;
	bool qdl_finalize_provisioning = false;
	bool allow_fusing = false;
	bool allow_missing = false;
	bool storage_type_set = false;
	bool erase_all = false;
	long out_chunk_size = 0;
	unsigned int slot = UINT_MAX;
	struct qdl_device *qdl = NULL;
	enum QDL_DEVICE_TYPE qdl_dev_type = QDL_DEVICE_USB;

	static struct option options[] = {
		{"debug", no_argument, 0, 'd'},
		{"version", no_argument, 0, 'v'},
		{"include", required_argument, 0, 'i'},
		{"finalize-provisioning", no_argument, 0, 'l'},
		{"out-chunk-size", required_argument, 0, 'u' },
		{"serial", required_argument, 0, 'S'},
		{"vip-table-path", required_argument, 0, 'D'},
		{"storage", required_argument, 0, 's'},
		{"allow-missing", no_argument, 0, 'f'},
		{"allow-fusing", no_argument, 0, 'c'},
		{"dry-run", no_argument, 0, 'n'},
		{"create-digests", required_argument, 0, 't'},
		{"slot", required_argument, 0, 'T'},
		{"no-auto-edl", no_argument, 0, 'E'},
		{"skip-md5", no_argument, 0, 'M'},
		{"firmware-dir", required_argument, 0, 'F'},
		{"find-loader", required_argument, 0, 'L'},
		{"pcie", no_argument, 0, 'P'},
		{"erase-all", no_argument, 0, 'e'},
		{"help", no_argument, 0, 'h'},
		{"help-all", no_argument, 0, 'H'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvi:lu:S:D:s:fcnt:T:EMF:L:Peh", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			qdl_debug = true;
			break;
		case 'n':
			qdl_dev_type = QDL_DEVICE_SIM;
			break;
		case 't':
			vip_generate_dir = optarg;
			/* we also enforce dry-run mode */
			qdl_dev_type = QDL_DEVICE_SIM;
			break;
		case 'v':
			print_version();
			return 0;
		case 'f':
			allow_missing = true;
			break;
		case 'i':
			incdir = optarg;
			break;
		case 'l':
			qdl_finalize_provisioning = true;
			break;
		case 'c':
			allow_fusing = true;
			break;
		case 'u':
			out_chunk_size = strtol(optarg, NULL, 10);
			break;
		case 's':
			storage_type = decode_storage(optarg);
			storage_type_set = true;
			break;
		case 'S':
			serial = optarg;
			break;
		case 'D':
			vip_table_path = optarg;
			break;
		case 'T':
			slot = (unsigned int)strtoul(optarg, NULL, 10);
			break;
		case 'E':
			qdl_auto_edl = false;
			break;
		case 'M':
			qdl_skip_md5 = true;
			break;
		case 'F':
			firmware_dir = optarg;
			break;
		case 'L':
			loader_dir = optarg;
			break;
		case 'P':
			qdl_dev_type = QDL_DEVICE_PCIE;
			break;
		case 'e':
			erase_all = true;
			break;
		case 'h':
			print_flash_help(stdout);
			return 0;
		case 'H':
			print_all_help(stdout);
			return 0;
		default:
			print_flash_help(stderr);
			return 1;
		}
	}

	if (firmware_dir && loader_dir) {
		fprintf(stderr, "Error: cannot use both -F and -L\n");
		return 1;
	}

	/* Handle firmware directory mode or require 2+ args */
	if (firmware_dir) {
		ret = firmware_detect(firmware_dir, &fw);
		if (ret < 0) {
			ux_err("failed to detect firmware in %s\n", firmware_dir);
			return 1;
		}

		/* Use detected storage type unless explicitly set */
		if (!storage_type_set)
			storage_type = fw.storage_type;

		/* Use firehose directory as include directory */
		incdir = fw.firehose_dir;
	} else if (loader_dir) {
		loader_programmer = find_programmer_recursive(loader_dir);
		if (!loader_programmer) {
			ux_err("no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_type_set)
			storage_type = detect_storage_from_directory(loader_dir);
		/* Still require XML files as positional args */
		if ((optind + 1) > argc) {
			fprintf(stderr, "Error: XML files required with -L\n");
			free(loader_programmer);
			return 1;
		}
	} else if ((optind + 2) > argc) {
		print_flash_help(stderr);
		return 1;
	}

	qdl = qdl_init(qdl_dev_type);
	if (!qdl) {
		ret = -1;
		goto out_cleanup;
	}

	qdl->slot = slot;

	if (vip_table_path) {
		if (vip_generate_dir)
			errx(1, "VIP mode and VIP table generation can't be enabled together\n");
		ret = vip_transfer_init(qdl, vip_table_path);
		if (ret)
			errx(1, "VIP initialization failed\n");
	}

	if (out_chunk_size)
		qdl_set_out_chunk_size(qdl, out_chunk_size);

	if (vip_generate_dir) {
		ret = vip_gen_init(qdl, vip_generate_dir);
		if (ret)
			goto out_cleanup;
	}

	ux_init();

	if (qdl_debug)
		print_version();

	if (firmware_dir) {
		/* Firmware directory mode: load auto-detected files */
		ret = decode_programmer(fw.programmer, sahara_images);
		if (ret < 0)
			exit(1);

		/* Load all rawread files first (backup before flash) */
		for (i = 0; i < fw.rawread_count; i++) {
			char *xml_dir_buf = strdup(fw.rawread[i]);
			char *xml_dir = dirname(xml_dir_buf);

			ret = read_op_load(fw.rawread[i], xml_dir);
			free(xml_dir_buf);
			if (ret < 0)
				errx(1, "read_op_load %s failed", fw.rawread[i]);
		}

		/* Load all rawprogram files, using each XML's directory as incdir */
		for (i = 0; i < fw.rawprogram_count; i++) {
			char *xml_dir_buf = strdup(fw.rawprogram[i]);
			char *xml_dir = dirname(xml_dir_buf);

			ret = program_load(fw.rawprogram[i], storage_type == QDL_STORAGE_NAND,
					   allow_missing, xml_dir);
			free(xml_dir_buf);
			if (ret < 0)
				errx(1, "program_load %s failed", fw.rawprogram[i]);
		}

		/* Load all patch files last */
		for (i = 0; i < fw.patch_count; i++) {
			ret = patch_load(fw.patch[i]);
			if (ret < 0)
				errx(1, "patch_load %s failed", fw.patch[i]);
		}

		if (!allow_fusing && program_is_sec_partition_flashed())
			errx(1, "secdata partition to be programmed, which can lead to irreversible"
				" changes. Allow explicitly with --allow-fusing parameter");
	} else {
		/* Manual mode: load files from command line */
		if (loader_programmer)
			ret = decode_programmer(loader_programmer, sahara_images);
		else
			ret = decode_programmer(argv[optind++], sahara_images);
		if (ret < 0)
			exit(1);

		do {
			type = detect_type(argv[optind]);
			if (type < 0 || type == QDL_FILE_UNKNOWN)
				errx(1, "failed to detect file type of %s\n", argv[optind]);

			switch (type) {
			case QDL_FILE_PATCH:
				ret = patch_load(argv[optind]);
				if (ret < 0)
					errx(1, "patch_load %s failed", argv[optind]);
				break;
			case QDL_FILE_PROGRAM:
				ret = program_load(argv[optind], storage_type == QDL_STORAGE_NAND, allow_missing, incdir);
				if (ret < 0)
					errx(1, "program_load %s failed", argv[optind]);

				if (!allow_fusing && program_is_sec_partition_flashed())
					errx(1, "secdata partition to be programmed, which can lead to irreversible"
						" changes. Allow explicitly with --allow-fusing parameter");
				break;
			case QDL_FILE_READ:
				ret = read_op_load(argv[optind], incdir);
				if (ret < 0)
					errx(1, "read_op_load %s failed", argv[optind]);
				break;
			case QDL_FILE_UFS:
				if (storage_type != QDL_STORAGE_UFS)
					errx(1, "attempting to load provisioning config when storage isn't \"ufs\"");

				ret = ufs_load(argv[optind], qdl_finalize_provisioning);
				if (ret < 0)
					errx(1, "ufs_load %s failed", argv[optind]);
				break;
			case QDL_CMD_READ:
				if (optind + 2 >= argc)
					errx(1, "read command missing arguments");
				ret = read_cmd_add(argv[optind + 1], argv[optind + 2]);
				if (ret < 0)
					errx(1, "failed to add read command");
				optind += 2;
				break;
			case QDL_CMD_WRITE:
				if (optind + 2 >= argc)
					errx(1, "write command missing arguments");
				ret = program_cmd_add(argv[optind + 1], argv[optind + 2]);
				if (ret < 0)
					errx(1, "failed to add write command");
				optind += 2;
				break;
			default:
				errx(1, "%s type not yet supported", argv[optind]);
				break;
			}
		} while (++optind < argc);
	}

	/* Verify MD5 checksums before connecting to device */
	ret = program_verify_md5();
	if (ret < 0)
		goto out_cleanup;

	/* Auto-detect PCIe if no transport explicitly chosen */
	if (qdl_dev_type == QDL_DEVICE_USB && pcie_has_device()) {
		ux_info("PCIe MHI modem detected, using PCIe transport\n");
		qdl_deinit(qdl);
		qdl = qdl_init(QDL_DEVICE_PCIE);
		if (!qdl) {
			ret = -1;
			goto out_cleanup;
		}
		qdl_dev_type = QDL_DEVICE_PCIE;
	}

	if (qdl_dev_type == QDL_DEVICE_PCIE) {
		/*
		 * PCIe: DIAG→EDL switch + programmer upload.
		 * Returns 0 if programmer uploaded via BHI (Linux),
		 * 1 if Sahara still needed (Windows), negative on error.
		 */
		int need_sahara;

		need_sahara = pcie_prepare(qdl, sahara_images[SAHARA_ID_EHOSTDL_IMG].name);
		if (need_sahara < 0)
			goto out_cleanup;

		ret = qdl_open(qdl, serial);
		if (ret)
			goto out_cleanup;

		if (need_sahara) {
			ret = sahara_run_with_retry(qdl, sahara_images,
						    NULL, NULL, serial);
			if (ret < 0)
				goto out_cleanup;
		}
	} else {
		ret = qdl_open(qdl, serial);
#ifdef _WIN32
		if (ret == -2) {
			/*
			 * USB driver not WinUSB-compatible (e.g. QDLoader).
			 * Fall back to COM port transport.
			 */
			qdl_deinit(qdl);
			qdl = qdl_init(QDL_DEVICE_PCIE);
			if (!qdl) {
				ret = 1;
				goto out_cleanup;
			}
			ret = qdl_open(qdl, serial);
		}
#endif
		if (ret)
			goto out_cleanup;

		ret = sahara_run_with_retry(qdl, sahara_images,
					    NULL, NULL, serial);
		if (ret < 0)
			goto out_cleanup;
	}

	qdl->storage_type = storage_type;

	if (ufs_need_provisioning())
		ret = firehose_provision(qdl);
	else
		ret = firehose_run(qdl, erase_all);
	if (ret < 0)
		goto out_cleanup;

out_cleanup:
	if (vip_generate_dir)
		vip_gen_finalize(qdl);

	qdl_close(qdl);
	free_firehose_ops();
	sahara_images_free(sahara_images, MAPPING_SZ);
	free_programs();
	free_patches();

	if (firmware_dir)
		firmware_free(&fw);

	free(loader_programmer);

	if (qdl->vip_data.state != VIP_DISABLED)
		vip_transfer_deinit(qdl);

	qdl_deinit(qdl);

	return !!ret;
}

static void print_all_help(FILE *out)
{
	print_usage(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== flash ==========");
	fprintf(out, "\n");
	print_flash_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== printgpt ==========");
	fprintf(out, "\n");
	print_printgpt_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== storageinfo ==========");
	fprintf(out, "\n");
	print_storageinfo_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== partinfo ==========");
	fprintf(out, "\n");
	print_partinfo_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== reset ==========");
	fprintf(out, "\n");
	print_reset_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== getslot ==========");
	fprintf(out, "\n");
	print_getslot_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== setslot ==========");
	fprintf(out, "\n");
	print_setslot_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== read ==========");
	fprintf(out, "\n");
	print_read_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== readall ==========");
	fprintf(out, "\n");
	print_readall_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== write ==========");
	fprintf(out, "\n");
	print_write_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== erase ==========");
	fprintf(out, "\n");
	print_erase_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== eraseall ==========");
	fprintf(out, "\n");
	print_eraseall_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== diag2edl ==========");
	fprintf(out, "\n");
	print_diag2edl_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== nvread ==========");
	fprintf(out, "\n");
	print_nvread_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== nvwrite ==========");
	fprintf(out, "\n");
	print_nvwrite_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsbackup ==========");
	fprintf(out, "\n");
	print_efsbackup_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsrestore ==========");
	fprintf(out, "\n");
	print_efsrestore_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efspull ==========");
	fprintf(out, "\n");
	print_efspull_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efspush ==========");
	fprintf(out, "\n");
	print_efspush_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsls ==========");
	fprintf(out, "\n");
	print_efsls_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsrm ==========");
	fprintf(out, "\n");
	print_efsrm_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsstat ==========");
	fprintf(out, "\n");
	print_efsstat_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsmkdir ==========");
	fprintf(out, "\n");
	print_efsmkdir_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efschmod ==========");
	fprintf(out, "\n");
	print_efschmod_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsln ==========");
	fprintf(out, "\n");
	print_efsln_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsrl ==========");
	fprintf(out, "\n");
	print_efsrl_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== efsdump ==========");
	fprintf(out, "\n");
	print_efsdump_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== xqcn2tar ==========");
	fprintf(out, "\n");
	print_xqcn2tar_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== tar2xqcn ==========");
	fprintf(out, "\n");
	print_tar2xqcn_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== smssend ==========");
	fprintf(out, "\n");
	print_smssend_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== smsread ==========");
	fprintf(out, "\n");
	print_smsread_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== smsrm ==========");
	fprintf(out, "\n");
	print_smsrm_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== smsstatus ==========");
	fprintf(out, "\n");
	print_smsstatus_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== ussd ==========");
	fprintf(out, "\n");
	print_ussd_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== atcmd ==========");
	fprintf(out, "\n");
	print_atcmd_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== atconsole ==========");
	fprintf(out, "\n");
	print_atconsole_help(out);

#ifdef HAVE_QCSERIALD
	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== qcseriald ==========");
	fprintf(out, "\n");
	print_qcseriald_help(out);
#endif

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== list ==========");
	fprintf(out, "\n");
	print_list_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== ramdump ==========");
	fprintf(out, "\n");
	print_ramdump_help(out);

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "========== ks ==========");
	fprintf(out, "\n");
	print_ks_help(out);
}

static void print_fenix_art(FILE *out)
{
	const char *art =
		"                             .*@@@-.\n"
		"                                  :@@@@-\n"
		"                                     @@@@#.\n"
		"      .+-                               #@@@@%.+@-\n"
		"    -@*@*@%                                @@@@@::@@=\n"
		".+%@@@@@@@@@%=.                            =@@@@# #@@- ..\n"
		"    .@@@@@:                                :@@@@@ =@@@..%=\n"
		"      .%-                                  -@@@@@:=@@@@  @@#\n"
		"      .#-         .%@@@@@@#.               +@@@@@.#@@@@  @@@.\n"
		"       :.             .%@@@@@@@@@@@%.     .@@@@@+:@@@@@  @@@-\n"
		"                        -@@@@@@@@@@@@@@@..@@@@@@.-@@@@@ .@@@-\n"
		"                          =@@@@@@@@*  .@@@@@@. @@@@@@..@@@@-\n"
		"                           @@@@@@:.-@@@@@@.  @@@@@@= %@@@@@.\n"
		"                          .@@@@. *@@@@@@- .+@@@@@@-.@@@@@@+\n"
		"                          %@@. =@@@@@*.  +@@@@@@%.-@@@@@@%\n"
		"                         =@.+@@@@@. -@@@@@@@*.:@@@@@@@*.\n"
		"                          ..@@@@= .@@@@@@: #@@@@@@@:\n"
		"                           .@@@@  +@@@@..%@@@@@+.\n"
		"                            @@@.  @@@. @@@*    .@.\n"
		"                         -*: .@@* :@@. @@.  -..@@\n"
		"                       =@@@@@@.*@- :@%  @* =@:=@#\n"
		"                      .@@@-+@@@@:%@..%- ...@%:@@:\n"
		"                       :@@ :+   *@     *@@#*@@@.\n"
		"                                  .*@@@:=@@@@:\n"
		"                            .@@@@#.-@@@@@.\n"
		"                         -@@@@@  @@@@@@%\n"
		"                        :@@@@# =@@@@@@%\n"
		"                         #@@@. @@@@@@*\n"
		"                              :@@@@@=\n"
		"                                   .=@@@@@-\n";

	fprintf(out, "\n");
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN, art);
	fprintf(out, "\n");
}

int main(int argc, char **argv)
{
	int ret;

	/*
	 * When stdout is a pipe (e.g. GUI subprocess), it defaults to
	 * fully-buffered, causing output to be trapped until process exit.
	 * Switch to line-buffered so each printf("\n") flushes immediately.
	 */
	if (!isatty(STDOUT_FILENO))
		setvbuf(stdout, NULL, _IOLBF, 0);

	ux_init();

#if defined(__APPLE__) || defined(__linux__)
	/* macOS/Linux require root for USB/serial device access.
	 * Skip sudo for commands that don't need it. */
	if (getuid() != 0 &&
	    !(argc < 2 ||
	      !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") ||
	      !strcmp(argv[1], "--help-all") ||
	      !strcmp(argv[1], "--version") || !strcmp(argv[1], "-v") ||
	      !strcmp(argv[1], "xqcn2tar") || !strcmp(argv[1], "tar2xqcn"))) {
		char **new_argv = malloc((argc + 2) * sizeof(char *));

		if (!new_argv) {
			fprintf(stderr, "Error: out of memory\n");
			return 1;
		}
		new_argv[0] = "sudo";
		for (int i = 0; i < argc; i++)
			new_argv[i + 1] = argv[i];
		new_argv[argc + 1] = NULL;
		execvp("sudo", new_argv);
		perror("sudo");
		free(new_argv);
		return 1;
	}
#endif

	/* Pre-scan for --log=<file> (global option, works with all subcommands) */
	for (int i = 1; i < argc; i++) {
		const char *log_path = NULL;
		int strip = 0;

		if (!strncmp(argv[i], "--log=", 6)) {
			log_path = argv[i] + 6;
			strip = 1;
		} else if (!strcmp(argv[i], "--log") && i + 1 < argc) {
			log_path = argv[i + 1];
			strip = 2;
		}

		if (log_path) {
			qdl_log_file = fopen(log_path, "w");
			if (!qdl_log_file) {
				fprintf(stderr, "Error: cannot open log file: %s\n",
					log_path);
				return 1;
			}
			/* Strip --log arg(s) so subcommands don't see them */
			for (int j = i; j + strip < argc; j++)
				argv[j] = argv[j + strip];
			argc -= strip;
			break;
		}
	}

	/* Handle no args, --help, --help-all, -h before subcommand dispatch */
	if (argc < 2 || !strcmp(argv[1], "--help") ||
	    !strcmp(argv[1], "-h")) {
		print_usage(argc < 2 ? stderr : stdout);
		return argc < 2 ? 1 : 0;
	}
	if (!strcmp(argv[1], "--help-all")) {
		print_all_help(stdout);
		return 0;
	}

	/* list: handle --help since it has no getopt loop */
	if (!strcmp(argv[1], "list")) {
		if (argc >= 3 && (!strcmp(argv[2], "--help") ||
				  !strcmp(argv[2], "-h"))) {
			print_list_help(stdout);
			return 0;
		}
		ret = qdl_list(stdout);
	} else if (!strcmp(argv[1], "ramdump")) {
		ret = qdl_ramdump(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "ks")) {
		ret = qdl_ks(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "diag2edl")) {
		ret = qdl_diag2edl(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "printgpt")) {
		ret = qdl_printgpt(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "storageinfo")) {
		ret = qdl_storageinfo(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "partinfo")) {
		ret = qdl_partinfo(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "reset")) {
		ret = qdl_reset(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "getslot")) {
		ret = qdl_getslot(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "setslot")) {
		ret = qdl_setslot(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "read")) {
		ret = qdl_read_partition(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "readall")) {
		ret = qdl_readall(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "erase")) {
		ret = qdl_erase(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "write")) {
		ret = qdl_write_partition(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "eraseall")) {
		ret = qdl_eraseall(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "nvread")) {
		ret = qdl_nvread(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "nvwrite")) {
		ret = qdl_nvwrite(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsls")) {
		ret = qdl_efsls(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efspull")) {
		ret = qdl_efspull(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efspush")) {
		ret = qdl_efspush(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsrm")) {
		ret = qdl_efsrm(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsstat")) {
		ret = qdl_efsstat(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsmkdir")) {
		ret = qdl_efsmkdir(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efschmod")) {
		ret = qdl_efschmod(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsln")) {
		ret = qdl_efsln(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsrl")) {
		ret = qdl_efsrl(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsdump")) {
		ret = qdl_efsdump(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsbackup")) {
		ret = qdl_efsbackup(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "efsrestore")) {
		ret = qdl_efsrestore(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "xqcn2tar")) {
		ret = qdl_xqcn2tar(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "tar2xqcn")) {
		ret = qdl_tar2xqcn(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "smssend")) {
		ret = qdl_smssend(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "smsread")) {
		ret = qdl_smsread(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "smsrm")) {
		ret = qdl_smsrm(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "smsstatus")) {
		ret = qdl_smsstatus(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "ussd")) {
		ret = qdl_ussd(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "atcmd")) {
		ret = qdl_atcmd(argc - 1, argv + 1);
	} else if (!strcmp(argv[1], "atconsole")) {
		ret = qdl_atconsole(argc - 1, argv + 1);
#ifdef HAVE_QCSERIALD
	} else if (!strcmp(argv[1], "qcseriald")) {
		ret = qdl_qcseriald(argc - 1, argv + 1);
#endif
	} else if (!strcmp(argv[1], "flash")) {
		/*
		 * "qfenix flash [options] [dir]" — treat bare positional
		 * arg as firmware directory (like -F).  If no dir given,
		 * default to current directory.
		 */
		int flash_argc = argc - 1;
		char **flash_argv = argv + 1;

		/* Check for --help / --help-all before rewriting args */
		for (int i = 1; i < flash_argc; i++) {
			if (!strcmp(flash_argv[i], "--help-all")) {
				print_all_help(stdout);
				return 0;
			}
			if (!strcmp(flash_argv[i], "--help") ||
			    !strcmp(flash_argv[i], "-h")) {
				print_flash_help(stdout);
				return 0;
			}
		}

		/*
		 * If the last arg looks like a directory (no leading -)
		 * and -F wasn't already given, rewrite it as -F <dir>.
		 * If no positional args at all, default to -F .
		 */
		bool has_F = false;
		for (int i = 1; i < flash_argc; i++) {
			if (!strcmp(flash_argv[i], "-F") ||
			    !strncmp(flash_argv[i], "--firmware-dir", 14))
				has_F = true;
		}

		if (!has_F) {
			/* Build new argv: progname -F <dir> [original options] */
			char **new_argv = calloc(flash_argc + 3, sizeof(char *));
			int n = 0;

			new_argv[n++] = flash_argv[0];
			new_argv[n++] = "-F";

			/* Find the positional arg (no leading -) */
			char *dir_arg = NULL;
			int dir_idx = -1;
			for (int i = flash_argc - 1; i >= 1; i--) {
				if (flash_argv[i][0] != '-') {
					dir_arg = flash_argv[i];
					dir_idx = i;
					break;
				}
			}
			new_argv[n++] = dir_arg ? dir_arg : ".";

			/* Copy remaining options (skip the dir arg) */
			for (int i = 1; i < flash_argc; i++) {
				if (i != dir_idx)
					new_argv[n++] = flash_argv[i];
			}
			new_argv[n] = NULL;

			ret = qdl_flash(n, new_argv);
			free(new_argv);
		} else {
			ret = qdl_flash(flash_argc, flash_argv);
		}
	} else {
		ret = qdl_flash(argc, argv);
	}

	/* Show fenix art on success, but not for lightweight subcommands
	 * (qcseriald, list, AT/SMS commands, version/help) that don't
	 * perform device flashing/DIAG operations */
	if (!ret && argc >= 2 &&
	    strcmp(argv[1], "qcseriald") != 0 &&
	    strcmp(argv[1], "list") != 0 &&
	    strcmp(argv[1], "smssend") != 0 &&
	    strcmp(argv[1], "smsread") != 0 &&
	    strcmp(argv[1], "smsrm") != 0 &&
	    strcmp(argv[1], "smsstatus") != 0 &&
	    strcmp(argv[1], "ussd") != 0 &&
	    strcmp(argv[1], "atcmd") != 0 &&
	    strcmp(argv[1], "atconsole") != 0)
		print_fenix_art(stdout);

	if (qdl_log_file) {
		fclose(qdl_log_file);
		qdl_log_file = NULL;
	}

	return ret;
}
