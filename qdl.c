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
 * @images: List of Sahara images, with @images[0] populated
 *
 * The single blob provided in @images[0] might be a CPIO archive containing
 * Sahara images, in files with names in the format "<id>:<filename>". Load
 * each such Sahara image into the relevant spot in the @images array.
 *
 * The original blob (in @images[0]) is freed once it has been consumed.
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
			return -1;
		}
		hdr = ptr;

		if (memcmp(hdr->c_magic, "070701", 6)) {
			ux_err("expected cpio header in programmer archive\n");
			return -1;
		}

		filesize = parse_ascii_hex32(hdr->c_filesize);
		namesize = parse_ascii_hex32(hdr->c_namesize);

		ptr += sizeof(*hdr);
		if (ptr + namesize > end || ptr + filesize + namesize > end) {
			ux_err("programmer archive is truncated\n");
			return -1;
		}

		if (namesize > sizeof(name)) {
			ux_err("unexpected filename length in progammer archive\n");
			return -1;
		}
		memcpy(name, ptr, namesize);

		if (!memcmp(name, "TRAILER!!!", 11))
			break;

		tok = strtok_r(name, ":", &save);
		id = strtoul(tok, NULL, 0);
		if (id == 0 || id >= MAPPING_SZ) {
			ux_err("invalid image id \"%s\" in programmer archive\n", tok);
			return -1;
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

static int find_files_recursive(const char *dir, const char *prefix, const char *suffix,
				char ***files_out, int *count_out)
{
	int capacity = 0;

	*files_out = NULL;
	*count_out = 0;
	return find_files_recursive_impl(dir, prefix, suffix,
					 files_out, count_out, &capacity, 0);
}

static enum qdl_storage_type detect_storage_from_filename(const char *filename)
{
	if (strcasestr(filename, "_nand") || strcasestr(filename, "nand_"))
		return QDL_STORAGE_NAND;
	if (strcasestr(filename, "_emmc") || strcasestr(filename, "emmc_"))
		return QDL_STORAGE_EMMC;
	if (strcasestr(filename, "_ufs") || strcasestr(filename, "ufs_"))
		return QDL_STORAGE_UFS;

	return QDL_STORAGE_UFS; /* default */
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
 * Returns detected type, or QDL_STORAGE_UFS as default.
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
	return QDL_STORAGE_UFS;
}

static int firmware_detect(const char *base_dir, struct firmware_files *fw)
{
	char *dir_buf;
	int i;

	memset(fw, 0, sizeof(*fw));
	fw->storage_type = QDL_STORAGE_UFS;

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
	if (fw->rawprogram_count == 0) {
		ux_err("no rawprogram XML files found under %s\n", base_dir);
		return -1;
	}

	/* Detect storage type from first rawprogram filename */
	fw->storage_type = detect_storage_from_filename(fw->rawprogram[0]);

	/* Find patch XML files recursively */
	find_files_recursive(base_dir, "patch", ".xml",
			     &fw->patch, &fw->patch_count);

	/* Find rawread XML files recursively */
	find_files_recursive(base_dir, "rawread", ".xml",
			     &fw->rawread, &fw->rawread_count);

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

	fprintf(out, "qfenix - Qualcomm Firehose / DIAG multi-tool\n");
#ifdef BUILD_STATIC
	fprintf(out, "qfenix %s, %s %s, static binary\n\n", VERSION, __DATE__, __TIME__);
#else
	fprintf(out, "qfenix %s, %s %s, dynamically linked\n\n", VERSION, __DATE__, __TIME__);
#endif
	fprintf(out, "Usage: %s [options] <prog.mbn> <program-xml|patch-xml|read-xml>...\n", __progname);
	fprintf(out, "       %s [options] -F <firmware-dir>\n", __progname);
	fprintf(out, "       %s [options] <prog.mbn> (read|write) <address> <binary>...\n", __progname);
	fprintf(out, "\nSubcommands:\n");
	fprintf(out, "  list          List connected EDL, DIAG, and PCIe devices\n");
	fprintf(out, "  diag2edl      Switch a device from DIAG to EDL mode\n");
	fprintf(out, "  printgpt      Print GPT partition tables\n");
	fprintf(out, "  storageinfo   Query storage hardware information\n");
	fprintf(out, "  reset         Reset, power-off, or EDL-reboot a device\n");
	fprintf(out, "  getslot       Show the active A/B slot\n");
	fprintf(out, "  setslot       Set the active A/B slot (a or b)\n");
	fprintf(out, "  readall       Dump all partitions to files\n");
	fprintf(out, "  nvread        Read an NV item via DIAG\n");
	fprintf(out, "  nvwrite       Write an NV item via DIAG\n");
	fprintf(out, "  efsls         List an EFS directory via DIAG\n");
	fprintf(out, "  efsget        Download a file from EFS via DIAG\n");
	fprintf(out, "  efsdump       Dump the EFS factory image via DIAG\n");
	fprintf(out, "  ramdump       Extract RAM dumps via Sahara\n");
	fprintf(out, "  ks            Keystore/Sahara over serial device nodes\n");
	fprintf(out, "\nUse '%s <subcommand> --help' for detailed subcommand usage.\n", __progname);
	fprintf(out, "\nFlash options:\n");
	fprintf(out, "  -d, --debug               Print detailed debug info\n");
	fprintf(out, "  -n, --dry-run             Dry run, no device reading or flashing\n");
	fprintf(out, "  -f, --allow-missing       Allow skipping of missing files\n");
	fprintf(out, "  -s, --storage=T           Set storage type: emmc|nand|nvme|spinor|ufs (default: ufs)\n");
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
	fprintf(out, "\nExamples:\n");
	fprintf(out, "  %s -F /path/to/firmware/          Auto-detect and flash\n", __progname);
	fprintf(out, "  %s prog_firehose_ddr.elf rawprogram*.xml patch*.xml\n", __progname);
	fprintf(out, "  %s printgpt -L /path/to/firmware/ Print GPT from auto-detected loader\n", __progname);
	fprintf(out, "  %s list                           List connected devices\n", __progname);
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

static int is_skip_name_list(const char *name)
{
	if (strstr(name, "AT Port") || strstr(name, "AT Interface") ||
	    strstr(name, "NMEA") || strstr(name, "GPS") ||
	    strstr(name, "Modem") || strstr(name, "Audio"))
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
	int edl_count = 0, diag_count = 0;
	int edl_header = 0, diag_header = 0;

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

	SetupDiDestroyDeviceInfoList(hDevInfo);

	return edl_count + diag_count;
}

#else /* Linux/POSIX */

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

#endif /* _WIN32 */

static int qdl_list(FILE *out)
{
	int found = 0;
	int n;

	n = list_usb_edl(out);
	found += n;

#ifdef _WIN32
	{
		int com_count;

		if (n > 0)
			fprintf(out, "\n");
		com_count = list_com_ports(out);
		found += com_count;
	}
#else
	{
		int edl_n, diag_n;

		edl_n = list_edl_ports(out);
		if (edl_n > 0 && n > 0)
			fprintf(out, "\n");
		found += edl_n;

		diag_n = list_diag_ports(out);
		found += diag_n;
	}
#endif

	if (!found)
		fprintf(out, "No devices found\n");

	return found ? 0 : 1;
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
			print_usage(stdout);
			return 0;
		default:
			print_usage(stderr);
			return 1;
		}
	}

	if (optind < argc)
		filter = argv[optind++];

	if (optind != argc) {
		print_usage(stderr);
		return 1;
	}

	ux_init();

	qdl = qdl_init(QDL_DEVICE_USB);
	if (!qdl)
		return 1;

	if (qdl_debug)
		print_version();

	ret = qdl_open(qdl, serial);
	if (ret) {
		ret = 1;
		goto out_cleanup;
	}

	ret = sahara_run(qdl, NULL, ramdump_path, filter);
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

static void print_ks_usage(FILE *out)
{
	extern const char *__progname;

	fprintf(out,
		"%s ks -p <sahara dev_node> -s <id:file path> ...\n",
		__progname);
	fprintf(out,
		" -h                   --help                      Print this usage info\n"
		" -p                   --port                      Sahara device node to use\n"
		" -s <id:file path>    --sahara <id:file path>     Sahara protocol file mapping\n"
		"\n"
		"One -p instance is required.  One or more -s instances are required.\n"
		"\n"
		"Example:\n"
		"%s ks -p /dev/mhi0_QAIC_SAHARA -s 1:/opt/qti-aic/firmware/fw1.bin"
		" -s 2:/opt/qti-aic/firmware/fw2.bin\n",
		__progname);
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
				print_ks_usage(stderr);
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
				print_ks_usage(stderr);
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
			print_ks_usage(stdout);
			return 0;
		default:
			print_ks_usage(stderr);
			return 1;
		}
	}

	if (!dev_node || !found_mapping) {
		print_ks_usage(stderr);
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

static void print_diag2edl_usage(FILE *out)
{
	extern const char *__progname;

	fprintf(out, "Usage: %s diag2edl [options]\n", __progname);
	fprintf(out, "\nSwitch a device from DIAG mode to EDL mode.\n");
	fprintf(out, "\nOptions:\n");
	fprintf(out, " -d, --debug\t\tPrint detailed debug info\n");
	fprintf(out, " -v, --version\t\tPrint the current version and exit\n");
	fprintf(out, " -S, --serial=T\t\tSelect target by serial number T\n");
	fprintf(out, " -h, --help\t\tPrint this usage info\n");
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
			print_diag2edl_usage(stdout);
			return 0;
		default:
			print_diag2edl_usage(stderr);
			return 1;
		}
	}

	if (qdl_debug)
		print_version();

	if (!diag_is_device_in_diag_mode(serial)) {
		fprintf(stderr, "No device found in DIAG mode\n");
		return 1;
	}

	printf("Device in DIAG mode, switching to EDL...\n");
	if (diag_switch_to_edl(serial) < 0) {
		fprintf(stderr, "Failed to switch device to EDL mode\n");
		return 1;
	}

	printf("EDL switch command sent successfully\n");
	return 0;
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

		need_sahara = pcie_prepare(qdl, sahara_images[0].name);
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
			ret = sahara_run(qdl, sahara_images, NULL, NULL);
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

		ret = sahara_run(qdl, sahara_images, NULL, NULL);
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

static int qdl_printgpt(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_UFS;
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
		default:
			fprintf(stderr, "Usage: qfenix printgpt [-L dir | <programmer>] [--serial=S] [--storage=T] [--pcie]\n");
			return opt == 'h' ? 0 : 1;
		}
	}

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	} else if (optind >= argc) {
		fprintf(stderr, "Error: programmer file or -L <dir> required\n");
		fprintf(stderr, "Usage: qfenix printgpt [-L dir | <programmer>] [--serial=S] [--storage=T] [--pcie]\n");
		return 1;
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ret = gpt_print_table(qdl);

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
}

static int qdl_storageinfo(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_UFS;
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
		default:
			fprintf(stderr, "Usage: qfenix storageinfo [-L dir | <programmer>] [--serial=S] [--storage=T] [--pcie]\n");
			return opt == 'h' ? 0 : 1;
		}
	}

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	} else if (optind >= argc) {
		fprintf(stderr, "Error: programmer file or -L <dir> required\n");
		return 1;
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

static int qdl_reset(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_UFS;
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
		default:
			fprintf(stderr, "Usage: qfenix reset [-L dir | <programmer>] [--mode=reset|off|edl] [--serial=S] [--storage=T] [--pcie]\n");
			return opt == 'h' ? 0 : 1;
		}
	}

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	} else if (optind >= argc) {
		fprintf(stderr, "Error: programmer file or -L <dir> required\n");
		return 1;
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

static int qdl_getslot(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_UFS;
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
		default:
			fprintf(stderr, "Usage: qfenix getslot [-L dir | <programmer>] [--serial=S] [--storage=T] [--pcie]\n");
			return opt == 'h' ? 0 : 1;
		}
	}

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	} else if (optind >= argc) {
		fprintf(stderr, "Error: programmer file or -L <dir> required\n");
		return 1;
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

static int qdl_setslot(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_UFS;
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
		default:
			fprintf(stderr, "Usage: qfenix setslot <a|b> [-L dir | <programmer>] [--serial=S] [--storage=T] [--pcie]\n");
			return opt == 'h' ? 0 : 1;
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

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	} else if (optind >= argc) {
		fprintf(stderr, "Error: programmer file or -L <dir> required\n");
		return 1;
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

static int qdl_readall(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_UFS;
	struct qdl_device *qdl = NULL;
	const char *outdir = ".";
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
		case 'h':
		default:
			fprintf(stderr, "Usage: qfenix readall [-L dir | <programmer>] [-o outdir] [--serial=S] [--storage=T] [--pcie]\n");
			return opt == 'h' ? 0 : 1;
		}
	}

	if (loader_dir) {
		programmer = find_programmer_recursive(loader_dir);
		if (!programmer) {
			fprintf(stderr, "Error: no programmer found in %s\n", loader_dir);
			return 1;
		}
		if (!storage_set)
			storage_type = detect_storage_from_directory(loader_dir);
	} else if (optind >= argc) {
		fprintf(stderr, "Error: programmer file or -L <dir> required\n");
		return 1;
	}

	ret = firehose_session_open(&qdl, programmer ? programmer : argv[optind],
				    storage_type, serial, use_pcie);
	if (ret) {
		free(programmer);
		return 1;
	}

	ret = gpt_read_all_partitions(qdl, outdir);

	firehose_session_close(qdl, true);
	free(programmer);
	return !!ret;
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
		default:
			fprintf(stderr, "Usage: qfenix nvread <item_id> [--index=N] [--serial=S] [--debug]\n");
			return opt == 'h' ? 0 : 1;
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
		default:
			fprintf(stderr, "Usage: qfenix nvwrite <item_id> <hex_data> [--index=N] [--serial=S] [--debug]\n");
			return opt == 'h' ? 0 : 1;
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

	if (ret == 0)
		printf("NV item %u written successfully\n", item_id);

	diag_close(sess);
	return !!ret;
}

static void efsls_print_entry(const struct efs_dirent *entry, void *ctx)
{
	const char *type_str;

	(void)ctx;

	if (entry->entry_type == 1)
		type_str = (entry->mode & 0040000) ? "dir" : "file";
	else
		type_str = "???";

	printf("%-4s %8d  %04o  %s\n",
	       type_str, entry->size, entry->mode & 0777, entry->name);
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
		default:
			fprintf(stderr, "Usage: qfenix efsls <path> [--serial=S] [--debug]\n");
			return opt == 'h' ? 0 : 1;
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

	printf("%-4s %8s  %4s  %s\n", "Type", "Size", "Mode", "Name");
	printf("---- --------  ----  ----\n");

	ret = diag_efs_listdir(sess, path, efsls_print_entry, NULL);

	diag_close(sess);
	return !!ret;
}

static int qdl_efsget(int argc, char **argv)
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
		default:
			fprintf(stderr, "Usage: qfenix efsget <remote_path> <local_path> [--serial=S] [--debug]\n");
			return opt == 'h' ? 0 : 1;
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

	ret = diag_efs_readfile(sess, src, dst);

	diag_close(sess);
	return !!ret;
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
		default:
			fprintf(stderr, "Usage: qfenix efsdump <output_file> [--serial=S] [--debug]\n");
			return opt == 'h' ? 0 : 1;
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

	ret = diag_efs_dump(sess, output);

	diag_close(sess);
	return !!ret;
}

static int qdl_flash(int argc, char **argv)
{
	enum qdl_storage_type storage_type = QDL_STORAGE_UFS;
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
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "dvi:lu:S:D:s:fcnt:T:EMF:L:Ph", options, NULL)) != -1) {
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
		case 'h':
			print_usage(stdout);
			return 0;
		default:
			print_usage(stderr);
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
		print_usage(stderr);
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

		/* Load all patch files */
		for (i = 0; i < fw.patch_count; i++) {
			ret = patch_load(fw.patch[i]);
			if (ret < 0)
				errx(1, "patch_load %s failed", fw.patch[i]);
		}

		/* Load all rawread files */
		for (i = 0; i < fw.rawread_count; i++) {
			char *xml_dir_buf = strdup(fw.rawread[i]);
			char *xml_dir = dirname(xml_dir_buf);

			ret = read_op_load(fw.rawread[i], xml_dir);
			free(xml_dir_buf);
			if (ret < 0)
				errx(1, "read_op_load %s failed", fw.rawread[i]);
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

	if (qdl_dev_type == QDL_DEVICE_PCIE) {
		/*
		 * PCIe: DIAG→EDL switch + programmer upload.
		 * Returns 0 if programmer uploaded via BHI (Linux),
		 * 1 if Sahara still needed (Windows), negative on error.
		 */
		int need_sahara;

		need_sahara = pcie_prepare(qdl, sahara_images[0].name);
		if (need_sahara < 0)
			goto out_cleanup;

		ret = qdl_open(qdl, serial);
		if (ret)
			goto out_cleanup;

		if (need_sahara) {
			ret = sahara_run(qdl, sahara_images, NULL, NULL);
			if (ret < 0)
				goto out_cleanup;
		}
	} else {
		ret = qdl_open(qdl, serial);
		if (ret)
			goto out_cleanup;

		ret = sahara_run(qdl, sahara_images, NULL, NULL);
		if (ret < 0)
			goto out_cleanup;
	}

	qdl->storage_type = storage_type;

	if (ufs_need_provisioning())
		ret = firehose_provision(qdl);
	else
		ret = firehose_run(qdl);
	if (ret < 0)
		goto out_cleanup;

out_cleanup:
	if (vip_generate_dir)
		vip_gen_finalize(qdl);

	qdl_close(qdl);
	free_firehose_ops();
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

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "list"))
		return qdl_list(stdout);
	if (argc >= 2 && !strcmp(argv[1], "ramdump"))
		return qdl_ramdump(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "ks"))
		return qdl_ks(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "diag2edl"))
		return qdl_diag2edl(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "printgpt"))
		return qdl_printgpt(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "storageinfo"))
		return qdl_storageinfo(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "reset"))
		return qdl_reset(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "getslot"))
		return qdl_getslot(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "setslot"))
		return qdl_setslot(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "readall"))
		return qdl_readall(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "nvread"))
		return qdl_nvread(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "nvwrite"))
		return qdl_nvwrite(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "efsls"))
		return qdl_efsls(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "efsget"))
		return qdl_efsget(argc - 1, argv + 1);
	if (argc >= 2 && !strcmp(argv[1], "efsdump"))
		return qdl_efsdump(argc - 1, argv + 1);

	return qdl_flash(argc, argv);
}
