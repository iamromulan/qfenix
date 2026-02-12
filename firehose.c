// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2016-2017, Linaro Ltd.
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * All rights reserved.
 */
#define _FILE_OFFSET_BITS 64
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "qdl.h"
#include "ufs.h"
#include "oscompat.h"
#include "vip.h"
#include "sparse.h"

enum {
	FIREHOSE_ACK = 0,
	FIREHOSE_NAK,
};

/*
 * Remainder buffer for serial stream reassembly.
 *
 * On COM port transport, the rawmode ACK XML and the following binary
 * data may arrive concatenated in a single read.  When firehose_read()
 * detects rawmode, it saves any trailing bytes (binary data) here so
 * firehose_issue_read() can consume them before calling qdl_read().
 */
static char fh_remainder[4096];
static size_t fh_remainder_len;

static void fh_remainder_save(const char *data, size_t len)
{
	if (len > sizeof(fh_remainder))
		len = sizeof(fh_remainder);
	memcpy(fh_remainder, data, len);
	fh_remainder_len = len;
}

static size_t fh_remainder_drain(void *buf, size_t max)
{
	size_t n = fh_remainder_len;

	if (n == 0)
		return 0;
	if (n > max)
		n = max;

	memcpy(buf, fh_remainder, n);
	fh_remainder_len -= n;
	if (fh_remainder_len > 0)
		memmove(fh_remainder, fh_remainder + n, fh_remainder_len);

	return n;
}

/*
 * Length-limited memory search (like memmem but portable to MSYS2).
 */
static void *find_in_mem(const void *haystack, size_t hay_len,
			 const void *needle, size_t needle_len)
{
	const char *h = haystack;
	const char *n = needle;
	size_t i;

	if (needle_len == 0)
		return (void *)haystack;
	if (needle_len > hay_len)
		return NULL;

	for (i = 0; i <= hay_len - needle_len; i++) {
		if (h[i] == n[0] && memcmp(h + i, n, needle_len) == 0)
			return (void *)(h + i);
	}

	return NULL;
}

static void xml_setpropf(xmlNode *node, const char *attr, const char *fmt, ...)
{
	xmlChar buf[128];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf((char *)buf, sizeof(buf), fmt, ap);
	xmlSetProp(node, (xmlChar *)attr, buf);
	va_end(ap);
}

static xmlNode *firehose_response_parse(const void *buf, size_t len, int *error)
{
	xmlNode *node;
	xmlNode *root;
	xmlDoc *doc;

	doc = xmlReadMemory(buf, len, NULL, NULL, 0);
	if (!doc) {
		ux_err("failed to parse firehose response\n");
		*error = -EINVAL;
		return NULL;
	}

	root = xmlDocGetRootElement(doc);
	for (node = root; node; node = node->next) {
		if (node->type != XML_ELEMENT_NODE)
			continue;
		if (xmlStrcmp(node->name, (xmlChar *)"data") == 0)
			break;
	}

	if (!node) {
		ux_err("firehose response without data tag\n");
		*error = -EINVAL;
		xmlFreeDoc(doc);
		return NULL;
	}

	for (node = node->children; node && node->type != XML_ELEMENT_NODE; node = node->next)
		;

	if (!node) {
		ux_err("empty firehose response\n");
		*error = -EINVAL;
		xmlFreeDoc(doc);
		return NULL;
	}

	return node;
}

static int firehose_generic_parser(xmlNode *node, void *data __unused, bool *rawmode)
{
	xmlChar *value;
	int ret = -EINVAL;

	value = xmlGetProp(node, (xmlChar *)"value");
	if (!value)
		return -EINVAL;

	if (xmlStrcmp(node->name, (xmlChar *)"log") == 0) {
		ux_log("LOG: %s\n", value);
		ret = -EAGAIN;
	} else if (xmlStrcmp(value, (xmlChar *)"ACK") == 0) {
		ret = FIREHOSE_ACK;
	} else if (xmlStrcmp(value, (xmlChar *)"NAK") == 0) {
		ret = FIREHOSE_NAK;
	}

	xmlFree(value);

	value = xmlGetProp(node, (xmlChar *)"rawmode");
	if (value) {
		if (xmlStrcmp(value, (xmlChar *)"true") == 0)
			*rawmode = true;
		xmlFree(value);
	}

	return ret;
}

static int firehose_read(struct qdl_device *qdl, int timeout_ms,
			 int (*response_parser)(xmlNode *node, void *data, bool *rawmode),
			 void *data)
{
	char buf[4096];
	xmlNode *node;
	int error;
	int resp = -EIO;
	int ret = -EAGAIN;
	int n;
	bool rawmode = false;
	struct timeval timeout;
	struct timeval now;
	struct timeval delta = { .tv_sec = timeout_ms / 1000,
				 .tv_usec = (timeout_ms % 1000) * 1000 };

	gettimeofday(&now, NULL);
	timeradd(&now, &delta, &timeout);

	/* In simulation mode we don't expent to read and parse any responses */
	if (qdl->dev_type == QDL_DEVICE_SIM)
		return 0;

	/*
	 * The goal of firehose_read() is to find a response to a request among
	 * one or more incoming messages AND to consume all incoming messages
	 * (otherwise subsequent writes will time out).
	 * The messages can be one of:
	 * - <log/>
	 * - <response value=""/>
	 * - <response value="" rawmode="true"/>
	 *
	 * Generally <log/> messages are coming prior to the <response/>, but
	 * on MSM8916 (at least) it's been observed that <log/> messages can
	 * arrive after the <response/>.
	 *
	 * We therefor need to consume messages until there are no more
	 * (timeout) and we have been able to parse out a response (using
	 * @response_parser).
	 *
	 * In the special case that the <response/> contain an attribute
	 * "rawmode=true", the device signals that it has entered a mode where
	 * it will not send/receive XML-formatted commands. So, (at least for
	 * reads) we need to shortcircuit the logic and directly terminate the
	 * consumption of incoming data.
	 */
	for (;;) {
		n = qdl_read(qdl, buf, sizeof(buf) - 1, 100);

		/* Timeout after seeing a response, we're done waiting for logs */
		if (n == -ETIMEDOUT && resp >= 0)
			break;
		/* We want to return resp on error, to not loose the reset resposne */
		else if (n == -EIO)
			break;

		if (n == -ETIMEDOUT || n == 0) {
			gettimeofday(&now, NULL);
			if (timercmp(&now, &timeout, <))
				continue;

			return -ETIMEDOUT;
		}
		buf[n] = '\0';

		ux_debug("FIREHOSE READ: %s\n", buf);

		/*
		 * COM port transport may deliver multiple XML documents
		 * in a single read (serial is a byte stream, unlike USB
		 * where each bulk transfer is a separate message).
		 *
		 * Additionally, a rawmode ACK may arrive concatenated
		 * with binary data that follows it.  We use the actual
		 * byte count (n) instead of strlen to handle embedded
		 * null bytes in binary data, truncate XML fragments at
		 * </data> boundaries, and save any trailing binary data
		 * as remainder for the raw-read loop.
		 */
		char *frag = buf;
		size_t buf_left = (size_t)n;

		while (buf_left > 0) {
			char *next_xml;
			char *data_end;
			size_t frag_len;
			size_t xml_len;

			/*
			 * Skip leading non-XML bytes — null bytes or
			 * binary residue from serial stream.
			 */
			while (buf_left > 0 && *frag != '<') {
				frag++;
				buf_left--;
			}
			if (buf_left == 0)
				break;

			/* Find next <?xml document boundary (null-safe) */
			next_xml = NULL;
			if (buf_left > 5)
				next_xml = find_in_mem(frag + 1, buf_left - 1,
						       "<?xml", 5);

			frag_len = next_xml ? (size_t)(next_xml - frag)
					    : buf_left;

			/*
			 * Truncate at </data> to separate XML from any
			 * trailing binary data (e.g. rawmode payload).
			 * Use find_in_mem for null-safety and to stay
			 * within fragment bounds.
			 */
			data_end = find_in_mem(frag, frag_len,
					       "</data>", 7);
			xml_len = frag_len;
			if (data_end)
				xml_len = (size_t)(data_end - frag) + 7;

			node = firehose_response_parse(frag, xml_len, &error);
			if (node) {
				ret = response_parser(node, data, &rawmode);
				xmlFreeDoc(node->doc);

				if (ret >= 0)
					resp = ret;
			}

			if (rawmode) {
				/*
				 * Save any data after the XML as
				 * remainder — this is the start of the
				 * binary raw-mode payload that arrived
				 * in the same read.
				 */
				char *after = frag + xml_len;
				size_t leftover = buf_left - xml_len;

				if (leftover > 0)
					fh_remainder_save(after, leftover);
				break;
			}

			if (next_xml) {
				buf_left -= (size_t)(next_xml - frag);
				frag = next_xml;
			} else {
				break;
			}
		}

		if (rawmode)
			break;
	}

	return resp;
}

static int firehose_write(struct qdl_device *qdl, xmlDoc *doc)
{
	int saved_errno;
	xmlChar *s;
	int len;
	int ret;

	xmlDocDumpMemory(doc, &s, &len);

	ret = vip_transfer_handle_tables(qdl);
	if (ret) {
		ux_err("VIP: error occurred during VIP table transmission\n");
		return -1;
	}
	if (vip_transfer_status_check_needed(qdl)) {
		ret = firehose_read(qdl, 30000, firehose_generic_parser, NULL);
		if (ret) {
			ux_err("VIP: sending of digest table failed\n");
			return -1;
		}

		ux_info("VIP: digest table has been sent successfully\n");

		vip_transfer_clear_status(qdl);
	}

	vip_gen_chunk_init(qdl);

	{
		int retries = 10;

		for (;;) {
			ux_debug("FIREHOSE WRITE: %s\n", s);
			vip_gen_chunk_update(qdl, s, len);
			ret = qdl_write(qdl, s, len, 1000);
			saved_errno = errno;

			/*
			 * db410c sometimes sends a <response> followed by
			 * <log> entries and won't accept write commands
			 * until these are drained, so attempt to read any
			 * pending data and then retry the write.
			 */
			if (ret < 0 && errno == ETIMEDOUT && retries-- > 0) {
				firehose_read(qdl, 100, firehose_generic_parser, NULL);
			} else {
				break;
			}
		}
	}
	xmlFree(s);
	vip_gen_chunk_store(qdl);
	return ret < 0 ? -saved_errno : 0;
}

/**
 * firehose_configure_response_parser() - parse a configure response
 * @node:	response xmlNode
 *
 * Return: max size supported by the remote, or negative errno on failure
 */
static int firehose_configure_response_parser(xmlNode *node, void *data,
					      bool *rawmode __unused)
{
	xmlChar *payload;
	xmlChar *value;
	size_t max_size;

	value = xmlGetProp(node, (xmlChar *)"value");
	if (!value)
		return -EINVAL;

	if (xmlStrcmp(node->name, (xmlChar *)"log") == 0) {
		ux_log("LOG: %s\n", value);
		xmlFree(value);
		return -EAGAIN;
	}

	payload = xmlGetProp(node, (xmlChar *)"MaxPayloadSizeToTargetInBytes");
	if (!payload) {
		xmlFree(value);
		return -EINVAL;
	}

	max_size = strtoul((char *)payload, NULL, 10);
	xmlFree(payload);

	/*
	 * When receiving an ACK the remote may indicate that we should attempt
	 * a larger payload size
	 */
	if (!xmlStrcmp(value, (xmlChar *)"ACK")) {
		payload = xmlGetProp(node, (xmlChar *)"MaxPayloadSizeToTargetInBytesSupported");
		if (!payload)
			return -EINVAL;

		max_size = strtoul((char *)payload, NULL, 10);
		xmlFree(payload);
	}

	*(size_t *)data = max_size;
	xmlFree(value);

	return FIREHOSE_ACK;
}

static int firehose_send_configure(struct qdl_device *qdl, size_t payload_size,
				   bool skip_storage_init,
				   enum qdl_storage_type storage,
				   size_t *max_payload_size)
{
	static const char * const memory_names[] = {
		[QDL_STORAGE_EMMC] = "emmc",
		[QDL_STORAGE_NAND] = "nand",
		[QDL_STORAGE_UFS] = "ufs",
		[QDL_STORAGE_NVME] = "nvme",
		[QDL_STORAGE_SPINOR] = "spinor",
	};
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	node = xmlNewChild(root, NULL, (xmlChar *)"configure", NULL);
	xml_setpropf(node, "MemoryName", memory_names[storage]);
	xml_setpropf(node, "MaxPayloadSizeToTargetInBytes", "%lu", payload_size);
	xml_setpropf(node, "Verbose", "%d", 0);
	xml_setpropf(node, "ZlpAwareHost", "%d", 1);
	xml_setpropf(node, "SkipStorageInit", "%d", skip_storage_init);

	firehose_write(qdl, doc);
	xmlFreeDoc(doc);

	return firehose_read(qdl, 100, firehose_configure_response_parser, max_payload_size);
}

static int firehose_try_configure(struct qdl_device *qdl, bool skip_storage_init,
				  enum qdl_storage_type storage)
{
	size_t max_sector_size;
	size_t sector_sizes[] = { 512, 4096 };
	struct read_op op;
	size_t size = 0;
	void *buf;
	int ret;
	unsigned int i;

	ret = firehose_send_configure(qdl, qdl->max_payload_size, skip_storage_init,
				      storage, &size);
	if (ret < 0)
		return ret;

	/*
	 * In simulateion mode "remote" target can't propose different size, so
	 * for QDL_DEVICE_SIM we just don't re-send configure packet
	 */
	if (qdl->dev_type == QDL_DEVICE_SIM)
		return 0;

	/* Retry if remote proposed different size */
	if (size != qdl->max_payload_size) {
		ret = firehose_send_configure(qdl, size, skip_storage_init, storage, &size);
		if (ret != FIREHOSE_ACK) {
			ux_err("configure request with updated payload size failed\n");
			return -1;
		}

		qdl->max_payload_size = size;
	}

	ux_debug("accepted max payload size: %zu\n", qdl->max_payload_size);

	if (storage != QDL_STORAGE_NAND) {
		max_sector_size = sector_sizes[ARRAY_SIZE(sector_sizes) - 1];
		buf = malloc(max_sector_size);
		memset(&op, 0, sizeof(op));
		op.partition = 0;
		op.start_sector = "1";
		op.num_sectors = 1;

		/*
		 * Testing has shown that the loader will fail gracefully if a
		 * read is issued with the wrong sector size, use this to attempt
		 * to discover the storage device's sector size.
		 */
		for (i = 0; i < ARRAY_SIZE(sector_sizes); i++) {
			op.sector_size = sector_sizes[i];

			ret = firehose_read_buf(qdl, &op, buf, max_sector_size);
			if (ret == 0) {
				qdl->sector_size = sector_sizes[i];
				break;
			}
		}
	}

	if (qdl->sector_size)
		ux_debug("detected sector size of: %zd\n", qdl->sector_size);

	return 0;
}

static int firehose_erase(struct qdl_device *qdl, struct program *program)
{
	unsigned int sector_size;
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;
	int ret;

	sector_size = program->sector_size ? : qdl->sector_size;

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	node = xmlNewChild(root, NULL, (xmlChar *)"erase", NULL);
	xml_setpropf(node, "SECTOR_SIZE_IN_BYTES", "%d", sector_size);
	xml_setpropf(node, "num_partition_sectors", "%d", program->num_sectors);
	xml_setpropf(node, "physical_partition_number", "%d", program->partition);
	xml_setpropf(node, "start_sector", "%s", program->start_sector);
	if (qdl->slot != UINT_MAX) {
		xml_setpropf(node, "slot", "%u", qdl->slot);
	}
	if (program->is_nand) {
		xml_setpropf(node, "PAGES_PER_BLOCK", "%d", program->pages_per_block);
	}

	ret = firehose_write(qdl, doc);
	if (ret < 0) {
		ux_err("failed to send program request\n");
		goto out;
	}

	ret = firehose_read(qdl, 30000, firehose_generic_parser, NULL);
	if (ret)
		ux_err("failed to erase %s+0x%x\n", program->start_sector, program->num_sectors);
	else
		ux_info("successfully erased %s+0x%x\n", program->start_sector, program->num_sectors);

out:
	xmlFreeDoc(doc);
	return ret == FIREHOSE_ACK ? 0 : -1;
}

static int firehose_program(struct qdl_device *qdl, struct program *program, int fd)
{
	unsigned int num_sectors;
	unsigned int sector_size;
	unsigned int zlp_timeout = 10000;
	struct stat sb;
	size_t chunk_size;
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;
	void *buf;
	time_t t0;
	time_t t;
	size_t left;
	int ret;
	int n;
	size_t i;
	uint32_t fill_value;

	/*
	 * ZLP has been measured to take up to 15 seconds on SPINOR devices,
	 * let's double it to be on the safe side...
	 */
	if (qdl->storage_type == QDL_STORAGE_SPINOR)
		zlp_timeout = 60000;

	num_sectors = program->num_sectors;
	sector_size = program->sector_size ? : qdl->sector_size;

	ret = fstat(fd, &sb);
	if (ret < 0)
		err(1, "failed to stat \"%s\"\n", program->filename);

	if (!program->sparse) {
		num_sectors = (sb.st_size + sector_size - 1) / sector_size;

		if (program->num_sectors && num_sectors > program->num_sectors) {
			ux_err("%s too big for %s truncated to %d\n",
			       program->filename,
			       program->label,
			       program->num_sectors * sector_size);
			num_sectors = program->num_sectors;
		}
	}

	buf = malloc(qdl->max_payload_size);
	if (!buf)
		err(1, "failed to allocate sector buffer");

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	node = xmlNewChild(root, NULL, (xmlChar *)"program", NULL);
	xml_setpropf(node, "SECTOR_SIZE_IN_BYTES", "%d", sector_size);
	xml_setpropf(node, "num_partition_sectors", "%d", num_sectors);
	xml_setpropf(node, "physical_partition_number", "%d", program->partition);
	xml_setpropf(node, "start_sector", "%s", program->start_sector);
	if (qdl->slot != UINT_MAX) {
		xml_setpropf(node, "slot", "%u", qdl->slot);
	}
	if (program->label)
		xml_setpropf(node, "label", "%s", program->label);
	if (program->filename)
		xml_setpropf(node, "filename", "%s", program->filename);

	if (program->is_nand) {
		xml_setpropf(node, "PAGES_PER_BLOCK", "%d", program->pages_per_block);
		/* Only add last_sector if it was explicitly set in the XML */
		if (program->last_sector)
			xml_setpropf(node, "last_sector", "%d", program->last_sector);
	}

	ret = firehose_write(qdl, doc);
	if (ret < 0) {
		ux_err("failed to send program request\n");
		goto out;
	}

	ret = firehose_read(qdl, 10000, firehose_generic_parser, NULL);
	if (ret) {
		ux_err("failed to setup programming\n");
		goto out;
	}

	t0 = time(NULL);

	if (!program->sparse) {
		lseek(fd, (off_t)program->file_offset * sector_size, SEEK_SET);
	} else {
		switch (program->sparse_chunk_type) {
		case CHUNK_TYPE_RAW:
			lseek(fd, program->sparse_offset, SEEK_SET);
			break;
		case CHUNK_TYPE_FILL:
			fill_value = program->sparse_fill_value;
			for (i = 0; i < qdl->max_payload_size; i += sizeof(fill_value))
				memcpy(buf + i, &fill_value, sizeof(fill_value));
			break;
		default:
			ux_err("[SPARSE] invalid chunk type\n");
			goto out;
		}
	}

	left = num_sectors;

	ux_debug("FIREHOSE RAW BINARY WRITE: %s, %d bytes\n",
		 program->filename, sector_size * num_sectors);

	while (left > 0) {
		/*
		 * We should calculate hash for every raw packet sent,
		 * not for the whole binary.
		 */
		vip_gen_chunk_init(qdl);
		chunk_size = MIN(qdl->max_payload_size / sector_size, left);

		if (!program->sparse || program->sparse_chunk_type != CHUNK_TYPE_FILL) {
			n = read(fd, buf, chunk_size * sector_size);
			if (n < 0) {
				ux_err("failed to read %s\n", program->filename);
				goto out;
			}

			if ((size_t)n < qdl->max_payload_size)
				memset(buf + n, 0, qdl->max_payload_size - n);
		}

		vip_gen_chunk_update(qdl, buf, chunk_size * sector_size);

		ret = vip_transfer_handle_tables(qdl);
		if (ret) {
			ux_err("VIP: error occurred during VIP table transmission\n");
			return -1;
		}
		if (vip_transfer_status_check_needed(qdl)) {
			ret = firehose_read(qdl, 30000, firehose_generic_parser, NULL);
			if (ret) {
				ux_err("VIP: sending of digest table failed\n");
				return -1;
			}

			ux_info("VIP: digest table has been sent successfully\n");

			vip_transfer_clear_status(qdl);
		}
		n = qdl_write(qdl, buf, chunk_size * sector_size, zlp_timeout);
		if (n < 0) {
			ux_err("USB write failed for data chunk\n");
			ret = firehose_read(qdl, 30000, firehose_generic_parser, NULL);
			if (ret)
				ux_err("flashing of chunk failed\n");

			goto out;
		}

		if ((size_t)n != chunk_size * sector_size) {
			ux_err("USB write truncated\n");
			ret = -1;
			goto out;
		}

		left -= chunk_size;
		vip_gen_chunk_store(qdl);

		ux_progress("%s", num_sectors - left, num_sectors, program->label);
	}

	t = time(NULL) - t0;

	ret = firehose_read(qdl, 120000, firehose_generic_parser, NULL);
	if (ret) {
		ux_err("flashing of %s failed\n", program->label);
	} else if (t) {
		ux_info("flashed \"%s\" successfully at %lukB/s\n",
			program->label,
			(unsigned long)sector_size * num_sectors / t / 1024);
	} else {
		ux_info("flashed \"%s\" successfully\n",
			program->label);
	}

out:
	xmlFreeDoc(doc);
	free(buf);

	return ret == FIREHOSE_ACK ? 0 : -1;
}

static int firehose_issue_read(struct qdl_device *qdl, struct read_op *read_op,
			       int fd, void *out_buf, size_t out_len, bool quiet)
{
	unsigned int sector_size;
	size_t chunk_size;
	size_t buf_size;
	size_t out_offset = 0;
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;
	void *buf;
	time_t t0;
	time_t t;
	size_t left;
	int ret;
	int n;

	/*
	 * Use a large accumulation buffer to minimise disk-write
	 * frequency during rawmode.  On serial transports (Windows
	 * COM port), each write(fd) creates a brief gap during which
	 * the driver's receive buffer accumulates incoming data.
	 * With NAND's 16 KB max_payload_size a 120 MB partition
	 * needs ~7 700 writes, and the cumulative gaps can overflow
	 * the COM port buffer.  A 1 MB floor reduces that to ~120.
	 */
	buf_size = qdl->max_payload_size;
	if (buf_size < 1024 * 1024)
		buf_size = 1024 * 1024;

	buf = malloc(buf_size);
	if (!buf)
		err(1, "failed to allocate sector buffer");

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	sector_size = read_op->sector_size ? : qdl->sector_size;

	node = xmlNewChild(root, NULL, (xmlChar *)"read", NULL);
	xml_setpropf(node, "SECTOR_SIZE_IN_BYTES", "%d", sector_size);
	xml_setpropf(node, "num_partition_sectors", "%d", read_op->num_sectors);
	xml_setpropf(node, "physical_partition_number", "%d", read_op->partition);
	xml_setpropf(node, "start_sector", "%s", read_op->start_sector);
	if (qdl->slot != UINT_MAX) {
		xml_setpropf(node, "slot", "%u", qdl->slot);
	}
	if (read_op->pages_per_block)
		xml_setpropf(node, "PAGES_PER_BLOCK", "%d", read_op->pages_per_block);
	if (read_op->filename)
		xml_setpropf(node, "filename", "%s", read_op->filename);

	ret = firehose_write(qdl, doc);
	if (ret < 0) {
		ux_err("failed to send read command\n");
		goto out;
	}

	ret = firehose_read(qdl, 10000, firehose_generic_parser, NULL);
	if (ret) {
		if (!quiet)
			ux_err("failed to setup reading operation\n");
		goto out;
	}

	t0 = time(NULL);

	left = read_op->num_sectors;
	while (left > 0) {
		size_t wanted;
		size_t got;

		chunk_size = MIN(buf_size / sector_size, left);
		wanted = chunk_size * sector_size;

		/*
		 * On serial transports the rawmode ACK and the start
		 * of the binary payload may arrive in one read, with
		 * firehose_read() saving the overflow to a remainder
		 * buffer.  Drain that first, then read the rest from
		 * the device, looping as needed since serial reads
		 * can return partial results.
		 */
		got = fh_remainder_drain(buf, wanted);
		while (got < wanted) {
			n = qdl_read(qdl, (char *)buf + got,
				     wanted - got, 30000);
			if (n < 0) {
				ux_err("raw read failed (error %d) at %.1f%% of %s\n",
				       n,
				       100.0 * (read_op->num_sectors - left) / read_op->num_sectors,
				       read_op->filename ? read_op->filename : "?");
				/*
				 * Write whatever we received before the
				 * error so the output file is as complete
				 * as possible (better to lose a few bytes
				 * at the end than an entire chunk).
				 */
				if (got > 0 && fd >= 0) {
					int wr __attribute__((unused));
					wr = write(fd, buf, got);
				}
				ret = -1;
				goto drain;
			}
			if (n == 0) {
				ux_err("unexpected EOF at %.1f%% of %s\n",
				       100.0 * (read_op->num_sectors - left) / read_op->num_sectors,
				       read_op->filename ? read_op->filename : "?");
				if (got > 0 && fd >= 0) {
					int wr __attribute__((unused));
					wr = write(fd, buf, got);
				}
				ret = -1;
				goto drain;
			}
			got += (size_t)n;
		}
		n = (int)got;

		if (out_buf) {
			if ((size_t)n > out_len - out_offset)
				n = out_len - out_offset;

			memcpy(out_buf + out_offset, buf, n);
			out_offset += n;
		} else {
			n = write(fd, buf, n);

			if (n < 0 || (size_t)n != chunk_size * sector_size) {
				err(1, "failed to write");
			}
		}

		left -= chunk_size;

		if (!quiet)
			ux_progress("%s", read_op->num_sectors - left, read_op->num_sectors, read_op->filename);
	}

drain:
	/*
	 * Drain remaining rawmode data and the closing ACK so the
	 * stream is re-synchronised for subsequent commands.
	 * On failure (mid-read error) discard whatever remains;
	 * on success this consumes the normal rawmode=false ACK.
	 */
	fh_remainder_len = 0;
	if (ret) {
		int drain_n;

		do {
			drain_n = qdl_read(qdl, buf, buf_size, 2000);
		} while (drain_n > 0);
	}

	if (firehose_read(qdl, 10000, firehose_generic_parser, NULL)) {
		if (!ret)
			ux_err("read operation failed\n");
		ret = -1;
		goto out;
	}

	t = time(NULL) - t0;

	if (!quiet) {
		if (t) {
			ux_info("read \"%s\" successfully at %ldkB/s\n",
				read_op->filename,
				(unsigned long)sector_size * read_op->num_sectors / t / 1024);
		} else {
			ux_info("read \"%s\" successfully\n",
				read_op->filename);
		}
	}

out:
	xmlFreeDoc(doc);
	free(buf);
	return ret;
}

int firehose_read_buf(struct qdl_device *qdl, struct read_op *read_op, void *out_buf, size_t out_size)
{
	return firehose_issue_read(qdl, read_op, -1, out_buf, out_size, true);
}

static int firehose_read_op(struct qdl_device *qdl, struct read_op *read_op, int fd)
{
	return firehose_issue_read(qdl, read_op, fd, NULL, 0, false);
}

static int firehose_apply_patch(struct qdl_device *qdl, struct patch *patch)
{
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;
	int ret;

	ux_debug("applying patch \"%s\"\n", patch->what);

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	node = xmlNewChild(root, NULL, (xmlChar *)"patch", NULL);
	xml_setpropf(node, "SECTOR_SIZE_IN_BYTES", "%d", patch->sector_size);
	xml_setpropf(node, "byte_offset", "%d", patch->byte_offset);
	xml_setpropf(node, "filename", "%s", patch->filename);
	xml_setpropf(node, "physical_partition_number", "%d", patch->partition);
	xml_setpropf(node, "size_in_bytes", "%d", patch->size_in_bytes);
	xml_setpropf(node, "start_sector", "%s", patch->start_sector);
	xml_setpropf(node, "value", "%s", patch->value);
	if (qdl->slot != UINT_MAX) {
		xml_setpropf(node, "slot", "%u", qdl->slot);
	}

	ret = firehose_write(qdl, doc);
	if (ret < 0)
		goto out;

	ret = firehose_read(qdl, 5000, firehose_generic_parser, NULL);
	if (ret)
		ux_err("patch application failed\n");

out:
	xmlFreeDoc(doc);
	return ret == FIREHOSE_ACK ? 0 : -1;
}

static int firehose_send_single_tag(struct qdl_device *qdl, xmlNode *node)
{
	xmlNode *root;
	xmlDoc *doc;
	int ret;

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);
	xmlAddChild(root, node);

	ret = firehose_write(qdl, doc);
	if (ret < 0)
		goto out;

	ret = firehose_read(qdl, 5000, firehose_generic_parser, NULL);
	if (ret) {
		ux_err("ufs request failed\n");
		ret = -EINVAL;
	}

out:
	xmlFreeDoc(doc);
	return ret;
}

int firehose_apply_ufs_common(struct qdl_device *qdl, struct ufs_common *ufs)
{
	xmlNode *node_to_send;
	int ret;

	node_to_send = xmlNewNode(NULL, (xmlChar *)"ufs");

	xml_setpropf(node_to_send, "bNumberLU", "%d", ufs->bNumberLU);
	xml_setpropf(node_to_send, "bBootEnable", "%d", ufs->bBootEnable);
	xml_setpropf(node_to_send, "bDescrAccessEn", "%d", ufs->bDescrAccessEn);
	xml_setpropf(node_to_send, "bInitPowerMode", "%d", ufs->bInitPowerMode);
	xml_setpropf(node_to_send, "bHighPriorityLUN", "%d", ufs->bHighPriorityLUN);
	xml_setpropf(node_to_send, "bSecureRemovalType", "%d", ufs->bSecureRemovalType);
	xml_setpropf(node_to_send, "bInitActiveICCLevel", "%d", ufs->bInitActiveICCLevel);
	xml_setpropf(node_to_send, "wPeriodicRTCUpdate", "%d", ufs->wPeriodicRTCUpdate);
	xml_setpropf(node_to_send, "bConfigDescrLock", "%d", ufs->bConfigDescrLock);
	if (qdl->slot != UINT_MAX) {
		xml_setpropf(node_to_send, "slot", "%u", qdl->slot);
	}

	if (ufs->wb) {
		xml_setpropf(node_to_send, "bWriteBoosterBufferPreserveUserSpaceEn",
			     "%d", ufs->bWriteBoosterBufferPreserveUserSpaceEn);
		xml_setpropf(node_to_send, "bWriteBoosterBufferType", "%d", ufs->bWriteBoosterBufferType);
		xml_setpropf(node_to_send, "shared_wb_buffer_size_in_kb", "%d", ufs->shared_wb_buffer_size_in_kb);
	}

	ret = firehose_send_single_tag(qdl, node_to_send);
	if (ret)
		ux_err("failed to send ufs common tag\n");

	return ret == FIREHOSE_ACK ? 0 : -1;
}

int firehose_apply_ufs_body(struct qdl_device *qdl, struct ufs_body *ufs)
{
	xmlNode *node_to_send;
	int ret;

	node_to_send = xmlNewNode(NULL, (xmlChar *)"ufs");

	xml_setpropf(node_to_send, "LUNum", "%d", ufs->LUNum);
	xml_setpropf(node_to_send, "bLUEnable", "%d", ufs->bLUEnable);
	xml_setpropf(node_to_send, "bBootLunID", "%d", ufs->bBootLunID);
	xml_setpropf(node_to_send, "size_in_kb", "%d", ufs->size_in_kb);
	xml_setpropf(node_to_send, "bDataReliability", "%d", ufs->bDataReliability);
	xml_setpropf(node_to_send, "bLUWriteProtect", "%d", ufs->bLUWriteProtect);
	xml_setpropf(node_to_send, "bMemoryType", "%d", ufs->bMemoryType);
	xml_setpropf(node_to_send, "bLogicalBlockSize", "%d", ufs->bLogicalBlockSize);
	xml_setpropf(node_to_send, "bProvisioningType", "%d", ufs->bProvisioningType);
	xml_setpropf(node_to_send, "wContextCapabilities", "%d", ufs->wContextCapabilities);
	if (qdl->slot != UINT_MAX) {
		xml_setpropf(node_to_send, "slot", "%u", qdl->slot);
	}
	if (ufs->desc)
		xml_setpropf(node_to_send, "desc", "%s", ufs->desc);

	ret = firehose_send_single_tag(qdl, node_to_send);
	if (ret)
		ux_err("failed to apply ufs body tag\n");

	return ret == FIREHOSE_ACK ? 0 : -1;
}

int firehose_apply_ufs_epilogue(struct qdl_device *qdl, struct ufs_epilogue *ufs,
				bool commit)
{
	xmlNode *node_to_send;
	int ret;

	node_to_send = xmlNewNode(NULL, (xmlChar *)"ufs");

	xml_setpropf(node_to_send, "LUNtoGrow", "%d", ufs->LUNtoGrow);
	xml_setpropf(node_to_send, "commit", "%d", commit);
	if (qdl->slot != UINT_MAX) {
		xml_setpropf(node_to_send, "slot", "%u", qdl->slot);
	}

	ret = firehose_send_single_tag(qdl, node_to_send);
	if (ret)
		ux_err("failed to apply ufs epilogue\n");

	return ret == FIREHOSE_ACK ? 0 : -1;
}

static int firehose_set_bootable(struct qdl_device *qdl, int part)
{
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;
	int ret;

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	node = xmlNewChild(root, NULL, (xmlChar *)"setbootablestoragedrive", NULL);
	xml_setpropf(node, "value", "%d", part);

	ret = firehose_write(qdl, doc);
	xmlFreeDoc(doc);
	if (ret < 0)
		return -1;

	ret = firehose_read(qdl, 5000, firehose_generic_parser, NULL);
	if (ret) {
		ux_err("failed to mark partition %d as bootable\n", part);
		return -1;
	}

	ux_info("partition %d is now bootable\n", part);
	return 0;
}

int firehose_power(struct qdl_device *qdl, const char *mode, int delay)
{
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;
	int ret;

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	node = xmlNewChild(root, NULL, (xmlChar *)"power", NULL);
	xml_setpropf(node, "value", "%s", mode);
	xml_setpropf(node, "DelayInSeconds", "%d", delay);

	ret = firehose_write(qdl, doc);
	xmlFreeDoc(doc);
	if (ret < 0)
		return -1;

	ret = firehose_read(qdl, 5000, firehose_generic_parser, NULL);
	if (ret < 0)
		ux_err("failed to send power command '%s'\n", mode);
	/* drain any remaining log messages */
	else
		firehose_read(qdl, 1000, firehose_generic_parser, NULL);

	return ret == FIREHOSE_ACK ? 0 : -1;
}

static int firehose_reset(struct qdl_device *qdl)
{
	return firehose_power(qdl, "reset", 10);
}

int firehose_detect_and_configure(struct qdl_device *qdl,
				  bool skip_storage_init,
				  enum qdl_storage_type storage,
				  unsigned int timeout_s)
{
	struct timeval timeout = { .tv_sec = timeout_s };
	struct timeval now;
	int ret;

	gettimeofday(&now, NULL);
	timeradd(&now, &timeout, &timeout);
	for (;;) {
		ret = firehose_try_configure(qdl, skip_storage_init, storage);

		if (ret == FIREHOSE_ACK) {
			break;
		} else if (ret != -ETIMEDOUT) {
			ux_err("configure request failed\n");
			return -1;
		}

		gettimeofday(&now, NULL);
		if (timercmp(&now, &timeout, >)) {
			ux_err("failed to detect firehose programmer\n");
			return -1;
		}
	}

	return 0;
}

int firehose_provision(struct qdl_device *qdl)
{
	int ret;

	ret = firehose_detect_and_configure(qdl, true, QDL_STORAGE_UFS, 5);
	if (ret)
		return ret;

	ret = ufs_provisioning_execute(qdl, firehose_apply_ufs_common,
				       firehose_apply_ufs_body,
				       firehose_apply_ufs_epilogue);
	if (!ret)
		ux_info("UFS provisioning succeeded\n");
	else
		ux_info("UFS provisioning failed\n");

	firehose_reset(qdl);

	return ret;

}

int firehose_run(struct qdl_device *qdl)
{
	bool multiple;
	int bootable;
	int ret;

	ux_info("waiting for programmer...\n");

	ret = firehose_detect_and_configure(qdl, false, qdl->storage_type, 5);
	if (ret)
		return ret;

	ret = read_resolve_gpt_deferrals(qdl);
	if (ret)
		return ret;

	ret = program_resolve_gpt_deferrals(qdl);
	if (ret)
		return ret;

	ret = firehose_op_execute(qdl, firehose_erase, firehose_program,
				  firehose_read_op, firehose_apply_patch);
	if (ret)
		return ret;

	bootable = program_find_bootable_partition(&multiple);
	if (bootable < 0) {
		ux_debug("no boot partition found\n");
	} else {
		if (multiple) {
			ux_info("Multiple candidates for primary bootloader found, using partition %d\n",
				bootable);
		}
		firehose_set_bootable(qdl, bootable);
	}

	firehose_reset(qdl);

	return 0;
}

static int firehose_getstorageinfo_parser(xmlNode *node, void *data,
					  bool *rawmode __unused)
{
	struct storage_info *info = data;
	xmlChar *value;
	int ret = -EINVAL;
	char *text;
	char *eq;

	value = xmlGetProp(node, (xmlChar *)"value");
	if (!value)
		return -EINVAL;

	text = (char *)value;

	if (xmlStrcmp(node->name, (xmlChar *)"log") == 0) {
		ux_log("LOG: %s\n", text);

		/* Parse key=value format (UFS/eMMC programmers) */
		if ((eq = strstr(text, "total_blocks=")))
			info->total_blocks = strtoul(eq + 13, NULL, 0);
		if ((eq = strstr(text, "block_size=")))
			info->block_size = strtoul(eq + 11, NULL, 0);
		if ((eq = strstr(text, "page_size=")))
			info->page_size = strtoul(eq + 10, NULL, 0);
		if ((eq = strstr(text, "num_physical_partitions=")))
			info->num_physical = strtoul(eq + 24, NULL, 0);
		if ((eq = strstr(text, "SECTOR_SIZE_IN_BYTES=")))
			info->sector_size = strtoul(eq + 21, NULL, 0);
		if ((eq = strstr(text, "mem_type=")))
			snprintf(info->mem_type, sizeof(info->mem_type),
				 "%s", eq + 9);
		if ((eq = strstr(text, "prod_name=")))
			snprintf(info->prod_name, sizeof(info->prod_name),
				 "%s", eq + 10);

		/* Parse JSON format (NAND programmers) */
		if ((eq = strstr(text, "\"total_blocks\":")))
			info->total_blocks = strtoul(eq + 15, NULL, 0);
		if ((eq = strstr(text, "\"block_size\":")))
			info->block_size = strtoul(eq + 13, NULL, 0);
		if ((eq = strstr(text, "\"page_size\":")))
			info->page_size = strtoul(eq + 12, NULL, 0);
		if ((eq = strstr(text, "\"num_physical\":")))
			info->num_physical = strtoul(eq + 15, NULL, 0);
		if ((eq = strstr(text, "\"mem_type\":\""))) {
			char *end = strchr(eq + 12, '"');
			if (end) {
				size_t len = end - (eq + 12);
				if (len >= sizeof(info->mem_type))
					len = sizeof(info->mem_type) - 1;
				memcpy(info->mem_type, eq + 12, len);
				info->mem_type[len] = '\0';
			}
		}
		if ((eq = strstr(text, "\"prod_name\":\""))) {
			char *end = strchr(eq + 13, '"');
			if (end) {
				size_t len = end - (eq + 13);
				if (len >= sizeof(info->prod_name))
					len = sizeof(info->prod_name) - 1;
				memcpy(info->prod_name, eq + 13, len);
				info->prod_name[len] = '\0';
			}
		}

		ret = -EAGAIN;
	} else if (xmlStrcmp(value, (xmlChar *)"ACK") == 0) {
		ret = FIREHOSE_ACK;
	} else if (xmlStrcmp(value, (xmlChar *)"NAK") == 0) {
		ret = FIREHOSE_NAK;
	}

	xmlFree(value);
	return ret;
}

int firehose_getstorageinfo(struct qdl_device *qdl,
			    unsigned int phys_partition,
			    struct storage_info *info)
{
	xmlNode *root;
	xmlNode *node;
	xmlDoc *doc;
	int ret;

	memset(info, 0, sizeof(*info));

	doc = xmlNewDoc((xmlChar *)"1.0");
	root = xmlNewNode(NULL, (xmlChar *)"data");
	xmlDocSetRootElement(doc, root);

	node = xmlNewChild(root, NULL, (xmlChar *)"getstorageinfo", NULL);
	xml_setpropf(node, "physical_partition_number", "%d", phys_partition);

	ret = firehose_write(qdl, doc);
	xmlFreeDoc(doc);
	if (ret < 0)
		return -1;

	ret = firehose_read(qdl, 10000, firehose_getstorageinfo_parser, info);
	return ret == FIREHOSE_ACK ? 0 : -1;
}

int firehose_read_to_file(struct qdl_device *qdl, unsigned int partition,
			  unsigned int start_sector, unsigned int num_sectors,
			  unsigned int sector_size, unsigned int pages_per_block,
			  const char *filename)
{
	struct read_op op;
	char start_str[32];
	unsigned int sectors_done = 0;
	int retries_left = 3;
	int fd;
	int ret;

	if (!sector_size)
		sector_size = qdl->sector_size;

	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		ux_err("failed to open %s for writing: %s\n",
		       filename, strerror(errno));
		return -1;
	}

retry:
	snprintf(start_str, sizeof(start_str), "%u",
		 start_sector + sectors_done);

	memset(&op, 0, sizeof(op));
	op.sector_size = sector_size;
	op.pages_per_block = pages_per_block;
	op.start_sector = start_str;
	op.num_sectors = num_sectors - sectors_done;
	op.partition = partition;
	op.filename = filename;

	ret = firehose_issue_read(qdl, &op, fd, NULL, 0, false);
	if (ret && retries_left > 0) {
		/*
		 * Check how many complete sectors were written.
		 * If we made progress, seek back to the sector
		 * boundary (in case of a partial write) and retry
		 * the remaining sectors with a new read command.
		 */
		off_t pos = lseek(fd, 0, SEEK_CUR);
		unsigned int written = pos > 0 ?
			(unsigned int)(pos / sector_size) : 0;

		if (written > sectors_done) {
			sectors_done = written;
			lseek(fd, (off_t)sectors_done * sector_size,
			      SEEK_SET);
			retries_left--;
			ux_info("retrying from sector %u (%u of %u remaining)\n",
				start_sector + sectors_done,
				num_sectors - sectors_done, num_sectors);
			goto retry;
		}
	}

	close(fd);
	return ret;
}
