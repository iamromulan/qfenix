// SPDX-License-Identifier: BSD-3-Clause
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libusb.h>
#include "oscompat.h"

#include "qdl.h"
#include "usb_ids.h"
#include "diag_switch.h"

#define DEFAULT_OUT_CHUNK_SIZE (1024 * 1024)

struct qdl_device_usb {
	struct qdl_device base;
	struct libusb_device_handle *usb_handle;

	int in_ep;
	int out_ep;

	size_t in_maxpktsize;
	size_t out_maxpktsize;
	size_t out_chunk_size;
};

/*
 * libusb commit f0cce43f882d ("core: Fix definition and use of enum
 * libusb_transfer_type") split transfer type and endpoint transfer types.
 * Provide an alias in order to make the code compile with the old (non-split)
 * definition.
 */
#ifndef LIBUSB_ENDPOINT_TRANSFER_TYPE_BULK
#define LIBUSB_ENDPOINT_TRANSFER_TYPE_BULK LIBUSB_TRANSFER_TYPE_BULK
#endif

/*
 * Runtime-extendable EDL-mode device allowlist.
 *
 * The built-in list in usb_ids.h covers well-known Qualcomm / Sony / Sierra
 * / etc. EDL PIDs. Callers (typically main() in qdl.c) can extend it at
 * runtime via usb_add_extra_edl_id() to cover:
 *
 *   - One-off OEM variants whose PID isn't in the built-in list yet.
 *   - OEM boot modes that speak Sahara but aren't publicly documented.
 *   - Ad-hoc debugging against an unknown PID without a recompile.
 *
 * Kept as file-scope state in usb.c (not usb_ids.h) because usb_ids.h is a
 * "static inline" header consumed by many translation units — a runtime
 * mutable array in a static-inline header would silently diverge per TU.
 */
#define USB_EXTRA_EDL_MAX 16

static struct {
	uint16_t vid;
	uint16_t pid;
} usb_extra_edl_ids[USB_EXTRA_EDL_MAX];
static unsigned int usb_extra_edl_count;

/*
 * Register an additional VID:PID pair as an EDL-mode endpoint for the
 * current qfenix process. Returns 0 on success, -1 if the table is full.
 * Duplicates (either against the built-in list or an existing extra) are
 * silently ignored.
 */
int usb_add_extra_edl_id(uint16_t vid, uint16_t pid)
{
	unsigned int i;

	if (is_edl_device(vid, pid))
		return 0;

	for (i = 0; i < usb_extra_edl_count; i++) {
		if (usb_extra_edl_ids[i].vid == vid &&
		    usb_extra_edl_ids[i].pid == pid)
			return 0;
	}

	if (usb_extra_edl_count >= USB_EXTRA_EDL_MAX) {
		warnx("usb: --usb-id table full (max %d), ignoring %04x:%04x",
		      USB_EXTRA_EDL_MAX, vid, pid);
		return -1;
	}

	usb_extra_edl_ids[usb_extra_edl_count].vid = vid;
	usb_extra_edl_ids[usb_extra_edl_count].pid = pid;
	usb_extra_edl_count++;
	return 0;
}

static bool usb_is_edl_device_runtime(uint16_t vid, uint16_t pid)
{
	unsigned int i;

	if (is_edl_device(vid, pid))
		return true;

	for (i = 0; i < usb_extra_edl_count; i++) {
		if (usb_extra_edl_ids[i].vid == vid &&
		    usb_extra_edl_ids[i].pid == pid)
			return true;
	}
	return false;
}

/*
 * Extract a serial-number-like string from a device's USB descriptors.
 *
 * Qualcomm's "Gobi" reference composition advertises a serial embedded in
 * iProduct as ``<name>_SN:<serial>`` — e.g. ``QUSB__BULK_SN:1234abcd``. This
 * has historically been the only signal qfenix consulted, which works fine
 * for Qualcomm-branded EDL devices but BREAKS for OEM boot modes that
 * populate iSerialNumber instead of stuffing the serial into iProduct.
 *
 * Concrete case that motivated this: Sierra Wireless EM7511 in
 * 1199:9090 AirPrime Boot mode. Its iProduct is ``Sierra Wireless EM7511
 * Qualcomm® Snapdragon™ X16 LTE-A`` (no ``_SN:``) but iSerialNumber is
 * ``YT94979507031546`` — a perfectly usable FSN. Previously qfenix rejected
 * the device with "ignoring device with no serial number".
 *
 * Fallback order:
 *   1. iProduct descriptor, after ``_SN:`` marker (Qualcomm-style embedding).
 *   2. iSerialNumber descriptor verbatim (OEM-style serial).
 *
 * Returns 1 on success (serial written to out, null-terminated, truncated
 * to out_sz-1) or 0 if neither source yielded a serial.
 */
static int usb_read_device_serial(struct libusb_device_handle *handle,
				  const struct libusb_device_descriptor *desc,
				  char *out, size_t out_sz)
{
	unsigned char buf[128];
	const char *src = NULL;
	size_t src_len = 0;
	int ret;

	if (!out || out_sz == 0)
		return 0;

	/* 1. Try iProduct ``_SN:`` embedding first — preserves prior behavior
	 *    for Qualcomm-branded EDL devices that already worked. */
	if (desc->iProduct) {
		ret = libusb_get_string_descriptor_ascii(handle, desc->iProduct,
							 buf, sizeof(buf) - 1);
		if (ret < 0) {
			/* Preserve the pre-refactor diagnostic: the old code
			 * logged libusb_strerror(ret) and aborted this device.
			 * We log and fall through so the iSerialNumber branch
			 * still gets a chance — a failed iProduct read doesn't
			 * preclude iSerialNumber from succeeding. */
			warnx("failed to read iProduct descriptor (idVendor=%04x idProduct=%04x): %s",
			      desc->idVendor, desc->idProduct,
			      libusb_strerror(ret));
		} else {
			buf[ret] = '\0';
			char *p = strstr((char *)buf, "_SN:");
			if (p) {
				p += strlen("_SN:");
				src = p;
				src_len = strcspn(p, " _");
			}
		}
	}

	/* 2. Fallback: iSerialNumber descriptor.
	 *    Trigger when step 1 didn't match OR matched but produced an
	 *    empty serial (iProduct contained ``_SN:`` followed immediately
	 *    by EOL/space/underscore). The empty-match case is rare but
	 *    exercised by malformed iProduct strings in the wild. */
	if ((!src || src_len == 0) && desc->iSerialNumber) {
		ret = libusb_get_string_descriptor_ascii(handle, desc->iSerialNumber,
							 buf, sizeof(buf) - 1);
		if (ret < 0) {
			warnx("failed to read iSerialNumber descriptor (idVendor=%04x idProduct=%04x): %s",
			      desc->idVendor, desc->idProduct,
			      libusb_strerror(ret));
		} else if (ret > 0) {
			buf[ret] = '\0';
			/* Trim trailing whitespace. */
			while (ret > 0 && (buf[ret - 1] == ' ' ||
					   buf[ret - 1] == '\t' ||
					   buf[ret - 1] == '\r' ||
					   buf[ret - 1] == '\n'))
				buf[--ret] = '\0';
			if (ret > 0) {
				src = (const char *)buf;
				src_len = (size_t)ret;
			}
		}
	}

	if (!src || src_len == 0)
		return 0;

	if (src_len >= out_sz)
		src_len = out_sz - 1;

	memcpy(out, src, src_len);
	out[src_len] = '\0';
	return 1;
}

static bool usb_match_usb_serial(struct libusb_device_handle *handle, const char *serial,
				 const struct libusb_device_descriptor *desc)
{
	char buf[128];

	/* If no serial is requested, consider everything a match */
	if (!serial)
		return true;

	if (!usb_read_device_serial(handle, desc, buf, sizeof(buf)))
		return false;

	return strcmp(buf, serial) == 0;
}

static int usb_try_open(libusb_device *dev, struct qdl_device_usb *qdl, const char *serial)
{
	const struct libusb_endpoint_descriptor *endpoint;
	const struct libusb_interface_descriptor *ifc;
	struct libusb_config_descriptor *config;
	struct libusb_device_descriptor desc;
	struct libusb_device_handle *handle;
	size_t out_size;
	size_t in_size;
	uint8_t type;
	int ret;
	int out;
	int in;
	int k;
	int l;

	ret = libusb_get_device_descriptor(dev, &desc);
	if (ret < 0) {
		warnx("failed to get USB device descriptor");
		return -1;
	}

	/* Consider only known EDL-mode devices (built-in list + any
	 * entries added at runtime via --usb-id). */
	if (!usb_is_edl_device_runtime(desc.idVendor, desc.idProduct))
		return 0;

	ret = libusb_get_active_config_descriptor(dev, &config);
	if (ret < 0) {
		warnx("failed to acquire USB device's active config descriptor");
		return -1;
	}

	for (k = 0; k < config->bNumInterfaces; k++) {
		ifc = config->interface[k].altsetting;

		in = -1;
		out = -1;
		in_size = 0;
		out_size = 0;

		for (l = 0; l < ifc->bNumEndpoints; l++) {
			endpoint = &ifc->endpoint[l];

			type = endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
			if (type != LIBUSB_ENDPOINT_TRANSFER_TYPE_BULK)
				continue;

			if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
				in = endpoint->bEndpointAddress;
				in_size = endpoint->wMaxPacketSize;
			} else {
				out = endpoint->bEndpointAddress;
				out_size = endpoint->wMaxPacketSize;
			}
		}

		if (ifc->bInterfaceClass != 0xff)
			continue;

		if (ifc->bInterfaceSubClass != 0xff)
			continue;

		/* bInterfaceProtocol of 0xff, 0x10 and 0x11 has been seen */
		if (ifc->bInterfaceProtocol != 0xff &&
		    ifc->bInterfaceProtocol != 16 &&
		    ifc->bInterfaceProtocol != 17)
			continue;

		ret = libusb_open(dev, &handle);
		if (ret < 0) {
#ifdef _WIN32
			/*
			 * NOT_SUPPORTED means no WinUSB driver (e.g.
			 * QDLoader driver is installed instead).
			 */
			if (ret == LIBUSB_ERROR_NOT_SUPPORTED) {
				libusb_free_config_descriptor(config);
				return -2;
			}
#endif
			warnx("unable to open USB device: %s",
			      libusb_strerror(ret));
			continue;
		}

		if (!usb_match_usb_serial(handle, serial, &desc)) {
			libusb_close(handle);
			continue;
		}

		libusb_detach_kernel_driver(handle, ifc->bInterfaceNumber);

		ret = libusb_claim_interface(handle, ifc->bInterfaceNumber);
		if (ret < 0) {
			warnx("failed to claim USB interface");
			libusb_close(handle);
			continue;
		}

		qdl->usb_handle = handle;
		qdl->in_ep = in;
		qdl->out_ep = out;
		qdl->in_maxpktsize = in_size;
		qdl->out_maxpktsize = out_size;

		if (qdl->out_chunk_size && qdl->out_chunk_size % out_size) {
			ux_warn("WARNING: requested out-chunk-size must be multiple of the device's wMaxPacketSize %ld, using %ld\n",
			       out_size, out_size);
			qdl->out_chunk_size = out_size;
		} else if (!qdl->out_chunk_size) {
			qdl->out_chunk_size = DEFAULT_OUT_CHUNK_SIZE;
		}

		ux_debug("USB: using out-chunk-size of %ld\n", qdl->out_chunk_size);

		break;
	}

	libusb_free_config_descriptor(config);

	return !!qdl->usb_handle;
}

static int usb_open(struct qdl_device *qdl, const char *serial)
{
	struct libusb_device **devs;
	struct libusb_device *dev;
	struct qdl_device_usb *qdl_usb = container_of(qdl, struct qdl_device_usb, base);
	bool wait_printed = false;
	bool diag_attempted = false;
	bool found = false;
	time_t wait_start = 0;
	ssize_t n;
	int ret;
	int i;
#ifdef _WIN32
	int not_supported_scans = 0;
#endif

	ret = libusb_init(NULL);
	if (ret < 0)
		err(1, "failed to initialize libusb");

	for (;;) {
#ifdef _WIN32
		bool scan_not_supported = false;
#endif
		n = libusb_get_device_list(NULL, &devs);
		if (n < 0)
			err(1, "failed to list USB devices");

		for (i = 0; devs[i]; i++) {
			dev = devs[i];

			ret = usb_try_open(dev, qdl_usb, serial);
			if (ret == 1) {
				found = true;
				break;
			}
#ifdef _WIN32
			if (ret == -2)
				scan_not_supported = true;
#endif
		}

		libusb_free_device_list(devs, 1);

		if (found) {
			if (wait_printed)
				fprintf(stderr, "\n");
			return 0;
		}

#ifdef _WIN32
		/*
		 * EDL device found but the USB driver is not WinUSB-
		 * compatible (e.g. Qualcomm QDLoader 9008 driver).
		 * Signal the caller to fall back to COM port transport.
		 */
		if (scan_not_supported) {
			if (++not_supported_scans >= 1) {
				ux_info("USB driver not WinUSB-compatible, trying COM port...\n");
				libusb_exit(NULL);
				return -2;
			}
		} else {
			not_supported_scans = 0;
		}
#endif

		/* Try DIAG-to-EDL switch if enabled and not yet attempted */
		if (qdl_auto_edl && !diag_attempted) {
			if (diag_is_device_in_diag_mode(serial)) {
				ux_info("Device in DIAG mode, switching to EDL...\n");
				if (diag_switch_to_edl(serial) == 0) {
					ux_info("EDL switch sent, waiting for re-enumeration...\n");
					sleep(3);
				}
				diag_attempted = true;
				continue;
			}
		}

		if (!wait_printed) {
			wait_start = time(NULL);
			wait_printed = true;
		}
		fprintf(stderr, "\rWaiting for EDL device... "
			"(Ctrl+C to abort) [%ds]",
			(int)(time(NULL) - wait_start));
		fflush(stderr);

		usleep(250000);
	}

	return -1;
}

struct qdl_device_desc *usb_list(unsigned int *devices_found)
{
	struct libusb_device_descriptor desc;
	struct libusb_device_handle *handle;
	struct qdl_device_desc *result;
	struct libusb_device **devices;
	struct libusb_device *dev;
	ssize_t device_count;
	unsigned int count = 0;
	int ret;
	int i;

	ret = libusb_init(NULL);
	if (ret < 0)
		err(1, "failed to initialize libusb");

	device_count = libusb_get_device_list(NULL, &devices);
	if (device_count < 0)
		err(1, "failed to list USB devices");
	if (device_count == 0) {
		libusb_free_device_list(devices, 1);
		libusb_exit(NULL);
		return NULL;
	}

	result = calloc(device_count, sizeof(struct qdl_device_desc));
	if (!result)
		err(1, "failed to allocate devices array\n");

	for (i = 0; i < device_count; i++) {
		dev = devices[i];

		ret = libusb_get_device_descriptor(dev, &desc);
		if (ret < 0) {
			warnx("failed to get USB device descriptor");
			continue;
		}

		if (!usb_is_edl_device_runtime(desc.idVendor, desc.idProduct))
			continue;

		ret = libusb_open(dev, &handle);
		if (ret < 0) {
			warnx("unable to open USB device: %s",
			      libusb_strerror(ret));
			continue;
		}

		if (!usb_read_device_serial(handle, &desc,
					    result[count].serial,
					    sizeof(result[count].serial))) {
			/*
			 * Neither iProduct ``_SN:`` nor iSerialNumber yielded
			 * a usable serial. Keep the device listed but record
			 * an empty serial — the caller can still target it by
			 * VID:PID when only one such device is present on the
			 * host. Serial-based selection (-S) won't match.
			 */
			ux_warn("device %04x:%04x has no usable serial descriptor; listing with empty serial\n",
				desc.idVendor, desc.idProduct);
			result[count].serial[0] = '\0';
		}

		result[count].vid = desc.idVendor;
		result[count].pid = desc.idProduct;
		count++;
		libusb_close(handle);
	}

	libusb_free_device_list(devices, 1);
	libusb_exit(NULL);
	*devices_found = count;

	return result;
}

struct usb_adb_desc *usb_list_adb(unsigned int *devices_found)
{
	struct libusb_device **devices;
	struct usb_adb_desc *result;
	ssize_t device_count;
	unsigned int count = 0;
	int ret;
	int i;

	*devices_found = 0;

	ret = libusb_init(NULL);
	if (ret < 0)
		return NULL;

	device_count = libusb_get_device_list(NULL, &devices);
	if (device_count <= 0) {
		if (device_count == 0)
			libusb_free_device_list(devices, 1);
		libusb_exit(NULL);
		return NULL;
	}

	result = calloc(device_count, sizeof(struct usb_adb_desc));
	if (!result) {
		libusb_free_device_list(devices, 1);
		libusb_exit(NULL);
		return NULL;
	}

	for (i = 0; i < device_count; i++) {
		struct libusb_device_descriptor desc;
		struct libusb_config_descriptor *config;
		int j, k;

		ret = libusb_get_device_descriptor(devices[i], &desc);
		if (ret < 0)
			continue;

		if (!is_diag_vendor(desc.idVendor))
			continue;

		/* Skip EDL devices (including runtime --usb-id extras — we
		 * want the DIAG list to exclude anything we've explicitly
		 * tagged as an EDL endpoint). */
		if (usb_is_edl_device_runtime(desc.idVendor, desc.idProduct))
			continue;

		ret = libusb_get_active_config_descriptor(devices[i],
							  &config);
		if (ret < 0)
			continue;

		for (j = 0; j < config->bNumInterfaces; j++) {
			const struct libusb_interface *iface;

			iface = &config->interface[j];
			for (k = 0; k < iface->num_altsetting; k++) {
				const struct libusb_interface_descriptor *alt;

				alt = &iface->altsetting[k];
				if (alt->bInterfaceClass == 0xFF &&
				    alt->bInterfaceSubClass == 0x42 &&
				    alt->bInterfaceProtocol == 0x01) {
					result[count].vid = desc.idVendor;
					result[count].pid = desc.idProduct;
					result[count].iface = alt->bInterfaceNumber;
					count++;
					goto next_device;
				}
			}
		}
next_device:
		libusb_free_config_descriptor(config);
	}

	libusb_free_device_list(devices, 1);
	libusb_exit(NULL);
	*devices_found = count;

	return result;
}

static void usb_close(struct qdl_device *qdl)
{
	struct qdl_device_usb *qdl_usb = container_of(qdl, struct qdl_device_usb, base);

	libusb_close(qdl_usb->usb_handle);
	libusb_exit(NULL);
}

static int usb_read(struct qdl_device *qdl, void *buf, size_t len, unsigned int timeout)
{
	struct qdl_device_usb *qdl_usb = container_of(qdl, struct qdl_device_usb, base);
	int actual;
	int ret;

	ret = libusb_bulk_transfer(qdl_usb->usb_handle, qdl_usb->in_ep, buf, len, &actual, timeout);
	if (ret != 0 && ret != LIBUSB_ERROR_TIMEOUT)
		return -EIO;

	if (ret == LIBUSB_ERROR_TIMEOUT && actual == 0)
		return -ETIMEDOUT;

	/* If what we read equals the endpoint's Max Packet Size, consume the ZLP explicitly */
	if (len == (size_t)actual && !(actual % qdl_usb->in_maxpktsize)) {
		ret = libusb_bulk_transfer(qdl_usb->usb_handle, qdl_usb->in_ep,
					   NULL, 0, NULL, timeout);
		if (ret)
			warnx("Unable to read ZLP: %s", libusb_strerror(ret));
	}

	return actual;
}

static int usb_write(struct qdl_device *qdl, const void *buf, size_t len, unsigned int timeout)
{
	unsigned char *data = (unsigned char *)buf;
	struct qdl_device_usb *qdl_usb = container_of(qdl, struct qdl_device_usb, base);
	unsigned int count = 0;
	size_t len_orig = len;
	int actual;
	int xfer;
	int ret;

	while (len > 0) {
		xfer = (len > qdl_usb->out_chunk_size) ? qdl_usb->out_chunk_size : len;

		ret = libusb_bulk_transfer(qdl_usb->usb_handle, qdl_usb->out_ep, data,
					   xfer, &actual, timeout);
		if (ret != 0 && ret != LIBUSB_ERROR_TIMEOUT) {
			warnx("bulk write failed: %s", libusb_strerror(ret));
			return -EIO;
		}
		if (ret == LIBUSB_ERROR_TIMEOUT && actual == 0)
			return -ETIMEDOUT;

		count += actual;
		len -= actual;
		data += actual;
	}

	if (len_orig % qdl_usb->out_maxpktsize == 0) {
		ret = libusb_bulk_transfer(qdl_usb->usb_handle, qdl_usb->out_ep, NULL,
					   0, &actual, timeout);
		if (ret < 0)
			return -EIO;
	}

	return count;
}

static void usb_set_out_chunk_size(struct qdl_device *qdl, long size)
{
	struct qdl_device_usb *qdl_usb = container_of(qdl, struct qdl_device_usb, base);

	qdl_usb->out_chunk_size = size;
}

struct qdl_device *usb_init(void)
{
	struct qdl_device *qdl = malloc(sizeof(struct qdl_device_usb));

	if (!qdl)
		return NULL;

	memset(qdl, 0, sizeof(struct qdl_device_usb));

	qdl->dev_type = QDL_DEVICE_USB;
	qdl->open = usb_open;
	qdl->read = usb_read;
	qdl->write = usb_write;
	qdl->close = usb_close;
	qdl->set_out_chunk_size = usb_set_out_chunk_size;
	qdl->max_payload_size = 1048576;

	return qdl;
}
