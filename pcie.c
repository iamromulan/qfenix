// SPDX-License-Identifier: BSD-3-Clause
/*
 * PCIe/MHI transport for Qualcomm modems.
 *
 * Supports programming PCIe-connected Qualcomm modems that expose
 * MHI character devices (/dev/mhi_DIAG, /dev/mhi_BHI, /dev/mhi_EDL).
 *
 * Flow: DIAG→EDL switch → BHI programmer upload → EDL firehose I/O
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "qdl.h"
#include "pcie.h"

#ifdef __linux__
#include <poll.h>
#include <sys/ioctl.h>

/* DIAG command to switch Qualcomm devices to EDL mode */
static const unsigned char edl_cmd[] = {0x4b, 0x65, 0x01, 0x00, 0x54, 0x0f, 0x7e};

struct qdl_device_pcie {
	struct qdl_device base;
	int edl_fd;		/* /dev/mhi_EDL fd for firehose I/O */
	int port_index;		/* MHI port instance (0-9) */
};

/*
 * Try to detect which MHI port index has a modem present.
 * Returns the index (0-9) or -1 if not found.
 */
static int pcie_find_port(void)
{
	char path[64];
	int i;

	for (i = 0; i < MHI_MAX_PORTS; i++) {
		if (i == 0)
			snprintf(path, sizeof(path), "/dev/mhi_BHI");
		else
			snprintf(path, sizeof(path), "/dev/mhi_BHI%d", i);

		if (access(path, F_OK) == 0)
			return i;
	}

	/* Also check for DIAG ports if no BHI found */
	for (i = 0; i < MHI_MAX_PORTS; i++) {
		if (i == 0)
			snprintf(path, sizeof(path), "/dev/mhi_DIAG");
		else
			snprintf(path, sizeof(path), "/dev/mhi_DIAG%d", i);

		if (access(path, F_OK) == 0)
			return i;
	}

	return -1;
}

static void pcie_port_path(char *buf, size_t size, const char *type, int index)
{
	if (index == 0)
		snprintf(buf, size, "/dev/mhi_%s", type);
	else
		snprintf(buf, size, "/dev/mhi_%s%d", type, index);
}

/*
 * Send EDL switch command via DIAG MHI port and wait for DIAG
 * port to disappear (indicating the device has switched modes).
 */
static int pcie_switch_to_edl(int port_index)
{
	char diag_path[64];
	int diagfd;
	int retries = 30;

	pcie_port_path(diag_path, sizeof(diag_path), "DIAG", port_index);

	diagfd = open(diag_path, O_RDWR | O_NOCTTY);
	if (diagfd < 0) {
		/* No DIAG port means device may already be in EDL */
		ux_debug("no DIAG port %s, device may already be in EDL\n",
			 diag_path);
		return 0;
	}

	ux_info("switching PCIe modem to EDL mode via %s\n", diag_path);

	while (access(diag_path, R_OK) == 0 && retries-- > 0) {
		if (write(diagfd, edl_cmd, sizeof(edl_cmd)) < 0)
			ux_debug("EDL command write failed: %s\n",
				 strerror(errno));
		sleep(1);
	}

	close(diagfd);

	if (retries <= 0) {
		ux_err("timeout waiting for EDL switch on %s\n", diag_path);
		return -1;
	}

	return 0;
}

/*
 * Upload firehose programmer via BHI ioctl.
 * The programmer MBN file is loaded, prepended with its size,
 * and sent via IOCTL_BHI_WRITEIMAGE.
 */
static int pcie_upload_programmer(int port_index, const char *programmer_path)
{
	struct bhi_info *info = NULL;
	char bhi_path[64];
	void *filebuf = NULL;
	size_t filesize;
	FILE *fp = NULL;
	long ret;
	int bhifd = -1;
	int rc = -1;

	pcie_port_path(bhi_path, sizeof(bhi_path), "BHI", port_index);

	info = malloc(sizeof(*info));
	if (!info) {
		ux_err("failed to allocate BHI info\n");
		return -1;
	}

	/* Load programmer file */
	fp = fopen(programmer_path, "rb");
	if (!fp) {
		ux_err("cannot open programmer %s: %s\n",
		       programmer_path, strerror(errno));
		goto out;
	}

	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	/*
	 * BHI WRITEIMAGE expects: [size_t filesize][file data]
	 * The size field comes first, then the raw programmer binary.
	 */
	filebuf = malloc(sizeof(filesize) + filesize);
	if (!filebuf) {
		ux_err("failed to allocate programmer buffer (%zu bytes)\n",
		       filesize);
		goto out;
	}

	memcpy(filebuf, &filesize, sizeof(filesize));
	if (fread((uint8_t *)filebuf + sizeof(filesize), 1, filesize, fp) !=
	    filesize) {
		ux_err("failed to read programmer file\n");
		goto out;
	}
	fclose(fp);
	fp = NULL;

	/* Open BHI device */
	sleep(1);
	bhifd = open(bhi_path, O_RDWR | O_NOCTTY);
	if (bhifd < 0) {
		ux_err("cannot open %s: %s\n", bhi_path, strerror(errno));
		goto out;
	}

	/* Get device info and verify EDL state */
	ret = ioctl(bhifd, IOCTL_BHI_GETDEVINFO, info);
	if (ret) {
		ux_err("BHI GETDEVINFO failed: %s\n", strerror(errno));
		goto out;
	}

	ux_debug("BHI: ee=%u, serial=%u, ver=%u.%u\n",
		 info->bhi_ee, info->bhi_sernum,
		 info->bhi_ver_major, info->bhi_ver_minor);

	if (info->bhi_ee != MHI_EE_EDL) {
		ux_err("device not in EDL mode (ee=%u, expected %u)\n",
		       info->bhi_ee, MHI_EE_EDL);
		goto out;
	}

	/* Upload programmer image */
	ux_info("uploading programmer via BHI (%zu bytes)\n", filesize);
	ret = ioctl(bhifd, IOCTL_BHI_WRITEIMAGE, filebuf);
	if (ret) {
		ux_err("BHI WRITEIMAGE failed: %s\n", strerror(errno));
		goto out;
	}

	ux_info("programmer uploaded successfully\n");
	rc = 0;

out:
	if (bhifd >= 0)
		close(bhifd);
	if (fp)
		fclose(fp);
	free(filebuf);
	free(info);
	return rc;
}

static int pcie_open(struct qdl_device *qdl, const char *serial)
{
	struct qdl_device_pcie *pcie;
	char edl_path[64];
	int port_index;
	int retries;

	pcie = container_of(qdl, struct qdl_device_pcie, base);

	if (serial) {
		/* If serial is a digit, use as port index */
		if (serial[0] >= '0' && serial[0] <= '9' &&
		    serial[1] == '\0') {
			port_index = serial[0] - '0';
		} else {
			ux_err("PCIe serial must be a port index (0-9)\n");
			return -1;
		}
	} else {
		port_index = pcie_find_port();
		if (port_index < 0) {
			ux_err("no PCIe MHI modem found\n");
			return -1;
		}
	}

	pcie->port_index = port_index;
	ux_info("using PCIe MHI port index %d\n", port_index);

	/* Open EDL port — it should appear after programmer upload */
	pcie_port_path(edl_path, sizeof(edl_path), "EDL", port_index);

	/* Wait for EDL port to appear */
	retries = 10;
	while (access(edl_path, F_OK) != 0 && retries-- > 0) {
		ux_debug("waiting for %s...\n", edl_path);
		sleep(1);
	}

	pcie->edl_fd = open(edl_path, O_RDWR | O_NOCTTY);
	if (pcie->edl_fd < 0) {
		ux_err("cannot open %s: %s\n", edl_path, strerror(errno));
		return -1;
	}

	ux_info("PCIe EDL port %s opened\n", edl_path);
	return 0;
}

static int pcie_read(struct qdl_device *qdl, void *buf, size_t len,
		     unsigned int timeout)
{
	struct qdl_device_pcie *pcie;
	struct pollfd pfd;
	int ret;

	pcie = container_of(qdl, struct qdl_device_pcie, base);

	pfd.fd = pcie->edl_fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, timeout ? (int)timeout : 30000);
	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;

	ret = read(pcie->edl_fd, buf, len);
	if (ret < 0)
		return -errno;

	return ret;
}

static int pcie_write(struct qdl_device *qdl, const void *buf, size_t len,
		      unsigned int timeout)
{
	struct qdl_device_pcie *pcie;
	int ret;

	(void)timeout;

	pcie = container_of(qdl, struct qdl_device_pcie, base);

	ret = write(pcie->edl_fd, buf, len);
	if (ret < 0)
		return -errno;

	return ret;
}

static void pcie_close(struct qdl_device *qdl)
{
	struct qdl_device_pcie *pcie;

	pcie = container_of(qdl, struct qdl_device_pcie, base);

	if (pcie->edl_fd >= 0) {
		close(pcie->edl_fd);
		pcie->edl_fd = -1;
	}
}

static void pcie_set_out_chunk_size(struct qdl_device *qdl, long size)
{
	(void)qdl;
	(void)size;
	/* PCIe/MHI doesn't need chunk size management */
}

int pcie_prepare(struct qdl_device *qdl, const char *programmer_path)
{
	struct qdl_device_pcie *pcie;
	int port_index;

	pcie = container_of(qdl, struct qdl_device_pcie, base);
	port_index = pcie->port_index;

	/* If port_index not yet set, auto-detect */
	if (port_index < 0) {
		port_index = pcie_find_port();
		if (port_index < 0) {
			ux_err("no PCIe MHI modem found\n");
			return -1;
		}
		pcie->port_index = port_index;
	}

	/* Step 1: Switch to EDL via DIAG port */
	if (pcie_switch_to_edl(port_index))
		return -1;

	/* Step 2: Upload programmer via BHI */
	return pcie_upload_programmer(port_index, programmer_path);
}

struct qdl_device *pcie_init(void)
{
	struct qdl_device_pcie *pcie;
	struct qdl_device *qdl;

	pcie = calloc(1, sizeof(*pcie));
	if (!pcie)
		return NULL;

	pcie->edl_fd = -1;
	pcie->port_index = -1;

	qdl = &pcie->base;
	qdl->dev_type = QDL_DEVICE_PCIE;
	qdl->open = pcie_open;
	qdl->read = pcie_read;
	qdl->write = pcie_write;
	qdl->close = pcie_close;
	qdl->set_out_chunk_size = pcie_set_out_chunk_size;
	qdl->max_payload_size = 1048576;

	return qdl;
}

#elif defined(_WIN32)
/*
 * Windows PCIe transport.
 *
 * On Windows, PCIe-connected Qualcomm modems (T99W175, T99W373, T99W545,
 * T99W640, etc.) use the QCMHI driver which exposes COM ports for DIAG
 * and EDL channels instead of MHI character devices.
 *
 * The EDL COM port carries the raw Sahara/Firehose protocol — no HDLC
 * framing, no BHI ioctls — so the programmer upload goes through Sahara
 * (same as USB), not BHI.
 */
#include <windows.h>
#include <setupapi.h>

#include "diag_switch.h"

/* GUID for COM ports class */
static const GUID GUID_DEVCLASS_PORTS_PCIE = {
	0x4d36e978, 0xe325, 0x11ce,
	{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
};

struct qdl_device_pcie_win {
	struct qdl_device base;
	HANDLE hSerial;
};

/*
 * Check if a friendly name indicates a Qualcomm modem.
 * Same logic as diag_switch.c / diag.c — duplicated here to avoid
 * cross-module dependencies from pcie.c.
 */
static int is_qc_modem_name(const char *name)
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

/*
 * Scan Windows COM ports for an EDL port from a PCIe/MHI modem.
 * Matches friendly names containing "EDL" combined with Qualcomm modem
 * keywords. Example: "DW5934e Snapdragon X72 5G EDL (COM51)"
 */
static int pcie_detect_edl_port_win(char *port_buf, size_t buf_size)
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA devInfoData;
	DWORD i;
	int found = 0;

	hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_PORTS_PCIE, NULL, NULL,
					DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
		return 0;

	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
		char hwid[512] = {0};
		char friendlyName[256] = {0};
		char portName[32] = {0};
		HKEY hKey;
		DWORD size;

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_HARDWAREID, NULL, (PBYTE)hwid,
			sizeof(hwid), NULL);

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName,
			sizeof(friendlyName), NULL);

		/*
		 * For USB devices with VID_, use the EDL device table.
		 * For PCIe/MHI devices (no VID_), match by friendly name.
		 */
		if (strstr(hwid, "VID_")) {
			int vid = 0, pid = 0;
			char *vidStr = strstr(hwid, "VID_");
			char *pidStr = strstr(hwid, "PID_");

			if (vidStr)
				vid = strtol(vidStr + 4, NULL, 16);
			if (pidStr)
				pid = strtol(pidStr + 4, NULL, 16);

			if (!is_edl_device(vid, pid))
				continue;
		} else {
			/* PCIe/MHI: must have EDL keyword + modem name */
			if (!strstr(friendlyName, "EDL"))
				continue;
			if (!is_qc_modem_name(friendlyName))
				continue;
		}

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

		snprintf(port_buf, buf_size, "%s", portName);
		found = 1;
		break;
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);
	return found;
}

static int pcie_open_win(struct qdl_device *qdl, const char *serial)
{
	struct qdl_device_pcie_win *pcie;
	char port[32] = {0};
	char portPath[48];
	HANDLE hSerial;
	DCB dcb = {0};
	COMMTIMEOUTS timeouts = {0};

	pcie = container_of(qdl, struct qdl_device_pcie_win, base);

	if (serial && strncmp(serial, "COM", 3) == 0) {
		/* User specified a COM port directly */
		snprintf(port, sizeof(port), "%s", serial);
	} else {
		/* Auto-detect EDL COM port */
		if (!pcie_detect_edl_port_win(port, sizeof(port))) {
			ux_err("no EDL COM port detected\n");
			return -1;
		}
	}

	ux_info("opening EDL port %s\n", port);
	snprintf(portPath, sizeof(portPath), "\\\\.\\%s", port);

	hSerial = CreateFileA(portPath, GENERIC_READ | GENERIC_WRITE,
			      0, NULL, OPEN_EXISTING, 0, NULL);
	if (hSerial == INVALID_HANDLE_VALUE) {
		ux_err("cannot open %s (error %lu)\n", port, GetLastError());
		return -1;
	}

	/*
	 * Set large receive/transmit buffers to prevent data loss.
	 * The default 4KB receive buffer can overflow when the device
	 * sends raw data at USB speed between our polling reads.
	 */
	SetupComm(hSerial, 1048576, 1048576);

	dcb.DCBlength = sizeof(dcb);
	if (!GetCommState(hSerial, &dcb)) {
		CloseHandle(hSerial);
		return -1;
	}

	dcb.BaudRate = 921600;
	dcb.ByteSize = 8;
	dcb.StopBits = ONESTOPBIT;
	dcb.Parity = NOPARITY;
	dcb.fBinary = TRUE;
	dcb.fParity = FALSE;
	dcb.fOutxCtsFlow = FALSE;
	dcb.fOutxDsrFlow = FALSE;
	dcb.fDtrControl = DTR_CONTROL_ENABLE;
	dcb.fRtsControl = RTS_CONTROL_ENABLE;
	dcb.fOutX = FALSE;
	dcb.fInX = FALSE;

	if (!SetCommState(hSerial, &dcb)) {
		CloseHandle(hSerial);
		return -1;
	}

	/*
	 * Default timeouts — pcie_read_win() overrides per-call
	 * using the MAXDWORD/MAXDWORD/timeout special case for
	 * blocking reads.  Set a 5s default here for any reads
	 * that occur before pcie_read_win() has a chance to adjust.
	 */
	timeouts.ReadIntervalTimeout = MAXDWORD;
	timeouts.ReadTotalTimeoutMultiplier = MAXDWORD;
	timeouts.ReadTotalTimeoutConstant = 5000;
	timeouts.WriteTotalTimeoutConstant = 5000;
	timeouts.WriteTotalTimeoutMultiplier = 0;

	if (!SetCommTimeouts(hSerial, &timeouts)) {
		CloseHandle(hSerial);
		return -1;
	}

	/*
	 * Only purge TX — preserve any Sahara hello the device already
	 * sent while we were waiting for the COM port to appear.
	 */
	PurgeComm(hSerial, PURGE_TXCLEAR);

	pcie->hSerial = hSerial;
	ux_info("EDL port %s opened\n", port);
	return 0;
}

static int pcie_read_win(struct qdl_device *qdl, void *buf, size_t len,
			 unsigned int timeout)
{
	struct qdl_device_pcie_win *pcie;
	COMMTIMEOUTS ct = {0};
	DWORD n = 0;

	pcie = container_of(qdl, struct qdl_device_pcie_win, base);

	/*
	 * Use the MAXDWORD/MAXDWORD/timeout special case (MSDN):
	 *
	 *  1. If data is already in the receive buffer, ReadFile
	 *     returns immediately with all available bytes.
	 *  2. If the buffer is empty, ReadFile blocks up to
	 *     ReadTotalTimeoutConstant ms for the first byte.
	 *  3. Once any byte arrives, ReadFile returns immediately
	 *     with all available data (no inter-character wait).
	 *
	 * This replaces the previous Sleep(10) polling loop, which
	 * left gaps where the COM port receive buffer could overflow
	 * during sustained raw-mode data transfers from NAND reads.
	 */
	ct.ReadIntervalTimeout = MAXDWORD;
	ct.ReadTotalTimeoutMultiplier = MAXDWORD;
	ct.ReadTotalTimeoutConstant = timeout ? timeout : 5000;
	SetCommTimeouts(pcie->hSerial, &ct);

	if (!ReadFile(pcie->hSerial, buf, (DWORD)len, &n, NULL))
		return -EIO;

	if (n == 0)
		return -ETIMEDOUT;

	return (int)n;
}

static int pcie_write_win(struct qdl_device *qdl, const void *buf, size_t len,
			  unsigned int timeout)
{
	struct qdl_device_pcie_win *pcie;
	DWORD written = 0;

	(void)timeout;

	pcie = container_of(qdl, struct qdl_device_pcie_win, base);

	if (!WriteFile(pcie->hSerial, buf, (DWORD)len, &written, NULL))
		return -EIO;

	return (int)written;
}

static void pcie_close_win(struct qdl_device *qdl)
{
	struct qdl_device_pcie_win *pcie;

	pcie = container_of(qdl, struct qdl_device_pcie_win, base);

	if (pcie->hSerial != INVALID_HANDLE_VALUE) {
		CloseHandle(pcie->hSerial);
		pcie->hSerial = INVALID_HANDLE_VALUE;
	}
}

static void pcie_set_out_chunk_size_win(struct qdl_device *qdl, long size)
{
	(void)qdl;
	(void)size;
}

/*
 * On Windows, pcie_prepare() just switches from DIAG to EDL mode.
 * The programmer upload happens via Sahara (not BHI ioctl).
 * Returns 1 to signal that Sahara is still needed.
 */
int pcie_prepare(struct qdl_device *qdl, const char *programmer_path)
{
	(void)qdl;
	(void)programmer_path;

	/*
	 * Try to switch from DIAG to EDL. If the device is already in
	 * EDL mode, this will fail gracefully (no DIAG port found).
	 */
	diag_switch_to_edl(NULL);

	/* Give the device time to re-enumerate in EDL mode */
	Sleep(3000);

	return 1; /* Sahara still needed */
}

struct qdl_device *pcie_init(void)
{
	struct qdl_device_pcie_win *pcie;
	struct qdl_device *qdl;

	pcie = calloc(1, sizeof(*pcie));
	if (!pcie)
		return NULL;

	pcie->hSerial = INVALID_HANDLE_VALUE;

	qdl = &pcie->base;
	qdl->dev_type = QDL_DEVICE_PCIE;
	qdl->open = pcie_open_win;
	qdl->read = pcie_read_win;
	qdl->write = pcie_write_win;
	qdl->close = pcie_close_win;
	qdl->set_out_chunk_size = pcie_set_out_chunk_size_win;
	qdl->max_payload_size = 1048576;

	return qdl;
}

#else /* !__linux__ && !_WIN32 */

int pcie_prepare(struct qdl_device *qdl, const char *programmer_path)
{
	(void)qdl;
	(void)programmer_path;
	ux_err("PCIe/MHI transport is not supported on this platform\n");
	return -1;
}

struct qdl_device *pcie_init(void)
{
	ux_err("PCIe/MHI transport is not supported on this platform\n");
	return NULL;
}

#endif
