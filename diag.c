// SPDX-License-Identifier: BSD-3-Clause
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diag.h"
#include "efs_paths.h"
#include "hdlc.h"
#include "usb_ids.h"
#include "qdl.h"
#include "oscompat.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#else
#include <termios.h>
#include <poll.h>
#include <dirent.h>
#include <ctype.h>
#endif

#ifndef _WIN32

static int poll_wait_diag(int fd, short events, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = events };
	int ret = poll(&pfd, 1, timeout_ms);

	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;
	if (pfd.revents & POLLERR)
		return -EIO;
	return 0;
}

static int diag_detect_port(char *port_buf, size_t buf_size,
			    const char *serial)
{
#ifdef __APPLE__
	(void)port_buf;
	(void)buf_size;
	(void)serial;
	ux_err("DIAG port detection is not supported on macOS\n");
	return 0;
#else
	const char *base = "/sys/bus/usb/devices";
	DIR *busdir, *infdir;
	struct dirent *de, *de2;
	char path[512], line[256];
	FILE *fp;
	int found = 0;

	busdir = opendir(base);
	if (!busdir)
		return 0;

	while ((de = readdir(busdir)) != NULL && !found) {
		int vid = 0, pid = 0;
		char dev_serial[128] = {0};
		int diag_iface;

		if (!isdigit(de->d_name[0]))
			continue;

		snprintf(path, sizeof(path), "%s/%s/uevent",
			 base, de->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		while (fgets(line, sizeof(line), fp)) {
			line[strcspn(line, "\n")] = 0;
			if (strncmp(line, "PRODUCT=", 8) == 0)
				sscanf(line + 8, "%x/%x", &vid, &pid);
		}
		fclose(fp);

		if (!vid)
			continue;

		/* Only match known DIAG-capable vendors */
		if (!is_diag_vendor(vid))
			continue;

		/* Skip devices already in EDL mode */
		if (is_edl_device(vid, pid))
			continue;

		/* Read serial number if available */
		snprintf(path, sizeof(path), "%s/%s/serial",
			 base, de->d_name);
		fp = fopen(path, "r");
		if (fp) {
			if (fgets(dev_serial, sizeof(dev_serial), fp))
				dev_serial[strcspn(dev_serial, "\n")] = 0;
			fclose(fp);
		}

		/* Filter by serial if specified */
		if (serial && serial[0] && dev_serial[0] &&
		    strcmp(serial, dev_serial) != 0)
			continue;

		/* Try the known DIAG interface first */
		diag_iface = get_diag_interface_num(vid, pid);
		snprintf(path, sizeof(path), "%s/%s:1.%d",
			 base, de->d_name, diag_iface);
		infdir = opendir(path);

		/* Fall back to scanning all interfaces */
		if (!infdir) {
			snprintf(path, sizeof(path), "%s/%s",
				 base, de->d_name);
			infdir = opendir(path);
		}
		if (!infdir)
			continue;

		while ((de2 = readdir(infdir)) != NULL && !found) {
			char subpath[1024];
			DIR *ttydir;
			struct dirent *de3;

			snprintf(subpath, sizeof(subpath),
				 "%s/%s/tty", path, de2->d_name);
			ttydir = opendir(subpath);
			if (!ttydir)
				continue;

			while ((de3 = readdir(ttydir)) != NULL) {
				if (strncmp(de3->d_name, "ttyUSB", 6) == 0 ||
				    strncmp(de3->d_name, "ttyACM", 6) == 0) {
					snprintf(port_buf, buf_size,
						 "/dev/%.240s",
						 de3->d_name);
					found = 1;
					break;
				}
			}
			closedir(ttydir);
		}
		closedir(infdir);
	}

	closedir(busdir);
	return found;
#endif /* __APPLE__ */
}

static int diag_port_open(const char *port)
{
	struct termios ios;
	int fd;

	fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		ux_err("cannot open %s: %s\n", port, strerror(errno));
		return -1;
	}

	memset(&ios, 0, sizeof(ios));
	cfmakeraw(&ios);
	cfsetispeed(&ios, B115200);
	cfsetospeed(&ios, B115200);

	if (tcsetattr(fd, TCSANOW, &ios) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int diag_port_write(int fd, const uint8_t *data, size_t len)
{
	int ret;

	ret = poll_wait_diag(fd, POLLOUT, 3000);
	if (ret)
		return ret;

	ret = write(fd, data, len);
	if (ret < 0)
		return -errno;
	return ret;
}

static int diag_port_read_frame(int fd, uint8_t *buf, size_t buf_size,
				int timeout_ms)
{
	size_t pos = 0;
	int ret;
	bool in_frame = false;

	while (pos < buf_size) {
		ret = poll_wait_diag(fd, POLLIN, timeout_ms);
		if (ret) {
			if (pos > 0 && ret == -ETIMEDOUT)
				break;
			return ret;
		}

		ret = read(fd, buf + pos, buf_size - pos);
		if (ret <= 0)
			return ret < 0 ? -errno : -EIO;

		pos += ret;

		/* Check if we have a complete frame (ends with 0x7E) */
		if (pos > 0 && buf[pos - 1] == 0x7E) {
			/* Skip leading 0x7E bytes */
			if (!in_frame && pos == 1) {
				pos = 0;
				continue;
			}
			in_frame = true;
			break;
		}
		in_frame = true;
	}

	return (int)pos;
}

#else /* _WIN32 */

/* GUID for COM ports class */
static const GUID GUID_DEVCLASS_PORTS_DIAG = {
	0x4d36e978, 0xe325, 0x11ce,
	{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
};

/*
 * Check if a friendly name indicates a Qualcomm modem.
 * Used for PCIe/MHI devices that don't expose USB VID/PID.
 */
static int is_qualcomm_modem_name(const char *name)
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

static int is_diag_port_name(const char *name)
{
	if (strstr(name, "DIAG") || strstr(name, "DM Port") ||
	    strstr(name, "QDLoader") || strstr(name, "Diagnostic") ||
	    strstr(name, "Sahara"))
		return 1;
	return 0;
}

static int is_skip_port_name(const char *name)
{
	if (strstr(name, "AT Port") || strstr(name, "AT Interface") ||
	    strstr(name, "NMEA") || strstr(name, "GPS") ||
	    strstr(name, "Modem") || strstr(name, "Audio"))
		return 1;
	return 0;
}

static int diag_detect_port(char *port_buf, size_t buf_size,
			    const char *serial)
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA devInfoData;
	DWORD i;
	int found = 0;
	char fallback_port[32] = {0};

	/* Direct COM port specification bypasses auto-detection */
	if (serial && strncmp(serial, "COM", 3) == 0) {
		snprintf(port_buf, buf_size, "%s", serial);
		return 1;
	}

	hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_PORTS_DIAG, NULL, NULL,
					DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
		return 0;

	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
		char hwid[512] = {0};
		char friendlyName[256] = {0};
		char portName[32] = {0};
		char *vidStr, *pidStr;
		HKEY hKey;
		DWORD size;
		int vid = 0, pid = 0;
		int is_known = 0;

		if (!SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
				SPDRP_HARDWAREID, NULL, (PBYTE)hwid,
				sizeof(hwid), NULL))
			continue;

		vidStr = strstr(hwid, "VID_");
		pidStr = strstr(hwid, "PID_");

		if (vidStr)
			vid = strtol(vidStr + 4, NULL, 16);
		if (pidStr)
			pid = strtol(pidStr + 4, NULL, 16);

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName,
			sizeof(friendlyName), NULL);

		if (vidStr) {
			/* USB device: check VID against known DIAG vendors */
			if (!is_diag_vendor(vid))
				continue;
			if (is_edl_device(vid, pid))
				continue;
			is_known = 1;
		} else {
			/*
			 * No VID_ in hardware ID — likely a PCIe/MHI device.
			 * Fall back to matching by friendly name keywords.
			 */
			if (!is_qualcomm_modem_name(friendlyName))
				continue;
			is_known = 1;
		}

		if (!is_known)
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

		/* Prefer ports with DIAG/DM in friendly name */
		if (is_diag_port_name(friendlyName)) {
			snprintf(port_buf, buf_size, "%s", portName);
			found = 1;
			break;
		}

		/* Skip known non-DIAG ports */
		if (is_skip_port_name(friendlyName))
			continue;

		if (fallback_port[0] == '\0')
			snprintf(fallback_port, sizeof(fallback_port),
				 "%s", portName);
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);

	if (!found && fallback_port[0] != '\0') {
		snprintf(port_buf, buf_size, "%s", fallback_port);
		found = 1;
	}

	return found;
}

static intptr_t diag_port_open(const char *port)
{
	HANDLE hSerial;
	DCB dcb = {0};
	COMMTIMEOUTS timeouts = {0};
	char portPath[32];

	snprintf(portPath, sizeof(portPath), "\\\\.\\%s", port);

	hSerial = CreateFileA(portPath, GENERIC_READ | GENERIC_WRITE,
			      0, NULL, OPEN_EXISTING, 0, NULL);
	if (hSerial == INVALID_HANDLE_VALUE) {
		ux_err("cannot open %s (error %lu)\n", port, GetLastError());
		return -1;
	}

	dcb.DCBlength = sizeof(dcb);
	if (!GetCommState(hSerial, &dcb)) {
		CloseHandle(hSerial);
		return -1;
	}

	dcb.BaudRate = CBR_115200;
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

	timeouts.ReadIntervalTimeout = 50;
	timeouts.ReadTotalTimeoutConstant = 3000;
	timeouts.ReadTotalTimeoutMultiplier = 0;
	timeouts.WriteTotalTimeoutConstant = 3000;
	timeouts.WriteTotalTimeoutMultiplier = 0;

	if (!SetCommTimeouts(hSerial, &timeouts)) {
		CloseHandle(hSerial);
		return -1;
	}

	PurgeComm(hSerial, PURGE_RXCLEAR | PURGE_TXCLEAR);

	return (intptr_t)hSerial;
}

static int diag_port_write(intptr_t fd, const uint8_t *data, size_t len)
{
	HANDLE h = (HANDLE)fd;
	DWORD written;

	if (!WriteFile(h, data, (DWORD)len, &written, NULL))
		return -1;

	return (int)written;
}

static int diag_port_read_frame(intptr_t fd, uint8_t *buf, size_t buf_size,
				int timeout_ms)
{
	HANDLE h = (HANDLE)fd;
	COMMTIMEOUTS timeouts = {0};
	size_t pos = 0;
	bool in_frame = false;
	DWORD n;

	timeouts.ReadIntervalTimeout = 50;
	timeouts.ReadTotalTimeoutConstant = timeout_ms;
	timeouts.ReadTotalTimeoutMultiplier = 0;
	SetCommTimeouts(h, &timeouts);

	while (pos < buf_size) {
		if (!ReadFile(h, buf + pos, (DWORD)(buf_size - pos),
			      &n, NULL) || n == 0) {
			if (pos > 0)
				break;
			return -1;
		}

		pos += n;

		/* Check if we have a complete frame (ends with 0x7E) */
		if (pos > 0 && buf[pos - 1] == 0x7E) {
			/* Skip leading 0x7E bytes */
			if (!in_frame && pos == 1) {
				pos = 0;
				continue;
			}
			in_frame = true;
			break;
		}
		in_frame = true;
	}

	return (int)pos;
}

#endif /* _WIN32 */

/*
 * Send SPC (Service Programming Code) for DIAG authentication.
 * Default SPC is "000000" (six ASCII zeros).
 */
static int diag_send_spc(struct diag_session *sess)
{
	uint8_t cmd[7];
	uint8_t resp[8];
	int n;

	cmd[0] = DIAG_SPC_F;
	/* Default SPC: "000000" = 0x30 x 6 */
	memset(&cmd[1], 0x30, 6);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 2)
		return -1;

	if (resp[0] != DIAG_SPC_F || resp[1] != 1) {
		ux_debug("SPC authentication failed (status=%d)\n",
			 n >= 2 ? resp[1] : -1);
		return -1;
	}

	ux_debug("SPC authentication successful\n");
	return 0;
}

/*
 * Send Security Password for DIAG authentication.
 * Default password is 0xFFFFFFFFFFFFFF7E (standard Qualcomm default).
 */
static int diag_send_password(struct diag_session *sess)
{
	uint8_t cmd[9];
	uint8_t resp[16];
	int n;

	cmd[0] = DIAG_PASSWORD_F;
	memset(&cmd[1], 0xFF, 7);
	cmd[8] = 0xFE;

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 2)
		return -1;

	if (resp[0] != DIAG_PASSWORD_F || resp[1] != 1) {
		ux_debug("security password authentication failed (status=%d)\n",
			 n >= 2 ? resp[1] : -1);
		return -1;
	}

	ux_debug("security password authentication successful\n");
	return 0;
}

struct diag_session *diag_open(const char *serial)
{
	struct diag_session *sess;
	char port[256] = {0};

	/* If serial looks like a port path, use it directly */
	if (serial && (serial[0] == '/' || strncmp(serial, "COM", 3) == 0)) {
		snprintf(port, sizeof(port), "%s", serial);
	} else {
		if (!diag_detect_port(port, sizeof(port), serial)) {
			ux_err("no DIAG port detected\n");
			return NULL;
		}
		ux_info("detected DIAG port: %s\n", port);
	}

	sess = calloc(1, sizeof(*sess));
	if (!sess)
		return NULL;

	sess->fd = diag_port_open(port);
	if (sess->fd < 0) {
		free(sess);
		return NULL;
	}

	/* Drain any pending data */
#ifndef _WIN32
	{
		uint8_t drain[512];
		int count = 0;

		while (count < 100) {
			if (poll_wait_diag(sess->fd, POLLIN, 100) != 0)
				break;
			if (read(sess->fd, drain, sizeof(drain)) <= 0)
				break;
			count++;
		}
	}
#endif

	/* Authenticate with SPC and security password */
	diag_send_spc(sess);
	diag_send_password(sess);

	return sess;
}

void diag_close(struct diag_session *sess)
{
	if (!sess)
		return;
#ifdef _WIN32
	if (sess->fd > 0)
		CloseHandle((HANDLE)sess->fd);
#else
	if (sess->fd >= 0)
		close(sess->fd);
#endif
	free(sess);
}

static int diag_set_mode(struct diag_session *sess, uint16_t mode)
{
	uint8_t cmd[3];
	uint8_t resp[64];
	int n;

	cmd[0] = DIAG_CONTROL_F;
	memcpy(&cmd[1], &mode, 2);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 1 || resp[0] != DIAG_CONTROL_F) {
		ux_err("DIAG mode change failed (mode=%u)\n", mode);
		return -1;
	}

	return 0;
}

int diag_offline(struct diag_session *sess)
{
	int ret;

	ux_info("switching modem to offline mode\n");
	ret = diag_set_mode(sess, DIAG_MODE_OFFLINE_D);
	if (ret)
		return ret;

	/* Give the modem time to transition */
	usleep(500000);
	return 0;
}

int diag_online(struct diag_session *sess)
{
	ux_info("switching modem back to online mode\n");
	return diag_set_mode(sess, DIAG_MODE_ONLINE);
}

int diag_send(struct diag_session *sess, const uint8_t *cmd, size_t cmd_len,
	      uint8_t *resp, size_t resp_size)
{
	uint8_t frame[8192];
	uint8_t raw[8192];
	int frame_len;
	int n;

	frame_len = hdlc_encode(cmd, cmd_len, frame, sizeof(frame));
	if (frame_len < 0) {
		ux_err("HDLC encode failed\n");
		return -1;
	}

	n = diag_port_write(sess->fd, frame, frame_len);
	if (n < 0) {
		ux_err("DIAG write failed: %s\n", strerror(-n));
		return -1;
	}

	n = diag_port_read_frame(sess->fd, raw, sizeof(raw), 3000);
	if (n <= 0) {
		ux_err("DIAG read failed\n");
		return -1;
	}

	return hdlc_decode(raw, n, resp, resp_size);
}

const char *diag_nv_status_str(uint16_t status)
{
	switch (status) {
	case NV_DONE_S:		return "OK";
	case NV_BUSY_S:		return "Busy";
	case NV_BADCMD_S:	return "Bad command";
	case NV_FULL_S:		return "NV full";
	case NV_FAIL_S:		return "Failed";
	case NV_NOTACTIVE_S:	return "Not active";
	case NV_BADPARM_S:	return "Bad parameter";
	case NV_READONLY_S:	return "Read-only";
	case NV_NOTDEF_S:	return "Not defined";
	default:		return "Unknown";
	}
}

int diag_nv_read(struct diag_session *sess, uint16_t item,
		 struct nv_item *out)
{
	uint8_t cmd[NV_ITEM_PKT_SIZE];
	uint8_t resp[NV_ITEM_PKT_SIZE + 16];
	int n;

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = DIAG_NV_READ_F;
	cmd[1] = item & 0xFF;
	cmd[2] = (item >> 8) & 0xFF;

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 0)
		return -1;

	if (n < NV_ITEM_PKT_SIZE || resp[0] != DIAG_NV_READ_F) {
		ux_debug("NV read: modem returned cmd=0x%02x len=%d"
			 " (item not supported)\n", resp[0], n);
		return -1;
	}

	out->item = resp[1] | (resp[2] << 8);
	memcpy(out->data, &resp[3], NV_ITEM_DATA_SIZE);
	out->status = resp[3 + NV_ITEM_DATA_SIZE] |
		      (resp[4 + NV_ITEM_DATA_SIZE] << 8);

	return 0;
}

int diag_nv_write(struct diag_session *sess, uint16_t item,
		  const uint8_t *data, size_t data_len)
{
	uint8_t cmd[NV_ITEM_PKT_SIZE];
	uint8_t resp[NV_ITEM_PKT_SIZE + 16];
	uint16_t status;
	int n;

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = DIAG_NV_WRITE_F;
	cmd[1] = item & 0xFF;
	cmd[2] = (item >> 8) & 0xFF;

	if (data_len > NV_ITEM_DATA_SIZE)
		data_len = NV_ITEM_DATA_SIZE;
	memcpy(&cmd[3], data, data_len);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 0)
		return -1;

	if (n < NV_ITEM_PKT_SIZE || resp[0] != DIAG_NV_WRITE_F) {
		ux_err("NV write error: unexpected response (cmd=0x%02x, len=%d)\n",
		       resp[0], n);
		return -1;
	}

	status = resp[3 + NV_ITEM_DATA_SIZE] |
		 (resp[4 + NV_ITEM_DATA_SIZE] << 8);
	if (status != NV_DONE_S) {
		ux_err("NV write failed: %s (status=%u)\n",
		       diag_nv_status_str(status), status);
		return -1;
	}

	return 0;
}

int diag_nv_read_sub(struct diag_session *sess, uint16_t item,
		     uint16_t index, struct nv_item *out)
{
	uint8_t cmd[4 + 2 + 2 + NV_ITEM_DATA_SIZE + 2];
	uint8_t resp[sizeof(cmd) + 16];
	int n;

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = DIAG_SUBSYS_CMD_F;
	cmd[1] = DIAG_SUBSYS_NV;
	cmd[2] = DIAG_SUBSYS_NV_READ;
	cmd[3] = 0x00;
	cmd[4] = item & 0xFF;
	cmd[5] = (item >> 8) & 0xFF;
	cmd[6] = index & 0xFF;
	cmd[7] = (index >> 8) & 0xFF;

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 0)
		return -1;

	if (n < (int)sizeof(cmd) || resp[0] != DIAG_SUBSYS_CMD_F) {
		ux_debug("NV indexed read: item not supported\n");
		return -1;
	}

	out->item = resp[4] | (resp[5] << 8);
	memcpy(out->data, &resp[8], NV_ITEM_DATA_SIZE);
	out->status = resp[8 + NV_ITEM_DATA_SIZE] |
		      (resp[9 + NV_ITEM_DATA_SIZE] << 8);

	return 0;
}

int diag_nv_write_sub(struct diag_session *sess, uint16_t item,
		      uint16_t index, const uint8_t *data, size_t data_len)
{
	uint8_t cmd[4 + 2 + 2 + NV_ITEM_DATA_SIZE + 2];
	uint8_t resp[sizeof(cmd) + 16];
	uint16_t status;
	int n;

	memset(cmd, 0, sizeof(cmd));
	cmd[0] = DIAG_SUBSYS_CMD_F;
	cmd[1] = DIAG_SUBSYS_NV;
	cmd[2] = DIAG_SUBSYS_NV_WRITE;
	cmd[3] = 0x00;
	cmd[4] = item & 0xFF;
	cmd[5] = (item >> 8) & 0xFF;
	cmd[6] = index & 0xFF;
	cmd[7] = (index >> 8) & 0xFF;

	if (data_len > NV_ITEM_DATA_SIZE)
		data_len = NV_ITEM_DATA_SIZE;
	memcpy(&cmd[8], data, data_len);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 0)
		return -1;

	if (n < (int)sizeof(cmd) || resp[0] != DIAG_SUBSYS_CMD_F) {
		ux_err("NV indexed write error: unexpected response\n");
		return -1;
	}

	status = resp[8 + NV_ITEM_DATA_SIZE] |
		 (resp[9 + NV_ITEM_DATA_SIZE] << 8);
	if (status != NV_DONE_S) {
		ux_err("NV indexed write failed: %s (status=%u)\n",
		       diag_nv_status_str(status), status);
		return -1;
	}

	return 0;
}

/* Forward declaration — used in readfile and backup tree walk */
static int efs_get_item(struct diag_session *sess, const char *path,
			uint8_t *buf, size_t buf_size, int32_t *data_len_out);

/* EFS helper: build subsystem command header */
static void efs_cmd_header(uint8_t *cmd, uint8_t method, uint8_t efs_cmd)
{
	cmd[0] = DIAG_SUBSYS_CMD_F;
	cmd[1] = method;
	cmd[2] = efs_cmd;
	cmd[3] = 0x00;
}

/*
 * EFS QUERY (opcode 1) — register DIAG client after HELLO.
 * Some devices require this for proper session setup.
 */
static int efs_query(struct diag_session *sess)
{
	uint8_t cmd[4];
	uint8_t resp[64];
	int n;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_QUERY);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 4 || resp[0] != DIAG_SUBSYS_CMD_F) {
		ux_debug("EFS query not supported\n");
		return -1;
	}

	ux_debug("EFS query successful\n");
	return 0;
}

int diag_efs_detect(struct diag_session *sess)
{
	uint8_t cmd[4 + 0x28];
	uint8_t resp[256];
	int n;

	/* Try alternate method first */
	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, DIAG_SUBSYS_EFS_ALT, EFS2_DIAG_HELLO);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n > 0 && resp[0] == DIAG_SUBSYS_CMD_F) {
		sess->efs_method = DIAG_SUBSYS_EFS_ALT;
		sess->efs_detected = true;
		ux_debug("EFS detected using alternate method (0x3E)\n");
		efs_query(sess);
		return 0;
	}

	/* Try standard method */
	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, DIAG_SUBSYS_EFS_STD, EFS2_DIAG_HELLO);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n > 0 && resp[0] == DIAG_SUBSYS_CMD_F) {
		sess->efs_method = DIAG_SUBSYS_EFS_STD;
		sess->efs_detected = true;
		ux_debug("EFS detected using standard method (0x13)\n");
		efs_query(sess);
		return 0;
	}

	ux_err("EFS not detected on this device\n");
	return -1;
}

static int efs_opendir(struct diag_session *sess, const char *path)
{
	uint8_t cmd[4 + 256];
	uint8_t resp[256];
	size_t path_len;
	int32_t dirp;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_OPENDIR);
	memcpy(&cmd[4], path, path_len);

	n = diag_send(sess, cmd, 4 + path_len, resp, sizeof(resp));
	if (n < 12)
		return -1;

	memcpy(&dirp, &resp[4], 4);
	memcpy(&diag_errno, &resp[8], 4);

	if (diag_errno != 0) {
		ux_err("EFS opendir '%s' failed (errno=%d)\n",
		       path, diag_errno);
		return -1;
	}

	return dirp;
}

static int efs_readdir(struct diag_session *sess, int32_t dirp,
		       uint32_t seqno, struct efs_dirent *entry)
{
	uint8_t cmd[12];
	uint8_t resp[512];
	int32_t diag_errno;
	int n;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_READDIR);
	memcpy(&cmd[4], &dirp, 4);
	memcpy(&cmd[8], &seqno, 4);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 40)
		return -1;

	memcpy(&diag_errno, &resp[12], 4);
	if (diag_errno != 0)
		return -1;

	memcpy(&entry->entry_type, &resp[16], 4);
	memcpy(&entry->mode, &resp[20], 4);
	memcpy(&entry->size, &resp[24], 4);
	memcpy(&entry->atime, &resp[28], 4);
	memcpy(&entry->mtime, &resp[32], 4);
	memcpy(&entry->ctime, &resp[36], 4);

	if (entry->entry_type == 0)
		return 1; /* No more entries */

	/* Copy filename */
	if (n > 40) {
		size_t name_len = n - 40;

		if (name_len >= sizeof(entry->name))
			name_len = sizeof(entry->name) - 1;
		memcpy(entry->name, &resp[40], name_len);
		entry->name[name_len] = '\0';
	} else {
		entry->name[0] = '\0';
	}

	return 0;
}

static void efs_closedir(struct diag_session *sess, int32_t dirp)
{
	uint8_t cmd[8];
	uint8_t resp[64];

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_CLOSEDIR);
	memcpy(&cmd[4], &dirp, 4);

	diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
}

int diag_efs_listdir(struct diag_session *sess, const char *path,
		     void (*callback)(const struct efs_dirent *entry,
				      void *ctx),
		     void *ctx)
{
	struct efs_dirent entry;
	int32_t dirp;
	uint32_t seqno = 1;
	int ret;

	if (!sess->efs_detected) {
		ret = diag_efs_detect(sess);
		if (ret)
			return ret;
	}

	dirp = efs_opendir(sess, path);
	if (dirp < 0)
		return -1;

	for (;;) {
		ret = efs_readdir(sess, dirp, seqno, &entry);
		if (ret < 0) {
			efs_closedir(sess, dirp);
			return -1;
		}
		if (ret > 0)
			break; /* No more entries */

		if (callback)
			callback(&entry, ctx);
		seqno++;
	}

	efs_closedir(sess, dirp);
	return 0;
}

static int efs_open(struct diag_session *sess, const char *path,
		    int32_t oflag, int32_t mode)
{
	uint8_t cmd[4 + 4 + 4 + 256];
	uint8_t resp[64];
	size_t path_len;
	int32_t fdata;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_OPEN);
	memcpy(&cmd[4], &oflag, 4);
	memcpy(&cmd[8], &mode, 4);
	memcpy(&cmd[12], path, path_len);

	n = diag_send(sess, cmd, 12 + path_len, resp, sizeof(resp));
	if (n < 12)
		return -1;

	memcpy(&fdata, &resp[4], 4);
	memcpy(&diag_errno, &resp[8], 4);

	if (fdata < 0 || diag_errno != 0) {
		ux_err("EFS open '%s' failed (fd=%d, errno=%d)\n",
		       path, fdata, diag_errno);
		return -1;
	}

	return fdata;
}

static int efs_read(struct diag_session *sess, int32_t fdata,
		    uint32_t nbytes, uint32_t offset,
		    uint8_t *buf, size_t buf_size)
{
	uint8_t cmd[16];
	uint8_t resp[2048];
	int32_t bytes_read;
	int32_t diag_errno;
	int n;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_READ);
	memcpy(&cmd[4], &fdata, 4);
	memcpy(&cmd[8], &nbytes, 4);
	memcpy(&cmd[12], &offset, 4);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 20)
		return -1;

	memcpy(&bytes_read, &resp[12], 4);
	memcpy(&diag_errno, &resp[16], 4);

	if (diag_errno != 0 || bytes_read < 0)
		return -1;

	if ((size_t)bytes_read > buf_size)
		bytes_read = buf_size;

	if (n > 20 && bytes_read > 0)
		memcpy(buf, &resp[20], bytes_read);

	return bytes_read;
}

static void efs_close(struct diag_session *sess, int32_t fdata)
{
	uint8_t cmd[8];
	uint8_t resp[64];

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_CLOSE);
	memcpy(&cmd[4], &fdata, 4);

	diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
}

static int efs_stat(struct diag_session *sess, const char *path,
		    struct efs_stat *st)
{
	uint8_t cmd[4 + 256];
	uint8_t resp[256];
	size_t path_len;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_STAT);
	memcpy(&cmd[4], path, path_len);

	n = diag_send(sess, cmd, 4 + path_len, resp, sizeof(resp));
	if (n < 32)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);
	if (diag_errno != 0)
		return -1;

	memcpy(&st->mode, &resp[8], 4);
	memcpy(&st->size, &resp[12], 4);
	memcpy(&st->nlink, &resp[16], 4);
	memcpy(&st->atime, &resp[20], 4);
	memcpy(&st->mtime, &resp[24], 4);
	memcpy(&st->ctime, &resp[28], 4);

	return 0;
}

int diag_efs_readfile(struct diag_session *sess, const char *src_path,
		      const char *dst_path)
{
	struct efs_stat st;
	uint8_t buf[EFS_MAX_READ_REQ];
	int32_t fdata;
	uint32_t offset = 0;
	int32_t remaining;
	int fd;
	int n;
	int ret = -1;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	fdata = efs_open(sess, src_path, 0 /* O_RDONLY */, 0);
	if (fdata < 0) {
		/* File interface failed — try item interface (GET) */
		uint8_t item_buf[4096];
		int32_t item_len = 0;

		if (efs_get_item(sess, src_path, item_buf,
				 sizeof(item_buf), &item_len) != 0)
			return -1;

		ux_debug("read '%s' via item interface (%d bytes)\n",
			 src_path, item_len);

		fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY,
			  0644);
		if (fd < 0) {
			ux_err("cannot create %s: %s\n",
			       dst_path, strerror(errno));
			return -1;
		}

		if (item_len > 0 &&
		    write(fd, item_buf, item_len) != item_len) {
			ux_err("local write failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}

		close(fd);
		ux_info("EFS file '%s' saved to '%s' (%d bytes, item)\n",
			src_path, dst_path, item_len);
		return 0;
	}

	if (efs_stat(sess, src_path, &st) < 0) {
		ux_err("EFS stat '%s' failed\n", src_path);
		efs_close(sess, fdata);
		return -1;
	}

	fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		ux_err("cannot create %s: %s\n", dst_path, strerror(errno));
		efs_close(sess, fdata);
		return -1;
	}

	remaining = st.size;
	ux_info("reading EFS file '%s' (%d bytes)\n", src_path, remaining);

	while (remaining > 0) {
		uint32_t chunk = remaining > EFS_MAX_READ_REQ ?
				 EFS_MAX_READ_REQ : remaining;

		n = efs_read(sess, fdata, chunk, offset, buf, sizeof(buf));
		if (n <= 0) {
			ux_err("EFS read failed at offset %u\n", offset);
			goto out;
		}

		if (write(fd, buf, n) != n) {
			ux_err("local write failed: %s\n", strerror(errno));
			goto out;
		}

		offset += n;
		remaining -= n;
	}

	ux_info("EFS file '%s' saved to '%s'\n", src_path, dst_path);
	ret = 0;

out:
	close(fd);
	efs_close(sess, fdata);
	return ret;
}

int diag_efs_dump(struct diag_session *sess, const char *output_file)
{
	uint8_t cmd[64];
	uint8_t resp[2048];
	int fd;
	int n;
	int ret = -1;
	uint8_t stream_state;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		ux_err("cannot create %s: %s\n", output_file, strerror(errno));
		return -1;
	}

	/* Prepare factory image */
	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_PREP_FACT_IMAGE);
	n = diag_send(sess, cmd, 4, resp, sizeof(resp));
	if (n < 0) {
		ux_err("EFS prep factory image failed\n");
		goto out;
	}

	/* Start factory image output */
	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_FACT_IMAGE_START);
	n = diag_send(sess, cmd, 4, resp, sizeof(resp));
	if (n < 0) {
		ux_err("EFS factory image start failed\n");
		goto out;
	}

	ux_info("dumping EFS factory image to %s\n", output_file);

	/* Read loop */
	for (;;) {
		memset(cmd, 0, sizeof(cmd));
		efs_cmd_header(cmd, sess->efs_method,
			       EFS2_DIAG_FACT_IMAGE_READ);
		/* Copy stream state from previous response */
		if (n >= 12)
			memcpy(&cmd[4], &resp[4], 8);

		n = diag_send(sess, cmd, 12, resp, sizeof(resp));
		if (n < 12) {
			ux_err("EFS factory image read failed\n");
			goto out;
		}

		stream_state = resp[4];

		/* Write data portion (after header) */
		if (n > 12) {
			if (write(fd, &resp[12], n - 12) != n - 12) {
				ux_err("write failed: %s\n", strerror(errno));
				goto out;
			}
		}

		if (stream_state == 0)
			break; /* No more data */
	}

	/* End factory image */
	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_FACT_IMAGE_END);
	diag_send(sess, cmd, 4, resp, sizeof(resp));

	ux_info("EFS dump complete: %s\n", output_file);
	ret = 0;

out:
	close(fd);
	return ret;
}

/*
 * EFS write operations for efsrestore
 */

static int efs_write(struct diag_session *sess, int32_t fdata,
		     uint32_t offset, const uint8_t *data, uint32_t len)
{
	uint8_t cmd[4 + 4 + 4 + 4 + EFS_MAX_WRITE_REQ];
	uint8_t resp[64];
	int32_t bytes_written;
	int32_t diag_errno;
	int n;

	if (len > EFS_MAX_WRITE_REQ)
		len = EFS_MAX_WRITE_REQ;

	memset(cmd, 0, 16);
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_WRITE);
	memcpy(&cmd[4], &fdata, 4);
	memcpy(&cmd[8], &offset, 4);
	memcpy(&cmd[12], &len, 4);
	memcpy(&cmd[16], data, len);

	n = diag_send(sess, cmd, 16 + len, resp, sizeof(resp));
	if (n < 20)
		return -1;

	memcpy(&bytes_written, &resp[12], 4);
	memcpy(&diag_errno, &resp[16], 4);

	if (diag_errno != 0 || bytes_written < 0)
		return -1;

	return bytes_written;
}

static int efs_mkdir_op(struct diag_session *sess, const char *path,
			int16_t mode)
{
	uint8_t cmd[4 + 2 + 256];
	uint8_t resp[64];
	size_t path_len;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_MKDIR);
	memcpy(&cmd[4], &mode, 2);
	memcpy(&cmd[6], path, path_len);

	n = diag_send(sess, cmd, 6 + path_len, resp, sizeof(resp));
	if (n < 8)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);

	/* EEXIST is OK for directories */
	if (diag_errno != 0 && diag_errno != 17)
		return -1;

	return 0;
}

static int efs_symlink_op(struct diag_session *sess, const char *target,
			  const char *linkpath)
{
	uint8_t cmd[4 + 512];
	uint8_t resp[64];
	size_t tgt_len, link_len;
	int32_t diag_errno;
	int n;

	tgt_len = strlen(target) + 1;
	link_len = strlen(linkpath) + 1;
	if (tgt_len + link_len > 508)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_SYMLINK);
	memcpy(&cmd[4], target, tgt_len);
	memcpy(&cmd[4 + tgt_len], linkpath, link_len);

	n = diag_send(sess, cmd, 4 + tgt_len + link_len, resp, sizeof(resp));
	if (n < 8)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);
	if (diag_errno != 0)
		return -1;

	return 0;
}

static int efs_chmod_op(struct diag_session *sess, const char *path,
			int16_t mode)
{
	uint8_t cmd[4 + 2 + 256];
	uint8_t resp[64];
	size_t path_len;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_CHMOD);
	memcpy(&cmd[4], &mode, 2);
	memcpy(&cmd[6], path, path_len);

	n = diag_send(sess, cmd, 6 + path_len, resp, sizeof(resp));
	if (n < 8)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);
	if (diag_errno != 0)
		return -1;

	return 0;
}

static int efs_readlink(struct diag_session *sess, const char *path,
			char *buf, size_t buf_size)
{
	uint8_t cmd[4 + 256];
	uint8_t resp[512];
	size_t path_len;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_READLINK);
	memcpy(&cmd[4], path, path_len);

	n = diag_send(sess, cmd, 4 + path_len, resp, sizeof(resp));
	if (n < 8)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);
	if (diag_errno != 0)
		return -1;

	/* Target string follows at resp[8] */
	if (n > 8) {
		size_t tgt_len = n - 8;

		if (tgt_len >= buf_size)
			tgt_len = buf_size - 1;
		memcpy(buf, &resp[8], tgt_len);
		buf[tgt_len] = '\0';
	} else {
		buf[0] = '\0';
	}

	return 0;
}

/*
 * EFS item interface — GET/PUT bypass file-level ACLs.
 * QPST uses these to access /nv/item_files/ and other restricted paths.
 */

static int efs_get_item(struct diag_session *sess, const char *path,
			uint8_t *buf, size_t buf_size, int32_t *data_len_out)
{
	uint8_t cmd[4 + 256];
	uint8_t resp[8192];
	size_t path_len;
	int32_t data_length;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_GET);
	memcpy(&cmd[4], path, path_len);

	n = diag_send(sess, cmd, 4 + path_len, resp, sizeof(resp));
	if (n < 12)
		return -1;

	memcpy(&data_length, &resp[4], 4);
	memcpy(&diag_errno, &resp[8], 4);

	if (diag_errno != 0)
		return -1;

	if (data_length < 0)
		return -1;

	if (data_len_out)
		*data_len_out = data_length;

	if ((size_t)data_length > buf_size)
		return -1;

	if (data_length > 0 && n > 12)
		memcpy(buf, &resp[12], data_length);

	return 0;
}

static int efs_put_item(struct diag_session *sess, const char *path,
			const uint8_t *data, int32_t data_len,
			int32_t flags, int32_t mode)
{
	uint8_t cmd[4096];
	uint8_t resp[64];
	size_t path_len;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if ((size_t)data_len + path_len > sizeof(cmd) - 16)
		return -1;

	memset(cmd, 0, 16);
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_PUT);
	memcpy(&cmd[4], &data_len, 4);
	memcpy(&cmd[8], &flags, 4);
	memcpy(&cmd[12], &mode, 4);
	memcpy(&cmd[16], data, data_len);
	memcpy(&cmd[16 + data_len], path, path_len);

	n = diag_send(sess, cmd, 16 + data_len + path_len, resp, sizeof(resp));
	if (n < 8)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);
	if (diag_errno != 0)
		return -1;

	return 0;
}

/*
 * FS_IMAGE protocol — modem-generated TAR backup
 */

static int efs_image_open(struct diag_session *sess, const char *path,
			  int *handle_out)
{
	uint8_t cmd[4 + 2 + 1 + 256];
	uint8_t resp[64];
	size_t path_len;
	uint16_t seq = 0;
	uint8_t image_type = 0; /* 0 = TAR */
	int32_t handle;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 250)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_FS_IMAGE_OPEN);
	memcpy(&cmd[4], &seq, 2);
	cmd[6] = image_type;
	memcpy(&cmd[7], path, path_len);

	n = diag_send(sess, cmd, 7 + path_len, resp, sizeof(resp));
	if (n < 12)
		return -1;

	memcpy(&handle, &resp[4], 4);
	memcpy(&diag_errno, &resp[8], 4);

	if (handle < 0 || diag_errno != 0) {
		ux_err("EFS image open failed (handle=%d, errno=%d)\n",
		       handle, diag_errno);
		return -1;
	}

	*handle_out = handle;
	return 0;
}

static int efs_image_read(struct diag_session *sess, int32_t handle,
			  uint16_t seq, uint8_t *buf, size_t buf_size,
			  size_t *bytes_out, bool *end_out)
{
	uint8_t cmd[10];
	uint8_t resp[2048];
	int32_t diag_errno;
	uint8_t end_flag;
	int n;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_FS_IMAGE_READ);
	memcpy(&cmd[4], &handle, 4);
	memcpy(&cmd[8], &seq, 2);

	n = diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
	if (n < 15)
		return -1;

	memcpy(&diag_errno, &resp[10], 4);
	end_flag = resp[14];

	if (diag_errno != 0) {
		ux_err("EFS image read failed (errno=%d)\n", diag_errno);
		return -1;
	}

	*end_out = (end_flag != 0);

	if (n > 15) {
		size_t data_len = n - 15;

		if (data_len > buf_size)
			data_len = buf_size;
		memcpy(buf, &resp[15], data_len);
		*bytes_out = data_len;
	} else {
		*bytes_out = 0;
	}

	return 0;
}

static void efs_image_close(struct diag_session *sess, int32_t handle)
{
	uint8_t cmd[8];
	uint8_t resp[64];

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_FS_IMAGE_CLOSE);
	memcpy(&cmd[4], &handle, 4);

	diag_send(sess, cmd, sizeof(cmd), resp, sizeof(resp));
}

/*
 * TAR helpers — POSIX ustar format (512-byte headers)
 */

static void tar_write_octal(char *buf, size_t size, unsigned long value)
{
	int width = (int)(size - 1);
	int n = snprintf(buf, size, "%0*lo", width, value);

	/* If value doesn't fit, truncate to field size */
	if (n >= (int)size)
		buf[size - 1] = '\0';
}

static unsigned int tar_checksum(const uint8_t *header)
{
	unsigned int sum = 0;
	int i;

	for (i = 0; i < 512; i++) {
		/* Checksum field (offset 148-155) treated as spaces */
		if (i >= 148 && i < 156)
			sum += ' ';
		else
			sum += header[i];
	}

	return sum;
}

static int tar_write_header(int fd, const char *name, int32_t mode,
			    int32_t size, int32_t mtime, char typeflag,
			    const char *linkname)
{
	uint8_t header[512];

	memset(header, 0, sizeof(header));

	/* name (offset 0, 100 bytes) */
	strncpy((char *)header, name, 99);

	/* mode (offset 100, 8 bytes) */
	tar_write_octal((char *)header + 100, 8, mode & 07777);

	/* uid (offset 108, 8 bytes) — use 0 */
	tar_write_octal((char *)header + 108, 8, 0);

	/* gid (offset 116, 8 bytes) — use 0 */
	tar_write_octal((char *)header + 116, 8, 0);

	/* size (offset 124, 12 bytes) */
	tar_write_octal((char *)header + 124, 12,
			typeflag == '0' ? (unsigned long)size : 0);

	/* mtime (offset 136, 12 bytes) */
	tar_write_octal((char *)header + 136, 12, (unsigned long)mtime);

	/* typeflag (offset 156) */
	header[156] = typeflag;

	/* linkname (offset 157, 100 bytes) */
	if (linkname)
		strncpy((char *)header + 157, linkname, 99);

	/* magic (offset 257, 6 bytes) + version (offset 263, 2 bytes) */
	memcpy(header + 257, "ustar", 5);
	header[263] = '0';
	header[264] = '0';

	/* checksum (offset 148, 8 bytes) */
	tar_write_octal((char *)header + 148, 7, tar_checksum(header));
	header[155] = ' ';

	if (write(fd, header, 512) != 512)
		return -1;

	return 0;
}

static unsigned long tar_parse_octal(const char *buf, size_t size)
{
	unsigned long val = 0;
	size_t i;

	for (i = 0; i < size && buf[i]; i++) {
		if (buf[i] >= '0' && buf[i] <= '7')
			val = (val << 3) | (buf[i] - '0');
	}

	return val;
}

static bool tar_checksum_valid(const uint8_t *header)
{
	unsigned int stored;

	stored = (unsigned int)tar_parse_octal((char *)header + 148, 8);
	return tar_checksum(header) == stored;
}

/*
 * Recursive EFS tree walk — manual TAR backup.
 *
 * Collects all entries first and closes the directory handle BEFORE
 * recursing into subdirectories. The modem has a very limited number
 * of simultaneous open directory handles (~4), so the old approach of
 * keeping parent dirs open during recursion caused EACCES failures at
 * depth >= 4.
 */

struct efs_entry_info {
	char name[256];
	int32_t mode;
	int32_t size;
	int32_t mtime;
};

static int efs_backup_tree(struct diag_session *sess, const char *path, int fd)
{
	struct efs_dirent entry;
	struct efs_stat st;
	struct efs_entry_info *entries = NULL;
	char fullpath[512];
	char linkbuf[256];
	int32_t dirp;
	uint32_t seqno = 1;
	int count = 0, capacity = 0;
	int ret, i;

	dirp = efs_opendir(sess, path);
	if (dirp < 0) {
		ux_err("cannot open EFS directory '%s'\n", path);
		return -1;
	}

	/* Collect all directory entries */
	for (;;) {
		ret = efs_readdir(sess, dirp, seqno, &entry);
		if (ret != 0)
			break;

		/* Skip . and .. */
		if (!strcmp(entry.name, ".") || !strcmp(entry.name, "..")) {
			seqno++;
			continue;
		}

		/* Build full path for stat */
		if (strcmp(path, "/") == 0)
			snprintf(fullpath, sizeof(fullpath), "/%s", entry.name);
		else
			snprintf(fullpath, sizeof(fullpath), "%s/%s",
				 path, entry.name);

		if (efs_stat(sess, fullpath, &st) < 0) {
			ux_warn("cannot stat '%s', skipping\n", fullpath);
			seqno++;
			continue;
		}

		/* Grow array if needed */
		if (count >= capacity) {
			capacity = capacity ? capacity * 2 : 64;
			entries = realloc(entries,
					  capacity * sizeof(*entries));
			if (!entries) {
				efs_closedir(sess, dirp);
				return -1;
			}
		}

		strncpy(entries[count].name, entry.name,
			sizeof(entries[count].name) - 1);
		entries[count].name[sizeof(entries[count].name) - 1] = '\0';
		entries[count].mode = st.mode;
		entries[count].size = st.size;
		entries[count].mtime = st.mtime;
		count++;
		seqno++;
	}

	/* Close directory handle BEFORE processing — frees it for recursion */
	efs_closedir(sess, dirp);

	/* Write directory header (skip for root "/") */
	if (strcmp(path, "/") != 0) {
		if (efs_stat(sess, path, &st) == 0) {
			snprintf(fullpath, sizeof(fullpath), "%s/",
				 path[0] == '/' ? path + 1 : path);
			tar_write_header(fd, fullpath, st.mode, 0,
					 st.mtime, '5', NULL);
		}
	}

	/* Process collected entries — directory handle is now closed */
	for (i = 0; i < count; i++) {
		if (strcmp(path, "/") == 0)
			snprintf(fullpath, sizeof(fullpath), "/%s",
				 entries[i].name);
		else
			snprintf(fullpath, sizeof(fullpath), "%s/%s",
				 path, entries[i].name);

		const char *tar_path = fullpath[0] == '/' ?
				       fullpath + 1 : fullpath;

		if (S_ISDIR(entries[i].mode)) {
			ret = efs_backup_tree(sess, fullpath, fd);
			if (ret < 0)
				ux_warn("failed to backup directory '%s'\n",
					fullpath);
		} else if (S_ISLNK(entries[i].mode)) {
			if (efs_readlink(sess, fullpath, linkbuf,
					 sizeof(linkbuf)) == 0)
				tar_write_header(fd, tar_path,
						 entries[i].mode, 0,
						 entries[i].mtime,
						 '2', linkbuf);
		} else {
			/*
			 * Regular files, EFS item files (mode 0160xxx),
			 * and anything else non-directory: try to read.
			 */
			int32_t fdata = efs_open(sess, fullpath,
						 0 /* O_RDONLY */, 0);
			if (fdata >= 0) {
				uint8_t buf[EFS_MAX_READ_REQ];
				uint32_t offset = 0;
				int32_t remaining = entries[i].size;

				tar_write_header(fd, tar_path,
						 entries[i].mode,
						 entries[i].size,
						 entries[i].mtime,
						 '0', NULL);

				while (remaining > 0) {
					uint32_t chunk = remaining >
							 EFS_MAX_READ_REQ ?
							 EFS_MAX_READ_REQ :
							 remaining;
					int n = efs_read(sess, fdata, chunk,
							 offset, buf,
							 sizeof(buf));
					if (n <= 0)
						break;

					if (write(fd, buf, n) != n)
						break;

					offset += n;
					remaining -= n;
				}
				efs_close(sess, fdata);

				if (entries[i].size % 512) {
					uint8_t pad[512] = {0};
					int pad_len = 512 -
						      (entries[i].size % 512);

					if (write(fd, pad, pad_len) != pad_len)
						ux_warn("TAR pad write failed\n");
				}
			} else {
				ux_warn("cannot read '%s', skipping\n",
					fullpath);
			}
		}
	}

	free(entries);
	return 0;
}

int diag_efs_backup(struct diag_session *sess, const char *path,
		    const char *output_file, bool manual)
{
	int fd;
	int handle;
	int ret = -1;
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		ux_err("cannot create %s: %s\n", output_file, strerror(errno));
		return -1;
	}

	if (!manual) {
		/* Try FS_IMAGE (modem-generated TAR) first */
		if (efs_image_open(sess, path, &handle) == 0) {
			uint8_t buf[2048];
			uint16_t seq = 0;
			size_t bytes;
			bool end;

			ux_info("backing up EFS '%s' via FS_IMAGE to %s\n",
				path, output_file);

			for (;;) {
				ret = efs_image_read(sess, handle, seq,
						     buf, sizeof(buf),
						     &bytes, &end);
				if (ret < 0)
					break;

				if (bytes > 0 && write(fd, buf, bytes) !=
				    (ssize_t)bytes) {
					ux_err("write failed: %s\n",
					       strerror(errno));
					ret = -1;
					break;
				}

				if (end) {
					ret = 0;
					break;
				}

				seq++;
			}

			efs_image_close(sess, handle);

			if (ret == 0) {
				ux_info("EFS backup complete: %s\n",
					output_file);
				close(fd);
				return 0;
			}

			ux_warn("FS_IMAGE failed, falling back to manual tree walk\n");
			/* Truncate and retry with manual method */
			if (ftruncate(fd, 0) < 0)
				ux_warn("ftruncate failed: %s\n",
					strerror(errno));
			lseek(fd, 0, SEEK_SET);
		} else {
			ux_info("FS_IMAGE not supported, using manual tree walk\n");
		}
	}

	/* Manual tree walk */
	ux_info("backing up EFS '%s' via tree walk to %s\n", path, output_file);

	ret = efs_backup_tree(sess, path, fd);

	/* Write two zero blocks to end the TAR archive */
	if (ret == 0) {
		uint8_t zeros[1024] = {0};

		if (write(fd, zeros, 1024) != 1024)
			ret = -1;
	}

	if (ret == 0)
		ux_info("EFS backup complete: %s\n", output_file);
	else
		ux_err("EFS backup failed\n");

	close(fd);
	return ret;
}

int diag_efs_restore(struct diag_session *sess, const char *tar_file)
{
	uint8_t header[512];
	uint8_t data[EFS_MAX_WRITE_REQ];
	char name[101];
	char linkname[101];
	unsigned long mode;
	unsigned long size;
	unsigned long mtime;
	char typeflag;
	char efs_path[256];
	int fd;
	int n;
	int ret = 0;
	int files_restored = 0;
	int dirs_created = 0;
	int links_created = 0;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	fd = open(tar_file, O_RDONLY | O_BINARY);
	if (fd < 0) {
		ux_err("cannot open %s: %s\n", tar_file, strerror(errno));
		return -1;
	}

	ux_info("restoring EFS from %s\n", tar_file);

	while (read(fd, header, 512) == 512) {
		/* Two consecutive zero blocks = end of archive */
		bool all_zero = true;
		int i;

		for (i = 0; i < 512; i++) {
			if (header[i] != 0) {
				all_zero = false;
				break;
			}
		}
		if (all_zero)
			break;

		if (!tar_checksum_valid(header)) {
			ux_err("invalid TAR header checksum\n");
			ret = -1;
			break;
		}

		/* Parse header fields */
		memset(name, 0, sizeof(name));
		memcpy(name, header, 100);

		mode = tar_parse_octal((char *)header + 100, 8);
		size = tar_parse_octal((char *)header + 124, 12);
		mtime = tar_parse_octal((char *)header + 136, 12);
		(void)mtime; /* preserved in TAR but not settable via DIAG */
		typeflag = header[156];

		memset(linkname, 0, sizeof(linkname));
		memcpy(linkname, header + 157, 100);

		/* Strip trailing slashes from directory names */
		size_t nlen = strlen(name);

		while (nlen > 1 && name[nlen - 1] == '/')
			name[--nlen] = '\0';

		/* Build EFS path — ensure leading / */
		if (name[0] == '/')
			snprintf(efs_path, sizeof(efs_path), "%s", name);
		else
			snprintf(efs_path, sizeof(efs_path), "/%s", name);

		switch (typeflag) {
		case '5': /* Directory */
			if (efs_mkdir_op(sess, efs_path, (int16_t)mode) == 0) {
				dirs_created++;
				ux_debug("mkdir %s\n", efs_path);
			} else {
				ux_warn("failed to create directory '%s'\n",
					efs_path);
			}
			break;

		case '0': /* Regular file */
		case '\0': /* Regular file (old TAR) */
		{
			/* EFS oflag: O_CREAT|O_WRONLY|O_TRUNC = 0x301 */
			int32_t fdata = efs_open(sess, efs_path, 0x301,
						 (int32_t)mode);
			if (fdata < 0) {
				ux_warn("failed to create file '%s'\n",
					efs_path);
				/* Skip data blocks */
				unsigned long blocks = (size + 511) / 512;

				lseek(fd, blocks * 512, SEEK_CUR);
				break;
			}

			uint32_t offset = 0;
			unsigned long remaining = size;

			while (remaining > 0) {
				uint32_t chunk = remaining > EFS_MAX_WRITE_REQ ?
						 EFS_MAX_WRITE_REQ : remaining;
				ssize_t r = read(fd, data, chunk);

				if (r <= 0) {
					ux_err("read from TAR failed\n");
					ret = -1;
					break;
				}

				int w = efs_write(sess, fdata, offset,
						  data, (uint32_t)r);
				if (w < 0) {
					ux_err("EFS write failed at offset %u\n",
					       offset);
					ret = -1;
					break;
				}

				offset += w;
				remaining -= w;

				/* If short write, adjust file position */
				if ((uint32_t)w < (uint32_t)r)
					lseek(fd, (off_t)w - r, SEEK_CUR);
			}

			efs_close(sess, fdata);
			efs_chmod_op(sess, efs_path, (int16_t)mode);

			/* Skip to next 512-byte TAR boundary */
			{
				unsigned long tar_blocks = (size + 511) / 512;
				unsigned long consumed = size - remaining;
				long to_skip = (long)(tar_blocks * 512 -
						      consumed);

				if (to_skip > 0)
					lseek(fd, to_skip, SEEK_CUR);
			}

			if (ret == 0) {
				files_restored++;
				ux_debug("restored %s (%lu bytes)\n",
					 efs_path, size);
			} else {
				break;
			}
			break;
		}

		case '2': /* Symlink */
			if (efs_symlink_op(sess, linkname, efs_path) == 0) {
				links_created++;
				ux_debug("symlink %s -> %s\n",
					 efs_path, linkname);
			} else {
				ux_warn("failed to create symlink '%s'\n",
					efs_path);
			}
			break;

		default:
			/* Skip unknown types */
			if (size > 0) {
				unsigned long blocks = (size + 511) / 512;

				lseek(fd, blocks * 512, SEEK_CUR);
			}
			break;
		}

		if (ret)
			break;
	}

	close(fd);

	if (ret == 0)
		ux_info("EFS restore complete: %d files, %d dirs, %d symlinks\n",
			files_restored, dirs_created, links_created);
	else
		ux_err("EFS restore failed\n");

	return ret;
}

/*
 * EFS file operation subcommands
 */

static int efs_unlink(struct diag_session *sess, const char *path)
{
	uint8_t cmd[4 + 256];
	uint8_t resp[64];
	size_t path_len;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_UNLINK);
	memcpy(&cmd[4], path, path_len);

	n = diag_send(sess, cmd, 4 + path_len, resp, sizeof(resp));
	if (n < 8)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);
	if (diag_errno != 0) {
		ux_err("EFS unlink '%s' failed (errno=%d)\n", path, diag_errno);
		return -1;
	}

	return 0;
}

static int efs_rmdir_op(struct diag_session *sess, const char *path)
{
	uint8_t cmd[4 + 256];
	uint8_t resp[64];
	size_t path_len;
	int32_t diag_errno;
	int n;

	path_len = strlen(path) + 1;
	if (path_len > 252)
		return -1;

	memset(cmd, 0, sizeof(cmd));
	efs_cmd_header(cmd, sess->efs_method, EFS2_DIAG_RMDIR);
	memcpy(&cmd[4], path, path_len);

	n = diag_send(sess, cmd, 4 + path_len, resp, sizeof(resp));
	if (n < 8)
		return -1;

	memcpy(&diag_errno, &resp[4], 4);
	if (diag_errno != 0) {
		ux_err("EFS rmdir '%s' failed (errno=%d)\n", path, diag_errno);
		return -1;
	}

	return 0;
}

static int efs_rm_recursive(struct diag_session *sess, const char *path)
{
	struct efs_dirent entry;
	struct efs_stat st;
	char fullpath[512];
	int32_t dirp;
	uint32_t seqno = 1;
	int ret;

	dirp = efs_opendir(sess, path);
	if (dirp < 0)
		return efs_unlink(sess, path);

	for (;;) {
		ret = efs_readdir(sess, dirp, seqno, &entry);
		if (ret != 0)
			break;

		if (!strcmp(entry.name, ".") || !strcmp(entry.name, "..")) {
			seqno++;
			continue;
		}

		if (strcmp(path, "/") == 0)
			snprintf(fullpath, sizeof(fullpath), "/%s", entry.name);
		else
			snprintf(fullpath, sizeof(fullpath), "%s/%s",
				 path, entry.name);

		if (efs_stat(sess, fullpath, &st) < 0) {
			seqno++;
			continue;
		}

		if (S_ISDIR(st.mode)) {
			ret = efs_rm_recursive(sess, fullpath);
			if (ret)
				ux_warn("failed to remove '%s'\n", fullpath);
		} else {
			ret = efs_unlink(sess, fullpath);
			if (ret)
				ux_warn("failed to unlink '%s'\n", fullpath);
			else
				ux_debug("removed %s\n", fullpath);
		}

		seqno++;
	}

	efs_closedir(sess, dirp);

	ret = efs_rmdir_op(sess, path);
	if (ret == 0)
		ux_debug("removed directory %s\n", path);

	return ret;
}

int diag_efs_put(struct diag_session *sess, const char *local_path,
		 const char *efs_path)
{
	struct stat sb;
	uint8_t buf[EFS_MAX_WRITE_REQ];
	int32_t fdata;
	uint32_t offset = 0;
	int local_fd;
	int n;
	int ret = -1;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	local_fd = open(local_path, O_RDONLY | O_BINARY);
	if (local_fd < 0) {
		ux_err("cannot open %s: %s\n", local_path, strerror(errno));
		return -1;
	}

	if (fstat(local_fd, &sb) < 0) {
		ux_err("cannot stat %s: %s\n", local_path, strerror(errno));
		close(local_fd);
		return -1;
	}

	/* EFS oflag: O_CREAT|O_WRONLY|O_TRUNC = 0x301 */
	fdata = efs_open(sess, efs_path, 0x301, 0644);
	if (fdata < 0) {
		ux_err("cannot create EFS file '%s'\n", efs_path);
		close(local_fd);
		return -1;
	}

	ux_info("writing '%s' to EFS '%s' (%ld bytes)\n",
		local_path, efs_path, (long)sb.st_size);

	while (offset < (uint32_t)sb.st_size) {
		uint32_t chunk = (uint32_t)sb.st_size - offset;

		if (chunk > EFS_MAX_WRITE_REQ)
			chunk = EFS_MAX_WRITE_REQ;

		ssize_t r = read(local_fd, buf, chunk);

		if (r <= 0) {
			ux_err("read from '%s' failed\n", local_path);
			goto out;
		}

		int w = efs_write(sess, fdata, offset, buf, (uint32_t)r);

		if (w < 0) {
			ux_err("EFS write failed at offset %u\n", offset);
			goto out;
		}

		offset += w;
	}

	ux_info("EFS file '%s' written (%u bytes)\n", efs_path, offset);
	ret = 0;

out:
	efs_close(sess, fdata);
	close(local_fd);
	return ret;
}

int diag_efs_rm(struct diag_session *sess, const char *path, bool recursive)
{
	struct efs_stat st;
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	if (recursive) {
		if (efs_stat(sess, path, &st) == 0 && S_ISDIR(st.mode))
			return efs_rm_recursive(sess, path);
	}

	n = efs_unlink(sess, path);
	if (n == 0)
		ux_info("removed '%s'\n", path);

	return n;
}

int diag_efs_stat_path(struct diag_session *sess, const char *path,
		       struct efs_stat *st)
{
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	return efs_stat(sess, path, st);
}

int diag_efs_mkdir_path(struct diag_session *sess, const char *path,
			int16_t mode)
{
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	return efs_mkdir_op(sess, path, mode);
}

int diag_efs_chmod_path(struct diag_session *sess, const char *path,
			int16_t mode)
{
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	return efs_chmod_op(sess, path, mode);
}

int diag_efs_ln(struct diag_session *sess, const char *target,
		const char *linkpath)
{
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	return efs_symlink_op(sess, target, linkpath);
}

int diag_efs_readlink_path(struct diag_session *sess, const char *path,
			   char *buf, size_t buf_size)
{
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	return efs_readlink(sess, path, buf, buf_size);
}

int diag_efs_get_item(struct diag_session *sess, const char *path,
		      uint8_t *buf, size_t buf_size, int32_t *data_len_out)
{
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	return efs_get_item(sess, path, buf, buf_size, data_len_out);
}

int diag_efs_put_item(struct diag_session *sess, const char *path,
		      const uint8_t *data, int32_t data_len,
		      int32_t flags, int32_t mode)
{
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	return efs_put_item(sess, path, data, data_len, flags, mode);
}

/*
 * DIAG feature query — retrieves modem feature bitmask.
 * Command 0x51 (DIAG_FEATURE_QUERY), response contains mask.
 */
#define DIAG_FEATURE_QUERY_F	0x51

int diag_feature_query(struct diag_session *sess, uint8_t *mask,
		       size_t mask_size, size_t *mask_len)
{
	uint8_t cmd = DIAG_FEATURE_QUERY_F;
	uint8_t resp[256];
	int n;
	uint16_t len;

	n = diag_send(sess, &cmd, 1, resp, sizeof(resp));
	if (n < 3 || resp[0] != DIAG_FEATURE_QUERY_F)
		return -1;

	len = resp[1] | (resp[2] << 8);
	if (len > (uint16_t)(n - 3))
		len = n - 3;
	if (len > mask_size)
		len = mask_size;

	memcpy(mask, &resp[3], len);
	if (mask_len)
		*mask_len = len;

	return 0;
}

/*
 * DIAG extended build ID — retrieves modem model/build info.
 * Command 0x7C returns build ID string.
 */
#define DIAG_EXT_BUILD_ID_F	0x7C

int diag_ext_build_id(struct diag_session *sess, char *model,
		      size_t model_size)
{
	uint8_t cmd = DIAG_EXT_BUILD_ID_F;
	uint8_t resp[512];
	int n;

	n = diag_send(sess, &cmd, 1, resp, sizeof(resp));
	if (n < 16 || resp[0] != DIAG_EXT_BUILD_ID_F)
		return -1;

	/*
	 * Response layout:
	 *   [0]     cmd echo
	 *   [1..12] version info (MSM, mobile model, etc.)
	 *   [13+]   null-terminated build ID string
	 */
	const char *build = (const char *)&resp[13];
	size_t build_len = strnlen(build, n - 13);

	if (build_len >= model_size)
		build_len = model_size - 1;
	memcpy(model, build, build_len);
	model[build_len] = '\0';

	return 0;
}

/*
 * Path hash set for deduplication during probe walk.
 * Simple open-addressing hash table with FNV-1a hash.
 */
struct path_set {
	char **entries;
	int capacity;
	int count;
};

static uint32_t path_hash(const char *s)
{
	uint32_t h = 2166136261U;

	while (*s) {
		h ^= (uint8_t)*s++;
		h *= 16777619U;
	}
	return h;
}

static void path_set_init(struct path_set *ps, int capacity)
{
	ps->capacity = capacity;
	ps->count = 0;
	ps->entries = calloc(capacity, sizeof(char *));
}

static void path_set_free(struct path_set *ps)
{
	int i;

	for (i = 0; i < ps->capacity; i++)
		free(ps->entries[i]);
	free(ps->entries);
	ps->entries = NULL;
	ps->count = 0;
}

static bool path_set_contains(struct path_set *ps, const char *path)
{
	uint32_t idx = path_hash(path) % ps->capacity;
	int i;

	for (i = 0; i < ps->capacity; i++) {
		uint32_t slot = (idx + i) % ps->capacity;

		if (!ps->entries[slot])
			return false;
		if (strcmp(ps->entries[slot], path) == 0)
			return true;
	}
	return false;
}

static void path_set_add(struct path_set *ps, const char *path)
{
	uint32_t idx;
	int i;

	if (path_set_contains(ps, path))
		return;
	if (ps->count >= ps->capacity * 3 / 4)
		return; /* table too full, skip */

	idx = path_hash(path) % ps->capacity;
	for (i = 0; i < ps->capacity; i++) {
		uint32_t slot = (idx + i) % ps->capacity;

		if (!ps->entries[slot]) {
			ps->entries[slot] = strdup(path);
			ps->count++;
			return;
		}
	}
}

/*
 * efs_backup_tree_tracked() — same as efs_backup_tree() but records
 * written paths into a path_set for later deduplication with probe walk.
 */
static int efs_backup_tree_tracked(struct diag_session *sess,
				   const char *path, int fd,
				   struct path_set *written)
{
	struct efs_dirent entry;
	struct efs_stat st;
	struct efs_entry_info *entries = NULL;
	char fullpath[512];
	char linkbuf[256];
	int32_t dirp;
	uint32_t seqno = 1;
	int count = 0, capacity = 0;
	int ret, i;

	dirp = efs_opendir(sess, path);
	if (dirp < 0) {
		ux_err("cannot open EFS directory '%s'\n", path);
		return -1;
	}

	for (;;) {
		ret = efs_readdir(sess, dirp, seqno, &entry);
		if (ret != 0)
			break;

		if (!strcmp(entry.name, ".") || !strcmp(entry.name, "..")) {
			seqno++;
			continue;
		}

		if (strcmp(path, "/") == 0)
			snprintf(fullpath, sizeof(fullpath), "/%s",
				 entry.name);
		else
			snprintf(fullpath, sizeof(fullpath), "%s/%s",
				 path, entry.name);

		if (efs_stat(sess, fullpath, &st) < 0) {
			ux_warn("cannot stat '%s', skipping\n", fullpath);
			seqno++;
			continue;
		}

		if (count >= capacity) {
			capacity = capacity ? capacity * 2 : 64;
			entries = realloc(entries,
					  capacity * sizeof(*entries));
			if (!entries) {
				efs_closedir(sess, dirp);
				return -1;
			}
		}

		strncpy(entries[count].name, entry.name,
			sizeof(entries[count].name) - 1);
		entries[count].name[sizeof(entries[count].name) - 1] = '\0';
		entries[count].mode = st.mode;
		entries[count].size = st.size;
		entries[count].mtime = st.mtime;
		count++;
		seqno++;
	}

	efs_closedir(sess, dirp);

	if (strcmp(path, "/") != 0) {
		if (efs_stat(sess, path, &st) == 0) {
			snprintf(fullpath, sizeof(fullpath), "%s/",
				 path[0] == '/' ? path + 1 : path);
			tar_write_header(fd, fullpath, st.mode, 0,
					 st.mtime, '5', NULL);
		}
	}

	for (i = 0; i < count; i++) {
		if (strcmp(path, "/") == 0)
			snprintf(fullpath, sizeof(fullpath), "/%s",
				 entries[i].name);
		else
			snprintf(fullpath, sizeof(fullpath), "%s/%s",
				 path, entries[i].name);

		const char *tar_path = fullpath[0] == '/' ?
				       fullpath + 1 : fullpath;

		if (S_ISDIR(entries[i].mode)) {
			ret = efs_backup_tree_tracked(sess, fullpath,
						      fd, written);
			if (ret < 0)
				ux_warn("failed to backup directory '%s'\n",
					fullpath);
		} else if (S_ISLNK(entries[i].mode)) {
			if (efs_readlink(sess, fullpath, linkbuf,
					 sizeof(linkbuf)) == 0) {
				tar_write_header(fd, tar_path,
						 entries[i].mode, 0,
						 entries[i].mtime,
						 '2', linkbuf);
				path_set_add(written, fullpath);
			}
		} else {
			int32_t fdata = efs_open(sess, fullpath,
						 0 /* O_RDONLY */, 0);
			if (fdata >= 0) {
				uint8_t buf[EFS_MAX_READ_REQ];
				uint32_t offset = 0;
				int32_t remaining = entries[i].size;

				tar_write_header(fd, tar_path,
						 entries[i].mode,
						 entries[i].size,
						 entries[i].mtime,
						 '0', NULL);

				while (remaining > 0) {
					uint32_t chunk = remaining >
							 EFS_MAX_READ_REQ ?
							 EFS_MAX_READ_REQ :
							 remaining;
					int n = efs_read(sess, fdata, chunk,
							 offset, buf,
							 sizeof(buf));
					if (n <= 0)
						break;
					if (write(fd, buf, n) != n)
						break;
					offset += n;
					remaining -= n;
				}
				efs_close(sess, fdata);

				if (entries[i].size % 512) {
					uint8_t pad[512] = {0};
					int pad_len = 512 -
						      (entries[i].size % 512);

					if (write(fd, pad, pad_len) !=
					    pad_len)
						ux_warn("TAR pad write failed\n");
				}
				path_set_add(written, fullpath);
			} else {
				ux_warn("cannot read '%s', skipping\n",
					fullpath);
			}
		}
	}

	free(entries);
	return 0;
}

/*
 * efs_probe_file() — probe a single EFS path and write to TAR if it exists
 * and wasn't already captured by tree walk.
 */
static int efs_probe_file(struct diag_session *sess, const char *path,
			  int fd, struct path_set *written)
{
	struct efs_stat st;
	int32_t fdata;
	uint8_t buf[EFS_MAX_READ_REQ];
	uint32_t offset;
	int32_t remaining;
	int n;
	const char *tar_path;

	if (path_set_contains(written, path))
		return 0;

	if (efs_stat(sess, path, &st) < 0)
		return 0; /* doesn't exist on this modem */

	if (S_ISDIR(st.mode))
		return 0;

	fdata = efs_open(sess, path, 0 /* O_RDONLY */, 0);
	if (fdata < 0)
		return 0;

	tar_path = path[0] == '/' ? path + 1 : path;
	tar_write_header(fd, tar_path, st.mode, st.size, st.mtime, '0', NULL);

	offset = 0;
	remaining = st.size;
	while (remaining > 0) {
		uint32_t chunk = remaining > EFS_MAX_READ_REQ ?
				 EFS_MAX_READ_REQ : remaining;

		n = efs_read(sess, fdata, chunk, offset, buf, sizeof(buf));
		if (n <= 0)
			break;
		if (write(fd, buf, n) != n)
			break;
		offset += n;
		remaining -= n;
	}
	efs_close(sess, fdata);

	if (st.size % 512) {
		uint8_t pad[512] = {0};
		int pad_len = 512 - (st.size % 512);

		if (write(fd, pad, pad_len) != pad_len)
			ux_warn("TAR pad write failed\n");
	}

	path_set_add(written, path);
	return 1;
}

/*
 * Enhanced EFS backup: tree walk + probe walk.
 * Captures both visible files (readdir) and virtual NV item files
 * (invisible to readdir but accessible by direct path).
 */
int diag_efs_backup_enhanced(struct diag_session *sess, const char *path,
			     const char *output_file, bool quick)
{
	struct path_set written;
	int fd;
	int ret;
	int n;
	int probe_count = 0;
	int i;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		ux_err("cannot create %s: %s\n", output_file, strerror(errno));
		return -1;
	}

	path_set_init(&written, 4096);

	/* Phase 1: tree walk (discovers device-specific files) */
	ux_info("backing up EFS '%s' via tree walk to %s\n", path, output_file);
	ret = efs_backup_tree_tracked(sess, path, fd, &written);
	if (ret < 0) {
		ux_err("tree walk failed\n");
		close(fd);
		path_set_free(&written);
		return -1;
	}

	ux_info("tree walk: %d files captured\n", written.count);

	if (!quick) {
		/* Phase 2: probe static EFS_Backup paths */
		ux_info("probing known provisioning paths...\n");
		for (i = 0; efs_backup_static_paths[i]; i++) {
			if (efs_probe_file(sess, efs_backup_static_paths[i],
					   fd, &written))
				probe_count++;
		}

		/* Phase 3: probe rfnv range dynamically */
		ux_info("probing rfnv range %d-%d...\n",
			RFNV_ID_MIN, RFNV_ID_MAX);
		for (i = RFNV_ID_MIN; i <= RFNV_ID_MAX; i++) {
			char rfpath[64];

			snprintf(rfpath, sizeof(rfpath),
				 "/nv/item_files/rfnv/%08d", i);
			if (efs_probe_file(sess, rfpath, fd, &written))
				probe_count++;

			if ((i - RFNV_ID_MIN) % 1000 == 0 && i > RFNV_ID_MIN)
				ux_progress("rfnv probe",
					    i - RFNV_ID_MIN,
					    RFNV_ID_MAX - RFNV_ID_MIN);
		}

		/* Phase 4: probe provisioning paths */
		ux_info("probing provisioning paths...\n");
		for (i = 0; provisioning_paths[i]; i++) {
			if (efs_probe_file(sess, provisioning_paths[i],
					   fd, &written))
				probe_count++;

			if (i % 100 == 0 && i > 0) {
				int total = 0;

				while (provisioning_paths[total])
					total++;
				ux_progress("provisioning probe", i, total);
			}
		}

		ux_info("probe walk: %d additional files found\n",
			probe_count);
	}

	/* Write two zero blocks to end TAR archive */
	{
		uint8_t zeros[1024] = {0};

		if (write(fd, zeros, 1024) != 1024)
			ret = -1;
	}

	ux_info("EFS backup complete: %d files total in %s\n",
		written.count, output_file);

	close(fd);
	path_set_free(&written);
	return ret;
}

/*
 * NV numbered item scanning.
 */
void nv_scan_result_free(struct nv_scan_result *r)
{
	free(r->items);
	r->items = NULL;
	r->count = 0;
	r->capacity = 0;
}

static void nv_scan_add(struct nv_scan_result *r, const struct nv_item *item)
{
	if (r->count >= r->capacity) {
		r->capacity = r->capacity ? r->capacity * 2 : 256;
		r->items = realloc(r->items, r->capacity * sizeof(*r->items));
	}
	memcpy(&r->items[r->count], item, sizeof(*item));
	r->count++;
}

int diag_nv_scan(struct diag_session *sess,
		 struct nv_scan_result *def_items,
		 struct nv_scan_result *sim1_items)
{
	struct nv_item item;
	int i;

	memset(def_items, 0, sizeof(*def_items));
	memset(sim1_items, 0, sizeof(*sim1_items));

	ux_info("scanning NV items 0-%d...\n", NV_SCAN_MAX_ID);

	/* Scan default subscription */
	for (i = 0; i <= NV_SCAN_MAX_ID; i++) {
		if (diag_nv_read(sess, (uint16_t)i, &item) == 0 &&
		    item.status == NV_DONE_S)
			nv_scan_add(def_items, &item);

		ux_progress("NV default", i, NV_SCAN_MAX_ID);
	}

	ux_info("default subscription: %d active NV items\n", def_items->count);

	/* Scan SIM_1 subscription (index 1) */
	for (i = 0; i <= NV_SCAN_MAX_ID; i++) {
		if (diag_nv_read_sub(sess, (uint16_t)i, 1, &item) == 0 &&
		    item.status == NV_DONE_S)
			nv_scan_add(sim1_items, &item);

		ux_progress("NV SIM_1", i, NV_SCAN_MAX_ID);
	}

	ux_info("SIM_1 subscription: %d active NV items\n", sim1_items->count);

	return 0;
}

/*
 * XQCN file data — collected EFS files + metadata for XQCN generation.
 */
struct efs_file_entry {
	char path[512];
	uint8_t *data;
	int32_t size;
	int32_t mode;
};

struct xqcn_efs_data {
	struct efs_file_entry *files;
	int count;
	int capacity;
};

static void xqcn_efs_free(struct xqcn_efs_data *d)
{
	int i;

	for (i = 0; i < d->count; i++)
		free(d->files[i].data);
	free(d->files);
	d->files = NULL;
	d->count = 0;
}

static int xqcn_efs_add(struct xqcn_efs_data *d, struct diag_session *sess,
			 const char *path, struct path_set *seen)
{
	struct efs_stat st;
	int32_t fdata;
	uint8_t *buf;
	uint32_t offset;
	int32_t remaining;
	int n;

	if (path_set_contains(seen, path))
		return 0;

	if (efs_stat(sess, path, &st) < 0)
		return 0;

	if (S_ISDIR(st.mode))
		return 0;

	fdata = efs_open(sess, path, 0 /* O_RDONLY */, 0);
	if (fdata < 0)
		return 0;

	buf = malloc(st.size > 0 ? st.size : 1);
	if (!buf) {
		efs_close(sess, fdata);
		return 0;
	}

	offset = 0;
	remaining = st.size;
	while (remaining > 0) {
		uint8_t tmp[EFS_MAX_READ_REQ];
		uint32_t chunk = remaining > EFS_MAX_READ_REQ ?
				 EFS_MAX_READ_REQ : remaining;

		n = efs_read(sess, fdata, chunk, offset, tmp, sizeof(tmp));
		if (n <= 0)
			break;
		memcpy(buf + offset, tmp, n);
		offset += n;
		remaining -= n;
	}
	efs_close(sess, fdata);

	if (d->count >= d->capacity) {
		d->capacity = d->capacity ? d->capacity * 2 : 256;
		d->files = realloc(d->files,
				   d->capacity * sizeof(*d->files));
	}

	strncpy(d->files[d->count].path, path,
		sizeof(d->files[d->count].path) - 1);
	d->files[d->count].path[sizeof(d->files[d->count].path) - 1] = '\0';
	d->files[d->count].data = buf;
	d->files[d->count].size = offset;
	d->files[d->count].mode = st.mode;
	d->count++;

	path_set_add(seen, path);
	return 1;
}

/*
 * Collect EFS files by walking tree + probing known paths.
 */
static int xqcn_collect_tree(struct diag_session *sess, const char *path,
			     struct xqcn_efs_data *d, struct path_set *seen)
{
	struct efs_dirent entry;
	struct efs_stat st;
	struct efs_entry_info *entries = NULL;
	char fullpath[512];
	int32_t dirp;
	uint32_t seqno = 1;
	int count = 0, capacity = 0;
	int ret, i;

	dirp = efs_opendir(sess, path);
	if (dirp < 0)
		return -1;

	for (;;) {
		ret = efs_readdir(sess, dirp, seqno, &entry);
		if (ret != 0)
			break;

		if (!strcmp(entry.name, ".") || !strcmp(entry.name, "..")) {
			seqno++;
			continue;
		}

		if (strcmp(path, "/") == 0)
			snprintf(fullpath, sizeof(fullpath), "/%s",
				 entry.name);
		else
			snprintf(fullpath, sizeof(fullpath), "%s/%s",
				 path, entry.name);

		if (efs_stat(sess, fullpath, &st) < 0) {
			seqno++;
			continue;
		}

		if (count >= capacity) {
			capacity = capacity ? capacity * 2 : 64;
			entries = realloc(entries,
					  capacity * sizeof(*entries));
			if (!entries) {
				efs_closedir(sess, dirp);
				return -1;
			}
		}

		strncpy(entries[count].name, entry.name,
			sizeof(entries[count].name) - 1);
		entries[count].name[sizeof(entries[count].name) - 1] = '\0';
		entries[count].mode = st.mode;
		entries[count].size = st.size;
		entries[count].mtime = st.mtime;
		count++;
		seqno++;
	}

	efs_closedir(sess, dirp);

	for (i = 0; i < count; i++) {
		if (strcmp(path, "/") == 0)
			snprintf(fullpath, sizeof(fullpath), "/%s",
				 entries[i].name);
		else
			snprintf(fullpath, sizeof(fullpath), "%s/%s",
				 path, entries[i].name);

		if (S_ISDIR(entries[i].mode))
			xqcn_collect_tree(sess, fullpath, d, seen);
		else if (!S_ISLNK(entries[i].mode))
			xqcn_efs_add(d, sess, fullpath, seen);
	}

	free(entries);
	return 0;
}

/*
 * Write hex-encoded stream data to XQCN file.
 */
static void xqcn_write_hex(FILE *fp, const uint8_t *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (i > 0)
			fprintf(fp, " ");
		fprintf(fp, "%02X", data[i]);
	}
}

/*
 * Build EFS_Backup dir entry: 8-byte header + null-terminated path.
 * Header: 01 00 01 01 + 4 bytes (mode as uint32_t LE).
 */
static void xqcn_write_backup_dir_entry(FILE *fp, int idx,
					 const char *path, int32_t mode)
{
	uint8_t header[8] = {0x01, 0x00, 0x01, 0x01, 0, 0, 0, 0};
	size_t path_len = strlen(path) + 1; /* include null */
	size_t total = 8 + path_len;

	memcpy(&header[4], &mode, 4);

	fprintf(fp, "          <Stream Length='%zu' Name='%08X' Value='",
		total, idx);
	xqcn_write_hex(fp, header, 8);
	fprintf(fp, " ");
	xqcn_write_hex(fp, (const uint8_t *)path, path_len);
	fprintf(fp, "'/>\n");
}

/*
 * Build Provisioning dir entry: raw null-terminated path.
 */
static void xqcn_write_prov_dir_entry(FILE *fp, int idx, const char *path)
{
	size_t path_len = strlen(path) + 1;

	fprintf(fp, "          <Stream Length='%zu' Name='%08X' Value='",
		path_len, idx);
	xqcn_write_hex(fp, (const uint8_t *)path, path_len);
	fprintf(fp, "'/>\n");
}

/*
 * Write file data stream.
 */
static void xqcn_write_data_entry(FILE *fp, int idx,
				   const uint8_t *data, int32_t size)
{
	fprintf(fp, "          <Stream Length='%d' Name='%08X' Value='",
		size, idx);
	xqcn_write_hex(fp, data, size);
	fprintf(fp, "'/>\n");
}

int diag_efs_backup_xqcn(struct diag_session *sess, const char *output_file)
{
	struct nv_scan_result def_nv = {0}, sim1_nv = {0};
	struct xqcn_efs_data efs_data = {0};
	struct path_set seen;
	uint8_t feature_mask[128];
	size_t fm_len = 0;
	char model[256] = {0};
	FILE *fp;
	int i, idx;
	int backup_count = 0, prov_count = 0, nvitems_count = 0;
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	/* Step 1: Scan NV numbered items */
	diag_nv_scan(sess, &def_nv, &sim1_nv);

	/* Step 2: Collect EFS files */
	path_set_init(&seen, 4096);

	ux_info("collecting EFS files via tree walk...\n");
	xqcn_collect_tree(sess, "/", &efs_data, &seen);
	ux_info("tree walk: %d files\n", efs_data.count);

	/* Probe static EFS_Backup paths */
	for (i = 0; efs_backup_static_paths[i]; i++)
		xqcn_efs_add(&efs_data, sess, efs_backup_static_paths[i],
			      &seen);

	/* Probe rfnv range */
	ux_info("probing rfnv range %d-%d...\n", RFNV_ID_MIN, RFNV_ID_MAX);
	for (i = RFNV_ID_MIN; i <= RFNV_ID_MAX; i++) {
		char rfpath[64];

		snprintf(rfpath, sizeof(rfpath),
			 "/nv/item_files/rfnv/%08d", i);
		xqcn_efs_add(&efs_data, sess, rfpath, &seen);

		if ((i - RFNV_ID_MIN) % 1000 == 0 && i > RFNV_ID_MIN)
			ux_progress("rfnv probe", i - RFNV_ID_MIN,
				    RFNV_ID_MAX - RFNV_ID_MIN);
	}

	/* Probe provisioning paths */
	ux_info("probing provisioning paths...\n");
	for (i = 0; provisioning_paths[i]; i++)
		xqcn_efs_add(&efs_data, sess, provisioning_paths[i], &seen);

	ux_info("total EFS files collected: %d\n", efs_data.count);

	/* Step 3: Get metadata */
	if (diag_feature_query(sess, feature_mask, sizeof(feature_mask),
			       &fm_len) < 0) {
		fm_len = 0;
		ux_warn("feature query failed, using empty mask\n");
	}

	if (diag_ext_build_id(sess, model, sizeof(model)) < 0) {
		strncpy(model, "Unknown", sizeof(model) - 1);
		ux_warn("build ID query failed\n");
	}

	/* Step 4: Write XQCN XML */
	fp = fopen(output_file, "w");
	if (!fp) {
		ux_err("cannot create %s: %s\n", output_file,
		       strerror(errno));
		nv_scan_result_free(&def_nv);
		nv_scan_result_free(&sim1_nv);
		xqcn_efs_free(&efs_data);
		path_set_free(&seen);
		return -1;
	}

	fprintf(fp, "<?xml version=\"1.0\" encoding=\"Windows-1252\" ?>\n");
	fprintf(fp, "<Storage Name='%s'>\n",
		strrchr(output_file, '/') ?
		strrchr(output_file, '/') + 1 : output_file);
	fprintf(fp, "  <Storage Name='00000000'>\n");
	fprintf(fp, "    <Storage Name='default'>\n");

	/* NV_NUMBERED_ITEMS */
	fprintf(fp, "      <Storage Name='NV_NUMBERED_ITEMS'>\n");

	/* NV_ITEM_ARRAY (default subscription) */
	{
		size_t arr_len = def_nv.count * XQCN_NV_RECORD_SIZE;

		fprintf(fp, "        <Stream Length='%zu'"
			" Name='NV_ITEM_ARRAY' Value='", arr_len);
		for (i = 0; i < def_nv.count; i++) {
			uint8_t rec[XQCN_NV_RECORD_SIZE];
			uint16_t rsize = XQCN_NV_RECORD_SIZE;
			uint16_t sub = 0x0001;
			uint32_t nv_id = def_nv.items[i].item;

			memset(rec, 0, sizeof(rec));
			memcpy(&rec[0], &rsize, 2);
			memcpy(&rec[2], &sub, 2);
			memcpy(&rec[4], &nv_id, 4);
			memcpy(&rec[8], def_nv.items[i].data,
			       NV_ITEM_DATA_SIZE);

			if (i > 0)
				fprintf(fp, " ");
			xqcn_write_hex(fp, rec, XQCN_NV_RECORD_SIZE);
		}
		fprintf(fp, "'/>\n");
	}

	/* NV_ITEM_ARRAY_SIM_1 */
	{
		size_t arr_len = sim1_nv.count * XQCN_NV_RECORD_SIZE;

		fprintf(fp, "        <Stream Length='%zu'"
			" Name='NV_ITEM_ARRAY_SIM_1' Value='", arr_len);
		for (i = 0; i < sim1_nv.count; i++) {
			uint8_t rec[XQCN_NV_RECORD_SIZE];
			uint16_t rsize = XQCN_NV_RECORD_SIZE;
			uint16_t sub = 0x0001;
			uint32_t nv_id = sim1_nv.items[i].item;

			memset(rec, 0, sizeof(rec));
			memcpy(&rec[0], &rsize, 2);
			memcpy(&rec[2], &sub, 2);
			memcpy(&rec[4], &nv_id, 4);
			memcpy(&rec[8], sim1_nv.items[i].data,
			       NV_ITEM_DATA_SIZE);

			if (i > 0)
				fprintf(fp, " ");
			xqcn_write_hex(fp, rec, XQCN_NV_RECORD_SIZE);
		}
		fprintf(fp, "'/>\n");
	}

	/* NV_ITEM_ARRAY_SIM_2 (empty) */
	fprintf(fp, "        <Stream Length='0'"
		" Name='NV_ITEM_ARRAY_SIM_2' Value=''/>\n");
	fprintf(fp, "      </Storage>\n");

	/*
	 * EFS_Backup section (rfnv + rfc/static paths — 8-byte header).
	 * QPST puts rfc paths in BOTH EFS_Backup and NV_Items for
	 * restore redundancy (file API + item API). We match this.
	 */
	fprintf(fp, "      <Storage Name='EFS_Backup'>\n");
	fprintf(fp, "        <Storage Name='EFS_Dir'>\n");
	idx = 0;
	for (i = 0; i < efs_data.count; i++) {
		int sec = efs_path_xqcn_section(efs_data.files[i].path);

		if (sec == XQCN_SECTION_BACKUP ||
		    sec == XQCN_SECTION_NVITEMS) {
			xqcn_write_backup_dir_entry(fp, idx,
						    efs_data.files[i].path,
						    efs_data.files[i].mode);
			idx++;
		}
	}
	backup_count = idx;
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "        <Storage Name='EFS_Data'>\n");
	idx = 0;
	for (i = 0; i < efs_data.count; i++) {
		int sec = efs_path_xqcn_section(efs_data.files[i].path);

		if (sec == XQCN_SECTION_BACKUP ||
		    sec == XQCN_SECTION_NVITEMS) {
			xqcn_write_data_entry(fp, idx,
					      efs_data.files[i].data,
					      efs_data.files[i].size);
			idx++;
		}
	}
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "      </Storage>\n");

	/* Provisioning_Item_Files section (config paths — raw path) */
	fprintf(fp, "      <Storage Name='Provisioning_Item_Files'>\n");
	fprintf(fp, "        <Storage Name='EFS_Dir'>\n");
	idx = 0;
	for (i = 0; i < efs_data.count; i++) {
		if (efs_path_xqcn_section(efs_data.files[i].path) ==
		    XQCN_SECTION_PROV) {
			xqcn_write_prov_dir_entry(fp, idx,
						  efs_data.files[i].path);
			idx++;
		}
	}
	prov_count = idx;
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "        <Storage Name='EFS_Data'>\n");
	idx = 0;
	for (i = 0; i < efs_data.count; i++) {
		if (efs_path_xqcn_section(efs_data.files[i].path) ==
		    XQCN_SECTION_PROV) {
			xqcn_write_data_entry(fp, idx,
					      efs_data.files[i].data,
					      efs_data.files[i].size);
			idx++;
		}
	}
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "      </Storage>\n");

	/* NV_Items section (RFC/calibration — raw path) */
	fprintf(fp, "      <Storage Name='NV_Items'>\n");
	fprintf(fp, "        <Storage Name='EFS_Dir'>\n");
	idx = 0;
	for (i = 0; i < efs_data.count; i++) {
		if (efs_path_xqcn_section(efs_data.files[i].path) ==
		    XQCN_SECTION_NVITEMS) {
			xqcn_write_prov_dir_entry(fp, idx,
						  efs_data.files[i].path);
			idx++;
		}
	}
	nvitems_count = idx;
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "        <Storage Name='EFS_Data'>\n");
	idx = 0;
	for (i = 0; i < efs_data.count; i++) {
		if (efs_path_xqcn_section(efs_data.files[i].path) ==
		    XQCN_SECTION_NVITEMS) {
			xqcn_write_data_entry(fp, idx,
					      efs_data.files[i].data,
					      efs_data.files[i].size);
			idx++;
		}
	}
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "      </Storage>\n");

	/* Mobile_Property_Info */
	{
		uint8_t mpi[512];
		size_t mpi_len;
		uint32_t magic = XQCN_MPI_MAGIC;
		uint32_t reserved = 0;
		uint16_t model_len = strlen(model);
		const char *tool = "QFenix";
		uint16_t tool_len = strlen(tool);

		memset(mpi, 0, sizeof(mpi));
		memcpy(&mpi[0], &magic, 4);
		memcpy(&mpi[4], &reserved, 4);
		memcpy(&mpi[8], &model_len, 2);
		memcpy(&mpi[10], model, model_len);
		memcpy(&mpi[10 + model_len], &tool_len, 2);
		memcpy(&mpi[12 + model_len], tool, tool_len);
		mpi_len = 12 + model_len + tool_len;

		fprintf(fp, "      <Stream Length='%zu'"
			" Name='Mobile_Property_Info' Value='",
			mpi_len);
		xqcn_write_hex(fp, mpi, mpi_len);
		fprintf(fp, "'/>\n");
	}

	/* Feature_Mask */
	if (fm_len > 0) {
		uint8_t fm_buf[256];
		uint16_t fm_data_len = fm_len;
		size_t total = 2 + fm_len;

		memcpy(&fm_buf[0], &fm_data_len, 2);
		memcpy(&fm_buf[2], feature_mask, fm_len);
		fprintf(fp, "      <Stream Length='%zu'"
			" Name='Feature_Mask' Value='", total);
		xqcn_write_hex(fp, fm_buf, total);
		fprintf(fp, "'/>\n");
	}

	fprintf(fp, "    </Storage>\n");
	fprintf(fp, "  </Storage>\n");

	/* File_Version */
	{
		uint8_t fv[6] = {0};
		uint32_t version = XQCN_FILE_VERSION;

		memcpy(fv, &version, 4);
		fprintf(fp, "  <Stream Length='6'"
			" Name='File_Version' Value='");
		xqcn_write_hex(fp, fv, 6);
		fprintf(fp, "'/>\n");
	}

	fprintf(fp, "</Storage>\n");
	fclose(fp);

	ux_info("XQCN backup complete: %s\n", output_file);
	ux_info("  NV items: %d default, %d SIM_1\n",
		def_nv.count, sim1_nv.count);
	ux_info("  EFS files: %d backup, %d provisioning, %d nv_items\n",
		backup_count, prov_count, nvitems_count);

	nv_scan_result_free(&def_nv);
	nv_scan_result_free(&sim1_nv);
	xqcn_efs_free(&efs_data);
	path_set_free(&seen);
	return 0;
}

/*
 * Parse hex string from XQCN XML Value attribute.
 * Returns allocated buffer and sets *out_len. Caller frees.
 */
static uint8_t *xqcn_parse_hex(const char *hex_str, size_t *out_len)
{
	size_t slen, blen;
	uint8_t *buf;
	size_t i, j;

	if (!hex_str || !*hex_str) {
		*out_len = 0;
		return NULL;
	}

	slen = strlen(hex_str);
	blen = (slen + 1) / 3 + 1; /* rough upper bound */
	buf = malloc(blen);
	if (!buf) {
		*out_len = 0;
		return NULL;
	}

	j = 0;
	for (i = 0; i < slen;) {
		unsigned int byte;
		char hex_pair[3];

		while (i < slen && hex_str[i] == ' ')
			i++;
		if (i + 1 >= slen)
			break;
		hex_pair[0] = hex_str[i];
		hex_pair[1] = hex_str[i + 1];
		hex_pair[2] = '\0';
		if (sscanf(hex_pair, "%x", &byte) != 1)
			break;
		buf[j++] = (uint8_t)byte;
		i += 2;
	}

	*out_len = j;
	return buf;
}

/*
 * XQCN restore — parse XQCN XML and restore NV items + EFS files.
 */
int diag_efs_restore_xqcn(struct diag_session *sess, const char *xqcn_file)
{
	xmlDocPtr doc;
	xmlNodePtr root, sub0, def_node, section, child, stream;
	int nv_written = 0, efs_written = 0;
	int n;

	if (!sess->efs_detected) {
		n = diag_efs_detect(sess);
		if (n)
			return n;
	}

	doc = xmlParseFile(xqcn_file);
	if (!doc) {
		ux_err("cannot parse XQCN file: %s\n", xqcn_file);
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	if (!root) {
		ux_err("empty XQCN document\n");
		xmlFreeDoc(doc);
		return -1;
	}

	/* Navigate: root -> 00000000 -> default */
	sub0 = NULL;
	for (xmlNodePtr c = root->children; c; c = c->next) {
		if (c->type == XML_ELEMENT_NODE &&
		    !strcmp((char *)c->name, "Storage")) {
			sub0 = c;
			break;
		}
	}
	if (!sub0) {
		ux_err("XQCN: missing subscription storage\n");
		xmlFreeDoc(doc);
		return -1;
	}

	def_node = NULL;
	for (xmlNodePtr c = sub0->children; c; c = c->next) {
		if (c->type == XML_ELEMENT_NODE &&
		    !strcmp((char *)c->name, "Storage")) {
			def_node = c;
			break;
		}
	}
	if (!def_node) {
		ux_err("XQCN: missing default storage\n");
		xmlFreeDoc(doc);
		return -1;
	}

	ux_info("restoring from XQCN: %s\n", xqcn_file);

	/* Process each section */
	for (section = def_node->children; section; section = section->next) {
		xmlChar *name;

		if (section->type != XML_ELEMENT_NODE)
			continue;

		name = xmlGetProp(section, (const xmlChar *)"Name");
		if (!name)
			continue;

		/* NV_NUMBERED_ITEMS */
		if (!strcmp((char *)name, "NV_NUMBERED_ITEMS") &&
		    !strcmp((char *)section->name, "Storage")) {
			for (stream = section->children; stream;
			     stream = stream->next) {
				xmlChar *sname, *val;
				uint8_t *data;
				size_t data_len;
				size_t off;

				if (stream->type != XML_ELEMENT_NODE)
					continue;

				sname = xmlGetProp(stream,
						   (const xmlChar *)"Name");
				if (!sname)
					continue;

				/* Only restore default NV_ITEM_ARRAY */
				if (strcmp((char *)sname,
					   "NV_ITEM_ARRAY") != 0) {
					xmlFree(sname);
					continue;
				}
				xmlFree(sname);

				val = xmlGetProp(stream,
						 (const xmlChar *)"Value");
				if (!val)
					continue;

				data = xqcn_parse_hex((char *)val, &data_len);
				xmlFree(val);
				if (!data)
					continue;

				for (off = 0;
				     off + XQCN_NV_RECORD_SIZE <= data_len;
				     off += XQCN_NV_RECORD_SIZE) {
					uint32_t nv_id;
					uint16_t item_id;

					memcpy(&nv_id, &data[off + 4], 4);
					item_id = (uint16_t)nv_id;
					if (diag_nv_write(sess, item_id,
							  &data[off + 8],
							  NV_ITEM_DATA_SIZE)
					    == 0) {
						nv_written++;
						ux_debug("NV %d written\n",
							 item_id);
					}
				}
				free(data);
			}
		}

		/* EFS sections: EFS_Backup, Provisioning, NV_Items */
		if ((!strcmp((char *)name, "EFS_Backup") ||
		     !strcmp((char *)name, "Provisioning_Item_Files") ||
		     !strcmp((char *)name, "NV_Items")) &&
		    !strcmp((char *)section->name, "Storage")) {
			xmlNodePtr dir_node = NULL, data_node = NULL;
			bool is_backup = !strcmp((char *)name, "EFS_Backup");
			int entry_count = 0;
			char **paths = NULL;
			uint8_t **datas = NULL;
			size_t *sizes = NULL;

			for (child = section->children; child;
			     child = child->next) {
				xmlChar *cname;

				if (child->type != XML_ELEMENT_NODE)
					continue;
				cname = xmlGetProp(child,
						   (const xmlChar *)"Name");
				if (!cname)
					continue;
				if (!strcmp((char *)cname, "EFS_Dir"))
					dir_node = child;
				else if (!strcmp((char *)cname, "EFS_Data"))
					data_node = child;
				xmlFree(cname);
			}

			if (!dir_node || !data_node) {
				xmlFree(name);
				continue;
			}

			/* Count entries in dir_node */
			for (stream = dir_node->children; stream;
			     stream = stream->next) {
				if (stream->type == XML_ELEMENT_NODE)
					entry_count++;
			}

			if (entry_count == 0) {
				xmlFree(name);
				continue;
			}

			paths = calloc(entry_count, sizeof(char *));
			datas = calloc(entry_count, sizeof(uint8_t *));
			sizes = calloc(entry_count, sizeof(size_t));

			/* Parse dir entries */
			n = 0;
			for (stream = dir_node->children; stream;
			     stream = stream->next) {
				xmlChar *val;
				uint8_t *raw;
				size_t raw_len;
				const char *pstart;
				size_t plen;

				if (stream->type != XML_ELEMENT_NODE ||
				    n >= entry_count)
					continue;

				val = xmlGetProp(stream,
						 (const xmlChar *)"Value");
				if (!val)
					continue;

				raw = xqcn_parse_hex((char *)val, &raw_len);
				xmlFree(val);
				if (!raw)
					continue;

				if (is_backup && raw_len > 8) {
					/* 8-byte header + path */
					pstart = (char *)raw + 8;
					plen = strnlen(pstart, raw_len - 8);
				} else {
					/* raw null-terminated path */
					pstart = (char *)raw;
					plen = strnlen(pstart, raw_len);
				}

				paths[n] = strndup(pstart, plen);
				free(raw);
				n++;
			}

			/* Parse data entries */
			n = 0;
			for (stream = data_node->children; stream;
			     stream = stream->next) {
				xmlChar *val;

				if (stream->type != XML_ELEMENT_NODE ||
				    n >= entry_count)
					continue;

				val = xmlGetProp(stream,
						 (const xmlChar *)"Value");
				if (!val)
					continue;

				datas[n] = xqcn_parse_hex((char *)val,
							  &sizes[n]);
				xmlFree(val);
				n++;
			}

			/* Write files to EFS */
			for (n = 0; n < entry_count; n++) {
				int32_t fdata;
				uint32_t off = 0;
				size_t rem;

				if (!paths[n] || !datas[n])
					continue;

				fdata = efs_open(sess, paths[n], 0x301,
						 0x1FF);
				if (fdata < 0) {
					ux_warn("cannot create '%s'\n",
						paths[n]);
					continue;
				}

				rem = sizes[n];
				while (rem > 0) {
					uint32_t chunk = rem >
							 EFS_MAX_WRITE_REQ ?
							 EFS_MAX_WRITE_REQ :
							 rem;
					int w = efs_write(sess, fdata, off,
							  datas[n] + off,
							  chunk);
					if (w < 0)
						break;
					off += w;
					rem -= w;
				}
				efs_close(sess, fdata);
				efs_written++;
				ux_debug("restored %s (%zu bytes)\n",
					 paths[n], sizes[n]);
			}

			for (n = 0; n < entry_count; n++) {
				free(paths[n]);
				free(datas[n]);
			}
			free(paths);
			free(datas);
			free(sizes);
		}

		xmlFree(name);
	}

	xmlFreeDoc(doc);

	ux_info("XQCN restore complete: %d NV items, %d EFS files\n",
		nv_written, efs_written);
	return 0;
}

/*
 * Offline XQCN -> TAR conversion.
 */
int diag_xqcn_to_tar(const char *xqcn_file, const char *tar_file)
{
	xmlDocPtr doc;
	xmlNodePtr root, sub0, def_node, section, child, stream;
	int fd;
	int file_count = 0;

	doc = xmlParseFile(xqcn_file);
	if (!doc) {
		ux_err("cannot parse XQCN file: %s\n", xqcn_file);
		return -1;
	}

	root = xmlDocGetRootElement(doc);
	sub0 = NULL;
	for (xmlNodePtr c = root->children; c; c = c->next) {
		if (c->type == XML_ELEMENT_NODE &&
		    !strcmp((char *)c->name, "Storage")) {
			sub0 = c;
			break;
		}
	}
	if (!sub0) {
		xmlFreeDoc(doc);
		return -1;
	}

	def_node = NULL;
	for (xmlNodePtr c = sub0->children; c; c = c->next) {
		if (c->type == XML_ELEMENT_NODE &&
		    !strcmp((char *)c->name, "Storage")) {
			def_node = c;
			break;
		}
	}
	if (!def_node) {
		xmlFreeDoc(doc);
		return -1;
	}

	fd = open(tar_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		ux_err("cannot create %s: %s\n", tar_file, strerror(errno));
		xmlFreeDoc(doc);
		return -1;
	}

	/* Process NV_NUMBERED_ITEMS -> synthetic tar entries */
	for (section = def_node->children; section; section = section->next) {
		xmlChar *name;

		if (section->type != XML_ELEMENT_NODE)
			continue;
		name = xmlGetProp(section, (const xmlChar *)"Name");
		if (!name)
			continue;

		if (!strcmp((char *)name, "NV_NUMBERED_ITEMS") &&
		    !strcmp((char *)section->name, "Storage")) {
			for (stream = section->children; stream;
			     stream = stream->next) {
				xmlChar *sname, *val;
				uint8_t *data;
				size_t data_len;
				size_t off;

				if (stream->type != XML_ELEMENT_NODE)
					continue;
				sname = xmlGetProp(stream,
						   (const xmlChar *)"Name");
				if (!sname)
					continue;
				if (strcmp((char *)sname,
					   "NV_ITEM_ARRAY") != 0) {
					xmlFree(sname);
					continue;
				}
				xmlFree(sname);

				val = xmlGetProp(stream,
						 (const xmlChar *)"Value");
				if (!val)
					continue;

				data = xqcn_parse_hex((char *)val, &data_len);
				xmlFree(val);
				if (!data)
					continue;

				/* Write NV items as nv_items/NNNNN.bin */
				for (off = 0;
				     off + XQCN_NV_RECORD_SIZE <= data_len;
				     off += XQCN_NV_RECORD_SIZE) {
					uint32_t nv_id;
					char nv_path[64];

					memcpy(&nv_id, &data[off + 4], 4);
					snprintf(nv_path, sizeof(nv_path),
						 "nv_items/%05u.bin", nv_id);
					tar_write_header(fd, nv_path, 0100644,
							 NV_ITEM_DATA_SIZE,
							 0, '0', NULL);
					if (write(fd, &data[off + 8],
						  NV_ITEM_DATA_SIZE) !=
					    NV_ITEM_DATA_SIZE)
						ux_warn("NV data write failed\n");
					/* Pad to 512-byte boundary */
					{
						uint8_t pad[512] = {0};
						int padsz = 512 -
							    (NV_ITEM_DATA_SIZE
							     % 512);

						if (write(fd, pad, padsz) !=
						    padsz)
							ux_warn("NV pad write failed\n");
					}
					file_count++;
				}
				free(data);
			}
		}

		/* EFS sections -> TAR entries */
		if ((!strcmp((char *)name, "EFS_Backup") ||
		     !strcmp((char *)name, "Provisioning_Item_Files") ||
		     !strcmp((char *)name, "NV_Items")) &&
		    !strcmp((char *)section->name, "Storage")) {
			xmlNodePtr dir_node = NULL, data_node = NULL;
			bool is_backup = !strcmp((char *)name, "EFS_Backup");
			int entry_count = 0;

			for (child = section->children; child;
			     child = child->next) {
				xmlChar *cname;

				if (child->type != XML_ELEMENT_NODE)
					continue;
				cname = xmlGetProp(child,
						   (const xmlChar *)"Name");
				if (!cname)
					continue;
				if (!strcmp((char *)cname, "EFS_Dir"))
					dir_node = child;
				else if (!strcmp((char *)cname, "EFS_Data"))
					data_node = child;
				xmlFree(cname);
			}

			if (!dir_node || !data_node) {
				xmlFree(name);
				continue;
			}

			for (stream = dir_node->children; stream;
			     stream = stream->next) {
				if (stream->type == XML_ELEMENT_NODE)
					entry_count++;
			}

			/* Read paths and data in parallel */
			{
				xmlNodePtr dir_s = dir_node->children;
				xmlNodePtr data_s = data_node->children;
				int idx;

				for (idx = 0; idx < entry_count; idx++) {
					xmlChar *dval, *pval;
					uint8_t *praw, *ddata;
					size_t praw_len, ddata_len;
					const char *pstart;
					size_t plen;
					char efs_path[512];
					const char *tar_path;

					while (dir_s &&
					       dir_s->type != XML_ELEMENT_NODE)
						dir_s = dir_s->next;
					while (data_s &&
					       data_s->type != XML_ELEMENT_NODE)
						data_s = data_s->next;
					if (!dir_s || !data_s)
						break;

					pval = xmlGetProp(dir_s,
						(const xmlChar *)"Value");
					dval = xmlGetProp(data_s,
						(const xmlChar *)"Value");
					dir_s = dir_s->next;
					data_s = data_s->next;

					if (!pval || !dval) {
						if (pval) xmlFree(pval);
						if (dval) xmlFree(dval);
						continue;
					}

					praw = xqcn_parse_hex((char *)pval,
							      &praw_len);
					ddata = xqcn_parse_hex((char *)dval,
							       &ddata_len);
					xmlFree(pval);
					xmlFree(dval);

					if (!praw || !ddata) {
						free(praw);
						free(ddata);
						continue;
					}

					if (is_backup && praw_len > 8) {
						pstart = (char *)praw + 8;
						plen = strnlen(pstart,
							       praw_len - 8);
					} else {
						pstart = (char *)praw;
						plen = strnlen(pstart,
							       praw_len);
					}

					snprintf(efs_path, sizeof(efs_path),
						 "%.*s", (int)plen, pstart);

					tar_path = efs_path[0] == '/' ?
						   efs_path + 1 : efs_path;

					tar_write_header(fd, tar_path,
							 0100644,
							 (int32_t)ddata_len,
							 0, '0', NULL);
					if (ddata_len > 0 &&
					    write(fd, ddata, ddata_len) !=
					    (ssize_t)ddata_len)
						ux_warn("EFS data write failed\n");
					if (ddata_len % 512) {
						uint8_t pad[512] = {0};
						int padsz = 512 -
							    (ddata_len % 512);

						if (write(fd, pad, padsz) !=
						    padsz)
							ux_warn("TAR pad write failed\n");
					}

					free(praw);
					free(ddata);
					file_count++;
				}
			}
		}

		xmlFree(name);
	}

	/* TAR end */
	{
		uint8_t zeros[1024] = {0};

		if (write(fd, zeros, 1024) != 1024)
			ux_warn("TAR end write failed\n");
	}

	close(fd);
	xmlFreeDoc(doc);

	ux_info("xqcn2tar: wrote %d entries to %s\n", file_count, tar_file);
	return 0;
}

/*
 * Offline TAR -> XQCN conversion.
 */
int diag_tar_to_xqcn(const char *tar_file, const char *xqcn_file)
{
	uint8_t header[512];
	int fd;
	FILE *fp;
	int file_count = 0;
	int nv_count = 0;
	int i;

	/* Collect files from TAR into arrays */
	struct {
		char path[512];
		uint8_t *data;
		size_t size;
	} *backup_files = NULL, *prov_files = NULL, *nvitems_files = NULL;
	int backup_count = 0, backup_cap = 0;
	int prov_count = 0, prov_cap = 0;
	int nvitems_count = 0, nvitems_cap = 0;

	/* NV items from synthetic nv_items/ paths */
	struct {
		uint32_t nv_id;
		uint8_t data[NV_ITEM_DATA_SIZE];
	} *nv_items = NULL;
	int nv_cap = 0;

	fd = open(tar_file, O_RDONLY | O_BINARY);
	if (fd < 0) {
		ux_err("cannot open %s: %s\n", tar_file, strerror(errno));
		return -1;
	}

	while (read(fd, header, 512) == 512) {
		bool all_zero = true;
		char name[101];
		unsigned long size;
		unsigned long blocks;
		uint8_t *data;
		char efs_path[512];
		int i;

		for (i = 0; i < 512; i++) {
			if (header[i] != 0) {
				all_zero = false;
				break;
			}
		}
		if (all_zero)
			break;

		if (!tar_checksum_valid(header))
			break;

		memset(name, 0, sizeof(name));
		memcpy(name, header, 100);
		size = tar_parse_octal((char *)header + 124, 12);

		if (header[156] != '0' && header[156] != '\0') {
			blocks = (size + 511) / 512;
			if (blocks > 0)
				lseek(fd, blocks * 512, SEEK_CUR);
			continue;
		}

		data = NULL;
		if (size > 0) {
			data = malloc(size);
			if (!data)
				break;
			if (read(fd, data, size) != (ssize_t)size) {
				free(data);
				break;
			}
			blocks = (size + 511) / 512;
			if (blocks * 512 > size)
				lseek(fd, blocks * 512 - size, SEEK_CUR);
		}

		/* Ensure leading / for EFS path */
		if (name[0] == '/')
			snprintf(efs_path, sizeof(efs_path), "%s", name);
		else
			snprintf(efs_path, sizeof(efs_path), "/%s", name);

		/* Check for synthetic NV item paths */
		if (strncmp(name, "nv_items/", 9) == 0) {
			uint32_t nv_id;

			if (sscanf(name + 9, "%u", &nv_id) == 1 &&
			    data && size >= NV_ITEM_DATA_SIZE) {
				if (nv_count >= nv_cap) {
					nv_cap = nv_cap ? nv_cap * 2 : 256;
					nv_items = realloc(nv_items,
						nv_cap * sizeof(*nv_items));
				}
				nv_items[nv_count].nv_id = nv_id;
				memcpy(nv_items[nv_count].data, data,
				       NV_ITEM_DATA_SIZE);
				nv_count++;
			}
			free(data);
			continue;
		}

		/* Classify into backup / provisioning / nv_items */
		switch (efs_path_xqcn_section(efs_path)) {
		case XQCN_SECTION_BACKUP:
			if (backup_count >= backup_cap) {
				backup_cap = backup_cap ?
					     backup_cap * 2 : 64;
				backup_files = realloc(backup_files,
					backup_cap *
					sizeof(*backup_files));
			}
			snprintf(backup_files[backup_count].path,
				 sizeof(backup_files[backup_count].path),
				 "%s", efs_path);
			backup_files[backup_count].data = data;
			backup_files[backup_count].size = size;
			backup_count++;
			break;
		case XQCN_SECTION_NVITEMS:
			if (nvitems_count >= nvitems_cap) {
				nvitems_cap = nvitems_cap ?
					      nvitems_cap * 2 : 16;
				nvitems_files = realloc(nvitems_files,
					nvitems_cap *
					sizeof(*nvitems_files));
			}
			snprintf(nvitems_files[nvitems_count].path,
				 sizeof(nvitems_files[nvitems_count].path),
				 "%s", efs_path);
			nvitems_files[nvitems_count].data = data;
			nvitems_files[nvitems_count].size = size;
			nvitems_count++;
			break;
		default:
			if (prov_count >= prov_cap) {
				prov_cap = prov_cap ? prov_cap * 2 : 256;
				prov_files = realloc(prov_files,
					prov_cap * sizeof(*prov_files));
			}
			snprintf(prov_files[prov_count].path,
				 sizeof(prov_files[prov_count].path),
				 "%s", efs_path);
			prov_files[prov_count].data = data;
			prov_files[prov_count].size = size;
			prov_count++;
			break;
		}
		file_count++;
	}

	close(fd);

	/* Write XQCN */
	fp = fopen(xqcn_file, "w");
	if (!fp) {
		ux_err("cannot create %s: %s\n", xqcn_file,
		       strerror(errno));
		goto out_free;
	}

	fprintf(fp, "<?xml version=\"1.0\" encoding=\"Windows-1252\" ?>\n");
	fprintf(fp, "<Storage Name='%s'>\n",
		strrchr(xqcn_file, '/') ?
		strrchr(xqcn_file, '/') + 1 : xqcn_file);
	fprintf(fp, "  <Storage Name='00000000'>\n");
	fprintf(fp, "    <Storage Name='default'>\n");

	/* NV_NUMBERED_ITEMS */
	fprintf(fp, "      <Storage Name='NV_NUMBERED_ITEMS'>\n");
	{
		size_t arr_len = nv_count * XQCN_NV_RECORD_SIZE;

		fprintf(fp, "        <Stream Length='%zu'"
			" Name='NV_ITEM_ARRAY' Value='", arr_len);
		for (i = 0; i < nv_count; i++) {
			uint8_t rec[XQCN_NV_RECORD_SIZE];
			uint16_t rsize = XQCN_NV_RECORD_SIZE;
			uint16_t sub = 0x0001;

			memset(rec, 0, sizeof(rec));
			memcpy(&rec[0], &rsize, 2);
			memcpy(&rec[2], &sub, 2);
			memcpy(&rec[4], &nv_items[i].nv_id, 4);
			memcpy(&rec[8], nv_items[i].data, NV_ITEM_DATA_SIZE);

			if (i > 0)
				fprintf(fp, " ");
			xqcn_write_hex(fp, rec, XQCN_NV_RECORD_SIZE);
		}
		fprintf(fp, "'/>\n");
	}
	fprintf(fp, "        <Stream Length='0'"
		" Name='NV_ITEM_ARRAY_SIM_1' Value=''/>\n");
	fprintf(fp, "        <Stream Length='0'"
		" Name='NV_ITEM_ARRAY_SIM_2' Value=''/>\n");
	fprintf(fp, "      </Storage>\n");

	/*
	 * EFS_Backup — includes backup files (rfnv) + nv_items files
	 * (rfc) with 8-byte headers, matching QPST's duplication.
	 */
	fprintf(fp, "      <Storage Name='EFS_Backup'>\n");
	fprintf(fp, "        <Storage Name='EFS_Dir'>\n");
	for (i = 0; i < backup_count; i++)
		xqcn_write_backup_dir_entry(fp, i,
					    backup_files[i].path, 0100644);
	for (i = 0; i < nvitems_count; i++)
		xqcn_write_backup_dir_entry(fp, backup_count + i,
					    nvitems_files[i].path, 0);
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "        <Storage Name='EFS_Data'>\n");
	for (i = 0; i < backup_count; i++)
		xqcn_write_data_entry(fp, i, backup_files[i].data,
				      backup_files[i].size);
	for (i = 0; i < nvitems_count; i++)
		xqcn_write_data_entry(fp, backup_count + i,
				      nvitems_files[i].data,
				      nvitems_files[i].size);
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "      </Storage>\n");

	/* Provisioning_Item_Files */
	fprintf(fp, "      <Storage Name='Provisioning_Item_Files'>\n");
	fprintf(fp, "        <Storage Name='EFS_Dir'>\n");
	for (i = 0; i < prov_count; i++)
		xqcn_write_prov_dir_entry(fp, i, prov_files[i].path);
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "        <Storage Name='EFS_Data'>\n");
	for (i = 0; i < prov_count; i++)
		xqcn_write_data_entry(fp, i, prov_files[i].data,
				      prov_files[i].size);
	fprintf(fp, "        </Storage>\n");
	fprintf(fp, "      </Storage>\n");

	/* NV_Items (RFC/calibration data) */
	if (nvitems_count > 0) {
		fprintf(fp, "      <Storage Name='NV_Items'>\n");
		fprintf(fp, "        <Storage Name='EFS_Dir'>\n");
		for (i = 0; i < nvitems_count; i++)
			xqcn_write_prov_dir_entry(fp, i,
						  nvitems_files[i].path);
		fprintf(fp, "        </Storage>\n");
		fprintf(fp, "        <Storage Name='EFS_Data'>\n");
		for (i = 0; i < nvitems_count; i++)
			xqcn_write_data_entry(fp, i,
					      nvitems_files[i].data,
					      nvitems_files[i].size);
		fprintf(fp, "        </Storage>\n");
		fprintf(fp, "      </Storage>\n");
	}

	/* Minimal metadata */
	{
		uint8_t mpi[16] = {0};
		uint32_t magic = XQCN_MPI_MAGIC;
		uint16_t zero = 0;

		memcpy(&mpi[0], &magic, 4);
		memcpy(&mpi[8], &zero, 2);
		memcpy(&mpi[10], &zero, 2);
		fprintf(fp, "      <Stream Length='12'"
			" Name='Mobile_Property_Info' Value='");
		xqcn_write_hex(fp, mpi, 12);
		fprintf(fp, "'/>\n");
	}

	fprintf(fp, "    </Storage>\n");
	fprintf(fp, "  </Storage>\n");

	/* File_Version */
	{
		uint8_t fv[6] = {0};
		uint32_t version = XQCN_FILE_VERSION;

		memcpy(fv, &version, 4);
		fprintf(fp, "  <Stream Length='6'"
			" Name='File_Version' Value='");
		xqcn_write_hex(fp, fv, 6);
		fprintf(fp, "'/>\n");
	}

	fprintf(fp, "</Storage>\n");
	fclose(fp);

	ux_info("tar2xqcn: %d NV items, %d backup, %d provisioning,"
		" %d nv_items files -> %s\n",
		nv_count, backup_count, prov_count, nvitems_count,
		xqcn_file);

out_free:
	for (i = 0; i < backup_count; i++)
		free(backup_files[i].data);
	for (i = 0; i < prov_count; i++)
		free(prov_files[i].data);
	for (i = 0; i < nvitems_count; i++)
		free(nvitems_files[i].data);
	free(backup_files);
	free(prov_files);
	free(nvitems_files);
	free(nv_items);
	return fp ? 0 : -1;
}
