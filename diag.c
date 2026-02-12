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
#include "hdlc.h"
#include "usb_ids.h"
#include "qdl.h"

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
		ux_err("NV read error: unexpected response (cmd=0x%02x, len=%d)\n",
		       resp[0], n);
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
		ux_err("NV indexed read error: unexpected response\n");
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

/* EFS helper: build subsystem command header */
static void efs_cmd_header(uint8_t *cmd, uint8_t method, uint8_t efs_cmd)
{
	cmd[0] = DIAG_SUBSYS_CMD_F;
	cmd[1] = method;
	cmd[2] = efs_cmd;
	cmd[3] = 0x00;
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
	if (fdata < 0)
		return -1;

	if (efs_stat(sess, src_path, &st) < 0) {
		ux_err("EFS stat '%s' failed\n", src_path);
		efs_close(sess, fdata);
		return -1;
	}

	fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

	fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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
