// SPDX-License-Identifier: BSD-3-Clause
/*
 * DIAG to EDL mode switching for Qualcomm devices
 *
 * Detects Qualcomm/Quectel devices in DIAG mode and sends the command
 * to switch them to Emergency Download (EDL) mode.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "diag_switch.h"
#include "oscompat.h"
#include "qdl.h"

/* Global flag to enable/disable automatic DIAG to EDL switching */
bool qdl_auto_edl = true;

/* DIAG command to switch Qualcomm devices to EDL mode */
static const unsigned char edl_cmd[] = {0x4b, 0x65, 0x01, 0x00, 0x54, 0x0f, 0x7e};

#ifdef _WIN32
/* ==================== Windows Implementation ==================== */

#include <windows.h>
#include <setupapi.h>

/* GUID for COM ports */
static const GUID GUID_DEVCLASS_PORTS_LOCAL = {
	0x4d36e978, 0xe325, 0x11ce,
	{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
};

static int str_starts_with(const char *str, const char *prefix)
{
	return strncmp(str, prefix, strlen(prefix)) == 0;
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

static int detect_diag_port_win(char *port_buf, size_t buf_size,
				const char *serial __unused)
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA devInfoData;
	DWORD i;
	int found = 0;
	char fallback_port[32] = {0};

	hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_PORTS_LOCAL, NULL, NULL,
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
		int vid = 0, pid = 0;

		if (!SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
				SPDRP_HARDWAREID, NULL, (PBYTE)hwid,
				sizeof(hwid), NULL))
			continue;

		/* Parse VID and PID from hardware ID string */
		char *vidStr = strstr(hwid, "VID_");
		char *pidStr = strstr(hwid, "PID_");

		if (vidStr)
			vid = strtol(vidStr + 4, NULL, 16);
		if (pidStr)
			pid = strtol(pidStr + 4, NULL, 16);

		/* Check for Qualcomm/Quectel devices */
		if (vid != DIAG_VID_QUECTEL && vid != DIAG_VID_QUALCOMM &&
		    vid != DIAG_VID_OTHER1 && vid != DIAG_VID_OTHER2)
			continue;

		/* Skip if already in EDL mode */
		if (vid == EDL_VID && (pid == EDL_PID_9008 ||
		    pid == EDL_PID_900E || pid == EDL_PID_901D))
			continue;

		SetupDiGetDeviceRegistryPropertyA(hDevInfo, &devInfoData,
			SPDRP_FRIENDLYNAME, NULL, (PBYTE)friendlyName,
			sizeof(friendlyName), NULL);

		hKey = SetupDiOpenDevRegKey(hDevInfo, &devInfoData,
					    DICS_FLAG_GLOBAL, 0, DIREG_DEV,
					    KEY_READ);
		if (hKey == INVALID_HANDLE_VALUE)
			continue;

		size = sizeof(portName);
		if (RegQueryValueExA(hKey, "PortName", NULL, NULL,
				     (LPBYTE)portName, &size) != ERROR_SUCCESS ||
		    !str_starts_with(portName, "COM")) {
			RegCloseKey(hKey);
			continue;
		}
		RegCloseKey(hKey);

		if (is_diag_port_name(friendlyName)) {
			snprintf(port_buf, buf_size, "%s", portName);
			found = 1;
			break;
		}

		if (is_skip_port_name(friendlyName))
			continue;

		if (fallback_port[0] == '\0')
			snprintf(fallback_port, sizeof(fallback_port), "%s", portName);
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);

	if (!found && fallback_port[0] != '\0') {
		snprintf(port_buf, buf_size, "%s", fallback_port);
		found = 1;
	}

	return found;
}

static int open_and_send_edl_cmd_win(const char *port)
{
	HANDLE hSerial;
	DCB dcbSerialParams = {0};
	COMMTIMEOUTS timeouts = {0};
	char portPath[32];
	DWORD bytesWritten, bytesRead;
	unsigned char buf[512];
	int attempts;

	snprintf(portPath, sizeof(portPath), "\\\\.\\%s", port);

	hSerial = CreateFileA(portPath, GENERIC_READ | GENERIC_WRITE,
			      0, NULL, OPEN_EXISTING, 0, NULL);
	if (hSerial == INVALID_HANDLE_VALUE) {
		warnx("Cannot open %s (error %lu)", port, GetLastError());
		return -1;
	}

	dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
	if (!GetCommState(hSerial, &dcbSerialParams)) {
		CloseHandle(hSerial);
		return -1;
	}

	dcbSerialParams.BaudRate = CBR_115200;
	dcbSerialParams.ByteSize = 8;
	dcbSerialParams.StopBits = ONESTOPBIT;
	dcbSerialParams.Parity = NOPARITY;
	dcbSerialParams.fBinary = TRUE;
	dcbSerialParams.fParity = FALSE;
	dcbSerialParams.fOutxCtsFlow = FALSE;
	dcbSerialParams.fOutxDsrFlow = FALSE;
	dcbSerialParams.fDtrControl = DTR_CONTROL_ENABLE;
	dcbSerialParams.fRtsControl = RTS_CONTROL_ENABLE;
	dcbSerialParams.fOutX = FALSE;
	dcbSerialParams.fInX = FALSE;

	if (!SetCommState(hSerial, &dcbSerialParams)) {
		CloseHandle(hSerial);
		return -1;
	}

	timeouts.ReadIntervalTimeout = 100;
	timeouts.ReadTotalTimeoutConstant = 3000;
	timeouts.ReadTotalTimeoutMultiplier = 0;
	timeouts.WriteTotalTimeoutConstant = 3000;
	timeouts.WriteTotalTimeoutMultiplier = 0;

	if (!SetCommTimeouts(hSerial, &timeouts)) {
		CloseHandle(hSerial);
		return -1;
	}

	/* Drain pending data */
	PurgeComm(hSerial, PURGE_RXCLEAR | PURGE_TXCLEAR);

	/* Send EDL command */
	if (!WriteFile(hSerial, edl_cmd, sizeof(edl_cmd), &bytesWritten, NULL) ||
	    bytesWritten != sizeof(edl_cmd)) {
		CloseHandle(hSerial);
		return -1;
	}

	/* Wait for echo */
	for (attempts = 0; attempts < 50; attempts++) {
		if (!ReadFile(hSerial, buf, sizeof(buf), &bytesRead, NULL))
			continue;

		if (bytesRead == sizeof(edl_cmd) &&
		    memcmp(buf, edl_cmd, sizeof(edl_cmd)) == 0) {
			CloseHandle(hSerial);
			return 0;
		}
	}

	CloseHandle(hSerial);
	return -1;
}

#else
/* ==================== Linux/POSIX Implementation ==================== */

#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <poll.h>
#include <dirent.h>
#include <ctype.h>

static int str_starts_with(const char *str, const char *prefix)
{
	if (!prefix || prefix[0] == '\0')
		return 1;
	return strncmp(str, prefix, strlen(prefix)) == 0;
}

/* Known USB interface numbers for DIAG port on various modules */
static int get_diag_interface(int vid, int pid)
{
	if (vid == DIAG_VID_QUECTEL) {
		switch (pid) {
		/* Laptop modules: EM05, EM06, EM12, RM520, etc. */
		case 0x0127: case 0x0310: case 0x030a: case 0x0311:
		case 0x0315: case 0x0309: case 0x6008: case 0x0128:
		case 0x6009: case 0x0803: case 0x012E: case 0x012F:
		case 0x0804: case 0x030d: case 0x0139: case 0x012c:
		case 0x013c:
			return 3;
		case 0x0514: case 0x0133: case 0x030b:
			return 2;
		}
	} else if (vid == DIAG_VID_QUALCOMM && pid == 0x90db) {
		return 2;
	} else if (vid == DIAG_VID_OTHER1 && pid == 0xffff) {
		return 8;
	}
	return 0;
}

static int poll_wait(int fd, short events, int timeout_ms)
{
	struct pollfd pfd = {.fd = fd, .events = events};
	int ret = poll(&pfd, 1, timeout_ms);

	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;
	if (pfd.revents & POLLERR)
		return -EIO;
	return 0;
}

static int detect_diag_port_linux(char *port_buf, size_t buf_size,
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
		int major = 0, vid = 0, pid = 0;
		char devtype[64] = {0}, product[64] = {0};
		char dev_serial[128] = {0};
		int diag_iface;

		if (!isdigit(de->d_name[0]))
			continue;

		snprintf(path, sizeof(path), "%s/%s/uevent", base, de->d_name);
		fp = fopen(path, "r");
		if (!fp)
			continue;

		while (fgets(line, sizeof(line), fp)) {
			line[strcspn(line, "\r\n")] = 0;
			if (str_starts_with(line, "MAJOR="))
				major = atoi(line + 6);
			else if (str_starts_with(line, "DEVTYPE=")) {
				snprintf(devtype, sizeof(devtype), "%s", line + 8);
			} else if (str_starts_with(line, "PRODUCT=")) {
				snprintf(product, sizeof(product), "%s", line + 8);
			}
		}
		fclose(fp);

		if (major != 189 || !str_starts_with(devtype, "usb_device"))
			continue;

		/* Check for Qualcomm/Quectel vendor */
		if (!(str_starts_with(product, "2c7c/") ||
		      str_starts_with(product, "5c6/") ||
		      str_starts_with(product, "3c93/") ||
		      str_starts_with(product, "3763/")))
			continue;

		/* Skip if already in EDL mode */
		if (str_starts_with(product, "5c6/9008") ||
		    str_starts_with(product, "5c6/900e") ||
		    str_starts_with(product, "5c6/901d"))
			continue;

		/* Read serial number if filter is specified */
		if (serial) {
			snprintf(path, sizeof(path), "%s/%s/serial",
				 base, de->d_name);
			fp = fopen(path, "r");
			if (fp) {
				if (fgets(dev_serial, sizeof(dev_serial), fp))
					dev_serial[strcspn(dev_serial, "\r\n")] = 0;
				fclose(fp);
			}
			if (dev_serial[0] && strcmp(dev_serial, serial) != 0)
				continue;
		}

		sscanf(product, "%x/%x", &vid, &pid);
		diag_iface = get_diag_interface(vid, pid);

		/* Look for ttyUSB in interface directory */
		snprintf(path, sizeof(path), "%s/%s:1.%d",
			 base, de->d_name, diag_iface);
		infdir = opendir(path);
		if (!infdir) {
			snprintf(path, sizeof(path), "%s/%s:1.0",
				 base, de->d_name);
			infdir = opendir(path);
		}
		if (!infdir)
			continue;

		while ((de2 = readdir(infdir)) != NULL) {
			if (str_starts_with(de2->d_name, "ttyUSB")) {
				snprintf(port_buf, buf_size, "/dev/%s",
					 de2->d_name);
				found = 1;
				break;
			} else if (strncmp(de2->d_name, "tty", 3) == 0 &&
				   strlen(de2->d_name) == 3) {
				char ttypath[520];
				DIR *ttydir;
				struct dirent *de3;

				snprintf(ttypath, sizeof(ttypath),
					 "%.511s/tty", path);
				ttydir = opendir(ttypath);
				if (ttydir) {
					while ((de3 = readdir(ttydir))) {
						if (str_starts_with(de3->d_name,
								    "ttyUSB") ||
						    str_starts_with(de3->d_name,
								    "ttyACM")) {
							snprintf(port_buf,
								 buf_size,
								 "/dev/%s",
								 de3->d_name);
							found = 1;
							break;
						}
					}
					closedir(ttydir);
				}
				if (found)
					break;
			}
		}
		closedir(infdir);
	}

	closedir(busdir);
	return found;
}

static int open_and_send_edl_cmd_linux(const char *port)
{
	int fd;
	struct termios ios;
	unsigned char buf[512];
	int ret, attempts, count;

	fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		warnx("Cannot open %s: %s", port, strerror(errno));
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

	/* Drain pending data */
	count = 0;
	while (count < 100) {
		if (poll_wait(fd, POLLIN, 100) != 0)
			break;
		if (read(fd, buf, sizeof(buf)) <= 0)
			break;
		count++;
	}

	/* Send EDL command */
	if (poll_wait(fd, POLLOUT, 3000) != 0) {
		close(fd);
		return -1;
	}

	ret = write(fd, edl_cmd, sizeof(edl_cmd));
	if (ret != sizeof(edl_cmd)) {
		close(fd);
		return -1;
	}

	/* Wait for echo */
	for (attempts = 0; attempts < 50; attempts++) {
		if (poll_wait(fd, POLLIN, 100) != 0)
			continue;

		ret = read(fd, buf, sizeof(buf));
		if (ret == sizeof(edl_cmd) &&
		    memcmp(buf, edl_cmd, sizeof(edl_cmd)) == 0) {
			close(fd);
			return 0;
		}
	}

	close(fd);
	return -1;
}

#endif /* _WIN32 */

/* ==================== Common Implementation ==================== */

int diag_switch_to_edl(const char *serial)
{
	char port[256] = {0};
	int ret;

#ifdef _WIN32
	if (!detect_diag_port_win(port, sizeof(port), serial))
		return -1;

	ux_debug("DIAG port detected: %s\n", port);

	ret = open_and_send_edl_cmd_win(port);
#else
	if (!detect_diag_port_linux(port, sizeof(port), serial))
		return -1;

	ux_debug("DIAG port detected: %s\n", port);

	ret = open_and_send_edl_cmd_linux(port);
#endif

	if (ret < 0) {
		warnx("Failed to send EDL switch command");
		return -1;
	}

	return 0;
}

bool diag_is_device_in_diag_mode(const char *serial)
{
	char port[256] = {0};

#ifdef _WIN32
	return detect_diag_port_win(port, sizeof(port), serial) != 0;
#else
	return detect_diag_port_linux(port, sizeof(port), serial) != 0;
#endif
}
