// SPDX-License-Identifier: BSD-3-Clause
/*
 * Cross-platform AT command port auto-detection
 *
 * Finds the AT command serial port for a connected Qualcomm modem.
 * macOS: uses qcseriald daemon status file
 * Linux: scans sysfs USB devices, probes with AT command
 * Windows: scans COM ports via SetupAPI
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "at_port.h"
#include "usb_ids.h"
#include "qdl.h"

#ifdef HAVE_QCSERIALD
#include "qcseriald.h"
#endif

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>

static int is_at_port_name(const char *name)
{
	if (strstr(name, "AT Port") || strstr(name, "AT Interface") ||
	    strstr(name, "Modem"))
		return 1;
	return 0;
}

static int is_skip_at_port_name(const char *name)
{
	if (strstr(name, "DIAG") || strstr(name, "DM Port") ||
	    strstr(name, "QDLoader") || strstr(name, "Diagnostic") ||
	    strstr(name, "Sahara") || strstr(name, "NMEA") ||
	    strstr(name, "GPS") || strstr(name, "Audio"))
		return 1;
	return 0;
}

/* GUID for COM ports */
static const GUID GUID_DEVCLASS_PORTS_AT = {
	0x4d36e978, 0xe325, 0x11ce,
	{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}
};

int at_detect_port(char *buf, size_t size, const char *serial)
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA devInfoData;
	DWORD i;
	int found = 0;
	char fallback_port[32] = {0};

	if (serial && strncmp(serial, "COM", 3) == 0) {
		snprintf(buf, size, "%s", serial);
		return 1;
	}

	hDevInfo = SetupDiGetClassDevsA(&GUID_DEVCLASS_PORTS_AT, NULL, NULL,
					DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
		return 0;

	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); i++) {
		char hwid[512] = {0};
		char friendlyName[256] = {0};
		char portName[32] = {0};
		HKEY hKey;
		DWORD psize;
		int vid = 0, pid = 0;
		char *vidStr, *pidStr;

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
			if (!is_diag_vendor(vid))
				continue;
			if (is_edl_device(vid, pid))
				continue;
		}

		hKey = SetupDiOpenDevRegKey(hDevInfo, &devInfoData,
					    DICS_FLAG_GLOBAL, 0, DIREG_DEV,
					    KEY_READ);
		if (hKey == INVALID_HANDLE_VALUE)
			continue;

		psize = sizeof(portName);
		if (RegQueryValueExA(hKey, "PortName", NULL, NULL,
				     (LPBYTE)portName, &psize) != ERROR_SUCCESS ||
		    strncmp(portName, "COM", 3) != 0) {
			RegCloseKey(hKey);
			continue;
		}
		RegCloseKey(hKey);

		if (is_at_port_name(friendlyName)) {
			snprintf(buf, size, "%s", portName);
			found = 1;
			break;
		}

		if (is_skip_at_port_name(friendlyName))
			continue;

		if (fallback_port[0] == '\0')
			snprintf(fallback_port, sizeof(fallback_port),
				 "%s", portName);
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);

	if (!found && fallback_port[0] != '\0') {
		snprintf(buf, size, "%s", fallback_port);
		found = 1;
	}

	return found;
}

#else
/* POSIX (Linux + macOS) */

#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <poll.h>
#include <dirent.h>
#include <ctype.h>

int at_detect_port(char *buf, size_t size, const char *serial)
{
#ifdef __APPLE__
#ifdef HAVE_QCSERIALD
	(void)serial;
	return qcseriald_wait_for_port("at0", buf, size);
#else
	(void)buf;
	(void)size;
	(void)serial;
	ux_err("AT port detection not supported on this macOS build\n");
	return 0;
#endif
#else
	/* Linux: scan /sys/bus/usb/devices */
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

		/* Skip the DIAG interface — we want AT ports */
		diag_iface = get_diag_interface_num(vid, pid);

		/* Scan all interfaces for ttyUSB/ttyACM devices */
		for (iface_num = 0; iface_num < 16 && !found; iface_num++) {
			if (iface_num == diag_iface)
				continue;

			snprintf(path, sizeof(path), "%s/%s:1.%d",
				 base, de->d_name, iface_num);
			infdir = opendir(path);
			if (!infdir)
				continue;

			while ((de2 = readdir(infdir)) != NULL && !found) {
				char port_path[300];
				int fd;
				struct termios tio;
				struct pollfd pfd;
				char resp[128] = {0};
				int resp_len = 0, ret;

				if (strncmp(de2->d_name, "ttyUSB", 6) == 0 ||
				    strncmp(de2->d_name, "ttyACM", 6) == 0) {
					snprintf(port_path, sizeof(port_path),
						 "/dev/%s", de2->d_name);
				} else if (strncmp(de2->d_name, "tty", 3) == 0 &&
					   strlen(de2->d_name) == 3) {
					/* Modern kernel: tty/ subdirectory */
					char ttypath[520];
					DIR *ttydir;
					struct dirent *de3;

					snprintf(ttypath, sizeof(ttypath),
						 "%.511s/tty", path);
					ttydir = opendir(ttypath);
					if (!ttydir)
						continue;

					port_path[0] = '\0';
					while ((de3 = readdir(ttydir))) {
						if (strncmp(de3->d_name, "ttyUSB", 6) == 0 ||
						    strncmp(de3->d_name, "ttyACM", 6) == 0) {
							snprintf(port_path, sizeof(port_path),
								 "/dev/%s", de3->d_name);
							break;
						}
					}
					closedir(ttydir);
					if (!port_path[0])
						continue;
				} else {
					continue;
				}

				/* Probe with AT command */
				fd = open(port_path, O_RDWR | O_NOCTTY | O_NONBLOCK);
				if (fd < 0)
					continue;

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
				ret = poll(&pfd, 1, 2000);
				if (ret > 0 && (pfd.revents & POLLIN)) {
					resp_len = read(fd, resp, sizeof(resp) - 1);
					if (resp_len > 0)
						resp[resp_len] = '\0';
				}

				close(fd);

				if (strstr(resp, "OK") ||
				    strstr(resp, "ERROR")) {
					snprintf(buf, size, "%s", port_path);
					found = 1;
				}
			}
			closedir(infdir);
		}
	}
	closedir(busdir);
	return found;
#endif /* __APPLE__ */
}

#endif /* _WIN32 */
