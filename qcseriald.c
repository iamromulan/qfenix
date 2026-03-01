// SPDX-License-Identifier: BSD-3-Clause
/*
 * qcseriald — macOS USB-to-serial bridge daemon for Qualcomm modems
 *
 * Ported from qcseriald-darwin by iamromulan
 * https://github.com/iamromulan/qcseriald-darwin
 *
 * Opens vendor-specific (class 0xFF) USB interfaces on Qualcomm-based modems,
 * creates pseudo-TTY pairs, and bridges data between USB bulk endpoints and PTYs.
 *
 * No DriverKit, no entitlements, no provisioning profiles needed.
 */

#ifdef __APPLE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <fcntl.h>
#include <glob.h>
#include <stdatomic.h>
#include <time.h>
#include <poll.h>
#include <util.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/usb/IOUSBLib.h>
#include <CoreFoundation/CoreFoundation.h>

#include "qdl.h"
#include "usb_ids.h"
#include "qcseriald.h"

/* ── Version ── */

#define QCSERIALD_VERSION "1.0.4"

/* ── Constants ── */

#define MAX_INTERFACES    8
#define USB_BUF_SIZE      4096
#define SHUTDOWN_TIMEOUT  3
#define MONITOR_INTERVAL  2
#define RESCAN_INTERVAL   5
#define PROBE_RDY_TIMEOUT 30
#define PROBE_AT_TIMEOUT  3

/*
 * Runtime file paths — /var/run and /var/log require root.
 * When auto-started by qfenix (non-root), use /tmp/ instead.
 * Paths are resolved at startup by init_runtime_paths().
 */
static char g_pid_file[256];
static char g_status_file[256];
static char g_log_file[256];

static void init_runtime_paths(void)
{
	if (getuid() == 0) {
		snprintf(g_pid_file, sizeof(g_pid_file),
			 "/var/run/qcseriald.pid");
		snprintf(g_status_file, sizeof(g_status_file),
			 "/var/run/qcseriald.status");
		snprintf(g_log_file, sizeof(g_log_file),
			 "/var/log/qcseriald.log");
	} else {
		snprintf(g_pid_file, sizeof(g_pid_file),
			 "/tmp/qcseriald.pid");
		snprintf(g_status_file, sizeof(g_status_file),
			 "/tmp/qcseriald.status");
		snprintf(g_log_file, sizeof(g_log_file),
			 "/tmp/qcseriald.log");
	}
}
#define SYMLINK_PREFIX  "tty.qcserial-"
#define DEV_DIR         "/dev"

/* ── Bridge states ── */

enum bridge_state {
	BRIDGE_IDLE     = 0,
	BRIDGE_RUNNING  = 1,
	BRIDGE_STOPPING = 2,
	BRIDGE_STOPPED  = 3
};

/* ── Types ── */

typedef struct {
	int                         iface_num;
	int                         pty_master;
	char                        pty_name[256];
	char                        link_name[256];
	char                        func_name[32];
	IOUSBInterfaceInterface300  **iface;
	UInt8                       pipe_in;
	UInt8                       pipe_out;
	pthread_t                   usb_to_pty_thread;
	pthread_t                   pty_to_usb_thread;
	_Atomic(int)                state;
	_Atomic(int)                usb_to_pty_alive;
	_Atomic(int)                pty_to_usb_alive;
} bridge_t;

/* ── Globals ── */

static _Atomic(int) g_running = 1;
static const char *g_daemon_state = "starting";

static bridge_t g_bridges[MAX_INTERFACES];
static int g_bridge_count;

static pthread_mutex_t g_exit_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_exit_cond  = PTHREAD_COND_INITIALIZER;

static char g_symlink_dir[512] = DEV_DIR;

/* ── Signal handler ── */

static void signal_handler(int sig)
{
	(void)sig;
	atomic_store(&g_running, 0);
}

/* ── PID file management ── */

static pid_t pid_file_read(void)
{
	FILE *f = fopen(g_pid_file, "r");
	pid_t pid = 0;

	if (!f)
		return 0;
	if (fscanf(f, "%d", &pid) != 1)
		pid = 0;
	fclose(f);
	return pid;
}

static int pid_file_write(pid_t pid)
{
	FILE *f = fopen(g_pid_file, "w");

	if (!f) {
		fprintf(stderr, "Failed to write PID file %s: %s\n",
			g_pid_file, strerror(errno));
		return -1;
	}
	fprintf(f, "%d\n", pid);
	fclose(f);
	return 0;
}

static void pid_file_remove(void)
{
	unlink(g_pid_file);
}

static int is_process_alive(pid_t pid)
{
	if (pid <= 0)
		return 0;
	return (kill(pid, 0) == 0 || errno == EPERM);
}

/* ── Symlink directory resolution ── */

static void resolve_symlink_dir(void)
{
	const char *test_link = DEV_DIR "/" SYMLINK_PREFIX "test";

	if (symlink("/dev/null", test_link) == 0) {
		unlink(test_link);
		snprintf(g_symlink_dir, sizeof(g_symlink_dir), "%s", DEV_DIR);
		printf("Symlink directory: %s (native)\n", g_symlink_dir);
		return;
	}

	/* /dev/ symlinks failed — fall back to ~/dev/ */
	const char *home = NULL;
	const char *sudo_user = getenv("SUDO_USER");

	if (sudo_user) {
		struct passwd *pw = getpwnam(sudo_user);

		if (pw)
			home = pw->pw_dir;
	}
	if (!home) {
		const char *logname = getenv("LOGNAME");

		if (logname) {
			struct passwd *pw = getpwnam(logname);

			if (pw)
				home = pw->pw_dir;
		}
	}
	if (!home)
		home = "/var/root";

	snprintf(g_symlink_dir, sizeof(g_symlink_dir), "%s/dev", home);

	struct stat st;

	if (stat(g_symlink_dir, &st) != 0) {
		if (mkdir(g_symlink_dir, 0755) == 0) {
			if (sudo_user) {
				struct passwd *pw = getpwnam(sudo_user);

				if (pw)
					chown(g_symlink_dir, pw->pw_uid,
					      pw->pw_gid);
			}
			printf("Created fallback symlink directory: %s\n",
			       g_symlink_dir);
		} else {
			fprintf(stderr,
				UX_COLOR_YELLOW "Warning: could not create %s: %s\n" UX_COLOR_RESET,
				g_symlink_dir, strerror(errno));
		}
	}

	printf("Symlink directory: %s (fallback — /dev/ symlinks blocked by SIP)\n",
	       g_symlink_dir);
}

static void make_symlink_path(char *buf, size_t size, const char *name)
{
	snprintf(buf, size, "%s/" SYMLINK_PREFIX "%s", g_symlink_dir, name);
}

/* ── Stale symlink cleanup ── */

static void cleanup_stale_symlinks(void)
{
	const char *patterns[2];
	char alt_pattern[600];
	int n = 0;

	patterns[n++] = DEV_DIR "/" SYMLINK_PREFIX "*";
	if (strcmp(g_symlink_dir, DEV_DIR) != 0) {
		snprintf(alt_pattern, sizeof(alt_pattern),
			 "%s/" SYMLINK_PREFIX "*", g_symlink_dir);
		patterns[n++] = alt_pattern;
	}

	for (int p = 0; p < n; p++) {
		glob_t gl;

		if (glob(patterns[p], 0, NULL, &gl) == 0) {
			for (size_t i = 0; i < gl.gl_pathc; i++) {
				struct stat st;

				if (stat(gl.gl_pathv[i], &st) != 0) {
					printf("Removing stale symlink: %s\n",
					       gl.gl_pathv[i]);
					unlink(gl.gl_pathv[i]);
				}
			}
			globfree(&gl);
		}
	}
}

/* ── Thread: USB bulk IN → PTY master ── */

static void *usb_to_pty(void *arg)
{
	bridge_t *b = (bridge_t *)arg;
	UInt8 buf[USB_BUF_SIZE];
	IOReturn kr;
	UInt32 len;
	int not_responding_count = 0;

	atomic_store(&b->usb_to_pty_alive, 1);
	printf("[%s] USB->PTY thread started\n", b->func_name);

	while (atomic_load(&g_running) &&
	       atomic_load(&b->state) == BRIDGE_RUNNING) {
		len = sizeof(buf);
		kr = (*b->iface)->ReadPipe(b->iface, b->pipe_in, buf, &len);
		if (kr != kIOReturnSuccess) {
			if (kr == kIOReturnAborted) {
				printf("[%s] USB->PTY ReadPipe: 0x%x (stopping)\n",
				       b->func_name, kr);
				break;
			}
			if (kr == kIOReturnNotResponding ||
			    kr == (IOReturn)0xe00002eb) {
				/* Transient USB hiccup — clear and retry */
				(*b->iface)->ClearPipeStall(b->iface,
							    b->pipe_in);
				not_responding_count++;
				if (not_responding_count > 50) {
					printf("[%s] USB->PTY: device unresponsive after %d retries, giving up\n",
					       b->func_name,
					       not_responding_count);
					break;
				}
				usleep(100000);
				continue;
			}
			fprintf(stderr, "[%s] USB->PTY ReadPipe error: 0x%x\n",
				b->func_name, kr);
			usleep(10000);
			continue;
		}
		not_responding_count = 0;
		if (len > 0) {
			ssize_t written = 0;

			while (written < (ssize_t)len) {
				ssize_t n = write(b->pty_master,
						  buf + written,
						  len - written);
				if (n < 0) {
					if (errno == EAGAIN || errno == EINTR)
						continue;
					if (errno == EIO)
						break;
					fprintf(stderr,
						"[%s] USB->PTY write error: %s\n",
						b->func_name, strerror(errno));
					goto done;
				}
				written += n;
			}
		}
	}
	printf("[%s] USB->PTY loop ended (running=%d state=%d)\n",
	       b->func_name, atomic_load(&g_running), atomic_load(&b->state));
done:
	atomic_store(&b->usb_to_pty_alive, 0);
	printf("[%s] USB->PTY thread exiting\n", b->func_name);

	pthread_mutex_lock(&g_exit_mutex);
	pthread_cond_signal(&g_exit_cond);
	pthread_mutex_unlock(&g_exit_mutex);

	return NULL;
}

/* ── Thread: PTY master → USB bulk OUT ── */

static void *pty_to_usb(void *arg)
{
	bridge_t *b = (bridge_t *)arg;
	UInt8 buf[USB_BUF_SIZE];
	IOReturn kr;

	atomic_store(&b->pty_to_usb_alive, 1);
	printf("[%s] PTY->USB thread started\n", b->func_name);

	int flags = fcntl(b->pty_master, F_GETFL, 0);

	if (flags >= 0)
		fcntl(b->pty_master, F_SETFL, flags | O_NONBLOCK);

	while (atomic_load(&g_running) &&
	       atomic_load(&b->state) == BRIDGE_RUNNING) {
		ssize_t n = read(b->pty_master, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				usleep(10000);
				continue;
			}
			if (errno == EIO) {
				usleep(10000);
				continue;
			}
			break;
		}
		if (n == 0) {
			usleep(10000);
			continue;
		}

		if (!atomic_load(&g_running) ||
		    atomic_load(&b->state) != BRIDGE_RUNNING)
			break;

		kr = (*b->iface)->WritePipe(b->iface, b->pipe_out,
					    buf, (UInt32)n);
		if (kr != kIOReturnSuccess) {
			if (kr == kIOReturnAborted ||
			    kr == kIOReturnNotResponding)
				break;
			fprintf(stderr, "[%s] WritePipe error: 0x%x\n",
				b->func_name, kr);
		}
	}

	atomic_store(&b->pty_to_usb_alive, 0);
	printf("[%s] PTY->USB thread exiting\n", b->func_name);

	pthread_mutex_lock(&g_exit_mutex);
	pthread_cond_signal(&g_exit_cond);
	pthread_mutex_unlock(&g_exit_mutex);

	return NULL;
}

/* ── USB device recovery ── */

static int attempt_usb_recovery(io_service_t device_service)
{
	IOCFPlugInInterface **plug = NULL;
	IOUSBDeviceInterface187 **dev = NULL;
	SInt32 score;
	IOReturn kr;

	kr = IOCreatePlugInInterfaceForService(device_service,
			kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID,
			&plug, &score);
	if (kr != kIOReturnSuccess || !plug) {
		fprintf(stderr, "Recovery: failed to create device plugin: 0x%x\n", kr);
		return -1;
	}

	(*plug)->QueryInterface(plug,
			CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID187),
			(LPVOID *)&dev);
	(*plug)->Release(plug);
	if (!dev) {
		fprintf(stderr, "Recovery: failed to get device interface\n");
		return -1;
	}

	kr = (*dev)->USBDeviceOpenSeize(dev);
	if (kr != kIOReturnSuccess) {
		fprintf(stderr, "Recovery: USBDeviceOpenSeize failed: 0x%x\n", kr);
		(*dev)->Release(dev);
		return -1;
	}

	printf("Recovery: triggering USB re-enumeration to clear stale locks...\n");
	kr = (*dev)->USBDeviceReEnumerate(dev, 0);

	(*dev)->USBDeviceClose(dev);
	(*dev)->Release(dev);

	if (kr != kIOReturnSuccess) {
		fprintf(stderr, "Recovery: USBDeviceReEnumerate failed: 0x%x\n", kr);
		return -1;
	}

	printf("Recovery: waiting for USB re-enumeration (3s)...\n");
	sleep(3);
	return 0;
}

/* ── Setup: find USB device and open interfaces ── */

static int setup_bridges(void)
{
	CFMutableDictionaryRef match = IOServiceMatching("IOUSBHostDevice");

	if (!match) {
		fprintf(stderr, "Failed to create matching dict\n");
		return -1;
	}

	io_iterator_t dev_iter;
	IOReturn kr = IOServiceGetMatchingServices(kIOMainPortDefault,
						   match, &dev_iter);
	if (kr != kIOReturnSuccess) {
		fprintf(stderr, "IOServiceGetMatchingServices failed: 0x%x\n", kr);
		return -1;
	}

	io_service_t device = IO_OBJECT_NULL;
	const char *matched_vendor = NULL;
	int matched_vid = 0, matched_pid = 0;
	io_service_t candidate;

	while ((candidate = IOIteratorNext(dev_iter))) {
		CFNumberRef vid_ref = IORegistryEntryCreateCFProperty(
			candidate, CFSTR("idVendor"), kCFAllocatorDefault, 0);
		if (vid_ref) {
			int vid = 0;

			CFNumberGetValue(vid_ref, kCFNumberIntType, &vid);
			CFRelease(vid_ref);
			matched_vendor = diag_vendor_name(vid);
			if (matched_vendor) {
				matched_vid = vid;
				CFNumberRef pid_ref =
					IORegistryEntryCreateCFProperty(
						candidate, CFSTR("idProduct"),
						kCFAllocatorDefault, 0);
				if (pid_ref) {
					CFNumberGetValue(pid_ref,
							 kCFNumberIntType,
							 &matched_pid);
					CFRelease(pid_ref);
				}
				device = candidate;
				break;
			}
		}
		IOObjectRelease(candidate);
	}
	IOObjectRelease(dev_iter);

	if (!device)
		return -1;

	printf("Matched vendor: %s (VID 0x%04x PID 0x%04x)\n",
	       matched_vendor, matched_vid, matched_pid);

	CFStringRef product = IORegistryEntryCreateCFProperty(
		device, CFSTR("USB Product Name"), kCFAllocatorDefault, 0);
	if (product) {
		char name[128];

		CFStringGetCString(product, name, sizeof(name),
				   kCFStringEncodingUTF8);
		printf("Found: %s\n", name);
		CFRelease(product);
	}

	int known_diag_iface = get_diag_interface_num((uint16_t)matched_vid,
						      (uint16_t)matched_pid);

	io_iterator_t child_iter;

	kr = IORegistryEntryCreateIterator(device, kIOServicePlane,
					   kIORegistryIterateRecursively,
					   &child_iter);
	if (kr != kIOReturnSuccess) {
		fprintf(stderr, "Failed to create child iterator: 0x%x\n", kr);
		IOObjectRelease(device);
		return -1;
	}

	int exclusive_access_hit = 0;
	io_service_t child;

	while ((child = IOIteratorNext(child_iter)) &&
	       g_bridge_count < MAX_INTERFACES) {
		if (!IOObjectConformsTo(child, "IOUSBHostInterface")) {
			IOObjectRelease(child);
			continue;
		}

		CFNumberRef class_ref = IORegistryEntryCreateCFProperty(
			child, CFSTR("bInterfaceClass"),
			kCFAllocatorDefault, 0);
		if (!class_ref) {
			IOObjectRelease(child);
			continue;
		}
		int iface_class = 0;

		CFNumberGetValue(class_ref, kCFNumberIntType, &iface_class);
		CFRelease(class_ref);
		if (iface_class != 0xFF) {
			IOObjectRelease(child);
			continue;
		}

		io_service_t iface_service = child;
		IOCFPlugInInterface **iplug = NULL;
		IOUSBInterfaceInterface300 **iface = NULL;
		SInt32 iscore;

		kr = IOCreatePlugInInterfaceForService(iface_service,
			kIOUSBInterfaceUserClientTypeID,
			kIOCFPlugInInterfaceID, &iplug, &iscore);
		IOObjectRelease(iface_service);
		if (kr != kIOReturnSuccess || !iplug)
			continue;

		(*iplug)->QueryInterface(iplug,
			CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID300),
			(LPVOID *)&iface);
		(*iplug)->Release(iplug);
		if (!iface)
			continue;

		UInt8 iface_num = 0;

		(*iface)->GetInterfaceNumber(iface, &iface_num);

		UInt8 iface_subclass = 0, iface_protocol = 0;

		(*iface)->GetInterfaceSubClass(iface, &iface_subclass);
		(*iface)->GetInterfaceProtocol(iface, &iface_protocol);

		/* Skip ADB interface */
		if (iface_subclass == 0x42 && iface_protocol == 0x01) {
			printf("Skipping ADB interface %d\n", iface_num);
			(*iface)->Release(iface);
			continue;
		}

		kr = (*iface)->USBInterfaceOpen(iface);
		if (kr != kIOReturnSuccess) {
			if (kr == (IOReturn)0xe00002c5)
				exclusive_access_hit = 1;
			fprintf(stderr, "Failed to open interface %d: 0x%x\n",
				iface_num, kr);
			(*iface)->Release(iface);
			continue;
		}

		UInt8 num_endpoints = 0;

		(*iface)->GetNumEndpoints(iface, &num_endpoints);

		UInt8 pipe_in = 0, pipe_out = 0;

		for (UInt8 i = 1; i <= num_endpoints; i++) {
			UInt8 direction, number, transfer_type, interval;
			UInt16 max_packet;

			(*iface)->GetPipeProperties(iface, i, &direction,
						    &number, &transfer_type,
						    &max_packet, &interval);
			if (transfer_type == kUSBBulk) {
				if (direction == kUSBIn && pipe_in == 0)
					pipe_in = i;
				else if (direction == kUSBOut && pipe_out == 0)
					pipe_out = i;
			}
		}

		if (pipe_in == 0 || pipe_out == 0) {
			printf("Interface %d: no bulk IN/OUT pair, skipping\n",
			       iface_num);
			(*iface)->USBInterfaceClose(iface);
			(*iface)->Release(iface);
			continue;
		}

		int master, slave;
		char slave_name[256];

		if (openpty(&master, &slave, slave_name, NULL, NULL) < 0) {
			perror("openpty");
			(*iface)->USBInterfaceClose(iface);
			(*iface)->Release(iface);
			continue;
		}

		struct termios tio;

		tcgetattr(master, &tio);
		cfmakeraw(&tio);
		tcsetattr(master, TCSANOW, &tio);

		chmod(slave_name, 0666);
		close(slave);

		char func_buf[32];
		const char *func;

		if (iface_subclass == 0xFF && iface_protocol == 0x30) {
			func = "diag";
		} else if (iface_num == known_diag_iface &&
			   iface_protocol != 0x30) {
			func = "diag";
		} else {
			snprintf(func_buf, sizeof(func_buf),
				 "port%d-loading", iface_num);
			func = func_buf;
		}

		char link[256];

		make_symlink_path(link, sizeof(link), func);
		unlink(link);
		if (symlink(slave_name, link) < 0) {
			fprintf(stderr,
				"Warning: symlink %s -> %s failed: %s\n",
				link, slave_name, strerror(errno));
			snprintf(link, sizeof(link), "%s", slave_name);
		}

		bridge_t *b = &g_bridges[g_bridge_count];

		memset(b, 0, sizeof(*b));
		b->iface_num = iface_num;
		b->pty_master = master;
		strncpy(b->pty_name, slave_name, sizeof(b->pty_name) - 1);
		strncpy(b->link_name, link, sizeof(b->link_name) - 1);
		strncpy(b->func_name, func, sizeof(b->func_name) - 1);
		b->iface = iface;
		b->pipe_in = pipe_in;
		b->pipe_out = pipe_out;
		atomic_store(&b->state, BRIDGE_RUNNING);
		atomic_store(&b->usb_to_pty_alive, 0);
		atomic_store(&b->pty_to_usb_alive, 0);

		printf("Interface %d (%s): %s -> %s\n",
		       iface_num, func, slave_name, link);
		printf("  Bulk IN pipe %d, Bulk OUT pipe %d, %d endpoints\n",
		       pipe_in, pipe_out, num_endpoints);

		pthread_attr_t attr;

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		pthread_create(&b->usb_to_pty_thread, &attr, usb_to_pty, b);
		pthread_create(&b->pty_to_usb_thread, &attr, pty_to_usb, b);
		pthread_attr_destroy(&attr);

		g_bridge_count++;
	}

	IOObjectRelease(child_iter);

	if (g_bridge_count == 0 && exclusive_access_hit) {
		printf("Exclusive access conflict — attempting USB recovery...\n");
		if (attempt_usb_recovery(device) == 0) {
			IOObjectRelease(device);
			return setup_bridges();
		}
		fprintf(stderr,
			"Recovery failed — modem unplug/replug may be required\n");
	}

	IOObjectRelease(device);

	if (g_bridge_count == 0)
		return -1;

	return 0;
}

/* Forward declaration */
static void write_status_file(void);

/* ── Port rename helper ── */

static void rename_bridge(bridge_t *b, const char *new_name)
{
	char new_link[256];

	make_symlink_path(new_link, sizeof(new_link), new_name);

	if (strcmp(b->link_name, new_link) == 0)
		return;

	unlink(b->link_name);
	unlink(new_link);
	if (symlink(b->pty_name, new_link) < 0) {
		fprintf(stderr, "Warning: symlink %s -> %s failed: %s\n",
			new_link, b->pty_name, strerror(errno));
		return;
	}

	printf("  Identified: %s -> %s/" SYMLINK_PREFIX "%s\n",
	       b->func_name, g_symlink_dir, new_name);
	strncpy(b->link_name, new_link, sizeof(b->link_name) - 1);
	strncpy(b->func_name, new_name, sizeof(b->func_name) - 1);
}

/* ── Port auto-detection via URC/AT probing ── */

enum port_type { PORT_UNKNOWN = 0, PORT_AT, PORT_NMEA };

static void probe_ports(void)
{
	int idx[MAX_INTERFACES];
	int fds[MAX_INTERFACES];
	enum port_type types[MAX_INTERFACES];
	int count = 0;

	for (int i = 0; i < g_bridge_count && count < MAX_INTERFACES; i++) {
		int fd;
		struct termios tio;

		if (strstr(g_bridges[i].func_name, "-loading") == NULL)
			continue;

		fd = open(g_bridges[i].link_name,
			  O_RDWR | O_NONBLOCK | O_NOCTTY);
		if (fd < 0) {
			fprintf(stderr, "Probe: failed to open %s: %s\n",
				g_bridges[i].link_name, strerror(errno));
			continue;
		}

		tcgetattr(fd, &tio);
		cfmakeraw(&tio);
		tcsetattr(fd, TCSANOW, &tio);

		idx[count] = i;
		fds[count] = fd;
		types[count] = PORT_UNKNOWN;
		count++;
	}

	if (count == 0)
		return;

	printf("Probing %d unknown port(s) — trying AT command...\n", count);

	for (int i = 0; i < count; i++) {
		tcflush(fds[i], TCIOFLUSH);
		write(fds[i], "AT\r", 3);
	}

	char accum[MAX_INTERFACES][512];
	int accum_len[MAX_INTERFACES];
	int any_responded = 0;
	time_t at_start;

	memset(accum_len, 0, sizeof(accum_len));

	at_start = time(NULL);
	while (time(NULL) - at_start < PROBE_AT_TIMEOUT &&
	       atomic_load(&g_running)) {
		struct pollfd pfds[MAX_INTERFACES];
		int poll_count = 0;
		int poll_map[MAX_INTERFACES];
		int ret;

		for (int i = 0; i < count; i++) {
			if (types[i] != PORT_UNKNOWN)
				continue;
			pfds[poll_count].fd = fds[i];
			pfds[poll_count].events = POLLIN;
			poll_map[poll_count] = i;
			poll_count++;
		}

		if (poll_count == 0)
			break;

		ret = poll(pfds, poll_count, 500);
		if (ret <= 0)
			continue;

		for (int p = 0; p < poll_count; p++) {
			int i, space;
			ssize_t n;

			if (!(pfds[p].revents & POLLIN))
				continue;

			i = poll_map[p];
			space = (int)sizeof(accum[i]) - accum_len[i] - 1;
			if (space <= 0)
				continue;

			n = read(fds[i], accum[i] + accum_len[i], space);
			if (n <= 0)
				continue;
			accum_len[i] += n;
			accum[i][accum_len[i]] = '\0';

			if (strstr(accum[i], "OK") ||
			    strstr(accum[i], "ERROR") ||
			    strstr(accum[i], "RDY")) {
				types[i] = PORT_AT;
				any_responded = 1;
				printf("  [%s] AT port detected\n",
				       g_bridges[idx[i]].func_name);
			} else if (strstr(accum[i], "$G")) {
				types[i] = PORT_NMEA;
				any_responded = 1;
				printf("  [%s] NMEA data detected — GPS port\n",
				       g_bridges[idx[i]].func_name);
			}
		}
	}

	/* If any port responded, try AT again on remaining unknowns */
	if (any_responded) {
		int unknown_remain = 0;

		for (int i = 0; i < count; i++) {
			if (types[i] == PORT_UNKNOWN)
				unknown_remain++;
		}
		if (unknown_remain > 0 && atomic_load(&g_running)) {
			printf("Retrying AT on %d remaining port(s)...\n",
			       unknown_remain);
			for (int i = 0; i < count; i++) {
				char resp[256] = {0};
				int resp_len = 0;
				time_t retry_start;

				if (types[i] != PORT_UNKNOWN)
					continue;
				if (!atomic_load(&g_running))
					break;

				tcflush(fds[i], TCIOFLUSH);
				write(fds[i], "AT\r", 3);

				retry_start = time(NULL);
				while (time(NULL) - retry_start < PROBE_AT_TIMEOUT) {
					struct pollfd pfd = {
						.fd = fds[i],
						.events = POLLIN
					};
					int ret = poll(&pfd, 1, 500);
					ssize_t n;

					if (ret <= 0)
						continue;
					n = read(fds[i], resp + resp_len,
						 sizeof(resp) - resp_len - 1);
					if (n > 0) {
						resp_len += n;
						resp[resp_len] = '\0';
						if (strstr(resp, "OK") ||
						    strstr(resp, "ERROR") ||
						    strstr(resp, "RDY"))
							break;
					}
				}
				if (strstr(resp, "OK") ||
				    strstr(resp, "ERROR") ||
				    strstr(resp, "RDY")) {
					types[i] = PORT_AT;
					printf("  [%s] AT port detected\n",
					       g_bridges[idx[i]].func_name);
				}
			}
		}
		goto done;
	}

	/* Phase 2: No port responded — wait for RDY URC */
	printf("No AT response — modem not ready, waiting for RDY URC (up to %ds)...\n",
	       PROBE_RDY_TIMEOUT);

	{
		time_t rdy_start = time(NULL);
		int modem_ready = 0;

		while (time(NULL) - rdy_start < PROBE_RDY_TIMEOUT &&
		       atomic_load(&g_running) && !modem_ready) {
			struct pollfd pfds[MAX_INTERFACES];
			int poll_count = 0;
			int poll_map[MAX_INTERFACES];
			int ret;

			for (int i = 0; i < count; i++) {
				if (types[i] != PORT_UNKNOWN)
					continue;
				pfds[poll_count].fd = fds[i];
				pfds[poll_count].events = POLLIN;
				poll_map[poll_count] = i;
				poll_count++;
			}
			if (poll_count == 0)
				break;

			ret = poll(pfds, poll_count, 1000);
			if (ret <= 0)
				continue;

			for (int p = 0; p < poll_count; p++) {
				int i, space;
				ssize_t n;

				if (!(pfds[p].revents & POLLIN))
					continue;

				i = poll_map[p];
				space = (int)sizeof(accum[i]) - accum_len[i] - 1;
				if (space <= 0) {
					int keep = (int)sizeof(accum[i]) / 2;

					memmove(accum[i],
						accum[i] + accum_len[i] - keep,
						keep);
					accum_len[i] = keep;
					space = (int)sizeof(accum[i]) - accum_len[i] - 1;
				}

				n = read(fds[i], accum[i] + accum_len[i], space);
				if (n <= 0)
					continue;
				accum_len[i] += n;
				accum[i][accum_len[i]] = '\0';

				if (strstr(accum[i], "RDY")) {
					types[i] = PORT_AT;
					modem_ready = 1;
					printf("  [%s] RDY URC — AT port (modem ready)\n",
					       g_bridges[idx[i]].func_name);
				} else if (strstr(accum[i], "$G")) {
					types[i] = PORT_NMEA;
					printf("  [%s] NMEA data — GPS port\n",
					       g_bridges[idx[i]].func_name);
				}
			}
		}

		/* AT-probe any remaining unknown ports */
		{
			int unknown_remain = 0;

			for (int i = 0; i < count; i++) {
				if (types[i] == PORT_UNKNOWN)
					unknown_remain++;
			}
			if (unknown_remain > 0 && atomic_load(&g_running)) {
				printf("AT-probing %d remaining port(s)...\n",
				       unknown_remain);
				for (int i = 0; i < count; i++) {
					char resp[256] = {0};
					int resp_len = 0;
					time_t retry_start;

					if (types[i] != PORT_UNKNOWN)
						continue;
					if (!atomic_load(&g_running))
						break;

					tcflush(fds[i], TCIOFLUSH);
					write(fds[i], "AT\r", 3);

					retry_start = time(NULL);
					while (time(NULL) - retry_start < PROBE_AT_TIMEOUT) {
						struct pollfd pfd = {
							.fd = fds[i],
							.events = POLLIN
						};
						int ret = poll(&pfd, 1, 500);
						ssize_t n;

						if (ret <= 0)
							continue;
						n = read(fds[i],
							 resp + resp_len,
							 sizeof(resp) - resp_len - 1);
						if (n > 0) {
							resp_len += n;
							resp[resp_len] = '\0';
							if (strstr(resp, "OK") ||
							    strstr(resp, "ERROR") ||
							    strstr(resp, "RDY"))
								break;
						}
					}
					if (strstr(resp, "OK") ||
					    strstr(resp, "ERROR") ||
					    strstr(resp, "RDY")) {
						types[i] = PORT_AT;
						printf("  [%s] AT port detected\n",
						       g_bridges[idx[i]].func_name);
					} else {
						printf("  [%s] No response\n",
						       g_bridges[idx[i]].func_name);
					}
				}
			}
		}
	}

done:
	for (int i = 0; i < count; i++)
		close(fds[i]);

	/* If AT ports found and one unknown remains, assume NMEA */
	{
		int at_found = 0, unknown_count = 0, nmea_found = 0;

		for (int i = 0; i < count; i++) {
			if (types[i] == PORT_AT)
				at_found++;
			else if (types[i] == PORT_NMEA)
				nmea_found++;
			else
				unknown_count++;
		}
		if (at_found > 0 && unknown_count == 1 && nmea_found == 0) {
			for (int i = 0; i < count; i++) {
				if (types[i] == PORT_UNKNOWN) {
					types[i] = PORT_NMEA;
					printf("  [%s] Remaining port assumed NMEA/GPS\n",
					       g_bridges[idx[i]].func_name);
					break;
				}
			}
		}
	}

	/* Rename ports based on identification results */
	{
		int at_index = 0;
		int nmea_done = 0;

		for (int i = 0; i < count; i++) {
			bridge_t *b = &g_bridges[idx[i]];
			char name_buf[32];

			switch (types[i]) {
			case PORT_AT:
				snprintf(name_buf, sizeof(name_buf), "at%d",
					 at_index++);
				rename_bridge(b, name_buf);
				break;
			case PORT_NMEA:
				if (!nmea_done) {
					rename_bridge(b, "nmea");
					nmea_done = 1;
				} else {
					snprintf(name_buf, sizeof(name_buf),
						 "nmea%d", nmea_done++);
					rename_bridge(b, name_buf);
				}
				break;
			default:
				snprintf(name_buf, sizeof(name_buf), "port%d",
					 b->iface_num);
				rename_bridge(b, name_buf);
				break;
			}
		}
	}

	write_status_file();
}

/* ── Robust shutdown ── */

static void shutdown_bridges(void)
{
	if (g_bridge_count == 0)
		return;

	printf("Shutting down %d bridge(s)...\n", g_bridge_count);

	for (int i = 0; i < g_bridge_count; i++)
		atomic_store(&g_bridges[i].state, BRIDGE_STOPPING);

	/* Close PTY masters FIRST to unblock pty_to_usb threads */
	for (int i = 0; i < g_bridge_count; i++) {
		if (g_bridges[i].pty_master >= 0) {
			close(g_bridges[i].pty_master);
			g_bridges[i].pty_master = -1;
		}
	}

	/* Abort BOTH pipe_in AND pipe_out */
	for (int i = 0; i < g_bridge_count; i++) {
		bridge_t *b = &g_bridges[i];

		if (b->iface) {
			(*b->iface)->AbortPipe(b->iface, b->pipe_in);
			(*b->iface)->AbortPipe(b->iface, b->pipe_out);
		}
	}

	/* Wait for threads with timeout */
	struct timespec deadline;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += SHUTDOWN_TIMEOUT;

	pthread_mutex_lock(&g_exit_mutex);
	for (;;) {
		int all_done = 1;

		for (int i = 0; i < g_bridge_count; i++) {
			if (atomic_load(&g_bridges[i].usb_to_pty_alive) ||
			    atomic_load(&g_bridges[i].pty_to_usb_alive)) {
				all_done = 0;
				break;
			}
		}
		if (all_done)
			break;

		int rc = pthread_cond_timedwait(&g_exit_cond, &g_exit_mutex,
						&deadline);
		if (rc == ETIMEDOUT) {
			fprintf(stderr, "Shutdown timeout — stuck threads:\n");
			for (int i = 0; i < g_bridge_count; i++) {
				bridge_t *b = &g_bridges[i];
				int u2p = atomic_load(&b->usb_to_pty_alive);
				int p2u = atomic_load(&b->pty_to_usb_alive);

				if (u2p || p2u)
					fprintf(stderr,
						"  [%s] usb_to_pty=%d pty_to_usb=%d\n",
						b->func_name, u2p, p2u);
			}
			break;
		}
	}
	pthread_mutex_unlock(&g_exit_mutex);

	/* Close USB interfaces and remove symlinks */
	for (int i = 0; i < g_bridge_count; i++) {
		bridge_t *b = &g_bridges[i];

		atomic_store(&b->state, BRIDGE_STOPPED);

		if (b->iface) {
			(*b->iface)->USBInterfaceClose(b->iface);
			(*b->iface)->Release(b->iface);
			b->iface = NULL;
		}

		if (b->link_name[0] &&
		    strcmp(b->link_name, b->pty_name) != 0)
			unlink(b->link_name);
	}

	g_bridge_count = 0;
	printf("All bridges shut down\n");
}

/* ── Status file ── */

static void write_status_file(void)
{
	char tmp[256];
	FILE *f;

	snprintf(tmp, sizeof(tmp), "%s.tmp", g_status_file);
	f = fopen(tmp, "w");
	if (!f)
		return;

	fprintf(f, "pid=%d\n", getpid());
	fprintf(f, "state=%s\n", g_daemon_state);
	fprintf(f, "bridges=%d\n", g_bridge_count);
	for (int i = 0; i < g_bridge_count; i++) {
		bridge_t *b = &g_bridges[i];
		int u2p = atomic_load(&b->usb_to_pty_alive);
		int p2u = atomic_load(&b->pty_to_usb_alive);
		const char *health = (u2p && p2u) ? "healthy" : "dead";

		fprintf(f, "port.%s=%s usb2pty=%d pty2usb=%d link=%s\n",
			b->func_name, health, u2p, p2u, b->link_name);
	}
	fclose(f);
	rename(tmp, g_status_file);
}

/* ── Health monitor + auto-restart loop ── */

static void run_monitor_loop(void)
{
	int prev_bridge_count = 0;

	while (atomic_load(&g_running)) {
		int alive_count = 0;

		for (int i = 0; i < g_bridge_count; i++) {
			if (atomic_load(&g_bridges[i].usb_to_pty_alive))
				alive_count++;
		}

		write_status_file();

		if (g_bridge_count > 0 && alive_count == 0) {
			printf(UX_COLOR_YELLOW
			       "All bridges dead — modem likely disconnected\n"
			       UX_COLOR_RESET);
			if (g_bridge_count > prev_bridge_count)
				prev_bridge_count = g_bridge_count;
			shutdown_bridges();
			g_daemon_state = "waiting";
			write_status_file();

			printf(UX_COLOR_YELLOW
			       "Waiting for modem to reconnect...\n"
			       UX_COLOR_RESET);

			int retries_with_partial = 0;

			while (atomic_load(&g_running)) {
				for (int s = 0;
				     s < RESCAN_INTERVAL &&
				     atomic_load(&g_running); s++)
					sleep(1);

				if (!atomic_load(&g_running))
					break;

				if (setup_bridges() == 0) {
					if (g_bridge_count < prev_bridge_count &&
					    retries_with_partial < 3) {
						printf(UX_COLOR_YELLOW
						       "Partial reconnect (%d/%d bridges) — retrying...\n"
						       UX_COLOR_RESET,
						       g_bridge_count,
						       prev_bridge_count);
						shutdown_bridges();
						retries_with_partial++;
						continue;
					}
					probe_ports();
					g_daemon_state = "running";
					printf(UX_COLOR_GREEN
					       "Modem reconnected — %d bridge(s) active\n"
					       UX_COLOR_RESET,
					       g_bridge_count);
					prev_bridge_count = g_bridge_count;
					printf("\n" UX_COLOR_BOLD
					       "Active ports:" UX_COLOR_RESET "\n");
					for (int i = 0; i < g_bridge_count; i++)
						printf("  " UX_COLOR_GREEN "%s"
						       UX_COLOR_RESET "\n",
						       g_bridges[i].link_name);
					break;
				}
			}
			continue;
		}

		for (int s = 0;
		     s < MONITOR_INTERVAL && atomic_load(&g_running); s++)
			sleep(1);
	}
}

/* ── ADB_LIBUSB=0 environment setup ── */

static int check_launchctl_env(void)
{
	FILE *fp = popen("launchctl getenv ADB_LIBUSB 2>/dev/null", "r");
	char buf[32] = {0};

	if (!fp)
		return 0;
	if (fgets(buf, sizeof(buf), fp))
		buf[strcspn(buf, "\n")] = '\0';
	pclose(fp);
	return (strcmp(buf, "0") == 0);
}

static void set_adb_libusb_env(void)
{
	system("launchctl setenv ADB_LIBUSB 0 2>/dev/null");
	if (check_launchctl_env()) {
		printf("ADB_LIBUSB=0 set (system-wide via launchctl)\n");
		return;
	}

	uid_t target_uid = getuid();
	const char *sudo_user = getenv("SUDO_USER");

	if (sudo_user) {
		struct passwd *pw = getpwnam(sudo_user);

		if (pw)
			target_uid = pw->pw_uid;
	}

	char cmd[256];

	snprintf(cmd, sizeof(cmd),
		 "launchctl asuser %u launchctl setenv ADB_LIBUSB 0 2>/dev/null",
		 target_uid);
	system(cmd);

	if (check_launchctl_env()) {
		printf("ADB_LIBUSB=0 set (user domain via launchctl)\n");
		return;
	}

	setenv("ADB_LIBUSB", "0", 1);
	fprintf(stderr,
		UX_COLOR_YELLOW
		"Warning: could not set ADB_LIBUSB=0 via launchctl (SIP restriction)\n"
		"ADB may have issues with this modem. To fix permanently, add to ~/.zshrc:\n"
		"  export ADB_LIBUSB=0\n"
		UX_COLOR_RESET);
}

/* ── cmd_start ── */

static int cmd_start(int foreground)
{
	init_runtime_paths();

	pid_t existing = pid_file_read();

	if (existing && is_process_alive(existing)) {
		ux_warn("qcseriald already running (PID %d)\n", existing);
		fprintf(stderr,
			"Use '" UX_COLOR_GREEN "qfenix qcseriald stop"
			UX_COLOR_RESET "' first, or '"
			UX_COLOR_GREEN "qfenix qcseriald status"
			UX_COLOR_RESET "' for details.\n");
		return 1;
	}

	if (existing) {
		printf("Cleaning up stale PID file (PID %d no longer running)\n",
		       existing);
		pid_file_remove();
	}
	resolve_symlink_dir();
	cleanup_stale_symlinks();

	set_adb_libusb_env();

	if (foreground) {
		signal(SIGINT, signal_handler);
		signal(SIGTERM, signal_handler);

		printf(UX_COLOR_BOLD UX_COLOR_GREEN "qcseriald" UX_COLOR_RESET
		       " v%s — User-space USB serial bridge (foreground)\n",
		       QCSERIALD_VERSION);
		printf("Looking for supported modem (%zu vendors)...\n",
		       ARRAY_SIZE(diag_vids));

		pid_file_write(getpid());

		if (setup_bridges() < 0) {
			fprintf(stderr,
				UX_COLOR_YELLOW
				"No modem found — entering rescan mode\n"
				UX_COLOR_RESET);
			g_daemon_state = "waiting";
		} else {
			probe_ports();
			g_daemon_state = "running";
			printf("\n%d serial port(s) created:\n",
			       g_bridge_count);
			for (int i = 0; i < g_bridge_count; i++)
				printf("  %s\n", g_bridges[i].link_name);
			printf("\n");
		}

		run_monitor_loop();

		printf("Shutting down...\n");
		shutdown_bridges();
		pid_file_remove();
		unlink(g_status_file);
		printf("Done\n");
		return 0;
	}

	/* Daemonize: fork, report back to parent via pipe */
	int pipefd[2];

	if (pipe(pipefd) < 0) {
		perror("pipe");
		return 1;
	}

	pid_t child_pid = fork();

	if (child_pid < 0) {
		perror("fork");
		return 1;
	}

	if (child_pid > 0) {
		char report[1024];
		ssize_t n = 0;
		ssize_t total = 0;

		close(pipefd[1]);
		while ((n = read(pipefd[0], report + total,
				 sizeof(report) - 1 - total)) > 0)
			total += n;
		close(pipefd[0]);
		report[total] = '\0';

		if (total > 0 && report[0] == '+') {
			printf("%s", report + 1);
			return 0;
		} else if (total > 0) {
			fprintf(stderr, "%s", report + 1);
			return 1;
		}
		fprintf(stderr, "Child process died unexpectedly\n");
		return 1;
	}

	/* Child: become daemon */
	close(pipefd[0]);

	if (setsid() < 0) {
		dprintf(pipefd[1], "-setsid failed: %s\n", strerror(errno));
		close(pipefd[1]);
		_exit(1);
	}

	int logfd = open(g_log_file, O_WRONLY | O_CREAT | O_APPEND, 0644);

	if (logfd >= 0) {
		dup2(logfd, STDOUT_FILENO);
		dup2(logfd, STDERR_FILENO);
		close(logfd);
	}
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	int devnull = open("/dev/null", O_RDONLY);

	if (devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		close(devnull);
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	printf(UX_COLOR_BOLD UX_COLOR_GREEN "qcseriald" UX_COLOR_RESET
	       " v%s daemon starting (PID %d)\n", QCSERIALD_VERSION, getpid());
	printf("Looking for supported modem (%zu vendors)...\n",
	       ARRAY_SIZE(diag_vids));

	pid_file_write(getpid());

	if (setup_bridges() < 0) {
		dprintf(pipefd[1],
			"+" UX_COLOR_BOLD UX_COLOR_GREEN "qcseriald"
			UX_COLOR_RESET " started (PID %d)\n"
			UX_COLOR_YELLOW "No modem found — waiting for connection...\n"
			UX_COLOR_RESET, getpid());
		close(pipefd[1]);

		printf(UX_COLOR_YELLOW
		       "No modem found — entering rescan mode\n"
		       UX_COLOR_RESET);
	} else {
		char msg[2048];
		int off = snprintf(msg, sizeof(msg),
			"+" UX_COLOR_BOLD UX_COLOR_GREEN "qcseriald"
			UX_COLOR_RESET " started (PID %d)\n"
			"%d serial port(s) created ("
			UX_COLOR_GREEN "identifying ports..." UX_COLOR_RESET
			"):\n", getpid(), g_bridge_count);
		for (int i = 0;
		     i < g_bridge_count && off < (int)sizeof(msg) - 128; i++)
			off += snprintf(msg + off, sizeof(msg) - off,
					"  " UX_COLOR_GREEN "%s" UX_COLOR_RESET
					"\n", g_bridges[i].link_name);

		write(pipefd[1], msg, off);
		close(pipefd[1]);

		printf("\n%d serial port(s) created — "
		       UX_COLOR_GREEN "probing for port identification..."
		       UX_COLOR_RESET "\n", g_bridge_count);

		probe_ports();
		g_daemon_state = "running";

		printf("\n" UX_COLOR_BOLD "Final port assignment:"
		       UX_COLOR_RESET "\n");
		for (int i = 0; i < g_bridge_count; i++)
			printf("  " UX_COLOR_GREEN "%s" UX_COLOR_RESET "\n",
			       g_bridges[i].link_name);
	}

	run_monitor_loop();

	printf("Daemon shutting down...\n");
	shutdown_bridges();
	pid_file_remove();
	unlink(g_status_file);
	printf("Done\n");
	_exit(0);
}

/* ── cmd_stop ── */

static int cmd_stop(void)
{
	init_runtime_paths();
	resolve_symlink_dir();

	pid_t pid = pid_file_read();

	if (!pid || !is_process_alive(pid)) {
		printf(UX_COLOR_YELLOW "qcseriald is not running\n"
		       UX_COLOR_RESET);
		if (pid)
			pid_file_remove();
		cleanup_stale_symlinks();
		return 0;
	}

	printf("Stopping qcseriald (PID %d)...\n", pid);
	kill(pid, SIGTERM);

	for (int i = 0; i < (SHUTDOWN_TIMEOUT + 2) * 10; i++) {
		usleep(100000);
		if (!is_process_alive(pid)) {
			printf(UX_COLOR_GREEN "Stopped\n" UX_COLOR_RESET);
			pid_file_remove();
			cleanup_stale_symlinks();
			return 0;
		}
	}

	fprintf(stderr,
		UX_COLOR_RED
		"Process didn't exit gracefully — sending SIGKILL\n"
		UX_COLOR_RESET);
	kill(pid, SIGKILL);
	usleep(200000);
	pid_file_remove();
	cleanup_stale_symlinks();
	printf(UX_COLOR_YELLOW "Killed\n" UX_COLOR_RESET);
	return 0;
}

/* ── cmd_status ── */

static int cmd_status(void)
{
	init_runtime_paths();

	pid_t pid = pid_file_read();

	if (!pid || !is_process_alive(pid)) {
		printf(UX_COLOR_YELLOW "qcseriald is not running\n"
		       UX_COLOR_RESET);
		if (pid)
			printf("  (stale PID file for PID %d)\n", pid);
		return 1;
	}

	printf(UX_COLOR_GREEN "qcseriald is running" UX_COLOR_RESET
	       " (PID %d)\n", pid);

	FILE *f = fopen(g_status_file, "r");

	if (!f) {
		printf("  (no status file — daemon may be starting up)\n");
		return 0;
	}

	char line[512];

	while (fgets(line, sizeof(line), f)) {
		size_t len = strlen(line);

		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';

		if (strncmp(line, "state=", 6) == 0) {
			const char *state = line + 6;

			if (strcmp(state, "waiting") == 0)
				printf("  " UX_COLOR_YELLOW
				       "Waiting for modem to reconnect..."
				       UX_COLOR_RESET "\n");
			else if (strcmp(state, "starting") == 0)
				printf("  " UX_COLOR_YELLOW
				       "Starting up..."
				       UX_COLOR_RESET "\n");
		} else if (strncmp(line, "bridges=", 8) == 0) {
			printf("  " UX_COLOR_BOLD "Bridges:" UX_COLOR_RESET
			       " %s\n", line + 8);
		} else if (strncmp(line, "port.", 5) == 0) {
			const char *color = strstr(line, "healthy") ?
				UX_COLOR_GREEN : UX_COLOR_RED;
			printf("  %s%s" UX_COLOR_RESET "\n", color, line);
		}
	}
	fclose(f);
	return 0;
}

/* ── cmd_printlog ── */

static int cmd_printlog(int follow)
{
	init_runtime_paths();

	if (access(g_log_file, R_OK) != 0) {
		ux_err("No log file found at %s\n", g_log_file);
		return 1;
	}

	if (follow) {
		execlp("tail", "tail", "-f", g_log_file, NULL);
		perror("tail");
		return 1;
	}

	FILE *f = fopen(g_log_file, "r");

	if (!f) {
		perror(g_log_file);
		return 1;
	}

	char buf[4096];
	size_t n;

	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		fwrite(buf, 1, n, stdout);
	fclose(f);
	return 0;
}

/* ── New functions for qfenix integration ── */

int qcseriald_is_running(void)
{
	init_runtime_paths();

	pid_t pid = pid_file_read();

	return (pid > 0 && is_process_alive(pid));
}

int qcseriald_ensure_running(void)
{
	if (qcseriald_is_running())
		return 0;

	ux_info("Starting qcseriald daemon...\n");

	/* Start the daemon */
	pid_t child = fork();

	if (child < 0) {
		ux_err("Failed to fork qcseriald: %s\n", strerror(errno));
		return -1;
	}

	if (child == 0) {
		/* Child: exec ourselves with qcseriald start */
		char self[1024];
		uint32_t size = sizeof(self);

		if (_NSGetExecutablePath(self, &size) != 0)
			snprintf(self, sizeof(self), "qfenix");
		execl(self, self, "qcseriald", "start", NULL);
		_exit(1);
	}

	/* Parent: wait for daemon to start and ports to be probed */
	int status;

	waitpid(child, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		ux_err("qcseriald failed to start\n");
		return -1;
	}

	/*
	 * Wait for port probing to complete. The daemon reports
	 * initial ports immediately, but probing (AT/RDY detection)
	 * can take up to 30s on cold boot. Poll the status file
	 * for completion.
	 */
	for (int i = 0; i < 70; i++) {
		FILE *f;
		char line[512];
		int has_loading = 0;
		int has_ports = 0;

		usleep(500000);

		f = fopen(g_status_file, "r");
		if (!f)
			continue;

		while (fgets(line, sizeof(line), f)) {
			if (strstr(line, "port."))
				has_ports = 1;
			if (strstr(line, "-loading"))
				has_loading = 1;
		}
		fclose(f);

		if (has_ports && !has_loading)
			return 0;
	}

	/* Timed out but daemon is running — ports may still work */
	if (qcseriald_is_running())
		return 0;

	ux_err("qcseriald timed out waiting for port probing\n");
	return -1;
}

static int read_status_port(char *buf, size_t size, const char *prefix)
{
	FILE *f;
	char line[512];
	char key[64];

	f = fopen(g_status_file, "r");
	if (!f)
		return 0;

	snprintf(key, sizeof(key), "port.%s=", prefix);

	while (fgets(line, sizeof(line), f)) {
		char *p, *link;

		if (strncmp(line, key, strlen(key)) != 0)
			continue;

		/* Find the link= field */
		link = strstr(line, "link=");
		if (!link) {
			fclose(f);
			return 0;
		}
		link += 5;

		/* Strip trailing whitespace */
		p = link + strlen(link) - 1;
		while (p > link && (*p == '\n' || *p == '\r' || *p == ' '))
			*p-- = '\0';

		if (link[0] && access(link, F_OK) == 0) {
			snprintf(buf, size, "%s", link);
			fclose(f);
			return 1;
		}
		fclose(f);
		return 0;
	}
	fclose(f);
	return 0;
}

int qcseriald_detect_diag_port(char *buf, size_t size)
{
	return read_status_port(buf, size, "diag");
}

int qcseriald_detect_at_port(char *buf, size_t size, int index)
{
	char prefix[16];

	snprintf(prefix, sizeof(prefix), "at%d", index);
	return read_status_port(buf, size, prefix);
}

/* ── Help text ── */

void print_qcseriald_help(FILE *out)
{
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN,
		       "\nqcseriald");
	fprintf(out, " — macOS USB-to-serial bridge daemon\n\n");
	fprintf(out, "Usage: qfenix qcseriald <command> [options]\n\n");
	ux_fputs_color(out, UX_COLOR_BOLD, "Commands:\n");
	fprintf(out, "  start              Daemonize, print ports, exit\n");
	fprintf(out, "  start --foreground Run in foreground (for launchd)\n");
	fprintf(out, "  stop               Stop running daemon\n");
	fprintf(out, "  restart            Stop + start (clean reset)\n");
	fprintf(out, "  status             Show running state and port health\n");
	fprintf(out, "  log                Print daemon log (%s)\n", g_log_file);
	fprintf(out, "  log -f             Follow daemon log (tail -f)\n");
}

/* ── Main dispatcher ── */

int qdl_qcseriald(int argc, char **argv)
{
	init_runtime_paths();

	if (argc < 2) {
		print_qcseriald_help(stderr);
		return 1;
	}

	if (strcmp(argv[1], "start") == 0) {
		int foreground = 0;

		if (argc >= 3 && strcmp(argv[2], "--foreground") == 0)
			foreground = 1;
		return cmd_start(foreground);
	} else if (strcmp(argv[1], "stop") == 0) {
		return cmd_stop();
	} else if (strcmp(argv[1], "restart") == 0) {
		int foreground = 0;

		cmd_stop();
		if (argc >= 3 && strcmp(argv[2], "--foreground") == 0)
			foreground = 1;
		return cmd_start(foreground);
	} else if (strcmp(argv[1], "status") == 0) {
		return cmd_status();
	} else if (strcmp(argv[1], "log") == 0) {
		int follow = (argc >= 3 && strcmp(argv[2], "-f") == 0);
		return cmd_printlog(follow);
	} else if (strcmp(argv[1], "--help") == 0 ||
		   strcmp(argv[1], "-h") == 0 ||
		   strcmp(argv[1], "help") == 0) {
		print_qcseriald_help(stdout);
		return 0;
	}

	ux_err("Unknown qcseriald command: %s\n", argv[1]);
	print_qcseriald_help(stderr);
	return 1;
}

#endif /* __APPLE__ */
