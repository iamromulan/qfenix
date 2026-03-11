// SPDX-License-Identifier: BSD-3-Clause
/*
 * Interactive AT command console for Qualcomm modems.
 *
 * Line-buffered input with local echo, real-time URC display,
 * and "exit" to quit. Uses poll() on both stdin and the serial port.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "atcmd.h"
#include "at_port.h"
#include "qdl.h"

#ifdef _WIN32

#include <windows.h>
#include <process.h>
#include <getopt.h>

/* Forward declarations */
void print_atconsole_help(FILE *out);

static DWORD g_orig_console_mode;
static int g_console_mode_saved;

static void restore_console(void)
{
	if (g_console_mode_saved) {
		HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

		SetConsoleMode(hIn, g_orig_console_mode);
	}
}

static int set_raw_mode_win(void)
{
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

	if (!GetConsoleMode(hIn, &g_orig_console_mode))
		return -1;

	g_console_mode_saved = 1;
	atexit(restore_console);

	DWORD mode = g_orig_console_mode;

	mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
		   ENABLE_PROCESSED_INPUT);
	if (!SetConsoleMode(hIn, mode))
		return -1;
	return 0;
}

static volatile int g_quit;

struct reader_ctx {
	struct at_session *sess;
};

static unsigned __stdcall serial_reader_thread(void *arg)
{
	struct reader_ctx *ctx = (struct reader_ctx *)arg;
	char line[512];
	int len;

	while (!g_quit) {
		len = at_read_line(ctx->sess, line, sizeof(line));
		if (len <= 0)
			continue;

		/*
		 * Convert bare \n or \r to \r\n for
		 * proper console display.
		 */
		for (int i = 0; i < len; i++) {
			if (line[i] == '\n') {
				DWORD w;

				WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
					  "\r\n", 2, &w, NULL);
			} else if (line[i] == '\r') {
				/* Skip \r — we emit \r\n on \n */
			} else {
				DWORD w;

				WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
					  &line[i], 1, &w, NULL);
			}
		}
	}
	return 0;
}

int qdl_atconsole(int argc, char **argv)
{
	char port[256] = {0};
	const char *serial = NULL;
	int debug = 0;
	int opt;
	struct at_session *sess;
	char line_buf[1024];
	int line_len = 0;
	HANDLE hIn, hThread;
	struct reader_ctx rctx;
	COMMTIMEOUTS timeouts = {0};

	optind = 1;
	while ((opt = getopt(argc, argv, "S:p:d")) != -1) {
		switch (opt) {
		case 'S':
			serial = optarg;
			break;
		case 'p':
			snprintf(port, sizeof(port), "%s", optarg);
			break;
		case 'd':
			debug = 1;
			break;
		default:
			print_atconsole_help(stderr);
			return 1;
		}
	}

	if (!port[0]) {
		if (!at_detect_port(port, sizeof(port), serial)) {
			ux_err("No AT port detected. Use -p to specify manually.\n");
			return 1;
		}
		ux_info("Auto-detected AT port: %s\n", port);
	}

	sess = at_open(port, 10000);
	if (!sess) {
		ux_err("Failed to open %s\n", port);
		return 1;
	}
	sess->debug = debug;

	/*
	 * Override read timeout to 100ms so the reader thread
	 * checks g_quit frequently instead of blocking for 10s.
	 */
	timeouts.ReadIntervalTimeout = 100;
	timeouts.ReadTotalTimeoutConstant = 100;
	timeouts.ReadTotalTimeoutMultiplier = 0;
	timeouts.WriteTotalTimeoutConstant = 3000;
	timeouts.WriteTotalTimeoutMultiplier = 0;
	SetCommTimeouts((HANDLE)sess->fd, &timeouts);

	hIn = GetStdHandle(STD_INPUT_HANDLE);

	/*
	 * Raw mode disables echo and line buffering on a real console.
	 * When stdin is a pipe (e.g. GUI subprocess), skip it.
	 */
	if (GetFileType(hIn) == FILE_TYPE_CHAR) {
		if (set_raw_mode_win() < 0) {
			ux_err("Failed to set console raw mode\n");
			at_close(sess);
			return 1;
		}
	}

	printf("Connected to %s (type 'exit' to quit)\r\n", port);

	/* Spawn serial reader thread */
	g_quit = 0;
	rctx.sess = sess;
	hThread = (HANDLE)_beginthreadex(NULL, 0, serial_reader_thread,
					 &rctx, 0, NULL);
	if (!hThread) {
		ux_err("Failed to create reader thread\n");
		at_close(sess);
		return 1;
	}

	/*
	 * Main thread: input loop.
	 * Console mode uses ReadConsoleInputA for key events.
	 * Pipe mode (GUI subprocess) uses ReadFile for raw bytes.
	 */
	if (GetFileType(hIn) != FILE_TYPE_CHAR)
		goto pipe_input;

	for (;;) {
		INPUT_RECORD rec;
		DWORD count;

		if (!ReadConsoleInputA(hIn, &rec, 1, &count) || count == 0)
			break;

		if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown)
			continue;

		char ch = rec.Event.KeyEvent.uChar.AsciiChar;
		WORD vk = rec.Event.KeyEvent.wVirtualKeyCode;

		/* Ctrl-C */
		if ((rec.Event.KeyEvent.dwControlKeyState &
		     (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) &&
		    vk == 'C')
			break;

		if (ch == '\r' || ch == '\n') {
			DWORD w;

			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
				  "\r\n", 2, &w, NULL);

			line_buf[line_len] = '\0';

			if (strcmp(line_buf, "exit") == 0)
				break;

			if (line_len > 0) {
				DWORD written;
				HANDLE hSerial = (HANDLE)sess->fd;

				WriteFile(hSerial, line_buf, line_len,
					  &written, NULL);
				WriteFile(hSerial, "\r", 1,
					  &written, NULL);
			}
			line_len = 0;
		} else if (vk == VK_BACK || ch == 0x08 || ch == 0x7f) {
			if (line_len > 0) {
				DWORD w;

				line_len--;
				WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
					  "\b \b", 3, &w, NULL);
			}
		} else if (ch >= ' ' && ch <= '~') {
			if (line_len < (int)sizeof(line_buf) - 1) {
				DWORD w;

				line_buf[line_len++] = ch;
				WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
					  &ch, 1, &w, NULL);
			}
		}
	}
	goto shutdown;

pipe_input:
	/* Pipe mode: stdin is not a console (e.g. GUI subprocess) */
	for (;;) {
		char ch;
		DWORD n;

		if (!ReadFile(hIn, &ch, 1, &n, NULL) || n == 0)
			break;

		if (ch == '\r' || ch == '\n') {
			DWORD w;

			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
				  "\r\n", 2, &w, NULL);

			line_buf[line_len] = '\0';

			if (strcmp(line_buf, "exit") == 0)
				break;

			if (line_len > 0) {
				DWORD written;
				HANDLE hSerial = (HANDLE)sess->fd;

				WriteFile(hSerial, line_buf, line_len,
					  &written, NULL);
				WriteFile(hSerial, "\r", 1,
					  &written, NULL);
			}
			line_len = 0;
		} else if (ch >= ' ' && ch <= '~') {
			if (line_len < (int)sizeof(line_buf) - 1) {
				DWORD w;

				line_buf[line_len++] = ch;
				WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
					  &ch, 1, &w, NULL);
			}
		}
	}

shutdown:
	/* Shutdown */
	g_quit = 1;
	WaitForSingleObject(hThread, 2000);
	CloseHandle(hThread);

	restore_console();
	g_console_mode_saved = 0;
	at_close(sess);
	printf("\n");
	return 0;
}

void print_atconsole_help(FILE *out)
{
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN, "\natconsole");
	fprintf(out, " — Interactive AT command console\n\n");
	fprintf(out, "Usage: qfenix atconsole [options]\n\n");
	ux_fputs_color(out, UX_COLOR_BOLD, "Options:\n");
	fprintf(out, "  -S <serial>  Target modem by USB serial number\n");
	fprintf(out, "  -p <port>    Serial port (e.g. COM9)\n");
	fprintf(out, "  -d           Debug mode (show raw I/O)\n\n");
	fprintf(out, "Type AT commands interactively. Modem responses and URCs\n");
	fprintf(out, "are displayed in real-time. Type 'exit' to quit.\n");
}

#else

#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <poll.h>
#include <getopt.h>

/* Forward declarations */
void print_atconsole_help(FILE *out);

static struct termios g_orig_termios;
static int g_termios_saved;

static void restore_terminal(void)
{
	if (g_termios_saved)
		tcsetattr(STDIN_FILENO, TCSANOW, &g_orig_termios);
}

static int set_raw_mode(void)
{
	struct termios raw;

	if (tcgetattr(STDIN_FILENO, &g_orig_termios) < 0)
		return -1;

	g_termios_saved = 1;
	atexit(restore_terminal);

	raw = g_orig_termios;
	raw.c_lflag &= ~(ECHO | ICANON | ISIG | IEXTEN);
	raw.c_iflag &= ~(IXON | ICRNL | BRKINT | INPCK | ISTRIP);
	raw.c_oflag &= ~(OPOST);
	raw.c_cflag |= CS8;
	raw.c_cc[VMIN] = 0;
	raw.c_cc[VTIME] = 0;

	if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0)
		return -1;
	return 0;
}

int qdl_atconsole(int argc, char **argv)
{
	char port[256] = {0};
	const char *serial = NULL;
	int debug = 0;
	int opt;
	struct at_session *sess;
	char line_buf[1024];
	int line_len = 0;

	while ((opt = getopt(argc, argv, "S:p:d")) != -1) {
		switch (opt) {
		case 'S':
			serial = optarg;
			break;
		case 'p':
			snprintf(port, sizeof(port), "%s", optarg);
			break;
		case 'd':
			debug = 1;
			break;
		default:
			print_atconsole_help(stderr);
			return 1;
		}
	}

	if (!port[0]) {
		if (!at_detect_port(port, sizeof(port), serial)) {
			ux_err("No AT port detected. Use -p to specify manually.\n");
			return 1;
		}
		ux_info("Auto-detected AT port: %s\n", port);
	}

	/*
	 * When stdout is a pipe (GUI subprocess), disable buffering so
	 * output appears immediately instead of being delayed until exit.
	 */
	if (!isatty(STDOUT_FILENO))
		setvbuf(stdout, NULL, _IONBF, 0);

	sess = at_open(port, 10000);
	if (!sess) {
		ux_err("Failed to open %s: %s\n", port, strerror(errno));
		return 1;
	}
	sess->debug = debug;

	/*
	 * Raw mode disables echo and line buffering on a real terminal.
	 * When stdin is a pipe (e.g. GUI subprocess), skip it — pipes
	 * don't support termios and the poll() loop works fine without it.
	 */
	if (isatty(STDIN_FILENO) && set_raw_mode() < 0) {
		ux_err("Failed to set terminal raw mode\n");
		at_close(sess);
		return 1;
	}

	printf("Connected to %s (type 'exit' to quit)\r\n", port);

	for (;;) {
		struct pollfd pfds[2];
		int ret;

		pfds[0].fd = STDIN_FILENO;
		pfds[0].events = POLLIN;
		pfds[1].fd = sess->fd;
		pfds[1].events = POLLIN;

		ret = poll(pfds, 2, 100);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		/* Handle stdin input */
		if (pfds[0].revents & POLLIN) {
			char ch;
			ssize_t n = read(STDIN_FILENO, &ch, 1);

			if (n <= 0)
				break;

			if (ch == '\n' || ch == '\r') {
				/* Echo newline */
				write(STDOUT_FILENO, "\r\n", 2);

				line_buf[line_len] = '\0';

				if (strcmp(line_buf, "exit") == 0)
					break;

				if (line_len > 0) {
					/* Send command + CR to modem */
					write(sess->fd, line_buf, line_len);
					write(sess->fd, "\r", 1);
				}
				line_len = 0;
			} else if (ch == 0x7f || ch == 0x08) {
				/* Backspace */
				if (line_len > 0) {
					line_len--;
					write(STDOUT_FILENO, "\b \b", 3);
				}
			} else if (ch == 0x03) {
				/* Ctrl-C */
				break;
			} else {
				if (line_len < (int)sizeof(line_buf) - 1) {
					line_buf[line_len++] = ch;
					write(STDOUT_FILENO, &ch, 1);
				}
			}
		}

		/* Handle serial port data */
		if (pfds[1].revents & POLLIN) {
			char buf[512];
			ssize_t n = read(sess->fd, buf, sizeof(buf));

			if (n > 0) {
				/*
				 * Convert bare \n or \r to \r\n for
				 * proper terminal display.
				 */
				for (ssize_t i = 0; i < n; i++) {
					if (buf[i] == '\n') {
						write(STDOUT_FILENO, "\r\n", 2);
					} else if (buf[i] == '\r') {
						/* Skip \r — we emit \r\n on \n */
					} else {
						write(STDOUT_FILENO,
						      &buf[i], 1);
					}
				}
			}
		}

		/* Check for serial port errors */
		if (pfds[1].revents & (POLLERR | POLLHUP)) {
			printf("\r\nSerial port disconnected\r\n");
			break;
		}
	}

	restore_terminal();
	g_termios_saved = 0;
	at_close(sess);
	printf("\n");
	return 0;
}

void print_atconsole_help(FILE *out)
{
	ux_fputs_color(out, UX_COLOR_BOLD UX_COLOR_GREEN, "\natconsole");
	fprintf(out, " — Interactive AT command console\n\n");
	fprintf(out, "Usage: qfenix atconsole [options]\n\n");
	ux_fputs_color(out, UX_COLOR_BOLD, "Options:\n");
	fprintf(out, "  -S <serial>  Target modem by USB serial number\n");
	fprintf(out, "  -p <port>    Serial port path (e.g. /dev/ttyUSB2)\n");
	fprintf(out, "  -d           Debug mode (show raw I/O)\n\n");
	fprintf(out, "Type AT commands interactively. Modem responses and URCs\n");
	fprintf(out, "are displayed in real-time. Type 'exit' to quit.\n");
}

#endif /* _WIN32 */
