// SPDX-License-Identifier: BSD-3-Clause
#include <stdarg.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ioctl.h>
#endif
#include <sys/time.h>
#include <unistd.h>

#include "qdl.h"

#define UX_PROGRESS_REFRESH_RATE	10
#define UX_PROGRESS_SIZE_MAX		80

#define HASHES "################################################################################"
#define DASHES "--------------------------------------------------------------------------------"

static const char * const progress_hashes = HASHES;
static const char * const progress_dashes = DASHES;

static unsigned int ux_width;
static unsigned int ux_cur_line_length;

static bool ux_color_stdout;
static bool ux_color_stderr;

/*
 * Levels of output:
 *
 * error: used to signal errors to the user (red)
 * warn:  used for warnings (yellow)
 * info:  used to inform the user about progress (mint green)
 * logs:  log prints from the device
 * debug: protocol logs
 *
 * When qdl_log_file is set, ALL levels (including log/debug) are
 * written to the file regardless of qdl_debug, giving a full
 * debug-level log without cluttering the terminal.
 */

/* Clear ux_cur_line_length characters of the progress bar from the screen */
static void ux_clear_line(void)
{
	if (!ux_cur_line_length)
		return;

	printf("%*s\r", ux_cur_line_length, "");
	fflush(stdout);
	ux_cur_line_length = 0;
}

#ifdef _WIN32

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

void ux_init(void)
{
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	HANDLE hOut, hErr;
	DWORD mode;
	char *env;
	int columns;

	hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	hErr = GetStdHandle(STD_ERROR_HANDLE);

	if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
		columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		ux_width = MIN(columns, UX_PROGRESS_SIZE_MAX);
	}

	/* Allow COLUMNS env var to override (e.g. GUI subprocess with piped stdout) */
	env = getenv("COLUMNS");
	if (env) {
		int cols = atoi(env);

		if (cols > 0)
			ux_width = MIN((unsigned int)cols, UX_PROGRESS_SIZE_MAX);
	}

	if (getenv("NO_COLOR"))
		return;

	/* Enable ANSI escape processing on stdout */
	if (GetConsoleMode(hOut, &mode)) {
		if (SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
			ux_color_stdout = true;
	}

	/* Enable ANSI escape processing on stderr */
	if (GetConsoleMode(hErr, &mode)) {
		if (SetConsoleMode(hErr, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
			ux_color_stderr = true;
	}

	/* FORCE_COLOR overrides console mode check (e.g. GUI subprocess) */
	if (getenv("FORCE_COLOR")) {
		ux_color_stdout = true;
		ux_color_stderr = true;
	}
}

#else

void ux_init(void)
{
	struct winsize w;
	char *env;
	int ret;

	ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	if (!ret)
		ux_width = MIN(w.ws_col, UX_PROGRESS_SIZE_MAX);

	/* Allow COLUMNS env var to override (e.g. GUI subprocess with piped stdout) */
	env = getenv("COLUMNS");
	if (env) {
		int cols = atoi(env);

		if (cols > 0)
			ux_width = MIN((unsigned int)cols, UX_PROGRESS_SIZE_MAX);
	}

	if (getenv("NO_COLOR"))
		return;

	ux_color_stdout = isatty(STDOUT_FILENO);
	ux_color_stderr = isatty(STDERR_FILENO);

	/* FORCE_COLOR overrides isatty (e.g. GUI subprocess with piped stdout) */
	if (getenv("FORCE_COLOR")) {
		ux_color_stdout = true;
		ux_color_stderr = true;
	}
}

#endif

void ux_err(const char *fmt, ...)
{
	va_list ap, ap_log;

	ux_clear_line();

	va_start(ap, fmt);
	if (qdl_log_file)
		va_copy(ap_log, ap);

	if (ux_color_stderr)
		fputs(UX_COLOR_RED, stderr);
	vfprintf(stderr, fmt, ap);
	if (ux_color_stderr)
		fputs(UX_COLOR_RESET, stderr);
	fflush(stderr);
	va_end(ap);

	if (qdl_log_file) {
		fputs("[ERROR] ", qdl_log_file);
		vfprintf(qdl_log_file, fmt, ap_log);
		fflush(qdl_log_file);
		va_end(ap_log);
	}
}

void ux_warn(const char *fmt, ...)
{
	va_list ap, ap_log;

	ux_clear_line();

	va_start(ap, fmt);
	if (qdl_log_file)
		va_copy(ap_log, ap);

	if (ux_color_stderr)
		fputs(UX_COLOR_YELLOW, stderr);
	vfprintf(stderr, fmt, ap);
	if (ux_color_stderr)
		fputs(UX_COLOR_RESET, stderr);
	fflush(stderr);
	va_end(ap);

	if (qdl_log_file) {
		fputs("[WARN]  ", qdl_log_file);
		vfprintf(qdl_log_file, fmt, ap_log);
		fflush(qdl_log_file);
		va_end(ap_log);
	}
}

void ux_info(const char *fmt, ...)
{
	va_list ap, ap_log;

	ux_clear_line();

	va_start(ap, fmt);
	if (qdl_log_file)
		va_copy(ap_log, ap);

	if (ux_color_stdout)
		fputs(UX_COLOR_GREEN, stdout);
	vprintf(fmt, ap);
	if (ux_color_stdout)
		fputs(UX_COLOR_RESET, stdout);
	fflush(stdout);
	va_end(ap);

	if (qdl_log_file) {
		fputs("[INFO]  ", qdl_log_file);
		vfprintf(qdl_log_file, fmt, ap_log);
		fflush(qdl_log_file);
		va_end(ap_log);
	}
}

void ux_log(const char *fmt, ...)
{
	va_list ap, ap_log;

	va_start(ap, fmt);
	if (qdl_log_file)
		va_copy(ap_log, ap);

	if (qdl_debug) {
		ux_clear_line();
		vprintf(fmt, ap);
		fflush(stdout);
	}
	va_end(ap);

	if (qdl_log_file) {
		fputs("[LOG]   ", qdl_log_file);
		vfprintf(qdl_log_file, fmt, ap_log);
		fflush(qdl_log_file);
		va_end(ap_log);
	}
}

void ux_debug(const char *fmt, ...)
{
	va_list ap, ap_log;

	va_start(ap, fmt);
	if (qdl_log_file)
		va_copy(ap_log, ap);

	if (qdl_debug) {
		ux_clear_line();
		vprintf(fmt, ap);
		fflush(stdout);
	}
	va_end(ap);

	if (qdl_log_file) {
		fputs("[DEBUG] ", qdl_log_file);
		vfprintf(qdl_log_file, fmt, ap_log);
		fflush(qdl_log_file);
		va_end(ap_log);
	}
}

void ux_fputs_color(FILE *f, const char *color, const char *text)
{
	bool use_color = false;

	if (f == stdout)
		use_color = ux_color_stdout;
	else if (f == stderr)
		use_color = ux_color_stderr;

	if (use_color)
		fputs(color, f);
	fputs(text, f);
	if (use_color)
		fputs(UX_COLOR_RESET, f);
}

void ux_progress(const char *fmt, unsigned int value, unsigned int max, ...)
{
	static struct timeval last_progress_update;
	unsigned long elapsed_us;
	unsigned int bar_length;
	unsigned int bars;
	unsigned int dashes;
	struct timeval now;
	char task_name[32];
	float percent;
	va_list ap;

	/* Don't print progress is window is too narrow, or if stdout is redirected */
	if (ux_width < 30)
		return;

	/* Avoid updating the console more than UX_PROGRESS_REFRESH_RATE per second */
	if (last_progress_update.tv_sec) {
		gettimeofday(&now, NULL);
		elapsed_us = (now.tv_sec - last_progress_update.tv_sec) * 1000000 +
			     (now.tv_usec - last_progress_update.tv_usec);

		if (elapsed_us < (1000000 / UX_PROGRESS_REFRESH_RATE))
			return;
	}

	if (value > max)
		value = max;

	va_start(ap, max);
	vsnprintf(task_name, sizeof(task_name), fmt, ap);
	va_end(ap);

	bar_length = ux_width - (20 + 4 + 6);
	percent = (float)value / max;
	bars = percent * bar_length;
	dashes = bar_length - bars;

	printf("%-20.20s [%.*s%.*s] %1.2f%%%n\r", task_name,
	       bars, progress_hashes,
	       dashes, progress_dashes,
	       percent * 100,
	       &ux_cur_line_length);
	fflush(stdout);

	gettimeofday(&last_progress_update, NULL);
}
