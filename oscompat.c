// SPDX-License-Identifier: BSD-3-Clause
#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include "oscompat.h"

extern const char *__progname;

void timeradd(const struct timeval *a, const struct timeval *b, struct timeval *result)
{
	result->tv_sec = a->tv_sec + b->tv_sec;
	result->tv_usec = a->tv_usec + b->tv_usec;
	if (result->tv_usec >= 1000000) {
		result->tv_sec += 1;
		result->tv_usec -= 1000000;
	}
}

void err(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", __progname);
	if (fmt) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", strerror(errno));
	va_end(ap);
	exit(eval);
}

void errx(int eval, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", __progname);
	if (fmt)
		vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(eval);
}

void warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", __progname);
	if (fmt) {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", strerror(errno));
	va_end(ap);
}

void warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", __progname);
	if (fmt)
		vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

char *strcasestr(const char *haystack, const char *needle)
{
	size_t needle_len;

	if (!needle || !haystack)
		return NULL;

	needle_len = strlen(needle);
	if (needle_len == 0)
		return (char *)haystack;

	while (*haystack) {
		if (strncasecmp(haystack, needle, needle_len) == 0)
			return (char *)haystack;
		haystack++;
	}

	return NULL;
}

#endif // _WIN32
