// SPDX-License-Identifier: BSD-3-Clause
/*
 * AT command serial I/O layer + SMS/USSD commands
 *
 * Ported from sms_tool by iamromulan, restructured for qfenix.
 * Uses poll()-based I/O instead of SIGALRM.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "atcmd.h"
#include "at_port.h"
#include "pdu.h"
#include "qdl.h"

#ifndef _WIN32
#include <poll.h>
#include <sys/file.h>
#include <termios.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

/* ── AT session management ── */

#ifndef _WIN32

struct at_session *at_open(const char *port, int timeout_ms)
{
	struct at_session *s;
	struct termios tio;
	int fd;

	fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		ux_err("Failed to open %s: %s\n", port, strerror(errno));
		return NULL;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		ux_err("Failed to lock %s: %s\n", port, strerror(errno));
		close(fd);
		return NULL;
	}

	memset(&tio, 0, sizeof(tio));
	cfmakeraw(&tio);
	cfsetspeed(&tio, B115200);
	tio.c_cflag |= CLOCAL | CREAD | CS8;
	tio.c_cflag &= ~(PARENB | CSTOPB | CRTSCTS);
	tio.c_cc[VMIN] = 1;
	tcsetattr(fd, TCSANOW, &tio);
	tcflush(fd, TCIOFLUSH);

	s = calloc(1, sizeof(*s));
	if (!s) {
		close(fd);
		return NULL;
	}
	s->fd = fd;
	snprintf(s->port, sizeof(s->port), "%s", port);
	s->timeout_ms = timeout_ms;
	return s;
}

void at_close(struct at_session *sess)
{
	if (!sess)
		return;
	if (sess->fd >= 0) {
		flock(sess->fd, LOCK_UN);
		close(sess->fd);
	}
	free(sess);
}

int at_read_line(struct at_session *sess, char *buf, size_t size)
{
	struct pollfd pfd = { .fd = sess->fd, .events = POLLIN };
	size_t pos = 0;
	int ret;

	while (pos < size - 1) {
		ret = poll(&pfd, 1, sess->timeout_ms);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ret == 0)
			break; /* timeout */

		char c;
		ssize_t n = read(sess->fd, &c, 1);

		if (n <= 0)
			break;
		buf[pos++] = c;
		if (c == '\n')
			break;
	}
	buf[pos] = '\0';
	return (int)pos;
}

int at_send_cmd(struct at_session *sess, const char *cmd,
		char *resp, size_t resp_size)
{
	char line[1024];
	size_t resp_pos = 0;
	int len;

	tcflush(sess->fd, TCIOFLUSH);

	/* Send command + CR */
	write(sess->fd, cmd, strlen(cmd));
	write(sess->fd, "\r", 1);

	if (resp)
		resp[0] = '\0';

	while ((len = at_read_line(sess, line, sizeof(line))) > 0) {
		if (sess->debug)
			ux_log("AT< %s", line);

		/* Skip empty lines and echo */
		if (line[0] == '\r' || line[0] == '\n')
			continue;

		/* Append to response buffer */
		if (resp && resp_pos + len < resp_size) {
			memcpy(resp + resp_pos, line, len);
			resp_pos += len;
			resp[resp_pos] = '\0';
		}

		/* Check for terminal responses */
		if (strncmp(line, "OK", 2) == 0)
			return 0;
		if (strncmp(line, "ERROR", 5) == 0 ||
		    strncmp(line, "+CMS ERROR", 10) == 0 ||
		    strncmp(line, "+CME ERROR", 10) == 0 ||
		    strncmp(line, "COMMAND NOT SUPPORT", 19) == 0)
			return -1;
	}

	return -1; /* timeout or read error */
}

#else
/* Windows compat for POSIX serial/sleep functions used in shared code */
#define TCIOFLUSH 2
#define usleep(us) Sleep((us) / 1000)

/*
 * tcflush() replacement for Windows — uses PurgeComm.
 * The fd field stores a Windows HANDLE cast to int.
 */
#define tcflush(fd, queue) \
	PurgeComm((HANDLE)(intptr_t)(fd), PURGE_RXCLEAR | PURGE_TXCLEAR)

/* Windows write() shim — wraps WriteFile for AT command I/O */
static inline ssize_t at_write(int fd, const void *buf, size_t len)
{
	DWORD written;

	if (!WriteFile((HANDLE)(intptr_t)fd, buf, (DWORD)len, &written, NULL))
		return -1;
	return (ssize_t)written;
}

/* Override write() calls in shared AT code to use at_write() */
#define write(fd, buf, len) at_write(fd, buf, len)

struct at_session *at_open(const char *port, int timeout_ms)
{
	struct at_session *s;
	HANDLE hSerial;
	DCB dcb = {0};
	COMMTIMEOUTS timeouts = {0};
	char portPath[280];

	snprintf(portPath, sizeof(portPath), "\\\\.\\%s", port);

	hSerial = CreateFileA(portPath, GENERIC_READ | GENERIC_WRITE,
			      0, NULL, OPEN_EXISTING, 0, NULL);
	if (hSerial == INVALID_HANDLE_VALUE) {
		ux_err("Failed to open %s (error %lu)\n",
		       port, GetLastError());
		return NULL;
	}

	dcb.DCBlength = sizeof(dcb);
	if (!GetCommState(hSerial, &dcb)) {
		ux_err("Failed to get COM state for %s\n", port);
		CloseHandle(hSerial);
		return NULL;
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
		ux_err("Failed to set COM state for %s\n", port);
		CloseHandle(hSerial);
		return NULL;
	}

	timeouts.ReadIntervalTimeout = 100;
	timeouts.ReadTotalTimeoutConstant = timeout_ms;
	timeouts.ReadTotalTimeoutMultiplier = 0;
	timeouts.WriteTotalTimeoutConstant = 3000;
	timeouts.WriteTotalTimeoutMultiplier = 0;

	if (!SetCommTimeouts(hSerial, &timeouts)) {
		ux_err("Failed to set timeouts for %s\n", port);
		CloseHandle(hSerial);
		return NULL;
	}

	PurgeComm(hSerial, PURGE_RXCLEAR | PURGE_TXCLEAR);

	s = calloc(1, sizeof(*s));
	if (!s) {
		CloseHandle(hSerial);
		return NULL;
	}
	s->fd = (int)(intptr_t)hSerial;
	snprintf(s->port, sizeof(s->port), "%s", port);
	s->timeout_ms = timeout_ms;
	return s;
}

void at_close(struct at_session *sess)
{
	if (!sess)
		return;
	if (sess->fd)
		CloseHandle((HANDLE)(intptr_t)sess->fd);
	free(sess);
}

int at_read_line(struct at_session *sess, char *buf, size_t size)
{
	HANDLE h = (HANDLE)(intptr_t)sess->fd;
	size_t pos = 0;
	DWORD n;
	char c;

	while (pos < size - 1) {
		if (!ReadFile(h, &c, 1, &n, NULL) || n == 0)
			break; /* timeout or error */
		buf[pos++] = c;
		if (c == '\n')
			break;
	}
	buf[pos] = '\0';
	return (int)pos;
}

int at_send_cmd(struct at_session *sess, const char *cmd,
		char *resp, size_t resp_size)
{
	HANDLE h = (HANDLE)(intptr_t)sess->fd;
	char line[1024];
	size_t resp_pos = 0;
	int len;
	DWORD written;

	PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);

	/* Send command + CR */
	WriteFile(h, cmd, (DWORD)strlen(cmd), &written, NULL);
	WriteFile(h, "\r", 1, &written, NULL);

	if (resp)
		resp[0] = '\0';

	while ((len = at_read_line(sess, line, sizeof(line))) > 0) {
		if (sess->debug)
			ux_log("AT< %s", line);

		/* Skip empty lines and echo */
		if (line[0] == '\r' || line[0] == '\n')
			continue;

		/* Append to response buffer */
		if (resp && resp_pos + len < resp_size) {
			memcpy(resp + resp_pos, line, len);
			resp_pos += len;
			resp[resp_pos] = '\0';
		}

		/* Check for terminal responses */
		if (strncmp(line, "OK", 2) == 0)
			return 0;
		if (strncmp(line, "ERROR", 5) == 0 ||
		    strncmp(line, "+CMS ERROR", 10) == 0 ||
		    strncmp(line, "+CME ERROR", 10) == 0 ||
		    strncmp(line, "COMMAND NOT SUPPORT", 19) == 0)
			return -1;
	}

	return -1; /* timeout or read error */
}

#endif /* _WIN32 */

/* ── Helpers ── */

static int char_to_hex(char c)
{
	if (isdigit(c))
		return c - '0';
	if (islower(c))
		return 10 + c - 'a';
	if (isupper(c))
		return 10 + c - 'A';
	return -1;
}

static void print_json_escape(char c1, char c2)
{
	if (c1 == 0x0) {
		if (c2 == '"')       printf("\\\"");
		else if (c2 == '\\') printf("\\\\");
		else if (c2 == '\b') printf("\\b");
		else if (c2 == '\n') printf("\\n");
		else if (c2 == '\f') printf("\\f");
		else if (c2 == '\r') printf("\\r");
		else if (c2 == '\t') printf("\\t");
		else if (c2 == '/')  printf("\\/");
		else if (c2 < ' ')   printf("\\u00%02x", (unsigned char)c2);
		else                  printf("%c", c2);
	} else {
		printf("\\u%02x%02x", (unsigned char)c1, (unsigned char)c2);
	}
}

/* ── SMS Send ── */

static int atcmd_sms_send(struct at_session *sess,
			   const char *phone, const char *message)
{
	unsigned char pdu[SMS_MAX_PDU_LENGTH];
	char pdustr[2 * SMS_MAX_PDU_LENGTH + 4];
	char cmdstr[128];
	char resp[1024];
	int pdu_len, pdu_len_except_smsc;
	int i;

	pdu_len = pdu_encode("", phone, message, pdu, sizeof(pdu));
	if (pdu_len < 0) {
		ux_err("Error encoding PDU for %s\n", phone);
		return -1;
	}

	pdu_len_except_smsc = pdu_len - 1 - pdu[0];
	snprintf(cmdstr, sizeof(cmdstr), "AT+CMGS=%d", pdu_len_except_smsc);

	for (i = 0; i < pdu_len; ++i)
		sprintf(pdustr + 2 * i, "%02X", pdu[i]);
	sprintf(pdustr + 2 * i, "%c", 0x1A); /* Ctrl-Z */

	/* Set PDU mode */
	if (at_send_cmd(sess, "AT+CMGF=0", resp, sizeof(resp)) < 0) {
		ux_err("Failed to set PDU mode\n");
		return -1;
	}

	/* Send CMGS command */
	tcflush(sess->fd, TCIOFLUSH);
	write(sess->fd, cmdstr, strlen(cmdstr));
	write(sess->fd, "\r", 1);

	/* Wait for ">" prompt */
	usleep(500000);

	/* Send PDU data + Ctrl-Z */
	write(sess->fd, pdustr, strlen(pdustr));
	write(sess->fd, "\r", 1);

	/* Read response */
	char line[256];
	int len;
	int old_timeout = sess->timeout_ms;

	sess->timeout_ms = 30000; /* 30s for SMS send */

	while ((len = at_read_line(sess, line, sizeof(line))) > 0) {
		if (strncmp(line, "+CMGS:", 6) == 0) {
			ux_info("SMS sent successfully: %s", line + 7);
			sess->timeout_ms = old_timeout;
			return 0;
		}
		if (strncmp(line, "+CMS ERROR:", 11) == 0) {
			ux_err("SMS not sent, code: %s", line + 11);
			sess->timeout_ms = old_timeout;
			return -1;
		}
		if (strncmp(line, "ERROR", 5) == 0) {
			ux_err("SMS not sent, command error\n");
			sess->timeout_ms = old_timeout;
			return -1;
		}
		if (strncmp(line, "OK", 2) == 0) {
			sess->timeout_ms = old_timeout;
			return 0;
		}
	}

	sess->timeout_ms = old_timeout;
	ux_err("No response from modem\n");
	return -1;
}

/* ── SMS Receive ── */

static int atcmd_sms_recv(struct at_session *sess, int json, int raw,
			   const char *storage, const char *datefmt)
{
	char resp[4096];
	char line[1024];
	int count = 0, len;
	unsigned char pdu[SMS_MAX_PDU_LENGTH];

	if (storage && strlen(storage) > 0) {
		char cmd[64];

		snprintf(cmd, sizeof(cmd), "AT+CPMS=\"%s\"", storage);
		at_send_cmd(sess, cmd, resp, sizeof(resp));
	}

	at_send_cmd(sess, "AT+CMGF=0", resp, sizeof(resp));

	/* Send list command */
	tcflush(sess->fd, TCIOFLUSH);
	write(sess->fd, "AT+CMGL=4\r", 10);

	if (json)
		printf("{\"msg\":[");

	while ((len = at_read_line(sess, line, sizeof(line))) > 0) {
		line[strcspn(line, "\r\n")] = '\0';

		if (strncmp(line, "OK", 2) == 0)
			break;

		if (strncmp(line, "+CMGL:", 6) == 0) {
			int idx = 0;

			if (sscanf(line, "+CMGL: %d,", &idx) != 1)
				continue;

			/* Read PDU line */
			len = at_read_line(sess, line, sizeof(line));
			if (len <= 0)
				break;
			line[strcspn(line, "\r\n")] = '\0';

			if (json) {
				if (count > 0)
					printf(",");
				printf("{\"index\":%d,", idx);
			} else {
				printf("MSG: %d\n", idx);
			}
			count++;

			if (raw) {
				if (json)
					printf("\"content\":\"%s\"}", line);
				else
					printf("%s\n", line);
				continue;
			}

			/* Hex to binary */
			int l = strlen(line);
			int i;

			for (i = 0; i < l; i += 2)
				pdu[i / 2] = 16 * char_to_hex(line[i]) +
					      char_to_hex(line[i + 1]);

			time_t sms_time;
			char phone_str[40];
			char sms_txt[161];
			int tp_dcs, ref_num, total_parts, part_num, skip;
			int sms_len;

			sms_len = pdu_decode(pdu, l / 2, &sms_time,
					     phone_str, sizeof(phone_str),
					     sms_txt, sizeof(sms_txt),
					     &tp_dcs, &ref_num, &total_parts,
					     &part_num, &skip);
			if (sms_len <= 0) {
				if (json)
					printf("\"error\":\"decode error\","
					       "\"sender\":\"\","
					       "\"timestamp\":\"\","
					       "\"content\":\"\"}");
				else
					fprintf(stderr, "Error decoding PDU %d\n",
						count - 1);
				continue;
			}

			if (json)
				printf("\"sender\":\"%s\",", phone_str);
			else
				printf("From: %s\n", phone_str);

			char time_str[64];

			strftime(time_str, sizeof(time_str),
				 datefmt ? datefmt : "%D %T",
				 gmtime(&sms_time));
			if (json)
				printf("\"timestamp\":\"%s\",", time_str);
			else
				printf("Date/Time: %s\n", time_str);

			if (total_parts > 0) {
				if (json)
					printf("\"reference\":%d,"
					       "\"part\":%d,"
					       "\"total\":%d,",
					       ref_num, part_num, total_parts);
				else
					printf("Reference: %d, Part %d of %d\n",
					       ref_num, part_num, total_parts);
			}

			if (json)
				printf("\"content\":\"");

			switch ((tp_dcs / 4) % 4) {
			case 0: {
				/* GSM 7-bit */
				int start = skip;

				if (skip > 0)
					start = (skip * 8 + 6) / 7;
				for (i = start; i < sms_len; i++) {
					if (json)
						print_json_escape(0, sms_txt[i]);
					else
						printf("%c", sms_txt[i]);
				}
				break;
			}
			case 2: {
				/* UCS-2 */
				for (i = skip; i < sms_len; i += 2) {
					if (json) {
						print_json_escape(sms_txt[i],
								  sms_txt[i + 1]);
					} else {
						int ucs2 = (0xFF & sms_txt[i + 1]) |
							   ((0xFF & sms_txt[i]) << 8);
						unsigned char utf8[5];
						int ulen = ucs2_to_utf8(ucs2, utf8);
						int j;

						for (j = 0; j < ulen; j++)
							printf("%c", utf8[j]);
					}
				}
				break;
			}
			default:
				break;
			}

			if (json)
				printf("\"}");
			else
				printf("\n\n");
		}
	}

	if (json)
		printf("]}\n");

	return 0;
}

/* ── SMS Delete ── */

static int atcmd_sms_delete(struct at_session *sess, const char *index_str)
{
	int start, end;
	char cmd[64], resp[256];

	if (!strcmp(index_str, "all")) {
		start = 0;
		end = 49;
	} else {
		start = atoi(index_str);
		end = start;
	}

	ux_info("Deleting messages %d to %d\n", start, end);
	for (int i = start; i <= end; i++) {
		snprintf(cmd, sizeof(cmd), "AT+CMGD=%d", i);
		if (at_send_cmd(sess, cmd, resp, sizeof(resp)) == 0)
			ux_info("Deleted message %d\n", i);
		else if (strstr(resp, "+CMS ERROR"))
			ux_warn("Error deleting message %d: %s\n", i, resp);
	}
	return 0;
}

/* ── SMS Status ── */

static int atcmd_sms_status(struct at_session *sess, const char *storage)
{
	char resp[512];

	if (storage && strlen(storage) > 0) {
		char cmd[64];

		snprintf(cmd, sizeof(cmd), "AT+CPMS=\"%s\"", storage);
		at_send_cmd(sess, cmd, resp, sizeof(resp));
	}

	if (at_send_cmd(sess, "AT+CPMS?", resp, sizeof(resp)) < 0) {
		ux_err("Failed to query SMS status\n");
		return -1;
	}

	char *p = strstr(resp, "+CPMS:");

	if (p) {
		char mem[9];
		int used, total;

		if (sscanf(p, "+CPMS: \"%2s\",%d,%d,", mem, &used, &total) == 3)
			printf("Storage type: %s, used: %d, total: %d\n",
			       mem, used, total);
	}
	return 0;
}

/* ── USSD ── */

enum sms_charset { SMS_CHARSET_7BIT = 0, SMS_CHARSET_8BIT = 1, SMS_CHARSET_UCS2 = 2 };

static int atcmd_ussd(struct at_session *sess, const char *code,
		      int raw_in, int raw_out, int dcs_override)
{
	unsigned char pdu_buf[SMS_MAX_PDU_LENGTH];
	char pdustr[2 * SMS_MAX_PDU_LENGTH + 4];
	char cmdstr[512];
	char line[1024];
	int len, old_timeout;

	if (raw_in) {
		snprintf(cmdstr, sizeof(cmdstr),
			 "AT+CUSD=1,\"%s\",15", code);
	} else {
		int pdu_len = pdu_encode_7bit(code, strlen(code),
					      pdu_buf, SMS_MAX_PDU_LENGTH);
		if (pdu_len > 0) {
			if (pdu_buf[pdu_len - 1] == 0)
				pdu_buf[pdu_len - 1] = 0x1d;
			for (int i = 0; i < pdu_len; ++i)
				sprintf(pdustr + 2 * i, "%02X", pdu_buf[i]);
			snprintf(cmdstr, sizeof(cmdstr),
				 "AT+CUSD=1,\"%s\",15", pdustr);
		} else {
			ux_err("Error encoding USSD: %s\n", code);
			return -1;
		}
	}

	if (sess->debug)
		ux_log("USSD> %s\n", cmdstr);

	tcflush(sess->fd, TCIOFLUSH);
	write(sess->fd, cmdstr, strlen(cmdstr));
	write(sess->fd, "\r", 1);

	old_timeout = sess->timeout_ms;
	sess->timeout_ms = 180000; /* 3 min for USSD */

	while ((len = at_read_line(sess, line, sizeof(line))) > 0) {
		line[strcspn(line, "\r\n")] = '\0';

		if (strncmp(line, "OK", 2) == 0)
			continue;
		if (strncmp(line, "+CME ERROR:", 11) == 0) {
			ux_err("USSD error: %s\n", line + 12);
			break;
		}
		if (strncmp(line, "+CUSD:", 6) == 0) {
			char tmp[8], ussd_buf[320];
			char ussd_txt[800];
			int tp_dcs_type = 0;
			int rc;

			if (sess->debug)
				ux_log("USSD< %s\n", line);

			rc = sscanf(line, "+CUSD:%7[^\"]\"%[^\"]\",%d",
				    tmp, ussd_buf, &tp_dcs_type);
			if (rc == 2 && raw_out)
				rc = 3;
			if (rc != 3) {
				ux_err("Unparsable CUSD response: %s\n", line);
				break;
			}

			if (raw_out) {
				printf("%s\n", ussd_buf);
				break;
			}

			int l = strlen(ussd_buf);

			for (int i = 0; i < l; i += 2)
				pdu_buf[i / 2] = 16 * char_to_hex(ussd_buf[i]) +
						 char_to_hex(ussd_buf[i + 1]);

			/* DCS detection */
			int upper = (tp_dcs_type & 0xf0) >> 4;
			int lower = tp_dcs_type & 0xf;
			int coding = -1;

			switch (upper) {
			case 0:
				coding = SMS_CHARSET_7BIT;
				break;
			case 1:
				if (lower == 0)
					coding = SMS_CHARSET_7BIT;
				if (lower == 1)
					coding = SMS_CHARSET_UCS2;
				break;
			case 2:
				if (lower <= 4)
					coding = SMS_CHARSET_7BIT;
				break;
			case 4:
			case 5:
			case 6:
			case 7:
			case 9:
				if (((tp_dcs_type & 0x0c) >> 2) < 3)
					coding = (tp_dcs_type & 0x0c) >> 2;
				break;
			case 15:
				if ((lower & 0x4) == 0)
					coding = SMS_CHARSET_7BIT;
				break;
			default:
				break;
			}

			/* Override with user-specified DCS */
			if (dcs_override == SMS_CHARSET_7BIT)
				coding = SMS_CHARSET_7BIT;
			else if (dcs_override == SMS_CHARSET_UCS2)
				coding = SMS_CHARSET_UCS2;

			switch (coding) {
			case SMS_CHARSET_7BIT: {
				l = pdu_decode_7bit(pdu_buf, l / 2,
						    ussd_txt, sizeof(ussd_txt));
				if (l > 0) {
					if (l < (int)sizeof(ussd_txt))
						ussd_txt[l] = 0;
					printf("%s\n", ussd_txt);
				} else {
					ux_err("Error decoding USSD\n");
				}
				break;
			}
			case SMS_CHARSET_UCS2: {
				int utf_pos = 0;

				for (int i = 0; i + 1 < l / 2; i += 2) {
					int ucs2 = (0xFF & pdu_buf[i + 1]) |
						   ((0xFF & pdu_buf[i]) << 8);

					utf_pos += ucs2_to_utf8(ucs2,
						(unsigned char *)&ussd_txt[utf_pos]);
				}
				if (utf_pos > 0) {
					if (utf_pos < (int)sizeof(ussd_txt))
						ussd_txt[utf_pos] = 0;
					printf("%s\n", ussd_txt);
				} else {
					ux_err("Error decoding USSD\n");
				}
				break;
			}
			default:
				ux_err("Unknown coding scheme: %d\n", tp_dcs_type);
				break;
			}
			break;
		}
	}

	sess->timeout_ms = old_timeout;
	return 0;
}

/* ── Raw AT command ── */

static int atcmd_raw(struct at_session *sess, const char *command)
{
	char line[1024];
	int len;

	tcflush(sess->fd, TCIOFLUSH);
	write(sess->fd, command, strlen(command));
	write(sess->fd, "\r", 1);

	while ((len = at_read_line(sess, line, sizeof(line))) > 0) {
		line[strcspn(line, "\r\n")] = '\0';

		if (line[0] == '\0')
			continue;

		if (strncmp(line, "OK", 2) == 0)
			return 0;
		if (strncmp(line, "ERROR", 5) == 0 ||
		    strncmp(line, "+CME ERROR", 10) == 0 ||
		    strncmp(line, "+CMS ERROR", 10) == 0 ||
		    strncmp(line, "COMMAND NOT SUPPORT", 19) == 0) {
			if (sess->debug)
				printf("%s\n", line);
			return -1;
		}
		printf("%s\n", line);
	}
	return -1;
}

/* ── Shared session helper ── */

static struct at_session *at_session_open(const char *serial,
					  const char *port,
					  int timeout, int debug)
{
	char port_buf[256];
	struct at_session *sess;

	if (!port) {
#ifdef __APPLE__
		if (!at_detect_port(port_buf, sizeof(port_buf), serial)) {
			ux_err("No AT port found. Use -p to specify manually.\n");
			return NULL;
		}
#else
		{
			int printed = 0;
			time_t start = time(NULL);

			while (!at_detect_port(port_buf, sizeof(port_buf), serial)) {
				int elapsed = (int)(time(NULL) - start);

				if (!printed)
					printed = 1;
				fprintf(stderr, "\rWaiting for AT port... "
					"(Ctrl+C to abort) [%ds]", elapsed);
				fflush(stderr);
				sleep(1);
			}
			if (printed)
				fprintf(stderr, "\n");
		}
#endif
		port = port_buf;
		ux_info("Using AT port: %s\n", port);
	}

	sess = at_open(port, timeout * 1000);
	if (!sess)
		return NULL;
	sess->debug = debug;
	return sess;
}

/* ── Help text ── */

void print_smssend_help(FILE *out)
{
	fprintf(out, "Usage: qfenix smssend [options] <phone> <message>\n\n");
	fprintf(out, "Send an SMS message via PDU mode.\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -S serial      Target by serial number (auto-detect port)\n");
	fprintf(out, "  -p port        Manual port path (/dev/ttyUSB2, COM9, etc.)\n");
	fprintf(out, "  -d             Debug mode\n");
	fprintf(out, "  -t seconds     Timeout (default 10s)\n");
}

void print_smsread_help(FILE *out)
{
	fprintf(out, "Usage: qfenix smsread [options]\n\n");
	fprintf(out, "Receive/list SMS messages from modem storage.\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -S serial      Target by serial number (auto-detect port)\n");
	fprintf(out, "  -p port        Manual port path (/dev/ttyUSB2, COM9, etc.)\n");
	fprintf(out, "  -d             Debug mode\n");
	fprintf(out, "  -t seconds     Timeout (default 10s)\n");
	fprintf(out, "  -j             JSON output\n");
	fprintf(out, "  -r             Raw PDU output (no decoding)\n");
	fprintf(out, "  -s storage     SMS storage type (e.g. SM, ME)\n");
	fprintf(out, "  -f format      Date format (default: %%D %%T)\n");
}

void print_smsrm_help(FILE *out)
{
	fprintf(out, "Usage: qfenix smsrm [options] <index|all>\n\n");
	fprintf(out, "Delete SMS message(s) by index or all.\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -S serial      Target by serial number (auto-detect port)\n");
	fprintf(out, "  -p port        Manual port path (/dev/ttyUSB2, COM9, etc.)\n");
	fprintf(out, "  -d             Debug mode\n");
	fprintf(out, "  -t seconds     Timeout (default 10s)\n");
}

void print_smsstatus_help(FILE *out)
{
	fprintf(out, "Usage: qfenix smsstatus [options]\n\n");
	fprintf(out, "Query SMS storage status (used/total slots).\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -S serial      Target by serial number (auto-detect port)\n");
	fprintf(out, "  -p port        Manual port path (/dev/ttyUSB2, COM9, etc.)\n");
	fprintf(out, "  -d             Debug mode\n");
	fprintf(out, "  -t seconds     Timeout (default 10s)\n");
	fprintf(out, "  -s storage     SMS storage type (e.g. SM, ME)\n");
}

void print_ussd_help(FILE *out)
{
	fprintf(out, "Usage: qfenix ussd [options] <code>\n\n");
	fprintf(out, "Send a USSD/USSI query (e.g. *#06#, *100#).\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -S serial      Target by serial number (auto-detect port)\n");
	fprintf(out, "  -p port        Manual port path (/dev/ttyUSB2, COM9, etc.)\n");
	fprintf(out, "  -d             Debug mode\n");
	fprintf(out, "  -t seconds     Timeout (default 10s)\n");
	fprintf(out, "  -c coding      USSD coding: 0=7bit, 2=UCS2 (default: auto)\n");
	fprintf(out, "  -r             Raw output (no PDU decoding)\n");
	fprintf(out, "  -R             Raw input (skip PDU encoding)\n");
}

void print_atcmd_help(FILE *out)
{
	fprintf(out, "Usage: qfenix atcmd [options] <AT command>\n\n");
	fprintf(out, "Send a raw AT command to the modem.\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -S serial      Target by serial number (auto-detect port)\n");
	fprintf(out, "  -p port        Manual port path (/dev/ttyUSB2, COM9, etc.)\n");
	fprintf(out, "  -d             Debug mode\n");
	fprintf(out, "  -t seconds     Timeout (default 10s)\n");
}

/* ── Top-level subcommand dispatchers ── */

int qdl_smssend(int argc, char **argv)
{
	const char *serial = NULL;
	const char *port = NULL;
	int debug = 0, timeout = 10, ch, ret;
	struct at_session *sess;

	optind = 1;
	while ((ch = getopt(argc, argv, "S:p:dt:h")) != -1) {
		switch (ch) {
		case 'S': serial = optarg; break;
		case 'p': port = optarg; break;
		case 'd': debug = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 'h':
			print_smssend_help(stdout);
			return 0;
		default:
			print_smssend_help(stderr);
			return 1;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 2) {
		ux_err("Usage: qfenix smssend <phone> <message>\n");
		return 1;
	}

	sess = at_session_open(serial, port, timeout, debug);
	if (!sess)
		return 1;

	ret = atcmd_sms_send(sess, argv[0], argv[1]) ? 1 : 0;
	at_close(sess);
	return ret;
}

int qdl_smsread(int argc, char **argv)
{
	const char *serial = NULL;
	const char *port = NULL;
	const char *storage = "";
	const char *datefmt = "%D %T";
	int debug = 0, timeout = 10, json = 0, raw = 0, ch, ret;
	struct at_session *sess;

	optind = 1;
	while ((ch = getopt(argc, argv, "S:p:dt:jrs:f:h")) != -1) {
		switch (ch) {
		case 'S': serial = optarg; break;
		case 'p': port = optarg; break;
		case 'd': debug = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 'j': json = 1; break;
		case 'r': raw = 1; break;
		case 's': storage = optarg; break;
		case 'f': datefmt = optarg; break;
		case 'h':
			print_smsread_help(stdout);
			return 0;
		default:
			print_smsread_help(stderr);
			return 1;
		}
	}

	sess = at_session_open(serial, port, timeout, debug);
	if (!sess)
		return 1;

	ret = atcmd_sms_recv(sess, json, raw, storage, datefmt) ? 1 : 0;
	at_close(sess);
	return ret;
}

int qdl_smsrm(int argc, char **argv)
{
	const char *serial = NULL;
	const char *port = NULL;
	int debug = 0, timeout = 10, ch, ret;
	struct at_session *sess;

	optind = 1;
	while ((ch = getopt(argc, argv, "S:p:dt:h")) != -1) {
		switch (ch) {
		case 'S': serial = optarg; break;
		case 'p': port = optarg; break;
		case 'd': debug = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 'h':
			print_smsrm_help(stdout);
			return 0;
		default:
			print_smsrm_help(stderr);
			return 1;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		ux_err("Usage: qfenix smsrm <index|all>\n");
		return 1;
	}

	sess = at_session_open(serial, port, timeout, debug);
	if (!sess)
		return 1;

	ret = atcmd_sms_delete(sess, argv[0]) ? 1 : 0;
	at_close(sess);
	return ret;
}

int qdl_smsstatus(int argc, char **argv)
{
	const char *serial = NULL;
	const char *port = NULL;
	const char *storage = "";
	int debug = 0, timeout = 10, ch, ret;
	struct at_session *sess;

	optind = 1;
	while ((ch = getopt(argc, argv, "S:p:dt:s:h")) != -1) {
		switch (ch) {
		case 'S': serial = optarg; break;
		case 'p': port = optarg; break;
		case 'd': debug = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 's': storage = optarg; break;
		case 'h':
			print_smsstatus_help(stdout);
			return 0;
		default:
			print_smsstatus_help(stderr);
			return 1;
		}
	}

	sess = at_session_open(serial, port, timeout, debug);
	if (!sess)
		return 1;

	ret = atcmd_sms_status(sess, storage) ? 1 : 0;
	at_close(sess);
	return ret;
}

int qdl_ussd(int argc, char **argv)
{
	const char *serial = NULL;
	const char *port = NULL;
	int debug = 0, timeout = 10, ch, ret;
	int raw_out = 0, raw_in = 0, dcs = -1;
	struct at_session *sess;

	optind = 1;
	while ((ch = getopt(argc, argv, "S:p:dt:c:rRh")) != -1) {
		switch (ch) {
		case 'S': serial = optarg; break;
		case 'p': port = optarg; break;
		case 'd': debug = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 'c': dcs = atoi(optarg); break;
		case 'r': raw_out = 1; break;
		case 'R': raw_in = 1; break;
		case 'h':
			print_ussd_help(stdout);
			return 0;
		default:
			print_ussd_help(stderr);
			return 1;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		ux_err("Usage: qfenix ussd <code>\n");
		return 1;
	}

	sess = at_session_open(serial, port, timeout, debug);
	if (!sess)
		return 1;

	ret = atcmd_ussd(sess, argv[0], raw_in, raw_out, dcs) ? 1 : 0;
	at_close(sess);
	return ret;
}

int qdl_atcmd(int argc, char **argv)
{
	const char *serial = NULL;
	const char *port = NULL;
	int debug = 0, timeout = 10, ch, ret;
	struct at_session *sess;

	optind = 1;
	while ((ch = getopt(argc, argv, "S:p:dt:h")) != -1) {
		switch (ch) {
		case 'S': serial = optarg; break;
		case 'p': port = optarg; break;
		case 'd': debug = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 'h':
			print_atcmd_help(stdout);
			return 0;
		default:
			print_atcmd_help(stderr);
			return 1;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		print_atcmd_help(stderr);
		return 1;
	}

	sess = at_session_open(serial, port, timeout, debug);
	if (!sess)
		return 1;

	/* Join all remaining args into one AT command string */
	char raw_cmd[1024] = {0};
	int off = 0;

	for (int i = 0; i < argc && off < (int)sizeof(raw_cmd) - 2; i++) {
		if (i > 0)
			raw_cmd[off++] = ' ';
		off += snprintf(raw_cmd + off, sizeof(raw_cmd) - off,
				"%s", argv[i]);
	}

	ret = atcmd_raw(sess, raw_cmd) ? 1 : 0;
	at_close(sess);
	return ret;
}
