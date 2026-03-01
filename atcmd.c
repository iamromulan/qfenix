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
#define tcflush(fd, queue) (void)(fd)
#define usleep(us) Sleep((us) / 1000)

/* Windows implementation stubs — uses CreateFile/DCB */

struct at_session *at_open(const char *port, int timeout_ms)
{
	(void)port;
	(void)timeout_ms;
	ux_err("AT commands not yet supported on Windows\n");
	return NULL;
}

void at_close(struct at_session *sess)
{
	free(sess);
}

int at_read_line(struct at_session *sess, char *buf, size_t size)
{
	(void)sess;
	(void)buf;
	(void)size;
	return -1;
}

int at_send_cmd(struct at_session *sess, const char *cmd,
		char *resp, size_t resp_size)
{
	(void)sess;
	(void)cmd;
	(void)resp;
	(void)resp_size;
	return -1;
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

/* ── Help text ── */

void print_atcmd_help(FILE *out)
{
	fprintf(out, "Usage: qfenix atcmd [options] <subcommand> [args]\n\n");
	fprintf(out, "Subcommands:\n");
	fprintf(out, "  send <phone> <message>     Send an SMS message\n");
	fprintf(out, "  recv [-j] [-r] [-s S] [-f F]  Receive/list SMS messages\n");
	fprintf(out, "  delete <index|all>         Delete SMS message(s)\n");
	fprintf(out, "  status [-s storage]        Query SMS storage status\n");
	fprintf(out, "  ussd [-c coding] [-R] <code>  Send USSD query\n");
	fprintf(out, "  <AT command>               Send raw AT command\n\n");
	fprintf(out, "Options:\n");
	fprintf(out, "  -S serial      Target by serial number (auto-detect port)\n");
	fprintf(out, "  -p port        Manual port path (/dev/ttyUSB2, COM9, etc.)\n");
	fprintf(out, "  -d             Debug mode\n");
	fprintf(out, "  -t seconds     Timeout (default 10s, 180s for USSD)\n");
	fprintf(out, "  -j             JSON output (for recv)\n");
	fprintf(out, "  -r             Raw output (for recv/ussd)\n");
	fprintf(out, "  -R             Raw input (for ussd — skip PDU encoding)\n");
	fprintf(out, "  -s storage     SMS storage type (for recv/status)\n");
	fprintf(out, "  -f format      Date format (for recv, default: %%D %%T)\n");
	fprintf(out, "  -c coding      USSD coding: 0=7bit, 2=UCS2 (default: auto)\n");
}

/* ── Main dispatcher ── */

int qdl_atcmd(int argc, char **argv)
{
	const char *serial = NULL;
	const char *port = NULL;
	const char *storage = "";
	const char *datefmt = "%D %T";
	int debug = 0;
	int timeout = 10;
	int json = 0;
	int raw_out = 0;
	int raw_in = 0;
	int dcs = -1;
	int ch;
	struct at_session *sess;
	char port_buf[256];
	int ret = 0;

	optind = 1;
	while ((ch = getopt(argc, argv, "S:p:dt:jrRs:f:c:h")) != -1) {
		switch (ch) {
		case 'S': serial = optarg; break;
		case 'p': port = optarg; break;
		case 'd': debug = 1; break;
		case 't': timeout = atoi(optarg); break;
		case 'j': json = 1; break;
		case 'r': raw_out = 1; break;
		case 'R': raw_in = 1; break;
		case 's': storage = optarg; break;
		case 'f': datefmt = optarg; break;
		case 'c': dcs = atoi(optarg); break;
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

	/* Determine port */
	if (!port) {
		if (!at_detect_port(port_buf, sizeof(port_buf), serial)) {
			ux_err("No AT port found. Use -p to specify manually.\n");
			return 1;
		}
		port = port_buf;
		ux_info("Using AT port: %s\n", port);
	}

	sess = at_open(port, timeout * 1000);
	if (!sess)
		return 1;
	sess->debug = debug;

	if (!strcmp(argv[0], "send")) {
		if (argc < 3) {
			ux_err("Usage: atcmd send <phone> <message>\n");
			ret = 1;
		} else {
			ret = atcmd_sms_send(sess, argv[1], argv[2]) ? 1 : 0;
		}
	} else if (!strcmp(argv[0], "recv")) {
		ret = atcmd_sms_recv(sess, json, raw_out, storage, datefmt) ? 1 : 0;
	} else if (!strcmp(argv[0], "delete")) {
		if (argc < 2) {
			ux_err("Usage: atcmd delete <index|all>\n");
			ret = 1;
		} else {
			ret = atcmd_sms_delete(sess, argv[1]) ? 1 : 0;
		}
	} else if (!strcmp(argv[0], "status")) {
		ret = atcmd_sms_status(sess, storage) ? 1 : 0;
	} else if (!strcmp(argv[0], "ussd")) {
		if (argc < 2) {
			ux_err("Usage: atcmd ussd <code>\n");
			ret = 1;
		} else {
			ret = atcmd_ussd(sess, argv[1], raw_in, raw_out, dcs) ? 1 : 0;
		}
	} else {
		/* Raw AT command — join all remaining args */
		char raw_cmd[1024] = {0};
		int off = 0;

		for (int i = 0; i < argc && off < (int)sizeof(raw_cmd) - 2; i++) {
			if (i > 0)
				raw_cmd[off++] = ' ';
			off += snprintf(raw_cmd + off, sizeof(raw_cmd) - off,
					"%s", argv[i]);
		}
		ret = atcmd_raw(sess, raw_cmd) ? 1 : 0;
	}

	at_close(sess);
	return ret;
}
