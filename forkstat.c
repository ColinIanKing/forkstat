/*
 * Copyright (C) 2014 Canonical Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Written by Colin Ian King <colin.king@canonical.com>
 *
 * Some of this code originally derived from eventstat and powerstat
 * also by the same author.
 *
 */
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <libgen.h>

#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>

#define APP_NAME		"forkstat"
#define MAX_PIDS		(32769)	/* Hash Max PIDs */

#define NULL_PID		(-1)

#define OPT_CMD_LONG		(0x00000001)
#define OPT_CMD_SHORT		(0x00000002)
#define OPT_CMD_DIRNAME_STRIP	(0x00000004)

/* /proc info cache */
typedef struct proc_info {
	pid_t	pid;		/* Process ID */
	char	*cmdline;	/* /proc/pid/cmdline text */
	struct timeval start;	/* time when process started */
	struct proc_info *next;	/* next proc info in hashed linked list */
} proc_info_t;

static bool stop_recv;				/* sighandler stop flag */
static proc_info_t *proc_info[MAX_PIDS];	/* Proc hash table */
static unsigned int opt_flags = OPT_CMD_LONG;	/* Default option */
static int row = 0;				/* tty row number */

/* Default void no process info struct */
static proc_info_t no_info = {
	NULL_PID,
	"<unknown>",
	{ 0, },
	NULL,
};

/*
 *  tty_height()
 *      try and find height of tty
 */
static int tty_height(void)
{
#ifdef TIOCGWINSZ
	int fd = 0;
	struct winsize ws;

	/* if tty and we can get a sane width, return it */
	if (isatty(fd) &&
	    (ioctl(fd, TIOCGWINSZ, &ws) != -1) &&
	    (0 < ws.ws_row) &&
	    (ws.ws_row == (size_t)ws.ws_row))
		return ws.ws_row;
#endif
	return 25;	/* else standard tty 80x25 */
}

void print_heading(void)
{
	printf("Time     Event  PID  Info  Duration Command\n");
}

/*
 *  row_increment()
 *	bump row increment and re-print heading if required
 */
static void row_increment(void)
{
	int tty_rows = tty_height();

	row++;
	if ((tty_rows > 2) && (row >= tty_rows)) {
		print_heading();
		row = 2;
	}
}

/*
 *  timeval_to_double()
 *      convert timeval to seconds as a double
 */
static inline double timeval_to_double(const struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  proc_info_hash()
 * 	hash on PID
 */
static inline int proc_info_hash(const pid_t pid)
{
	return pid % MAX_PIDS;
}

/*
 *  proc_comm()
 *	get process name from comm field
 */
static char *proc_comm(const pid_t pid)
{
	char buffer[4096];
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%d/comm", pid);
	if ((fd = open(buffer, O_RDONLY)) < 0) {
		return NULL;
	}
	if ((ret = read(fd, buffer, sizeof(buffer) - 1)) <= 0) {
		close(fd);
		return NULL;
	}
	buffer[ret - 1] = '\0';
	return strdup(buffer);
}

/*
 *  proc_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *proc_cmdline(const pid_t pid)
{
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%d/cmdline", pid);
	if ((fd = open(buffer, O_RDONLY)) < 0) {
		return proc_comm(pid);
	}

	if ((ret = read(fd, buffer, sizeof(buffer) - 1)) <= 0) {
		close(fd);
		return proc_comm(pid);
	}
	close(fd);
	buffer[ret] = '\0';

	/*
	 *  OPT_CMD_LONG option we get the full cmdline args
	 */
	if (opt_flags & OPT_CMD_LONG) {
		for (ptr = buffer; ptr < buffer + ret - 1; ptr++) {
			if (*ptr == '\0')
				*ptr = ' ';
		}
		*ptr = '\0';
	}
	/*
	 *  OPT_CMD_SHORT option we discard anything after a space
	 */
	if (opt_flags & OPT_CMD_SHORT) {
		for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
			if (*ptr == ' ')
				*ptr = '\0';
		}
	}

	if (opt_flags & OPT_CMD_DIRNAME_STRIP)
		return strdup(basename(buffer));

	return strdup(buffer);
}

/*
 *  proc_info_get()
 *	get proc info on a given pid
 */
static proc_info_t *proc_info_get(const pid_t pid)
{
	int i = proc_info_hash(pid);
	proc_info_t *info = proc_info[i];

	while (info) {
		if (proc_info[i]->pid == pid)
			return info;
		info = info->next;
	}
	return &no_info;
}

/*
 *  proc_info_free()
 *	free cached process info and remove from hash table
 */
static void proc_info_free(const pid_t pid)
{
	int i = proc_info_hash(pid);
	proc_info_t *info = proc_info[i];

	while (info) {
		if (info->pid == pid) {
			info->pid = NULL_PID;
			free(info->cmdline);
			info->cmdline = NULL;
			return;
		}
		info = info->next;
	}
}

/*
 *   proc_info_unload()
 *	free all hashed proc info entries
 */
static void proc_info_unload(void)
{
	int i;

	for (i = 0; i < MAX_PIDS; i++) {
		proc_info_t *info = proc_info[i];

		while (info) {
			proc_info_t *next = info->next;
			free(info->cmdline);
			free(info);
			info = next;
		}
	}
}

/*
 *  proc_info_update()
 *	uopdate process name, for example, if exec has occurred
 */
static proc_info_t const *proc_info_update(const pid_t pid)
{
	proc_info_t *info = proc_info_get(pid);
	char *newcmd;

	if (info == &no_info)
		return &no_info;
	if ((newcmd = proc_cmdline(pid)) == NULL)
		return &no_info;

	free(info->cmdline);
	info->cmdline = newcmd;

	return info;
}

/*
 *   proc_info_add()
 *	add processes info of a given pid to the hash table
 */
static proc_info_t *proc_info_add(const pid_t pid, struct timeval *tv)
{
	int i = proc_info_hash(pid);
	proc_info_t *info;
	char *cmdline;

	if ((cmdline = proc_cmdline(pid)) == NULL) {
		free(cmdline);
		return NULL;
	}

	/* Re-use any info on the list if it's free */
	info = proc_info[i];
	while (info) {
		if (info->pid == NULL_PID)
			break;
		info = info->next;
	}

	if (info == NULL) {
		if ((info = calloc(1, sizeof(proc_info_t))) == NULL) {
			fprintf(stderr, "Cannot allocate all proc info\n");
			free(cmdline);
			return NULL;
		}
		info->next = proc_info[i];
		proc_info[i] = info;
	}
	info->cmdline = cmdline;
	info->pid = pid;

	if (tv)
		info->start = *tv;
	else {
		info->start.tv_sec = 0;
		info->start.tv_usec = 0;
	}

	return info;
}

/*
 *  proc_thread_info_add()
 *	Add a processes' thread into proc cache
 */
static void proc_thread_info_add(pid_t pid)
{
	DIR *dir;
	struct dirent *dirent;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%i/task", pid);

	if ((dir = opendir(path)) == NULL)
		return;

	while ((dirent = readdir(dir))) {
		if (isdigit(dirent->d_name[0])) {
			pid_t tpid = atoi(dirent->d_name);
			if (tpid != pid)
				(void)proc_info_add(tpid, NULL);
		}
	}

	(void)closedir(dir);
}

/*
 *  proc_info_load()
 *	load up all current processes info into hash table
 */
static int proc_info_load(void)
{
	DIR *dir;
	struct dirent *dirent;

	if ((dir = opendir("/proc")) == NULL)
		return -1;

	while ((dirent = readdir(dir))) {
		if (isdigit(dirent->d_name[0])) {
			pid_t pid = atoi(dirent->d_name);
			(void)proc_info_add(pid, NULL);
			proc_thread_info_add(pid);
		}
	}

	(void)closedir(dir);
	return 0;
}

/*
 *  handle_sigint()
 *	catch SIGINT and flag a stop
 */
static void handle_sigint(int dummy)
{
	(void)dummy;
	stop_recv = true;
}

/*
 *  netlink_connect()
 *	connect to netlink socket
 */
static int netlink_connect(void)
{
	int sock;
	struct sockaddr_nl addr;

	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)) < 0) {
		if (errno == EPROTONOSUPPORT)
			return -EPROTONOSUPPORT;
		fprintf(stderr, "Socket failed: %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.nl_pid = getpid();
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = CN_IDX_PROC;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Bind failed: %s\n", strerror(errno));
		(void)close(sock);
		return -1;
	}

	return sock;
}

/*
 *  netlink_listen()
 *	proc connector listen
 */
static int netlink_listen(const int sock)
{
	struct iovec iov[3];
	struct nlmsghdr nlmsghdr;
	struct cn_msg cn_msg;
	enum proc_cn_mcast_op op;

	memset(&nlmsghdr, 0, sizeof(nlmsghdr));
	nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
	nlmsghdr.nlmsg_pid = getpid();
	nlmsghdr.nlmsg_type = NLMSG_DONE;
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = sizeof(nlmsghdr);

	memset(&cn_msg, 0, sizeof(cn_msg));
	cn_msg.id.idx = CN_IDX_PROC;
	cn_msg.id.val = CN_VAL_PROC;
	cn_msg.len = sizeof(enum proc_cn_mcast_op);
	iov[1].iov_base = &cn_msg;
	iov[1].iov_len = sizeof(cn_msg);

	op = PROC_CN_MCAST_LISTEN;
	iov[2].iov_base = &op;
	iov[2].iov_len = sizeof(op);

	return writev(sock, iov, 3);
}

/*
 *   monitor()
 *	monitor system activity and power consumption
 */
static int monitor(const int sock)
{
	ssize_t len;
	struct nlmsghdr *nlmsghdr;

	print_heading();

	while (!stop_recv) {
		fd_set readfds;
		int ret;
		char __attribute__ ((aligned(NLMSG_ALIGNTO)))buf[4096];

		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		ret = select(sock+1, &readfds, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno == EINTR)
				break;
			fprintf(stderr,"select: %s\n", strerror(errno));
			return -1;
		}

		/* Time out, so measure some more samples */
		if (ret == 0) {
			continue;
		}

		if ((len = recv(sock, buf, sizeof(buf), 0)) == 0) {
			return 0;
		}
		if (len == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				fprintf(stderr,"recv: %s\n", strerror(errno));
				return -1;
			}
		}

		for (nlmsghdr = (struct nlmsghdr *)buf;
			NLMSG_OK (nlmsghdr, len);
			nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {

			struct cn_msg *cn_msg;
			struct proc_event *proc_ev;
			struct tm tm;
			struct timeval tv;
			time_t now;
			char when[10];
			char duration[32];
			proc_info_t const *info1, *info2;

			if ((nlmsghdr->nlmsg_type == NLMSG_ERROR) ||
			    (nlmsghdr->nlmsg_type == NLMSG_NOOP))
				continue;

			cn_msg = NLMSG_DATA(nlmsghdr);

			if ((cn_msg->id.idx != CN_IDX_PROC) ||
			    (cn_msg->id.val != CN_VAL_PROC))
				continue;

			proc_ev = (struct proc_event *)cn_msg->data;

			(void)time(&now);
			(void)localtime_r(&now, &tm);

			snprintf(when, sizeof(when), "%2.2d:%2.2d:%2.2d",
				tm.tm_hour, tm.tm_min, tm.tm_sec);

			switch (proc_ev->what) {
			case PROC_EVENT_FORK:
				gettimeofday(&tv, NULL);
				info1 = proc_info_get(proc_ev->event_data.fork.parent_pid);
				info2 = proc_info_add(proc_ev->event_data.fork.child_pid, &tv);
				if (info1 != NULL && info2 != NULL) {
					row_increment();
					printf("%s fork %5d parent %8s %s\n",
						when,
						proc_ev->event_data.fork.parent_pid,
						"", info1->cmdline);
					row_increment();
					printf("%s fork %5d child  %8s %s\n",
						when,
						proc_ev->event_data.fork.child_pid,
						"", info2->cmdline);
				}
				break;
			case PROC_EVENT_EXEC:
				info1 = proc_info_update(proc_ev->event_data.exec.process_pid);
				row_increment();
				printf("%s exec %5d        %8s %s\n",
					when,
				proc_ev->event_data.exec.process_pid,
					"", info1->cmdline);
				break;
			case PROC_EVENT_EXIT:
				info1 = proc_info_get(proc_ev->event_data.exec.process_pid);
				if (info1->start.tv_sec) {
					double d1, d2;

					gettimeofday(&tv, NULL);
					d1 = timeval_to_double(&info1->start);
					d2 = timeval_to_double(&tv);
					snprintf(duration, sizeof(duration), "%8.3f", d2 - d1);
				} else {
					snprintf(duration, sizeof(duration), "unknown");
				}
				row_increment();
				printf("%s exit %5d  %5d %8s %s\n",
					when,
					proc_ev->event_data.exit.process_pid,
					proc_ev->event_data.exit.exit_code,
					duration, info1->cmdline);

				if (proc_ev->event_data.exit.process_pid ==
					   proc_ev->event_data.exit.process_tgid)
					proc_info_free(proc_ev->event_data.exit.process_pid);
				break;
			default:
				break;
			}
		}
	}
	return 0;
}

/*
 *  show_help()
 *	simple help
 */
void show_help(char *const argv[])
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("usage: %s [-d|-h|-s]\n", argv[0]);
	printf("-d\tstrip off directory path from process name.\n");
	printf("-h\tshow this help.\n");
	printf("-s\tshow short process name.\n");
}

int main(int argc, char * const argv[])
{
	int sock = -1, ret = EXIT_FAILURE;

	signal(SIGINT, &handle_sigint);
	siginterrupt(SIGINT, 1);

	for (;;) {
		int c = getopt(argc, argv, "dhs");
		if (c == -1)
			break;
		switch (c) {
		case 'd':
			opt_flags |= OPT_CMD_DIRNAME_STRIP;
			break;
		case 'h':
			show_help(argv);
			exit(EXIT_SUCCESS);
		case 's':
			opt_flags &= ~OPT_CMD_LONG;
			opt_flags |= OPT_CMD_SHORT;
			break;
		default:
			show_help(argv);
			exit(EXIT_FAILURE);
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "Need to run with root access.\n");
		goto abort_sock;
	}

	if (proc_info_load() < 0) {
		fprintf(stderr, "Cannot load process cache. Is /proc mounted?\n");
		goto abort_sock;
	}

	sock = netlink_connect();
	if (sock == -EPROTONOSUPPORT) {
		fprintf(stderr, "Cannot show process activity with this kernel, netlink required.\n");
		goto abort_sock;
	}
	if (netlink_listen(sock) < 0) {
		fprintf(stderr, "Netlink listen failed: %s\n", strerror(errno));
		goto abort_sock;
	}

	if (monitor(sock) == 0)
		ret = EXIT_SUCCESS;

	close(sock);
abort_sock:
	proc_info_unload();

	exit(ret);
}
