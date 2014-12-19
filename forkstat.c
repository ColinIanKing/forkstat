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
#include <inttypes.h>
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

#include <linux/version.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>

#define APP_NAME		"forkstat"
#define MAX_PIDS		(32769)	/* Hash Max PIDs */

#define NULL_PID		(-1)

#define OPT_CMD_LONG		(0x00000001)
#define OPT_CMD_SHORT		(0x00000002)
#define OPT_CMD_DIRNAME_STRIP	(0x00000004)
#define OPT_STATS		(0x00000008)
#define OPT_QUIET		(0x00000010)

#define OPT_EV_FORK		(0x00000100)
#define OPT_EV_EXEC		(0x00000200)
#define OPT_EV_EXIT		(0x00000400)
#define OPT_EV_CORE		(0x00000800)
#define OPT_EV_COMM		(0x00001000)
#define OPT_EV_MASK		(0x00001f00)
#define OPT_EV_ALL		(OPT_EV_MASK)

/* /proc info cache */
typedef struct proc_info {
	pid_t	pid;		/* Process ID */
	char	*cmdline;	/* /proc/pid/cmdline text */
	bool	kernel_thread;	/* true if a kernel thread */
	struct timeval start;	/* time when process started */
	struct proc_info *next;	/* next proc info in hashed linked list */
} proc_info_t;

/* For kernel task checking */
typedef struct {
	char *task;		/* Name of kernel task */
	size_t len;		/* Length */
} kernel_task_info;

typedef enum {
	STAT_FORK = 0,
	STAT_EXEC,
	STAT_EXIT,
	STAT_CORE,
	STAT_COMM,
	STAT_LAST
} event_t;

typedef struct proc_stats {
	char *name;		/* Process name */
	uint64_t count[STAT_LAST]; /* Tally count */
	uint64_t total;		/* Tally count total of all counts */
	struct proc_stats *next;/* Next one in list */
} proc_stats_t;

typedef struct {
	const char *event;	/* Event name */
	const char *label;	/* Human readable label */
	const int flag;		/* option flag */
	const event_t stat;	/* stat enum */
} ev_map_t;

/* Mapping of event names to option flags and event_t types */
static const ev_map_t ev_map[] = {
	{ "fork", "Fork", OPT_EV_FORK, STAT_FORK },
	{ "exec", "Exec", OPT_EV_EXEC, STAT_EXEC },
	{ "exit", "Exit", OPT_EV_EXIT, STAT_EXIT },
	{ "core", "Coredump", OPT_EV_CORE, STAT_CORE },
	{ "comm", "Comm", OPT_EV_COMM, STAT_COMM },
	{ "all",  ""	, OPT_EV_ALL,   0 },
	{ NULL  ,  NULL,   0,           0 }
};

#define KERN_TASK_INFO(str)	{ str, sizeof(str) - 1 }

static bool stop_recv;				/* sighandler stop flag */
static bool sane_procs;				/* true if not inside a container */
static proc_info_t *proc_info[MAX_PIDS];	/* Proc hash table */
static proc_stats_t *proc_stats[MAX_PIDS];	/* Proc stats hash table */
static unsigned int opt_flags = OPT_CMD_LONG;	/* Default option */
static int row = 0;				/* tty row number */
static long int opt_duration = -1;		/* duration, < 0 means run forever */

/* Default void no process info struct */
static proc_info_t no_info = {
	.pid = NULL_PID,
	.cmdline = "<unknown>",
	.kernel_thread = false,
	.start = { 0, 0 },
	.next = NULL,
};

static proc_info_t *proc_info_get(pid_t pid);

/*
 *  sane_proc_pid_info()
 *	detect if proc info mapping from /proc/timer_stats
 *	maps to proc pids OK. If we are in a container or
 *	we can't tell, return false.
 */
static bool sane_proc_pid_info(void)
{
	FILE *fp;
	static const char pattern[] = "container=";
	const char *ptr = pattern;
	bool ret = true;

	fp = fopen("/proc/1/environ", "r");
	if (!fp)
		return false;

	while (!feof(fp)) {
		int ch = getc(fp);

		if (*ptr == ch) {
			ptr++;
			/* Match? So we're inside a container */
			if (*ptr == '\0') {
				ret = false;
				break;
			}
		} else {
			/* No match, skip to end of var and restart scan */
			do {
				ch = getc(fp);
			} while ((ch != EOF) && (ch != '\0'));
			ptr = pattern;
		}
	}

	(void)fclose(fp);

	return ret;
}

/*
 *  pid_a_kernel_thread
 *	is a process a kernel thread?
 */
static bool pid_a_kernel_thread(const char *task, const pid_t id)
{
	if (sane_procs) {
		return getpgid(id) == 0;
	} else {
		/* In side a container, make a guess at kernel threads */
		int i;
		pid_t pgid = getpgid(id);

		/* This fails for kernel threads inside a container */
		if (pgid >= 0)
			return pgid == 0;

		/*
		 * This is not exactly accurate, but if we can't look up
		 * a process then try and infer something from the comm field.
		 * Until we have better kernel support to map /proc/timer_stats
		 * pids to containerised pids this is the best we can do.
		 */
		static kernel_task_info kernel_tasks[] = {
			KERN_TASK_INFO("swapper/"),
			KERN_TASK_INFO("kworker/"),
			KERN_TASK_INFO("ksoftirqd/"),
			KERN_TASK_INFO("watchdog/"),
			KERN_TASK_INFO("migration/"),
			KERN_TASK_INFO("irq/"),
			KERN_TASK_INFO("mmcqd/"),
			KERN_TASK_INFO("jbd2/"),
			KERN_TASK_INFO("kthreadd"),
			KERN_TASK_INFO("kthrotld"),
			KERN_TASK_INFO("kswapd"),
			KERN_TASK_INFO("ecryptfs-kthrea"),
			KERN_TASK_INFO("kauditd"),
			KERN_TASK_INFO("kblockd"),
			KERN_TASK_INFO("kcryptd"),
			KERN_TASK_INFO("kdevtmpfs"),
			KERN_TASK_INFO("khelper"),
			KERN_TASK_INFO("khubd"),
			KERN_TASK_INFO("khugepaged"),
			KERN_TASK_INFO("khungtaskd"),
			KERN_TASK_INFO("flush-"),
			KERN_TASK_INFO("bdi-default-"),
			{ NULL, 0 }
		};

		for (i = 0; kernel_tasks[i].task != NULL; i++) {
			if (strncmp(task, kernel_tasks[i].task, kernel_tasks[i].len) == 0)
				return true;
		}
	}
	return false;
}

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

/*
 *  print_heading()
 *	print heading to output
 */
static void print_heading(void)
{
	if (opt_flags & OPT_QUIET)
		return;

	printf("Time     Event  PID  Info  Duration Process\n");
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
 *  proc_name_hash()
 *	hash on proc name, from Aho, Sethi, Ullman, Compiling Techniques.
 */
static inline int proc_name_hash(const char *str)
{
	unsigned long h = 0;

	while (*str) {
		unsigned long g;
		h = (h << 4) + (*str);
		if (0 != (g = h & 0xf0000000)) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
		str++;
	}

	return h % MAX_PIDS;
}

static void proc_stats_account(const pid_t pid, const event_t event)
{
	int h;
	char *name;
	proc_stats_t *stats;
	proc_info_t *info;

	if (!(opt_flags & OPT_STATS))
		return;

	info = proc_info_get(pid);
	if (info == &no_info)
		return;

	name = info->cmdline;
	h = proc_name_hash(name);
	stats = proc_stats[h];

	while (stats) {
		if (!strcmp(stats->name, name)) {
			stats->count[event]++;
			stats->total++;
			return;
		}
	}
	stats = calloc(1, sizeof(*stats));
	if (stats == NULL)
		return;		/* silently ignore */

	stats->name = strdup(name);
	if (stats->name == NULL) {
		free(stats);
		return;
	}
	stats->count[event]++;
	stats->total++;
	stats->next = proc_stats[h];
	proc_stats[h] = stats;
}

/*
 *  stats_cmp()
 *	compare stats total, used for sorting list
 */
int stats_cmp(const void *v1, const void *v2)
{
	proc_stats_t **s1 = (proc_stats_t **)v1;
	proc_stats_t **s2 = (proc_stats_t **)v2;

	return (*s2)->total - (*s1)->total;
}

/*
 *  proc_stats_report()
 *	report event statistics
 */
void proc_stats_report(void)
{
	int i;
	int n = 0;
	proc_stats_t *stats, **sorted;

	if (!(opt_flags & OPT_STATS))
		return;

	for (i = 0; i < MAX_PIDS; i++)
		for (stats = proc_stats[i]; stats; stats = stats->next)
			n++;

	if (!n) {
		printf("\nNo statistics gathered.\n");
		return;
	}

	printf("\n");
	for (i = 0; i < STAT_LAST; i++)
		printf("%8s ", ev_map[i].label);
	printf("   Total Process\n");

	sorted = calloc(n, sizeof(proc_stats_t *));
	if (sorted == NULL) {
		fprintf(stderr, "Cannot sort statistics, out of memory.\n");
		return;
	}

	for (n = 0, i = 0; i < MAX_PIDS; i++)
		for (stats = proc_stats[i]; stats; stats = stats->next)
			sorted[n++] = stats;

	qsort(sorted, n, sizeof(proc_stats_t *), stats_cmp);
	for (i = 0; i < n; i++) {
		int j;
		stats = sorted[i];

		for (j = 0; j < STAT_LAST; j++)
			printf("%8" PRIu64 " ", stats->count[j]);
		printf("%8" PRIu64 " %s\n", stats->total, stats->name);
	}
	free(sorted);
}

/*
 *  proc_stats_free()
 *	free stats list
 */
void proc_stats_free(void)
{
	int i;

	for (i = 0; i < MAX_PIDS; i++) {
		proc_stats_t *stats = proc_stats[i];

		while (stats) {
			proc_stats_t *next = stats->next;

			free(stats->name);
			free(stats);

			stats = next;
		}
	}
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
		(void)close(fd);
		return NULL;
	}
	(void)close(fd);
	buffer[ret - 1] = '\0';		/* remove trailing '\n' */
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

	memset(buffer, 0, sizeof(buffer));
	if ((ret = read(fd, buffer, sizeof(buffer) - 1)) <= 0) {
		(void)close(fd);
		return proc_comm(pid);
	}
	(void)close(fd);
	buffer[ret] = '\0';	/* Keeps coverity scan happy */

	/*
	 *  OPT_CMD_LONG option we get the full cmdline args
	 */
	if (opt_flags & OPT_CMD_LONG) {
		for (ptr = buffer; ptr < buffer + ret; ptr++) {
			if (*ptr == '\0') {
				if (*(ptr + 1) == '\0')
					break;
				*ptr = ' ';
			}
		}
	}
	/*
	 *  OPT_CMD_SHORT option we discard anything after a space
	 */
	if (opt_flags & OPT_CMD_SHORT) {
		for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
			if (*ptr == ' ') {
				*ptr = '\0';
				break;
			}
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
	info->kernel_thread = pid_a_kernel_thread(cmdline, pid);

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
static void proc_thread_info_add(const pid_t pid)
{
	DIR *dir;
	struct dirent *dirent;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%i/task", pid);

	if ((dir = opendir(path)) == NULL)
		return;

	while ((dirent = readdir(dir))) {
		if (isdigit(dirent->d_name[0])) {
			pid_t tpid;

			errno = 0;
			tpid = (pid_t)strtol(dirent->d_name, NULL, 10);
			if ((!errno) && (tpid != pid))
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
			pid_t pid;

			errno = 0;
			pid = (pid_t)strtol(dirent->d_name, NULL, 10);
			(void)proc_info_add(pid, NULL);
			if (!errno)
				proc_thread_info_add(pid);
		}
	}

	(void)closedir(dir);
	return 0;
}

/*
 *  handle_sigistop()
 *	catch signal and flag a stop
 */
static void handle_sigstop(int dummy)
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
		char __attribute__ ((aligned(NLMSG_ALIGNTO)))buf[4096];

		if ((len = recv(sock, buf, sizeof(buf), 0)) == 0) {
			return 0;
		}
		if (len == -1) {
			switch (errno) {
			case EINTR:
				return 0;
			case ENOBUFS: {
				time_t now;
				struct tm tm;

				(void)localtime_r(&now, &tm);
				printf("%2.2d:%2.2d:%2.2d recv ----- "
					"nobufs %8.8s (%s)\n",
					tm.tm_hour, tm.tm_min, tm.tm_sec, "",
					strerror(errno));
				break;
			}
			default:
				fprintf(stderr,"recv: %d %s\n", errno, strerror(errno));
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
			char *comm;
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
			case PROC_EVENT_FORK:
				proc_stats_account(proc_ev->event_data.fork.parent_pid, STAT_FORK);
				gettimeofday(&tv, NULL);
				info1 = proc_info_get(proc_ev->event_data.fork.parent_pid);
				info2 = proc_info_add(proc_ev->event_data.fork.child_pid, &tv);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_FORK)) {
					if (info1 != NULL && info2 != NULL) {
						row_increment();
						printf("%s fork %5d parent %8s %s%s%s\n",
							when,
							proc_ev->event_data.fork.parent_pid,
							"",
							info1->kernel_thread ? "[" : "",
							info1->cmdline,
							info1->kernel_thread ? "]" : "");
						row_increment();
						printf("%s fork %5d child  %8s %s%s%s\n",
							when,
							proc_ev->event_data.fork.child_pid,
							"",
							info1->kernel_thread ? "[" : "",
							info2->cmdline,
							info1->kernel_thread ? "]" : "");
					}
				}
				break;
			case PROC_EVENT_EXEC:
				proc_stats_account(proc_ev->event_data.exec.process_pid, STAT_EXEC);
				info1 = proc_info_update(proc_ev->event_data.exec.process_pid);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_EXEC)) {
					row_increment();
					printf("%s exec %5d        %8s %s%s%s\n",
						when,
						proc_ev->event_data.exec.process_pid,
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				break;
			case PROC_EVENT_EXIT:
				proc_stats_account(proc_ev->event_data.exit.process_pid, STAT_EXIT);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_EXIT)) {
					info1 = proc_info_get(proc_ev->event_data.exit.process_pid);
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
					printf("%s exit %5d  %5d %8s %s%s%s\n",
						when,
						proc_ev->event_data.exit.process_pid,
						proc_ev->event_data.exit.exit_code,
						duration,
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				proc_info_free(proc_ev->event_data.exit.process_pid);
				break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
			case PROC_EVENT_COREDUMP:
				proc_stats_account(proc_ev->event_data.coredump.process_pid, STAT_CORE);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_CORE)) {
					info1 = proc_info_get(proc_ev->event_data.coredump.process_pid);
					row_increment();
					printf("%s core %5d        %8s %s%s%s\n",
						when,
						proc_ev->event_data.exit.process_pid,
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
			case PROC_EVENT_COMM:
				proc_stats_account(proc_ev->event_data.comm.process_pid, STAT_COMM);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_COMM)) {
					info1 = proc_info_get(proc_ev->event_data.comm.process_pid);
					comm = proc_comm(proc_ev->event_data.comm.process_pid);
					if (comm == NULL)
						break;
					row_increment();

					printf("%s comm %5d        %8s %s%s%s -> %s\n",
						when,
						proc_ev->event_data.exit.process_pid,
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "",
						comm);
					free(comm);
				}
				break;
#endif
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
	printf("usage: %s [-d|-D|-e|-h|-s|-S|-q]\n", argv[0]);
	printf("-d\tstrip off directory path from process name.\n");
	printf("-D\tspecify run duration in seconds.\n");
	printf("-e\tselect which events to monitor.\n");
	printf("-h\tshow this help.\n");
	printf("-s\tshow short process name.\n");
	printf("-S\tshow event statistics at end of the run.\n");
	printf("-q\trun quietly and enable -S option.\n");
}

static int parse_ev(const char *arg)
{
	char *str, *token, *saveptr = NULL;

	for (str = (char*)arg; (token = strtok_r(str, ",", &saveptr)) != NULL; str = NULL) {
		int i;
		bool found = false;

		for (i = 0; ev_map[i].event; i++) {
			if (!strcmp(token, ev_map[i].event)) {
				opt_flags |= ev_map[i].flag;
				found = true;
			}
		}
		if (!found) {
			fprintf(stderr, "Unknown event '%s'.\n", token);
			return -1;
		}
	}
	return 0;
}

int main(int argc, char * const argv[])
{
	int sock = -1, ret = EXIT_FAILURE;

	signal(SIGINT, &handle_sigstop);
	signal(SIGALRM, &handle_sigstop);
	siginterrupt(SIGINT, 1);

	for (;;) {
		int c = getopt(argc, argv, "dD:e:hsSq");
		if (c == -1)
			break;
		switch (c) {
		case 'd':
			opt_flags |= OPT_CMD_DIRNAME_STRIP;
			break;
		case 'D':
			opt_duration = strtol(optarg, NULL, 10);
			if (opt_duration <= 0) {
				fprintf(stderr, "Illegal duration.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'e':
			if (parse_ev(optarg) < 0)
				exit(EXIT_FAILURE);
			break;
		case 'h':
			show_help(argv);
			exit(EXIT_SUCCESS);
		case 's':
			opt_flags &= ~OPT_CMD_LONG;
			opt_flags |= OPT_CMD_SHORT;
			break;
		case 'S':
			opt_flags |= OPT_STATS;
			break;
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		default:
			show_help(argv);
			exit(EXIT_FAILURE);
		}
	}

	if ((opt_flags & OPT_EV_MASK) == 0)
		opt_flags |= (OPT_EV_FORK | OPT_EV_EXEC | OPT_EV_EXIT);

	if (geteuid() != 0) {
		fprintf(stderr, "Need to run with root access.\n");
		goto abort_sock;
	}

	sane_procs = sane_proc_pid_info();

	if (proc_info_load() < 0) {
		fprintf(stderr, "Cannot load process cache. Is /proc mounted?\n");
		goto abort_sock;
	}

	sock = netlink_connect();
	if (sock == -EPROTONOSUPPORT) {
		fprintf(stderr, "Cannot show process activity with this kernel, netlink required.\n");
		goto abort_sock;
	}
	/* Handle other failures */
	if (sock < 0)
		goto abort_sock;

	if (netlink_listen(sock) < 0) {
		fprintf(stderr, "Netlink listen failed: %s\n", strerror(errno));
		goto close_abort;
	}

	if (opt_duration > 0)
		alarm(opt_duration);

	if (monitor(sock) == 0) {
		ret = EXIT_SUCCESS;
		proc_stats_report();
	}

close_abort:
	(void)close(sock);
abort_sock:
	proc_info_unload();
	proc_stats_free();

	exit(ret);
}
