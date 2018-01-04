/*
 * Copyright (C) 2014-2017 Canonical Ltd.
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
#include <sched.h>
#include <pwd.h>

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <linux/version.h>
#include <linux/connector.h>
#include <linux/netlink.h>
#include <linux/cn_proc.h>

#define APP_NAME		"forkstat"
#define MAX_PIDS		(32769)		/* Hash Max PIDs */

#define NULL_PID		(pid_t)(-1)
#define NULL_UID		(uid_t)(-1)
#define NULL_GID		(gid_t)(-1)
#define NULL_TTY		(dev_t)(-1)

#define OPT_CMD_LONG		(0x00000001)	/* Long command line info */
#define OPT_CMD_SHORT		(0x00000002)	/* Short command line info */
#define OPT_CMD_DIRNAME_STRIP	(0x00000004)	/* Strip dirpath from command */
#define OPT_STATS		(0x00000008)	/* Show stats at end of run */
#define OPT_QUIET		(0x00000010)	/* Run quietly */
#define OPT_REALTIME		(0x00000020)	/* Run with Real Time scheduling */
#define OPT_EXTRA		(0x00000040)	/* Show extra stats */

#define OPT_EV_FORK		(0x00000100)	/* Fork event */
#define OPT_EV_EXEC		(0x00000200)	/* Exec event */
#define OPT_EV_EXIT		(0x00000400)	/* Exit event */
#define OPT_EV_CORE		(0x00000800)	/* Coredump event */
#define OPT_EV_COMM		(0x00001000)	/* Comm proc info event */
#define OPT_EV_CLNE		(0x00002000)	/* Clone event */
#define OPT_EV_PTRC		(0x00004000)	/* Ptrace event */
#define OPT_EV_UID		(0x00008000)	/* UID event */
#define OPT_EV_SID		(0x00010000)	/* SID event */
#define OPT_EV_MASK		(0x0001ff00)	/* Event mask */
#define OPT_EV_ALL		(OPT_EV_MASK)	/* All events */

#define	GOT_TGID		(0x01)
#define GOT_PPID		(0x02)
#define GOT_ALL			(GOT_TGID | GOT_PPID)

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE KERNEL_VERSION(2,0,0)
#endif

/* /proc info cache */
typedef struct proc_info {
	struct proc_info *next;	/* next proc info in hashed linked list */
	pid_t	pid;		/* Process ID */
	uid_t	uid;		/* User ID */
	gid_t	gid;		/* GUID */
	dev_t	tty;		/* TTY dev */
	char	*cmdline;	/* /proc/pid/cmdline text */
	bool	kernel_thread;	/* true if a kernel thread */
	struct timeval start;	/* time when process started */
} proc_info_t;

/* For kernel task checking */
typedef struct {
	char *task;		/* Name of kernel task */
	size_t len;		/* Length */
} kernel_task_info;

typedef enum {
	STAT_FORK = 0,		/* Fork */
	STAT_EXEC,		/* Exec */
	STAT_EXIT,		/* Exit */
	STAT_CORE,		/* Core dump */
	STAT_COMM,		/* Proc comm field change */
	STAT_CLNE,		/* Clone */
	STAT_PTRC,		/* Ptrace */
	STAT_UID,		/* UID change */
	STAT_SID,		/* SID change */
	STAT_LAST		/* Always last sentinal */
} event_t;

typedef struct proc_stats {
	struct proc_stats *next;/* Next one in list */
	char *name;		/* Process name */
	uint64_t count[STAT_LAST]; /* Tally count */
	uint64_t total;		/* Tally count total of all counts */
} proc_stats_t;

typedef struct {
	const char *event;	/* Event name */
	const char *label;	/* Human readable label */
	const int flag;		/* option flag */
	const event_t stat;	/* stat enum */
} ev_map_t;

/* Mapping of event names to option flags and event_t types */
static const ev_map_t ev_map[] = {
	{ "fork", "Fork", 	OPT_EV_FORK,	STAT_FORK },
	{ "exec", "Exec", 	OPT_EV_EXEC,	STAT_EXEC },
	{ "exit", "Exit", 	OPT_EV_EXIT,	STAT_EXIT },
	{ "core", "Coredump",	OPT_EV_CORE,	STAT_CORE },
	{ "comm", "Comm", 	OPT_EV_COMM,	STAT_COMM },
	{ "clone","Clone",	OPT_EV_CLNE,	STAT_CLNE },
	{ "ptrce","Ptrace",	OPT_EV_PTRC,	STAT_PTRC },
	{ "uid",  "Uid",	OPT_EV_UID,	STAT_UID  },
	{ "sid",  "Sid",	OPT_EV_SID,	STAT_SID  },
	{ "all",  "",		OPT_EV_ALL,	0 },
	{ NULL,	  NULL, 	0,		0 }
};

#define KERN_TASK_INFO(str)	{ str, sizeof(str) - 1 }

static volatile bool stop_recv;			/* sighandler stop flag */
static bool sane_procs;				/* true if not inside a container */
static proc_info_t *proc_info[MAX_PIDS];	/* Proc hash table */
static proc_stats_t *proc_stats[MAX_PIDS];	/* Proc stats hash table */
static unsigned int opt_flags = OPT_CMD_LONG;	/* Default option */
static int row = 0;				/* tty row number */
static long int opt_duration = -1;		/* duration, < 0 means run forever */

/* Default void no process info struct */
static proc_info_t no_info = {
	.pid = NULL_PID,
	.uid = NULL_UID,
	.cmdline = "<unknown>",
	.kernel_thread = false,
	.start = { 0, 0 },
	.next = NULL,
};

/*
 *  Attempt to catch a range of signals so
 *  we can clean
 */
static const int signals[] = {
	/* POSIX.1-1990 */
#ifdef SIGHUP
	SIGHUP,
#endif
#ifdef SIGINT
	SIGINT,
#endif
#ifdef SIGQUIT
	SIGQUIT,
#endif
#ifdef SIGFPE
	SIGFPE,
#endif
#ifdef SIGTERM
	SIGTERM,
#endif
#ifdef SIGUSR1
	SIGUSR1,
#endif
#ifdef SIGUSR2
	SIGUSR2,
	/* POSIX.1-2001 */
#endif
#ifdef SIGXCPU
	SIGXCPU,
#endif
#ifdef SIGXFSZ
	SIGXFSZ,
#endif
	/* Linux various */
#ifdef SIGIOT
	SIGIOT,
#endif
#ifdef SIGSTKFLT
	SIGSTKFLT,
#endif
#ifdef SIGPWR
	SIGPWR,
#endif
#ifdef SIGINFO
	SIGINFO,
#endif
#ifdef SIGVTALRM
	SIGVTALRM,
#endif
	-1,
};

static proc_info_t *proc_info_get(pid_t pid);

/*
 *  get_username()
 *	get username from a given user id
 */
static char *get_username(const uid_t uid)
{
	struct passwd *pwd;
	static char buf[12];

	pwd = getpwuid(uid);
	if (pwd)
		return pwd->pw_name;

	snprintf(buf, sizeof(buf), "%d", uid);
	return buf;
}

/*
 *  get_tty()
 *	get a TTY name with device ID dev
 */
static char *get_tty(const dev_t dev)
{
	DIR *dir;
	struct dirent *dirent;
	static char tty[16];

	strncpy(tty, "?", sizeof(tty));

	dir = opendir("/dev/pts");
	if (!dir)
		goto err;

	while ((dirent = readdir(dir))) {
		struct stat buf;
		char path[PATH_MAX];

		if (dirent->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "/dev/pts/%s", dirent->d_name);
		if (stat(path, &buf) < 0)
			continue;

		if (buf.st_rdev == dev) {
			snprintf(tty, sizeof(tty), "pts/%s", dirent->d_name);
			break;
		}
	}

	(void)closedir(dir);
err:
	return tty;
}

/*
 *  get_extra()
 *	quick and dirty way to get UID and GID from a PID,
 *	note that this does not cater of changes
 *	because of use of an effective ID.
 */
static void get_extra(const pid_t pid, proc_info_t *info)
{
	ssize_t ret;
	long dev;
	int fd;
	char path[PATH_MAX];
	char buffer[4096];
	struct stat buf;

	info->uid = NULL_UID;
	info->gid = NULL_GID;
	info->tty = NULL_TTY;

	if (!(opt_flags & OPT_EXTRA))
		return;

	snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	if (fstat(fd, &buf) == 0) {
		info->uid = buf.st_uid;
		info->gid = buf.st_gid;
	}

	ret = read(fd, buffer, sizeof(buffer));
	(void)close(fd);
	if (ret < 0)
		return;

	if (sscanf(buffer, "%*d %*s %*s %*d %*d %*d %ld", &dev) == 1)
		info->tty = (dev_t)dev;
}

/*
 *  pid_max_digits()
 *	determine (or guess) maximum digits of pids
 */
static int pid_max_digits(void)
{
	static int max_digits;
	ssize_t n;
	int fd;
	const int default_digits = 6;
	const int min_digits = 5;
	char buf[32];

	if (max_digits)
		goto ret;

	max_digits = default_digits;
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0)
		goto ret;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n < 0)
		goto ret;

	buf[n] = '\0';
	max_digits = 0;
	while (buf[max_digits] >= '0' && buf[max_digits] <= '9')
		max_digits++;
	if (max_digits < min_digits)
		max_digits = min_digits;
ret:
	return max_digits;

}

/*
 *  get_parent_pid()
 *	get parent pid and set is_thread to true if process
 *	not forked but a newly created thread
 */
static pid_t get_parent_pid(const pid_t pid, bool *is_thread)
{
	FILE *fp;
	pid_t tgid = 0, ppid = 0;
	unsigned int got = 0;
	char path[PATH_MAX];
	char buffer[4096];

	*is_thread = false;
	snprintf(path, sizeof(path), "/proc/%u/status", pid);
	fp = fopen(path, "r");
	if (!fp)
		return 0;

	while (((got & GOT_ALL) != GOT_ALL) &&
	       (fgets(buffer, sizeof(buffer), fp) != NULL)) {
		if (!strncmp(buffer, "Tgid:", 5)) {
			if (sscanf(buffer + 5, "%u", &tgid) == 1) {
				got |= GOT_TGID;
			} else {
				tgid = 0;
			}
		}
		if (!strncmp(buffer, "PPid:", 5)) {
			if (sscanf(buffer + 5, "%u", &ppid) == 1) {
				got |= GOT_PPID;
			} else {
				ppid = 0;
			}
		}
	}
	(void)fclose(fp);

	if ((got & GOT_ALL) == GOT_ALL) {
		/*  TGID and PID are not the same if it is a thread */
		if (tgid != pid) {
			/* In this case, the parent is the TGID */
			ppid = tgid;
			*is_thread = true;
		}
	} else {
		ppid = 0;
	}

	return ppid;
}

/*
 *  sane_proc_pid_info()
 *	detect if proc info mapping from /proc/timer_stats
 *	maps to proc pids OK. If we are in a container or
 *	we can't tell, return false.
 */
static bool sane_proc_pid_info(void)
{
	static const char pattern[] = "container=";
	FILE *fp;
	bool ret = true;
	const char *ptr = pattern;

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
		const pid_t pgid = getpgid(id);

		/* This fails for kernel threads inside a container */
		if (pgid >= 0)
			return pgid == 0;

		/*
		 * This is not exactly accurate, but if we can't look up
		 * a process then try and infer something from the comm field.
		 * Until we have better kernel support to map /proc/timer_stats
		 * pids to containerised pids this is the best we can do.
		 */
		static const kernel_task_info kernel_tasks[] = {
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
	const int fd = 0;
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
	int pid_size;

	if (opt_flags & OPT_QUIET)
		return;

	pid_size = pid_max_digits();

	printf("Time     Event %*.*s %sInfo   Duration Process\n",
		pid_size, pid_size, "PID",
		(opt_flags & OPT_EXTRA) ? "   UID TTY    " : "");
}

/*
 *  row_increment()
 *	bump row increment and re-print heading if required
 */
static void row_increment(void)
{
	const int tty_rows = tty_height();

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
static inline size_t proc_info_hash(const pid_t pid)
{
	return pid % MAX_PIDS;
}


/*
 *  proc_name_hash()
 *	Hash a string, from Dan Bernstein comp.lang.c (xor version)
 */
static inline unsigned int proc_name_hash(const char *str)
{
	register unsigned int hash = 5381;
	register unsigned int c;

	while ((c = *str++)) {
		/* (hash * 33) ^ c */
		hash = ((hash << 5) + hash) ^ c;
	}
	return hash % MAX_PIDS;
}

static void proc_stats_account(const pid_t pid, const event_t event)
{
	unsigned int h;
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
		stats = stats->next;
	}
	stats = calloc(1, sizeof(*stats));
	if (!stats)
		return;		/* silently ignore */

	stats->name = strdup(name);
	if (!stats->name) {
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
static int stats_cmp(const void *v1, const void *v2)
{
	proc_stats_t *const *s1 = (proc_stats_t *const *)v1;
	proc_stats_t *const *s2 = (proc_stats_t *const *)v2;

	if ((*s2)->total == (*s1)->total)
		return 0;

	return ((*s2)->total > (*s1)->total) ? 1 : -1;
}

/*
 *  proc_stats_report()
 *	report event statistics
 */
static void proc_stats_report(void)
{
	size_t i, n = 0;
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
	if (!sorted) {
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
static void proc_stats_free(void)
{
	size_t i;

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
	int fd;
	ssize_t ret;
	char buffer[4096];

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
	char *ptr;
	int fd;
	ssize_t ret;
	char buffer[4096];

	snprintf(buffer, sizeof(buffer), "/proc/%d/cmdline", pid);
	if ((fd = open(buffer, O_RDONLY)) < 0) {
		return proc_comm(pid);
	}

	(void)memset(buffer, 0, sizeof(buffer));
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
	const size_t i = proc_info_hash(pid);
	proc_info_t *info = proc_info[i];

	while (info) {
		if (info->pid == pid)
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
	const size_t i = proc_info_hash(pid);
	proc_info_t *info = proc_info[i];

	while (info) {
		if (info->pid == pid) {
			info->pid = NULL_PID;
			info->uid = NULL_UID;
			info->gid = NULL_GID;
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
	size_t i;

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
	newcmd = proc_cmdline(pid);
	if (!newcmd)
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
	const size_t i = proc_info_hash(pid);
	proc_info_t *info;
	char *cmdline;

	cmdline = proc_cmdline(pid);
	if (!cmdline)
		return NULL;

	/* Re-use any info on the list if it's free */
	info = proc_info[i];
	while (info) {
		if (info->pid == NULL_PID)
			break;
		info = info->next;
	}

	if (!info) {
		info = calloc(1, sizeof(proc_info_t));
		if (!info) {
			fprintf(stderr, "Cannot allocate all proc info\n");
			free(cmdline);
			return NULL;
		}
		info->next = proc_info[i];
		proc_info[i] = info;
	}
	info->cmdline = cmdline;
	info->pid = pid;
	get_extra(pid, info);
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

	dir = opendir(path);
	if (!dir)
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

	dir = opendir("/proc");
	if (!dir)
		return -1;

	while ((dirent = readdir(dir))) {
		if (isdigit(dirent->d_name[0])) {
			pid_t pid;

			errno = 0;
			pid = (pid_t)strtol(dirent->d_name, NULL, 10);
			if (!errno) {
				(void)proc_info_add(pid, NULL);
				proc_thread_info_add(pid);
			}
		}
	}

	(void)closedir(dir);
	return 0;
}

static char *extra_info(const uid_t uid)
{
	static char buf[20];

	*buf = '\0';
	if (opt_flags & OPT_EXTRA) {
		const proc_info_t *info = proc_info_get(uid);

		if (info && info->uid != NULL_UID)
			snprintf(buf, sizeof(buf), "%6d %-6.6s ", info->uid, get_tty(info->tty));
		else
			snprintf(buf, sizeof(buf), "%14s", "");
	}

	return buf;
}


/*
 *  handle_sig()
 *	catch signal and flag a stop
 */
static void handle_sig(int dummy)
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
		fprintf(stderr, "socket failed: errno=%d (%s)\n",
			errno, strerror(errno));
		return -1;
	}

	(void)memset(&addr, 0, sizeof(addr));
	addr.nl_pid = getpid();
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = CN_IDX_PROC;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind failed: errno=%d (%s)\n",
			errno, strerror(errno));
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
	enum proc_cn_mcast_op op;
	struct nlmsghdr nlmsghdr;
	struct cn_msg cn_msg;
	struct iovec iov[3];

	(void)memset(&nlmsghdr, 0, sizeof(nlmsghdr));
	nlmsghdr.nlmsg_len = NLMSG_LENGTH(sizeof(cn_msg) + sizeof(op));
	nlmsghdr.nlmsg_pid = getpid();
	nlmsghdr.nlmsg_type = NLMSG_DONE;
	iov[0].iov_base = &nlmsghdr;
	iov[0].iov_len = sizeof(nlmsghdr);

	(void)memset(&cn_msg, 0, sizeof(cn_msg));
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
 *	monitor system activity
 */
static int monitor(const int sock)
{
	struct nlmsghdr *nlmsghdr;
	const int pid_size = pid_max_digits();

	print_heading();

	while (!stop_recv) {
		ssize_t len;
		char __attribute__ ((aligned(NLMSG_ALIGNTO)))buf[4096];

		if ((len = recv(sock, buf, sizeof(buf), 0)) == 0) {
			return 0;
		}
		if (len == -1) {
			const int err = errno;

			switch (err) {
			case EINTR:
				return 0;
			case ENOBUFS: {
				time_t now;
				struct tm tm;

				now = time(NULL);
				if (now == ((time_t) -1)) {
					printf("--:--:-- recv ----- "
						"nobufs %8.8s (%s)\n",
						"", strerror(err));
				} else {
					(void)localtime_r(&now, &tm);
					printf("%2.2d:%2.2d:%2.2d recv ----- "
						"nobufs %8.8s (%s)\n",
						tm.tm_hour, tm.tm_min, tm.tm_sec, "",
						strerror(err));
				}
				break;
			}
			default:
				fprintf(stderr,"recv failed: errno=%d (%s)\n",
					err, strerror(err));
				return -1;
			}
		}

		for (nlmsghdr = (struct nlmsghdr *)buf;
			NLMSG_OK (nlmsghdr, len);
			nlmsghdr = NLMSG_NEXT (nlmsghdr, len)) {

			struct cn_msg *cn_msg;
			struct proc_event *proc_ev;
			struct tm tm;
			char when[10];
			time_t now;
			pid_t pid, ppid;
			bool is_thread;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
			struct timeval tv;
			char duration[32];
			proc_info_t const *info1, *info2;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
			char *comm;
#endif

			if (stop_recv)
				break;

			if ((nlmsghdr->nlmsg_type == NLMSG_ERROR) ||
			    (nlmsghdr->nlmsg_type == NLMSG_NOOP))
				continue;

			cn_msg = NLMSG_DATA(nlmsghdr);
			if ((cn_msg->id.idx != CN_IDX_PROC) ||
			    (cn_msg->id.val != CN_VAL_PROC))
				continue;

			proc_ev = (struct proc_event *)cn_msg->data;

			now = time(NULL);
			if (now == ((time_t) -1)) {
				snprintf(when, sizeof(when), "--:--:--");
			} else {
				(void)localtime_r(&now, &tm);
				snprintf(when, sizeof(when), "%2.2d:%2.2d:%2.2d",
					tm.tm_hour, tm.tm_min, tm.tm_sec);
			}

			switch (proc_ev->what) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
			case PROC_EVENT_FORK:
				ppid = get_parent_pid(proc_ev->event_data.fork.child_pid, &is_thread);
				pid = proc_ev->event_data.fork.child_pid;
				proc_stats_account(proc_ev->event_data.fork.parent_pid,
					is_thread ? STAT_CLNE : STAT_FORK);
				if (gettimeofday(&tv, NULL) < 0) {
					(void)memset(&tv, 0, sizeof tv);
				}
				info1 = proc_info_get(ppid);
				info2 = proc_info_add(pid, &tv);
				if (!(opt_flags & OPT_QUIET) &&
					(((opt_flags & OPT_EV_FORK) && !is_thread) ||
					 ((opt_flags & OPT_EV_CLNE) && is_thread))) {
					if (info1 != NULL && info2 != NULL) {
						char *type = is_thread ? "clone" : "fork";
						row_increment();
						printf("%s %-5.5s %*d %sparent %8s %s%s%s\n",
							when,
							type,
							pid_size, ppid,
							extra_info(ppid),
							"",
							info1->kernel_thread ? "[" : "",
							info1->cmdline,
							info1->kernel_thread ? "]" : "");
						row_increment();
						printf("%s %-5.5s %*d %s%6.6s %8s %s%s%s\n",
							when,
							type,
							pid_size, pid,
							extra_info(pid),
							is_thread ? "thread" : "child",
							"",
							info1->kernel_thread ? "[" : "",
							info2->cmdline,
							info1->kernel_thread ? "]" : "");
					}
				}
				break;
			case PROC_EVENT_EXEC:
				proc_stats_account(proc_ev->event_data.exec.process_pid, STAT_EXEC);
				pid = proc_ev->event_data.exec.process_pid;
				info1 = proc_info_update(pid);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_EXEC)) {
					row_increment();
					printf("%s exec  %*d %s       %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				break;
			case PROC_EVENT_EXIT:
				proc_stats_account(proc_ev->event_data.exit.process_pid, STAT_EXIT);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_EXIT)) {
					pid = proc_ev->event_data.exit.process_pid;
					info1 = proc_info_get(pid);
					if (info1->start.tv_sec) {
						double d1, d2;

						if (gettimeofday(&tv, NULL) < 0) {
							(void)memset(&tv, 0, sizeof tv);
						}
						d1 = timeval_to_double(&info1->start);
						d2 = timeval_to_double(&tv);
						snprintf(duration, sizeof(duration), "%8.3f", d2 - d1);
					} else {
						snprintf(duration, sizeof(duration), "unknown");
					}
					row_increment();
					printf("%s exit  %*d %s%6d %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						proc_ev->event_data.exit.exit_code,
						duration,
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				proc_info_free(proc_ev->event_data.exit.process_pid);
				break;
			case PROC_EVENT_UID:
				proc_stats_account(proc_ev->event_data.exec.process_pid, STAT_UID);
				info1 = proc_info_update(proc_ev->event_data.exec.process_pid);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_UID)) {
					row_increment();
					pid = proc_ev->event_data.exec.process_pid;
					if (proc_ev->what == PROC_EVENT_UID) {
						printf("%s uid   %*d %s%6s %8s %s%s%s\n",
							when,
							pid_size, pid,
							extra_info(pid),
							get_username(proc_ev->event_data.id.e.euid),
							"",
							info1->kernel_thread ? "[" : "",
							info1->cmdline,
							info1->kernel_thread ? "]" : "");
					} else {
						printf("%s gid   %*d %6s %s%8s %s%s%s\n",
							when,
							pid_size, pid,
							extra_info(pid),
							get_username(proc_ev->event_data.id.e.euid),
							"",
							info1->kernel_thread ? "[" : "",
							info1->cmdline,
							info1->kernel_thread ? "]" : "");
					}
				}
				break;
			case PROC_EVENT_SID:
				proc_stats_account(proc_ev->event_data.exec.process_pid, STAT_SID);
				info1 = proc_info_update(proc_ev->event_data.exec.process_pid);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_UID)) {
					row_increment();
					pid = proc_ev->event_data.exec.process_pid;
					printf("%s sid   %*d %s%6d %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						proc_ev->event_data.sid.process_pid,
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
			case PROC_EVENT_COREDUMP:
				proc_stats_account(proc_ev->event_data.coredump.process_pid, STAT_CORE);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_CORE)) {
					pid = proc_ev->event_data.coredump.process_pid;
					info1 = proc_info_get(pid);
					row_increment();
					printf("%s core  %*d %s       %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
			case PROC_EVENT_PTRACE:
				proc_stats_account(proc_ev->event_data.comm.process_pid, STAT_PTRC);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_PTRC)) {
					const bool attach = (proc_ev->event_data.ptrace.tracer_pid != 0);

#if 0
					pid = attach ? proc_ev->event_data.ptrace.tracer_pid :
						       proc_ev->event_data.ptrace.process_pid;
#else
					pid = proc_ev->event_data.ptrace.process_pid;
#endif
					info1 = proc_info_get(pid);
					row_increment();
					printf("%s ptrce %*d %s%6s %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						attach ? "attach" : "detach",
						"",
						info1->kernel_thread ? "[" : "",
						attach ? info1->cmdline : "",
						info1->kernel_thread ? "]" : "");
				}
				break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
			case PROC_EVENT_COMM:
				proc_stats_account(proc_ev->event_data.comm.process_pid, STAT_COMM);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_COMM)) {
					pid = proc_ev->event_data.comm.process_pid;
					info1 = proc_info_get(pid);
					comm = proc_comm(pid);
					if (!comm)
						break;
					row_increment();

					printf("%s comm  %*d %s       %8s %s%s%s -> %s\n",
						when,
						pid_size, pid,
						extra_info(pid),
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
static void show_help(char *const argv[])
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("usage: %s [-d|-D|-e|-h|-l|-s|-S|-q]\n", argv[0]);
	printf("-d\tstrip off directory path from process name.\n"
	       "-D\tspecify run duration in seconds.\n"
	       "-e\tselect which events to monitor.\n"
	       "-h\tshow this help.\n"
	       "-l\tforce stdout line buffering.\n"
	       "-r\trun with real time FIFO scheduler.\n"
	       "-s\tshow short process name.\n"
	       "-S\tshow event statistics at end of the run.\n"
	       "-q\trun quietly and enable -S option.\n"
	       "-x\tshow extra process information.\n");
}

/*
 *  parse_ev()
 *	parse event strings, turn into flag mask
 */
static int parse_ev(char *arg)
{
	char *str, *token;

	for (str = arg; (token = strtok(str, ",")) != NULL; str = NULL) {
		size_t i;
		bool found = false;

		for (i = 0; ev_map[i].event; i++) {
			if (!strcmp(token, ev_map[i].event)) {
				opt_flags |= ev_map[i].flag;
				found = true;
			}
		}
		if (!found) {
			fprintf(stderr, "Unknown event '%s'. Allowed events:", token);
			for (i = 0; ev_map[i].event; i++)
				printf(" %s", ev_map[i].event);
			printf("\n");
			return -1;
		}
	}
	return 0;
}

int main(int argc, char * const argv[])
{
	size_t i;
	int sock = -1, ret = EXIT_FAILURE;
	struct sigaction new_action;

	for (;;) {
		const int c = getopt(argc, argv, "dD:e:hlrsSqx");
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
		case 'r':
			opt_flags |= OPT_REALTIME;
			break;
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
		case 'l':
			if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) {
				fprintf(stderr, "Error setting line buffering.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'x':
			opt_flags |= OPT_EXTRA;
			break;
		default:
			show_help(argv);
			exit(EXIT_FAILURE);
		}
	}

	if ((opt_flags & OPT_EV_MASK) == 0)
		opt_flags |= (OPT_EV_FORK | OPT_EV_EXEC | OPT_EV_EXIT | OPT_EV_CLNE | OPT_EV_PTRC);

	if (geteuid() != 0) {
		fprintf(stderr, "Need to run with root access.\n");
		goto abort_sock;
	}

	(void)memset(&new_action, 0, sizeof(new_action));
	for (i = 0; signals[i] != -1; i++) {
		new_action.sa_handler = handle_sig;
		sigemptyset(&new_action.sa_mask);
		new_action.sa_flags = 0;

		if (sigaction(signals[i], &new_action, NULL) < 0) {
			fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
			goto abort_sock;
		}
	}

	sane_procs = sane_proc_pid_info();

	if (proc_info_load() < 0) {
		fprintf(stderr, "Cannot load process cache. Is /proc mounted?\n");
		goto abort_sock;
	}

	if (opt_flags & OPT_REALTIME) {
		struct sched_param param;
		int max_prio;
		const int policy = SCHED_FIFO;

		max_prio = sched_get_priority_max(policy);
		if (max_prio < 0) {
			fprintf(stderr, "sched_get_priority_max failed: errno=%d (%s)\n",
				errno, strerror(errno));
			goto abort_sock;
		}

		(void)memset(&param, 0, sizeof(param));
		param.sched_priority = max_prio;
		if (sched_setscheduler(getpid(), policy, &param) < 0) {
			fprintf(stderr, "sched_setscheduler failed: errno=%d (%s)\n",
				errno, strerror(errno));
			goto abort_sock;
		}
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
		fprintf(stderr, "netlink listen failed: errno=%d (%s)\n",
			errno, strerror(errno));
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
