/*
 * Copyright (C) 2014-2021 Canonical Ltd.
 * Copyright (C) 2021-2025 Colin Ian King.
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
 * Written by Colin Ian King <colin.i.king@gmail.com>
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
#define MAX_UIDS		(1237)		/* Hash Max UIDs */
#define MAX_TTYS		(199)		/* Hash Max TTYs */

#define TTY_NAME_LEN		(16)		/* Max TTY name length */

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
#define OPT_GLYPH		(0x00000080)	/* Show glyphs */
#define OPT_COMM		(0x00000100)	/* Show comm info */

#define OPT_EV_FORK		(0x00100000)	/* Fork event */
#define OPT_EV_EXEC		(0x00200000)	/* Exec event */
#define OPT_EV_EXIT		(0x00400000)	/* Exit event */
#define OPT_EV_CORE		(0x00800000)	/* Coredump event */
#define OPT_EV_COMM		(0x01000000)	/* Comm proc info event */
#define OPT_EV_CLNE		(0x02000000)	/* Clone event */
#define OPT_EV_PTRC		(0x04000000)	/* Ptrace event */
#define OPT_EV_UID		(0x08000000)	/* UID event */
#define OPT_EV_SID		(0x10000000)	/* SID event */
#define OPT_EV_NONZERO_EXIT	(0x20000000)	/* Exit event, non-zero exit */
#define OPT_EV_MASK		(0x3ff00000)	/* Event mask */
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
	char	*cmdline;	/* /proc/pid/cmdline text */
	dev_t	tty;		/* TTY dev */
	pid_t	pid;		/* Process ID */
	uid_t	uid;		/* User ID */
	gid_t	gid;		/* GUID */
	uid_t	euid;		/* EUID */
	struct timeval start;	/* time when process started */
	bool	kernel_thread;	/* true if a kernel thread */
} proc_info_t;

/* For kernel task checking */
typedef struct {
	char *task;		/* Name of kernel task */
	size_t len;		/* Length */
} kernel_task_info;

/* For UID to name cache */
typedef struct uid_name_info {
	struct uid_name_info *next;
	char	*name;		/* User name */
	uid_t	uid;		/* User ID */
} uid_name_info_t;

/* For tty to tty name cache */
typedef struct tty_name_info {
	struct tty_name_info *next;
	dev_t	dev;		/* tty device */
	char	tty_name[TTY_NAME_LEN];	/* tty name */
} tty_name_info_t;

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
	STAT_NONZERO_EXIT,	/* Non-zero exit */
	STAT_LAST,		/* Always last sentinal */
	STAT_NONE
} event_t;

typedef struct proc_stats {
	struct proc_stats *next;/* Next one in list */
	char *name;		/* Process name */
	uint64_t total;		/* Tally count total of all counts */
	uint64_t count[STAT_LAST]; /* Tally count */
} proc_stats_t;

typedef struct {
	const char *event;	/* Event name */
	const char *label;	/* Human readable label */
	const int flag;		/* option flag */
	const event_t stat;	/* stat enum */
} ev_map_t;

/* scaling factor */
typedef struct {
	const char ch;		/* Scaling suffix */
	const uint32_t base;	/* Base of part following . point */
	const uint64_t scale;	/* Amount to scale by */
} time_scale_t;

/* Mapping of event names to option flags and event_t types */
static const ev_map_t ev_map[] = {
	{ "fork", 	"Fork", 	OPT_EV_FORK,		STAT_FORK },
	{ "exec", 	"Exec", 	OPT_EV_EXEC,		STAT_EXEC },
	{ "exit", 	"Exit", 	OPT_EV_EXIT,		STAT_EXIT },
	{ "core", 	"Coredump",	OPT_EV_CORE,		STAT_CORE },
	{ "comm", 	"Comm", 	OPT_EV_COMM,		STAT_COMM },
	{ "clone",	"Clone",	OPT_EV_CLNE,		STAT_CLNE },
	{ "ptrce",	"Ptrace",	OPT_EV_PTRC,		STAT_PTRC },
	{ "uid",  	"Uid",		OPT_EV_UID,		STAT_UID  },
	{ "sid",  	"Sid",		OPT_EV_SID,		STAT_SID  },
	{ "nonzeroexit","NonzeroExit",  OPT_EV_NONZERO_EXIT, 	STAT_NONZERO_EXIT },
	{ "all",  	"",		OPT_EV_ALL,		STAT_NONE },
	{ NULL,	  	NULL, 		0,			STAT_NONE },
};

#define KERN_TASK_INFO(str)	{ str, sizeof(str) - 1 }

static volatile bool stop_recv;			/* sighandler stop flag */
static bool sane_procs;				/* true if not inside a container */
static proc_info_t *proc_info[MAX_PIDS];	/* Proc hash table */
static proc_stats_t *proc_stats[MAX_PIDS];	/* Proc stats hash table */
static uid_name_info_t *uid_name_info[MAX_UIDS];/* UID to name hash table */
static tty_name_info_t *tty_name_info[MAX_TTYS];/* TTY dev to name hash table */
static unsigned int opt_flags = OPT_CMD_LONG;	/* Default option */
static int row = 0;				/* tty row number */
static long int opt_duration = -1;		/* duration, < 0 means run forever */
static pid_t opt_pgrp = -1;

static char unknown[] = "<unknown>";

static proc_info_t *proc_info_add(const pid_t pid, const struct timeval * const tv);

/* Default void no process info struct */
static proc_info_t no_info = {
	.pid = NULL_PID,
	.uid = NULL_UID,
	.gid = NULL_GID,
	.tty = NULL_TTY,
	.cmdline = unknown,
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
#ifdef SIGALRM
	SIGALRM,
#endif
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

/* seconds scale suffixes, secs, mins, hours, etc */
static const time_scale_t second_scales[] = {
	{ 's',	1000, 1 },
	{ 'm',	 600, 60 },
	{ 'h',   600, 3600 },
	{ 'd',  1000, 24 * 3600 },
	{ 'w',  1000, 7 * 24 * 3600 },
	{ 'y',  1000, 365 * 24 * 3600 },
	{ ' ',  1000,  INT64_MAX },
};

/*
 *  proc_comm_dup()
 *	duplicate a comm filed string, if it fails, return unknown
 */
static char *proc_comm_dup(const char *str)
{
	char *comm = strdup(str);

	if (!comm)
		return unknown;

	return comm;
}

/*
 *  get_proc_self_stat_field()
 *	find nth field of /proc/$PID/stat data. This works around
 *	the problem that the comm field can contain spaces and
 *	multiple ) so sscanf on this field won't work.  The returned
 *	pointer is the start of the Nth field and it is up to the
 *	caller to determine the end of the field
 */
static const char *get_proc_self_stat_field(const char *buf, const int num)
{
	const char *ptr, *comm_end;
	int n;

	if (num < 1 || !buf || !*buf)
		return NULL;
	if (num == 1)
		return buf;
	if (num == 2)
		return strstr(buf, "(");

	comm_end = NULL;
	for (ptr = buf; *ptr; ptr++) {
		if (*ptr == ')')
			comm_end = ptr;
	}
	if (!comm_end)
		return NULL;
	comm_end++;
	n = num - 2;

	ptr = comm_end;
	while (*ptr) {
		while (*ptr == ' ')
			ptr++;
		n--;
		if (n <= 0)
			break;
		while (*ptr && *ptr != ' ')
			ptr++;
	}

	return ptr;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
/*
 *  secs_to_str()
 *	report seconds in different units.
 */
static char *secs_to_str(const double secs)
{
	static char buf[16];
	size_t i;
	double s = secs, fract;

	for (i = 0; i < 5; i++) {
		if (s <= second_scales[i + 1].scale)
			break;
	}
	s /= second_scales[i].scale;
	s += 0.0005;	/* Round up */
	fract = (s * second_scales[i].base) - (double)((int)s * second_scales[i].base);
	(void)snprintf(buf, sizeof(buf), "%3u.%3.3u%c",
		(unsigned int)s, (unsigned int)fract, second_scales[i].ch);
	return buf;
}
#endif

/*
 *  get_username()
 *	get username from a given user id
 */
static char *get_username(const uid_t uid)
{
	struct passwd *pwd;
	static char buf[12];
	const size_t hash = uid % MAX_UIDS;
	uid_name_info_t *uni = uid_name_info[hash];
	char *name = NULL;

	if (uid != NULL_UID) {
		/*
		 *  Try and find it in cache first
		 */
		while (uni) {
			if (uni->uid == uid)
				return uni->name;
			uni = uni->next;
		}

		pwd = getpwuid(uid);
		if (pwd)
			name = pwd->pw_name;
	}

	/* Unknow UID, use numeric instead */
	if (!name) {
		(void)snprintf(buf, sizeof(buf), "%d", uid);
		name = buf;
	}

	/*
	 *  Try and allocate a cached uid name mapping
	 *  but don't worry if we can't as we can look
	 *  it up if we run out of memory next time round
	 */
	uni = malloc(sizeof(*uni));
	if (!uni)
		return name;
	uni->name = strdup(name);
	if (!uni->name) {
		free(uni);
		return name;
	}
	uni->uid = uid;
	uni->next = uid_name_info[hash];
	uid_name_info[hash] = uni;

	return uni->name;
}

/*
 *  uid_name_info_free()
 *	free uid name info cache
 */
static void uid_name_info_free(void)
{
	size_t i;

	for (i = 0; i < MAX_UIDS; i++) {
		uid_name_info_t *uni = uid_name_info[i];

		while (uni) {
			uid_name_info_t *next = uni->next;

			free(uni->name);
			free(uni);
			uni = next;
		}
	}
}

/*
 *  get_tty()
 *	get a TTY name with device ID dev
 */
static char *get_tty(const dev_t dev)
{
	DIR *dir;
	struct dirent *dirent;
	static char tty[TTY_NAME_LEN];
	const size_t hash = ((size_t)dev) % MAX_TTYS;
	tty_name_info_t *tni = tty_name_info[hash];

	/*
	 *  Try and find it in cache first
	 */
	while (tni) {
		if (tni->dev == dev)
			return tni->tty_name;
		tni = tni->next;
	}

	(void)memset(tty, 0, sizeof(tty));
	*tty = '?';

	dir = opendir("/dev/pts");
	if (!dir)
		goto err;

	while ((dirent = readdir(dir))) {
		struct stat buf;
		char path[PATH_MAX];

		if (dirent->d_name[0] == '.')
			continue;

		(void)snprintf(path, sizeof(path), "/dev/pts/%s",
			dirent->d_name);
		if (stat(path, &buf) < 0)
			continue;

		if (buf.st_rdev == dev) {
			(void)snprintf(tty, sizeof(tty), "pts/%-11.11s",
				dirent->d_name);
			break;
		}
	}

	(void)closedir(dir);
err:
	tty[TTY_NAME_LEN - 1] = '\0';

	/*
	 *  Try to add a new tty name to cache,
	 *  this is not critical if we can't, just
	 *  give up and lookup again next time
	 */
	tni = malloc(sizeof(*tni));
	if (!tni)
		return tty;

	(void)strncpy(tni->tty_name, tty, sizeof(tni->tty_name));
	tni->dev = dev;
	tni->next = tty_name_info[hash];
	tty_name_info[hash] = tni;

	return tni->tty_name;
}

/*
 *  tty_name_info_free()
 *	free tty name info cache
 */
static void tty_name_info_free(void)
{
	size_t i;

	for (i = 0; i < MAX_TTYS; i++) {
		tty_name_info_t *tni = tty_name_info[i];

		while (tni) {
			tty_name_info_t *next = tni->next;

			free(tni);
			tni = next;
		}
	}
}

/*
 *  proc_name_clean()
 *	clean up unwanted chars from process name
 */
static void proc_name_clean(char *buffer, const int len)
{
	char *ptr;

	/*
	 *  Convert '\r' and '\n' into spaces
	 */
	for (ptr = buffer; *ptr && (ptr < buffer + len); ptr++) {
		if ((*ptr == '\r') || (*ptr =='\n'))
			*ptr = ' ';
	}
	/*
	 *  OPT_CMD_SHORT option we discard anything after a space
	 */
	if (opt_flags & OPT_CMD_SHORT) {
		for (ptr = buffer; *ptr && (ptr < buffer + len); ptr++) {
			if (*ptr == ' ') {
				*ptr = '\0';
				break;
			}
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

	(void)snprintf(buffer, sizeof(buffer), "/proc/%d/comm", pid);
	if ((fd = open(buffer, O_RDONLY)) < 0)
		return unknown;
	if ((ret = read(fd, buffer, sizeof(buffer) - 1)) <= 0) {
		(void)close(fd);
		return unknown;
	}
	(void)close(fd);
	buffer[ret - 1] = '\0';		/* remove trailing '\n' */
	proc_name_clean(buffer, ret);

	return proc_comm_dup(buffer);
}


/*
 *  get_extra()
 *	quick and dirty way to get UID, EUID and GID from a PID
 */
static void get_extra(const pid_t pid, proc_info_t * const info)
{
	long dev;
	FILE *fp;
	char path[PATH_MAX];
	char buffer[1024];
	struct stat buf;

	info->uid = NULL_UID;
	info->gid = NULL_GID;
	info->euid = NULL_UID;
	info->tty = NULL_TTY;

	if (!(opt_flags & OPT_EXTRA))
		return;

	(void)snprintf(path, sizeof(path), "/proc/%u/status", pid);
	fp = fopen(path, "r");
	if (!fp)
		return;

	(void)memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer) - 1, fp)) {
		int gid, uid, euid;

		if (!strncmp(buffer, "Uid:", 4)) {
			if (sscanf(buffer + 4, "%d %d", &uid, &euid) == 2) {
				info->uid = uid;
				info->euid = euid;
			}
		}
		if (!strncmp(buffer, "Gid:", 4)) {
			if (sscanf(buffer + 4, "%d", &gid) == 1) {
				info->gid = gid;
			}
		}
		if ((info->uid != NULL_UID) &&
		    (info->euid != NULL_UID) &&
		    (info->gid != NULL_GID))
			break;
	}
	(void)fclose(fp);

	(void)snprintf(path, sizeof(path), "/proc/%u/stat", pid);
	fp = fopen(path, "r");
	if (!fp)
		return;

	/*
	 *  Failed to parse /proc/$PID/status? then at least get
	 *  some info by stat'ing /proc/$PID/stat
	 */
	if ((info->uid == NULL_UID) || (info->gid == NULL_GID)) {
		if (fstat(fileno(fp), &buf) == 0) {
			info->uid = buf.st_uid;
			info->gid = buf.st_gid;
		}
	}

	info->tty = (dev_t)0;
	if (fgets(buffer, sizeof(buffer) - 1, fp) != NULL) {
		const char *ptr = get_proc_self_stat_field(buffer, 7);

		if (ptr && sscanf(ptr , "%ld", &dev) == 1)
			info->tty = (dev_t)dev;
	}
	(void)fclose(fp);
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
	while ((max_digits < n) && (buf[max_digits] >= '0') && (buf[max_digits] <= '9'))
		max_digits++;
	if (max_digits < min_digits)
		max_digits = min_digits;
ret:
	return max_digits;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
/*
 *  get_parent_pid()
 *	get parent pid and set is_thread to true if process
 *	not forked but a newly created thread
 */
static pid_t get_parent_pid(const pid_t pid, bool * const is_thread)
{
	FILE *fp;
	pid_t tgid = 0, ppid = 0;
	unsigned int got = 0;
	char path[PATH_MAX];
	char buffer[4096];

	*is_thread = false;
	(void)snprintf(path, sizeof(path), "/proc/%u/status", pid);
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
			if (sscanf(buffer + 5, "%u", &ppid) == 1)
				got |= GOT_PPID;
			else
				ppid = 0;
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
#endif

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

	/* Fast check */
	if (access("/run/systemd/container", R_OK) == 0)
		return true;

	/* Privileged slower check */
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
static bool pid_a_kernel_thread(const char * const task, const pid_t id)
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

	(void)memset(&ws, 0, sizeof(ws));
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

	(void)printf("Time     Event %*.*s %s%sInfo   Duration Process\n",
		pid_size, pid_size, "PID",
		(opt_flags & OPT_EXTRA) ? "    UID    EUID TTY    " : "",
		(opt_flags & OPT_GLYPH) ? " " : "");
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
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
#endif

/*
 *  timeval_to_double()
 *      convert timeval to seconds as a double
 */
static inline double timeval_to_double(const struct timeval * const tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *   proc_info_get_timeval()
 *	get time when process started
 */
static void proc_info_get_timeval(const pid_t pid, struct timeval * const tv)
{
	int fd;
	unsigned long long starttime;
	unsigned long jiffies;
	char path[PATH_MAX];
	char buffer[4096];
	const char *ptr;
	double uptime_secs, secs;
	struct timeval now;
	ssize_t n;

	(void)snprintf(path, sizeof(path), "/proc/%d/stat", pid);

	fd = open("/proc/uptime", O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buffer, sizeof(buffer) - 1);
	if (n <= 0) {
		(void)close(fd);
		return;
	}
	buffer[n] = '\0';
	(void)close(fd);
	n = sscanf(buffer, "%lg", &uptime_secs);
	if (n != 1)
		return;
	if (uptime_secs < 0.0)
		return;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buffer, sizeof(buffer) - 1);
	if (n <= 0) {
		(void)close(fd);
		return;
	}
	buffer[n] = '\0';
	(void)close(fd);

	ptr = get_proc_self_stat_field(buffer, 22);
	if (!ptr)
		return;
	n = sscanf(ptr, "%llu", &starttime);
	if (n != 1)
		return;

	errno = 0;
	jiffies = sysconf(_SC_CLK_TCK);
	if (errno)
		return;
	secs = uptime_secs - ((double)starttime / (double)jiffies);
	if (secs < 0.0)
		return;

	if (gettimeofday(&now, NULL) < 0)
		return;

	secs = timeval_to_double(&now) - secs;
	tv->tv_sec = secs;
	tv->tv_usec = (suseconds_t)secs % 1000000;
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
/*
 *  proc_stats_account()
 *	perform per process accounting
 */
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
#endif

/*
 *  stats_cmp()
 *	compare stats total, used for sorting list
 */
static int stats_cmp(const void *v1, const void *v2)
{
	const proc_stats_t *const *s1 = (const proc_stats_t *const *)v1;
	const proc_stats_t *const *s2 = (const proc_stats_t *const *)v2;

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
		(void)printf("\nNo statistics gathered.\n");
		return;
	}

	printf("\n");
	for (i = 0; i < STAT_LAST; i++)
		(void)printf("%8s ", ev_map[i].label);
	(void)printf("   Total Process\n");

	sorted = calloc(n, sizeof(proc_stats_t *));
	if (!sorted) {
		(void)fprintf(stderr, "Cannot sort statistics, out of memory.\n");
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
			(void)printf("%8" PRIu64 " ", stats->count[j]);
		(void)printf("%8" PRIu64 " %s\n", stats->total, stats->name);
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
 *  free_proc_comm()
 *	free comm field only if it's not the static unknown string
 */
static void free_proc_comm(char *comm)
{
	if (comm != unknown)
		free(comm);
}

/*
 *  proc_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *proc_cmdline(const pid_t pid)
{
	int fd;
	const size_t buffer_sz = 65536;
	ssize_t ret;
	char *buffer, *tmp;

	if (pid == 0)
		return proc_comm_dup("[swapper]");

	if (opt_flags & OPT_COMM)
		return proc_comm(pid);

	buffer = malloc(buffer_sz);
	if (!buffer)
		return proc_comm(pid);

	(void)snprintf(buffer, buffer_sz, "/proc/%d/cmdline", pid);
	if ((fd = open(buffer, O_RDONLY)) < 0) {
		free(buffer);
		return proc_comm(pid);
	}

	(void)memset(buffer, 0, buffer_sz);
	if ((ret = read(fd, buffer, buffer_sz - 1)) <= 0) {
		free(buffer);
		(void)close(fd);
		return proc_comm(pid);
	}
	(void)close(fd);
	buffer[ret] = '\0';	/* Keeps coverity scan happy */

	/*
	 *  OPT_CMD_LONG option we get the full cmdline args
	 */
	if (opt_flags & OPT_CMD_LONG) {
		char *ptr;

		for (ptr = buffer; ptr < buffer + ret; ptr++) {
			if (*ptr == '\0') {
				*ptr = ' ';
			}
		}
		*ptr = '\0';
	}

	proc_name_clean(buffer, ret);

	if (opt_flags & OPT_CMD_DIRNAME_STRIP) {
		tmp = proc_comm_dup(basename(buffer));
	} else {
		tmp = proc_comm_dup(buffer);
	}
	free(buffer);
	return tmp;
}

/*
 *  proc_info_get()
 *	get proc info on a given pid
 */
static proc_info_t *proc_info_get(const pid_t pid)
{
	const size_t i = proc_info_hash(pid);
	proc_info_t *info = proc_info[i];
	struct timeval tv;

	while (info) {
		if (info->pid == pid) {
			if (info->cmdline == unknown)
				info->cmdline = proc_cmdline(pid);
			return info;
		}
		info = info->next;
	}

	/* Hrm, not already cached, so get new info */
	(void)memset(&tv, 0, sizeof(tv));
	proc_info_get_timeval(pid, &tv);
	info = proc_info_add(pid, &tv);
	if (!info)
		info = &no_info;

	return info;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
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
			info->euid = NULL_UID;
			free_proc_comm(info->cmdline);
			info->cmdline = NULL;
			return;
		}
		info = info->next;
	}
}
#endif

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
			free_proc_comm(info->cmdline);
			free(info);
			info = next;
		}
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
/*
 *  proc_info_update()
 *	update process name, for example, if exec has occurred
 */
static proc_info_t const *proc_info_update(const pid_t pid)
{
	proc_info_t * const info = proc_info_get(pid);
	char *newcmd;

	if (info == &no_info)
		return &no_info;
	newcmd = proc_cmdline(pid);

	/*
	 *  Don't update if newcmd is unknown, at least
	 *  we temporarily keep the parent's name or
	 *  the processes old name
	 */
	if (newcmd != unknown) {
		free_proc_comm(info->cmdline);
		info->cmdline = newcmd;
	}

	return info;
}
#endif

/*
 *   proc_info_add()
 *	add processes info of a given pid to the hash table
 */
static proc_info_t *proc_info_add(const pid_t pid, const struct timeval * const tv)
{
	const size_t i = proc_info_hash(pid);
	proc_info_t *info;
	char *cmdline;

	cmdline = proc_cmdline(pid);

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
			(void)fprintf(stderr, "Cannot allocate all proc info\n");
			free_proc_comm(cmdline);
			return NULL;
		}
		info->next = proc_info[i];
		proc_info[i] = info;
	}
	info->cmdline = cmdline;
	info->pid = pid;
	get_extra(pid, info);
	info->kernel_thread = pid_a_kernel_thread(cmdline, pid);
	info->start = *tv;

	return info;
}

/*
 *  proc_thread_info_add()
 *	Add a processes' thread into proc cache
 */
static void proc_thread_info_add(const pid_t pid, const struct timeval *const parent_tv)
{
	DIR *dir;
	struct dirent *dirent;
	char path[PATH_MAX];

	(void)snprintf(path, sizeof(path), "/proc/%i/task", pid);

	dir = opendir(path);
	if (!dir)
		return;

	while ((dirent = readdir(dir))) {
		if (isdigit(dirent->d_name[0])) {
			pid_t tpid;
			struct timeval tv;

			errno = 0;
			tpid = (pid_t)strtol(dirent->d_name, NULL, 10);
			if ((!errno) && (tpid != pid)) {
				tv = *parent_tv;
				proc_info_get_timeval(pid, &tv);
				(void)proc_info_add(tpid, &tv);
			}
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
			struct timeval tv;

			errno = 0;
			pid = (pid_t)strtol(dirent->d_name, NULL, 10);
			if (!errno) {
				(void)memset(&tv, 0, sizeof(tv));
				proc_info_get_timeval(pid, &tv);
				(void)proc_info_add(pid, &tv);
				proc_thread_info_add(pid, &tv);
			}
		}
	}

	(void)closedir(dir);
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
/*
 *  extra_info()
 *	format up extra process information if selected
 */
static char *extra_info(const uid_t uid)
{
	static char buf[28];

	*buf = '\0';
	if (opt_flags & OPT_EXTRA) {
		const proc_info_t *info = proc_info_get(uid);

		if (info && info->uid != NULL_UID)
			(void)snprintf(buf, sizeof(buf), "%7.7s %7.7s %6.6s ",
				get_username(info->uid),
				get_username(info->euid),
				get_tty(info->tty));
		else
			(void)snprintf(buf, sizeof(buf), "%14s", "");
	}

	return buf;
}
#endif

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
		(void)fprintf(stderr, "socket failed: errno=%d (%s)\n",
			errno, strerror(errno));
		return -1;
	}

	(void)memset(&addr, 0, sizeof(addr));
	addr.nl_pid = getpid();
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = CN_IDX_PROC;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		(void)fprintf(stderr, "bind failed: errno=%d (%s)\n",
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

		if ((len = recv(sock, buf, sizeof(buf), 0)) == 0)
			return 0;

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
					(void)printf("--:--:-- recv ----- "
						"nobufs %8.8s (%s)\n",
						"", strerror(err));
				} else {
					(void)localtime_r(&now, &tm);
					(void)printf("%2.2d:%2.2d:%2.2d recv ----- "
						"nobufs %8.8s (%s)\n",
						tm.tm_hour, tm.tm_min, tm.tm_sec, "",
						strerror(err));
				}
				break;
			}
			default:
				(void)fprintf(stderr,"recv failed: errno=%d (%s)\n",
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
			pid_t pid, ppid, pgrp;
			bool is_thread;
#endif

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
				(void)snprintf(when, sizeof(when), "--:--:--");
			} else {
				(void)localtime_r(&now, &tm);
				(void)snprintf(when, sizeof(when), "%2.2d:%2.2d:%2.2d",
					tm.tm_hour, tm.tm_min, tm.tm_sec);
			}

			switch (proc_ev->what) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
			case PROC_EVENT_FORK:
				ppid = get_parent_pid(proc_ev->event_data.fork.child_pid, &is_thread);
				pid = proc_ev->event_data.fork.child_pid;
				pgrp = getpgid(pid);
				if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
					break;
				proc_stats_account(proc_ev->event_data.fork.parent_pid,
					is_thread ? STAT_CLNE : STAT_FORK);
				if (gettimeofday(&tv, NULL) < 0)
					(void)memset(&tv, 0, sizeof tv);
				info1 = proc_info_get(ppid);
				info2 = proc_info_add(pid, &tv);
				if (!(opt_flags & OPT_QUIET) &&
					(((opt_flags & OPT_EV_FORK) && !is_thread) ||
					 ((opt_flags & OPT_EV_CLNE) && is_thread))) {
					if (info1 != NULL && info2 != NULL) {
						const char * const type = is_thread ? "clone" : "fork";

						row_increment();
						(void)printf("%s %-5.5s %*d %s%sparent %8s %s%s%s\n",
							when,
							type,
							pid_size, ppid,
							extra_info(ppid),
							(opt_flags & OPT_GLYPH) ? "\u252c" : "",
							"",
							info1->kernel_thread ? "[" : "",
							info1->cmdline,
							info1->kernel_thread ? "]" : "");
						row_increment();
						(void)printf("%s %-5.5s %*d %s%s%6.6s %8s %s%s%s\n",
							when,
							type,
							pid_size, pid,
							extra_info(pid),
							(opt_flags & OPT_GLYPH) ? "\u2514" : "",
							is_thread ? "thread" : "child ",
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
				pgrp = getpgid(pid);
				if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
					break;
				info1 = proc_info_update(pid);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_EXEC)) {
					row_increment();
					(void)printf("%s exec  %*d %s%s       %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						(opt_flags & OPT_GLYPH) ? "\u2192" : "",
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,5,0)
			case PROC_EVENT_NONZERO_EXIT:
#endif
			case PROC_EVENT_EXIT:
				proc_stats_account(proc_ev->event_data.exit.process_pid, STAT_EXIT);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_EXIT)) {
					pid = proc_ev->event_data.exit.process_pid;
					pgrp = getpgid(pid);
					if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
						break;
					info1 = proc_info_get(pid);
					if (info1->start.tv_sec) {
						double d1, d2;

						if (gettimeofday(&tv, NULL) < 0) {
							(void)memset(&tv, 0, sizeof tv);
						}
						d1 = timeval_to_double(&info1->start);
						d2 = timeval_to_double(&tv);
						(void)snprintf(duration, sizeof(duration), "%8s", secs_to_str(d2 - d1));
					} else {
						(void)snprintf(duration, sizeof(duration), "unknown");
					}
					row_increment();
					(void)printf("%s exit  %*d %s%s%6d %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						(opt_flags & OPT_GLYPH) ? "\u21e5" : "",
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
					pgrp = getpgid(pid);
					if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
						break;
					if (proc_ev->what == PROC_EVENT_UID) {
						(void)printf("%s uid   %*d %s%s%6s %8s %s%s%s\n",
							when,
							pid_size, pid,
							extra_info(pid),
							(opt_flags & OPT_GLYPH) ? " " : "",
							get_username(proc_ev->event_data.id.e.euid),
							"",
							info1->kernel_thread ? "[" : "",
							info1->cmdline,
							info1->kernel_thread ? "]" : "");
					} else {
						(void)printf("%s gid   %*d %6s %s%8s %s%s%s\n",
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
					pgrp = getpgid(pid);
					if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
						break;
					(void)printf("%s sid   %*d %s%s%6d %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						(opt_flags & OPT_GLYPH) ? " " : "",
						proc_ev->event_data.sid.process_pid,
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "");
				}
				break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
			case PROC_EVENT_COREDUMP:
				proc_stats_account(proc_ev->event_data.coredump.process_pid, STAT_CORE);
				if (!(opt_flags & OPT_QUIET) && (opt_flags & OPT_EV_CORE)) {
					pid = proc_ev->event_data.coredump.process_pid;
					pgrp = getpgid(pid);
					if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
						break;
					info1 = proc_info_get(pid);
					row_increment();
					(void)printf("%s core  %*d %s%s       %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						(opt_flags & OPT_GLYPH) ? "\u2620" : "",
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
					pgrp = getpgid(pid);
					if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
						break;
					info1 = proc_info_get(pid);
					row_increment();
					(void)printf("%s ptrce %*d %s%s%6s %8s %s%s%s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						(opt_flags & OPT_GLYPH) ? " " : "",
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
					pgrp = getpgid(pid);
					if ((opt_pgrp >= 0) && (opt_pgrp != pgrp))
						break;
					info1 = proc_info_get(pid);
					comm = proc_cmdline(pid);
					row_increment();

					(void)printf("%s comm  %*d %s%s%s       %8s %s%s%s -> %s\n",
						when,
						pid_size, pid,
						extra_info(pid),
						(opt_flags & OPT_GLYPH) ? "\u21bb" : "",
						"",
						"",
						info1->kernel_thread ? "[" : "",
						info1->cmdline,
						info1->kernel_thread ? "]" : "",
						comm);
					free_proc_comm(comm);
					proc_info_update(pid);
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
	(void)printf("%s, version %s\n\n", APP_NAME, VERSION);
	(void)printf("usage: %s [-c|-d|-D|-e|-E|-g|-h|-l|-s|-S|-q|-x|-X]\n", argv[0]);
	(void)printf(
		"-c\tuse task comm field for process name.\n"
		"-d\tstrip off directory path from process name.\n"
		"-D\tspecify run duration in seconds.\n"
		"-e\tselect which events to monitor.\n"
		"-E\tequivalent to -e all.\n"
		"-g\tshow glyphs for event types.\n"
		"-h\tshow this help.\n"
		"-l\tforce stdout line buffering.\n"
		"-r\trun with real time FIFO scheduler.\n"
		"-s\tshow short process name.\n"
		"-S\tshow event statistics at end of the run.\n"
		"-q\trun quietly and enable -S option.\n"
		"-x\tshow extra process information.\n"
		"-X\tequivalent to -EgrSx.\n");
}

/*
 *  parse_ev()
 *	parse event strings, turn into flag mask
 */
static int parse_ev(char * const arg)
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
			(void)fprintf(stderr, "Unknown event '%s'. Allowed events:", token);
			for (i = 0; ev_map[i].event; i++)
				(void)printf(" %s", ev_map[i].event);
			(void)printf("\n");
			return -1;
		}
	}
	return 0;
}

int main(int argc, char * const argv[])
{
	size_t i;
	int sock, ret = EXIT_FAILURE;
	struct sigaction new_action;

	for (;;) {
		const int c = getopt(argc, argv, "cdD:e:EghlrsSp:qxX");

		if (c == -1)
			break;
		switch (c) {
		case 'c':
			opt_flags |= OPT_COMM;
			break;
		case 'd':
			opt_flags |= OPT_CMD_DIRNAME_STRIP;
			break;
		case 'D':
			opt_duration = strtol(optarg, NULL, 10);
			if (opt_duration <= 0) {
				(void)fprintf(stderr, "Illegal duration '%s'.\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'e':
			if (parse_ev(optarg) < 0)
				exit(EXIT_FAILURE);
			break;
		case 'E':
			opt_flags |= OPT_EV_ALL;
			break;
		case 'g':
			opt_flags |= OPT_GLYPH;
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
		case 'p':
			opt_pgrp = strtol(optarg, NULL, 10);
			if (opt_pgrp < 0) {
				(void)fprintf(stderr, "Illegal pgroup '%s'.\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'q':
			opt_flags |= OPT_QUIET;
			break;
		case 'l':
			if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) {
				(void)fprintf(stderr, "Error setting line buffering.\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'x':
			opt_flags |= OPT_EXTRA;
			break;
		case 'X':
			opt_flags |= (OPT_EV_ALL | OPT_GLYPH | OPT_STATS | OPT_EXTRA | OPT_REALTIME);
			break;
		default:
			show_help(argv);
			exit(EXIT_FAILURE);
		}
	}

	if ((opt_flags & OPT_EV_MASK) == 0)
		opt_flags |= (OPT_EV_FORK | OPT_EV_EXEC | OPT_EV_EXIT | OPT_EV_CLNE | OPT_EV_PTRC);

	if (geteuid() != 0) {
		(void)fprintf(stderr, "Need to run with root access.\n");
		goto abort_sock;
	}

	(void)memset(&new_action, 0, sizeof(new_action));
	for (i = 0; signals[i] != -1; i++) {
		new_action.sa_handler = handle_sig;
		sigemptyset(&new_action.sa_mask);
		new_action.sa_flags = 0;

		if (sigaction(signals[i], &new_action, NULL) < 0) {
			(void)fprintf(stderr, "sigaction failed: errno=%d (%s)\n",
				errno, strerror(errno));
			goto abort_sock;
		}
	}

	sane_procs = sane_proc_pid_info();

	if (proc_info_load() < 0) {
		(void)fprintf(stderr, "Cannot load process cache. Is /proc mounted?\n");
		goto abort_sock;
	}

	if (opt_flags & OPT_REALTIME) {
		struct sched_param param;
		int max_prio;
		const int policy = SCHED_FIFO;

		max_prio = sched_get_priority_max(policy);
		if (max_prio < 0) {
			(void)fprintf(stderr, "sched_get_priority_max failed: errno=%d (%s)\n",
				errno, strerror(errno));
			goto abort_sock;
		}

		(void)memset(&param, 0, sizeof(param));
		param.sched_priority = max_prio;
		if (sched_setscheduler(getpid(), policy, &param) < 0) {
			(void)fprintf(stderr, "sched_setscheduler failed: errno=%d (%s)\n",
				errno, strerror(errno));
			goto abort_sock;
		}
	}

	sock = netlink_connect();
	if (sock == -EPROTONOSUPPORT) {
		(void)fprintf(stderr, "Cannot show process activity with this kernel, netlink required.\n");
		goto abort_sock;
	}
	/* Handle other failures */
	if (sock < 0)
		goto abort_sock;

	if (netlink_listen(sock) < 0) {
		(void)fprintf(stderr, "netlink listen failed: errno=%d (%s)\n",
			errno, strerror(errno));
		goto close_abort;
	}

	if (opt_duration > 0)
		(void)alarm(opt_duration);

	if (monitor(sock) == 0) {
		ret = EXIT_SUCCESS;
		proc_stats_report();
	}

close_abort:
	(void)close(sock);
abort_sock:
	proc_info_unload();
	proc_stats_free();
	uid_name_info_free();
	tty_name_info_free();

	exit(ret);
}
