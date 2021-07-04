/*
 * Utility functions for iscsictl CLI
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* for dirent */
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>

#define PROC_DIR	"/proc"
#define MAX_PROC_FILE_PATH 128

/**
 * signal_pid_by_name -- find the process with started with cmd <name> and
 * 	send it the signal <signo>.
 * @name: the cmd name which started the process
 * @signo: signal number to be sent
 *
 * This implementation uses Linux's /proc/ system
 */
static int signal_pid_by_name(char *name, int signo)
{
	DIR    *dirp;
	struct dirent *de;
	pid_t   self;
	int     cnt = 0;

	self = getpid();

	dirp = opendir(PROC_DIR);
	if (!dirp) {
		perror(PROC_DIR);
		return -1;
	}

	while ((de = readdir(dirp))) {
		char	fbuffer[MAX_PROC_FILE_PATH];
		char    *buffer;
		int     len;
		FILE   *fp;
		char   *cmd;
		pid_t   pid;

		pid = (pid_t) atoi(de->d_name);
		if (!pid || pid == self)
			continue;

		len = snprintf(fbuffer, MAX_PROC_FILE_PATH,
			       PROC_DIR "/%d/cmdline", pid);
		if (len <= 0)
			continue;
		fbuffer[len] = 0;
		fp = fopen(fbuffer, "r");
		if (!fp)
			continue;

		len = 1;
		while (fgetc(fp) != EOF)
			len++;

		if (!len) {
			fclose(fp);
			continue;
		}

		fseek(fp, 0, SEEK_SET);

		/* cmdline arguments separated by nulls */
		buffer = calloc(1, len);
		if (!buffer) {
			fclose(fp);
			return -ENOMEM;
		}
		fscanf(fp, "%s", buffer);
		fclose(fp);

		cmd = buffer;
		for (len--; len; len--) {
			if (buffer[len] == '/') {
				cmd = buffer + len + 1;
				break;
			}
		}

		if (!strlen(cmd)) {
			free(buffer);
			continue;
		}
		if (!strcmp(cmd, name)) {
			cnt++;
			kill(pid, signo);
		}
		free(buffer);
	}
	return cnt;
}

int iscsictl_update_isns_client(void)
{
	int     rv;
	rv = signal_pid_by_name("chisns", SIGUSR2);
	if (rv)
		printf("%d isns client updated.\n", rv);
	return 0;
}
