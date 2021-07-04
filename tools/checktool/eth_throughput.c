#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <time.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define FALSE	0
#define DIGITS			"0123456789"

struct sigaction alrm_act, int_act;
int sigint_caught = 0;

int	networks = 0;  	/* number of networks in system  */


/* Number of ticks per second */
unsigned int hz;

/* Interval and count parameters */
long interval = -1, count = 0,  loop=1;

#define NETMAX 32

struct net_stat {
	unsigned long if_name[17];
	unsigned long long if_ibytes;
	unsigned long long if_obytes;
	unsigned long long if_ipackets;
	unsigned long long if_opackets;
	unsigned long if_ierrs;
	unsigned long if_oerrs;
	unsigned long if_idrop;   
	unsigned long if_ififo;   
	unsigned long if_iframe;   
	unsigned long if_odrop;   
	unsigned long if_ofifo;   
	unsigned long if_ocarrier;   
	unsigned long if_ocolls;   
} ;

struct data {
	struct net_stat ifnets[NETMAX];
	
	struct timeval tv;
	double time;
} database[2], *p, *q;


void usage(char *progname)
{
	fprintf(stderr, "Usage: %s [ <interval> [ <count> ] ]\n", progname);
	exit(1);
}


/* Convert secs + micro secs to a double */
double	doubletime(void)
{
	gettimeofday(&p->tv, 0);
	return((double)p->tv.tv_sec + p->tv.tv_usec * 1.0e-6);
}

void strip_spaces(char *s)
{
char *p;
int spaced=1;

	p=s;
	for(p=s;*p!=0;p++) {
		if(*p == ':')
			*p=' ';
		if(*p != ' ') {
			*s=*p;
			s++;
			spaced=0;
		} else if(spaced) {
			/* do no thing as this is second space */
			} else {
				*s=*p;
				s++;
				spaced=1;
			}

	}
	*s = 0;
}

void proc_net()
{
	static FILE *fp = (FILE *)-1;
	char buf[1024];
	int i=0;
	int ret;
	unsigned long junk;

	if( fp == (FILE *)-1) {
           if( (fp = fopen("/proc/net/dev","r")) == NULL) {
		error("failed to open - /proc/net/dev");
		networks=0;
		return;
	   }
	}

	if(fgets(buf,1024,fp) == NULL) goto end; /* throw away the header lines */
	if(fgets(buf,1024,fp) == NULL) goto end; /* throw away the header lines */
/*
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1956      30    0    0    0     0          0         0     1956      30    0    0    0     0       0          0
  eth0:       0       0    0    0    0     0          0         0   458718       0  781    0    0     0     781          0
  sit0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  eth1:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
*/
	for(i=0;i<NETMAX;i++) {
		if(fgets(buf,1024,fp) == NULL)
			break;
		strip_spaces(buf);
				     /* 1   2   3    4   5   6   7   8   9   10   11   12  13  14  15  16 */
		ret = sscanf(&buf[0], "%s %llu %llu %lu %lu %lu %lu %lu %lu %llu %llu %lu %lu %lu %lu %lu",
		(char *)&p->ifnets[i].if_name,
			&p->ifnets[i].if_ibytes,
			&p->ifnets[i].if_ipackets,
			&p->ifnets[i].if_ierrs,
			&p->ifnets[i].if_idrop,
			&p->ifnets[i].if_ififo,
			&p->ifnets[i].if_iframe,
			&junk,
			&junk,
			&p->ifnets[i].if_obytes,
			&p->ifnets[i].if_opackets,
			&p->ifnets[i].if_oerrs,
			&p->ifnets[i].if_odrop,
			&p->ifnets[i].if_ofifo,
			&p->ifnets[i].if_ocolls,
			&p->ifnets[i].if_ocarrier
			);

		if(ret != 16) 
			fprintf(stderr,"sscanf wanted 16 returned = %d line=%s\n", ret, (char *)buf);
	}
	
	end:
	rewind(fp);
	networks = i;
}


void alarm_handler(int sig)
{
	alarm(interval);
}


/* only place the q=previous and p=currect pointers are modified */
void switcher(void)
{
	static int	which = 1;
	int i;

	if (which) {
		p = &database[0];
		q = &database[1];
		which = 0;
	} else {
		p = &database[1];
		q = &database[0];
		which = 1;
	}
}


/*
 ***************************************************************************
 * Get number of clock ticks per second.
 ***************************************************************************
 */
void get_HZ(void)
{
	long ticks;

	if ((ticks = sysconf(_SC_CLK_TCK)) == -1) {
		perror("sysconf");
	}

	hz = (unsigned int) ticks;
}


int main(int argc, char **argv)
{
	int opt = 0, i, actset = FALSE;
	double	elapsed;		/* actual seconds between screen updates */
	int curr = 1;

	/* Get HZ */
	get_HZ();


	while (++opt < argc) {
		if (interval < 0) {
			/* Get interval */
			if (strspn(argv[opt], DIGITS) != strlen(argv[opt])) {
				usage(argv[0]);
			}
			interval = atol(argv[opt]);
			if (interval < 0) {
				usage(argv[0]);
			}
			count = -1;
		}

		else if (count <= 0) {
			/* Get count value */
			if ((strspn(argv[opt], DIGITS) != strlen(argv[opt])) ||
			    !interval) {
				usage(argv[0]);
			}
			count = atol(argv[opt]);
			if (count < 1) {
				usage(argv[0]);
			}
			loop=0;
		}

		else {
			usage(argv[0]);
		}
	}
	if (interval < 1) {
		/* Interval not set => display stats since boot time */
		interval = 1;
	}

	switcher();

	/* Set a handler for SIGALRM */
	memset(&alrm_act, 0, sizeof(alrm_act));
	alrm_act.sa_handler = alarm_handler;
	sigaction(SIGALRM, &alrm_act, NULL);
	alarm(interval);

	pause();

	/* Initialise the time stamps for the first loop */
	p->time = doubletime();
	q->time = doubletime();
	proc_net();
	memcpy(q->ifnets, p->ifnets, sizeof(struct net_stat) * networks);

	do {

		p->time = doubletime();
		elapsed = p->time - q->time;

		proc_net();

//		printf( "I/F Name\t  Recv=Mb/s  Trans=Mb/s  packin packout  insize outsize\n ");
		printf( "I/F Name\t  Recv=Mb/s  Trans=Mb/s   packin  packout  \n ");
		for (i = 0; i < networks; i++) {

#define IFDELTA(member) ((float)( (q->ifnets[i].member > p->ifnets[i].member) ? 0 : (p->ifnets[i].member - q->ifnets[i].member)/elapsed) )
#define IFDELTA_ZERO(member1,member2) ((IFDELTA(member1) == 0) || (IFDELTA(member2)== 0)? 0.0 : IFDELTA(member1)/IFDELTA(member2) )

//			printf( "%8s\t%11.2f %11.2f %7.0f %7.0f %7.0f %7.0f \n ",
			printf( "%8s\t%11.2f %11.2f %8.0f %8.0f \n ",
			    &p->ifnets[i].if_name[0],
			    IFDELTA(if_ibytes) / (1024.0 * 1024.) * 8,   
			    IFDELTA(if_obytes) / (1024.0 * 1024.) * 8, 
			    IFDELTA(if_ipackets), 
			    IFDELTA(if_opackets));
			    /*
			    IFDELTA_ZERO(if_ibytes, if_ipackets),
			    IFDELTA_ZERO(if_obytes, if_opackets)
			);
				*/
		}
		printf ("\n");
		fflush(stdout);

		if (count > 0) {
			count--;
		}

		if (count) {
			pause();

			if (sigint_caught) {
				/* SIGINT signal caught => Display average stats */
				count = 0;
				printf("\n");	/* Skip "^C" displayed on screen */
			}
			else {
				curr ^= 1;
			}
		}
		
		switcher();
		sleep (interval);
	}
	while (count || loop);
}

