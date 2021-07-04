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

/* Interval and count parameters */
long interval = -1, count = 0,  loop=1;

void usage(char *str)
{
	printf("Usage : %s interval count [1] \n", str);
	printf("        interal : time in sec between each report \n");
	printf("        count : number of report generates \n");
	printf("        1 : report all counter.  otherwise check only error counter \n");
	
	exit(1);
}

typedef struct _hash {
	char *name;
	char *val;
	struct _hash *next;
} Hash, *pHash;

typedef struct _hashTable {
	int hashSize;
	int nameSize;
	int valSize;
	pHash phash;
} HashTable, *pHashTable;

typedef struct _list {
	struct _list *next;
	char name[256];
} List, *pList;

typedef struct _listHead {
	pList head;
	pList tail;
} ListHead, *pListHead;


pHashTable createHashTable(int s)
{
	int i;
	pHashTable pht = (pHashTable)malloc(sizeof(HashTable));
	pht->hashSize = s;
	pht->nameSize= 128;
	pht->valSize=128;
	
	pht->phash = (pHash)malloc(sizeof(Hash) * s);
	for (i = 0; i < s; i++) {
		pht->phash[i].name = (char *)malloc(sizeof(char) * pht->nameSize);
		pht->phash[i].val = (char *)malloc(sizeof(char) * pht->valSize);
		memset(pht->phash[i].name, 0, sizeof(char) * pht->nameSize);
		memset(pht->phash[i].val, 0, sizeof(char) * pht->valSize);
		pht->phash[i].next = NULL;
	}
	return pht;
}


#define BASE (256)
unsigned long
hash(const char *s, unsigned long m)
{
	unsigned long h;
	unsigned const char *us;

	/* cast s to unsigned const char * */
	/* this ensures that elements of s will be treated as having values >= 0 */
	us = (unsigned const char *) s;
 
	h = 0;
	while(*us != '\0') {
		h = (h * BASE + *us) % m;
		us++;
	} 
	return h;
}

char *secureHash(pHashTable pht, char *key)
{
	unsigned long h = hash(key, pht->hashSize);
	if (pht->phash[h].name[0] == '\0') {
		strncpy(pht->phash[h].name, key, pht->nameSize);
		return pht->phash[h].val;
	}
	else if (!strcmp(pht->phash[h].name, key)) {
		return pht->phash[h].val;
	} else {
		// Collision Handling by Separate Chain
		pHash ph0;
		pHash ph = (pHash)malloc(sizeof(Hash));
		ph->name = (char *)malloc(sizeof(char) * pht->nameSize);
		ph->val = (char *)malloc(sizeof(char) * pht->valSize);
		ph->next = NULL;

		strncpy(ph->name, key, pht->nameSize);
		memset(ph->val, 0, sizeof(char) * pht->valSize);

		// add bucket to tail
		if (pht->phash[h].next == NULL) {
			pht->phash[h].next = ph;
		} else {
			ph0 = pht->phash[h].next;
			while (ph0->next != NULL) {
				ph0 = ph0->next;
			}
			ph0->next = ph;
		}
		return ph->val;
	}
}

char *getHashVal(pHashTable pht, char *key)
{
	unsigned long h = hash(key, pht->hashSize);
	if (!strcmp(pht->phash[h].name, key))
	{
		return pht->phash[h].val;
	} else {
		// search chain
		pHash ph = pht->phash[h].next;
		while (ph != NULL) {
			if (!strcmp(ph->name, key))
				return ph->val;
			ph = ph->next;
		}
		return NULL;
	}
}

int isSpace(char c)
{
	if (c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v' || c == '\0' || c == ' ')
		return 1;
	return 0;
}

pList addList(pListHead h) {
	if (h == NULL)
		return NULL;
		
	pList p = (pList)malloc(sizeof(List));
	memset(p, 0, sizeof(pList));
	if (h->head == NULL) {
		h->head = p;
		h->tail = p;
	} else {
		h->tail->next = p;
		h->tail = p;
	}
	return p;
}

void mergeList(pListHead p0, pListHead p1)
{
	if (p0-> head == NULL) {
		p0-> head = p1->head;
		p0-> tail = p1->tail;
	} else {
		p0->tail->next = p1->head;
		p0->tail = p1->tail;
	}
	free(p1);
}

pListHead createListHead() {
	pListHead p = (pListHead)malloc(sizeof(ListHead));
	memset(p, 0, sizeof(ListHead));
	return p;
}

void freeList(pListHead head){
	pList p;
	if (head == NULL) return;
	
	p = head->head;
	while (p != NULL)
	{
		pList d = p;
		p = p->next;
		free (d);
	}
	free (head);
}

pListHead stringSplitN(char *line, char delimiter)
{
	int i, j;
	pListHead plh;
	pList plist=NULL; 

	plh = createListHead();

	j=0;	
	for (i=0; i <= strlen(line); i++)
	{
		// if space or NULL found, assign NULL into element
		// but do not add empty for whitespace
		if (j == 0) {
			// skip whitespace
			if(isSpace(line[i])) continue;
			plist = addList(plh); /* add element */
		}
		if( line[i] == delimiter)
        {
            plist->name[j] = '\0';
            j=0;    //for next word, set index to 0
        } else {
            plist->name[j++]=line[i];
        }
	}
	plist = plh->head;
	while (plist != NULL) {
		if (isSpace(plist->name[strlen(plist->name)-1]) )
			plist->name[strlen(plist->name)-1] = '\0';
		plist = plist->next;
	}
	return plh;
}

pListHead popenList(char *cmd)
{	
	FILE *fp;
	pListHead phead, phead0;
	char output[1000];

	fp = popen(cmd, "r");
	if (fp == NULL) {
		printf("%s Failed \n", cmd );
		exit(1);
	}
	phead = createListHead();
	while (fgets(output, sizeof(output)-1, fp) != NULL) {
		phead0 = stringSplitN(output, ' ');  // head of list , and return head of list. 
													// both should be the same except firt NULL.
		mergeList(phead, phead0);
 	}
	pclose(fp);
	return phead;
}

void printDate()
{
	char buf[128];
	time_t t;
	struct tm *tmp;
	
	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL) {
		printf("0000 ");
	} else {
		if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tmp) == 0) {
			printf("0000 ");
		} else {
           printf("%s ", buf);
		}
	}
}

int getDriverName(char *ethtool, char *dev, char *dname)
{
	char cmd[128];
	FILE *fp;
	int ret;

	sprintf(cmd, "%s -i %s | grep driver", ethtool, dev);
	fp = popen(cmd, "r");
	if (fp == NULL) {
		printf("%s Failed \n", cmd );
		exit(1);
	}
	if ( fgets(dname, 50, fp) == NULL) {
    	sprintf(dname, "unknown");
		ret=0;
	} else {
		if (isSpace(dname[strlen(dname)-1]) )
			dname[strlen(dname)-1] = '\0';

		ret=1;
	}
	/* close */
	pclose(fp);
	return ret;
}

int main(int argc, char **argv)
{
	FILE *fp;
	char ethtool[100];
	char output[1000];
	char *token;
	pListHead pDevList;
	pListHead cxgb4_list;
	pListHead qstats_list;
	pListHead ethtool_list;
	pList plist, plist2;
	int hashSize = 2049;
	char hashKey[512];
	int all_check=0;

	long interval = -1, count = 0,  loop=0;
	
	pHashTable hashTableEth = createHashTable(hashSize);
	pHashTable hashTableQst = createHashTable(hashSize);
	
	int opt = 0, i, actset = FALSE;
	double	elapsed;		/* actual seconds between screen updates */
	
	while (++opt < argc) {
		if (interval < 0) {
			/* Get interval */
			if (strspn(argv[opt], DIGITS) != strlen(argv[opt])) {
				usage(argv[0]);
			}
			interval = atol(argv[opt]);
			count = -1;
		}

		else if (count < 0) {
			/* Get count value */
			if (strspn(argv[opt], DIGITS) != strlen(argv[opt])){
				usage(argv[0]);
			}
			count = atol(argv[opt]);
		}
		else if (all_check <= 0) {
			/* Get count value */
			if (strspn(argv[opt], DIGITS) != strlen(argv[opt])) {
				usage(argv[0]);
			}
			all_check = atol(argv[opt]);
		}

		else {
			usage(argv[0]);
		}
	}
	if (interval < 1) {
		/* Interval not set => display stats since boot time */
		interval = 2;
	}

	if (count <= 0) {
		loop=1;
	}

	printf("interval=%d count=%d Check %s \n", interval, count, (all_check) ? "all counter" : "error counter only");

	/* 
		which ethtool 
	*/
	fp = popen("which ethtool", "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		exit(1);
	}
	
	if ( fgets(ethtool, sizeof(ethtool)-1, fp) == NULL) {
    	printf("Cannot find etherool");
		exit(1);
	}
	/* close */
	pclose(fp);

	// remove \n
	if (isSpace(ethtool[strlen(ethtool)-1]) )
		ethtool[strlen(ethtool)-1] = '\0';

	/* 
	   pDevList=`ls /sys/class/net/` 
	*/
	pDevList=popenList("ls /sys/class/net/");

	/*
		cxgb4_list=`ls -d /sys/kernel/debug/cxgb4/*`
	*/
	cxgb4_list=popenList("ls -d /sys/kernel/debug/cxgb4/*");

	for (i = 0; i < count || loop; i++)
	{
		plist = pDevList->head;
		while (plist != NULL) {
			if (strcmp(plist->name, "lo") &&
				strcmp(plist->name, "virbr0") &&
				strcmp(plist->name, "virbr0-nic") ) {
				
				char cmd[512];
				sprintf(cmd, "%s -S %s", ethtool, plist->name);
				fp = popen(cmd, "r");
				if (fp == NULL) {
					printf("%s Failed \n", cmd );
					exit(1);
				}
				while (fgets(output, sizeof(output)-1, fp) != NULL) {
					char *pVal;
					pList p1, p2;
					pListHead plh;
					plh = stringSplitN(output, ':');  // head of list , and return head of list. 
					
					p1 = plh->head; // parameter name
					if (p1 == NULL) {
						freeList(plh);
						 continue;
					}
					p2 = p1->next;  // new value
					if (p2 == NULL) {
						freeList(plh);
						continue;
					}
					
					char *comp1 = strcasestr(p1->name, "err");
					char *comp2 = strcasestr(p1->name, "drop");
					char *comp3 = strcasestr(p1->name, "retr");

					if (comp1 || comp2 || comp3 || all_check ) {
						sprintf(hashKey, "%s%s", plist->name, p1->name); 
						if (i == 0) {
							pVal = secureHash(hashTableEth, hashKey);
							if (!pVal) {
								printf("Bug secureHash \n");
								exit(1);
							}
						} else {		
							// compare
							pVal = getHashVal(hashTableEth, hashKey);  // previous value
							if (!pVal) {
								printf("Bug getHashVal \n");
								exit(1);
							}	
							if (strncmp(pVal, p2->name, hashTableEth->valSize)) {
								char dname[256];
								printDate();
								getDriverName(ethtool, plist->name, dname);
								if (strstr(dname, "cxg")) {
									printf("Chelsio %s", dname);
								} else {
									printf("Another %s", dname);
								}
								printf(" %s : %s %s -> %s \n", plist->name, p1->name, pVal, p2->name);
							}
						}
						// store to hash table
						strncpy(pVal, p2->name, hashTableEth->nameSize);
					}
					freeList(plh);
				}
				pclose(fp);
			} // if
			plist = plist->next;
		} // while pDevList

		// qstats
		plist = cxgb4_list->head;
		while (plist != NULL) {
			int qtype_index=1;
			char qtype[128];
			char cmd[512];
			qtype[0]='0';

			sprintf(cmd, "cat %s/qstats", plist->name);
			fp = popen(cmd, "r");
			if (fp == NULL) {
				printf("%s Failed \n", cmd );
				exit(1);
			}

			while (fgets(output, sizeof(output)-1, fp) != NULL) {
				char *pVal;
				pList p1, p2;
				pListHead plh;
				int j=1; // column start from 1
				int qtype_flag=0;
				char *parameterName=NULL;
				
				plh = stringSplitN(output, ' ');  // split by space. return List 
				p1 = plh->head;
				while (p1 != NULL) {
		/* 
				Qtype:       <qtype >  ..
				<Para name>  val1(j=2)  val2(j=3) ...
				...

				QType:               Ethernet         Ethernet         Ethernet         Ethernet
				.... < qtype_index = 1 > 
				QType:               Ethernet         Ethernet         Ethernet         Ethernet
				.... < qtype_index = 2 >
				

		*/
					if (j == 1) { // 1st column. i.e "QType:" or <parameterName>.
						char *comp1 = strstr(p1->name, "QType");
//						char *comp2 = strstr(p1->name, "Interface");
						if (comp1) {
							qtype_flag=1; // flag of Line of "Qtype"
						} else {
							parameterName = p1->name; // parameterName such as TxPkts
						}
					} else {
						if (j == 2 && qtype_flag) { // This line is name of qtype such as "Ethernet"
							if (strcmp(qtype, p1->name)) { 
								// change qtype name
								strcpy(qtype, p1->name);
								qtype_index=1;
							}  else  {
								qtype_index++;
							}
						}
						else if ( !qtype_flag ) {  // this line has real value
							char *comp1 = strcasestr(parameterName, "Err");
							char *comp2 = strcasestr(parameterName, "Drop");
							if (comp1 || comp2 || all_check ) {
								// key is QType name + index + parameter name + column#. Interface name is not used
								sprintf(hashKey, "%s%d%s%d", qtype, qtype_index, parameterName, j); 
								if (i == 0) {
									pVal = secureHash(hashTableQst, hashKey);
								} else {
									// compare value
									pVal = getHashVal(hashTableQst, hashKey);	
									if (pVal == NULL){
										printf("Bug NULL : %s //%s,%d,%s,%d \n", 
													p1->name, qtype, qtype_index, parameterName, j);
										exit(1);
									}
									if (strncmp(pVal, p1->name, hashTableQst->valSize)) {
										char dname[256];
										printDate();
										printf("qstats %s(%d) %s(%d): %s -> %s  \n",
											qtype, qtype_index, parameterName, j-1, pVal, p1->name);
									}
								}
								// store to hash table
								strncpy(pVal, p1->name, hashTableQst->nameSize);
							}
						}
					}
					p1 = p1->next;
					j++;
				}
				freeList(plh);
			}
			pclose(fp);
			plist = plist->next;
		}
		sleep (interval);
	}
	return 0;
}


