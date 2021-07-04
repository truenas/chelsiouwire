/*
 * copy the file here: openssl-1.0.2d/myapp
 * cc -g -ldl -I..  -I../include/ client_latency.c ../libssl.a ../libcrypto.a -o ssl_client
 *
 *./ssl_client <ip> <port>
 * It will read over ssl from server and write to a file written.txt in current directory 
 **/

#include <stdio.h>
#include <errno.h>
#include<fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define BUFFSIZZ  50000
#define FAIL    -1

static long int copy_buff_to_file(char *f,char *b, long int len)
{

        int s;
	long int i;
        s = open(f, O_RDWR|O_CREAT|O_APPEND, S_IRWXU| S_IRWXG | S_IRWXO);
        if(s<0)
        {
                fprintf(stderr,"error opening the file \n");
                return 0;
        }
	if((i = write(s, b, len))< 0)
	{
                printf("%s: error in writing to file %s (%s)\n", __func__, f, strerror(errno));
                return -1;
        }

        close(s);
        return i;
}

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx;
    SSL_library_init();	
    OpenSSL_add_all_algorithms();	/* Load cryptos, et.al. */
    SSL_load_error_strings();	/* Bring in and register error messages */
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);		/* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        free(line);			/* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        free(line);			/* free the malloc'ed string */
        X509_free(cert);	/* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[BUFFSIZZ];
    long int bytes, read_bytes= 0;
    char *hostname, *portnum;
    struct timeval start, end;
    char datafile[25] = {0};
    int min =100, max =0, avg =0, val;
    static int run=0;
    int buffer_len, iteration;
    int wtof = 1;
    if ( count < 3 || count > 5)
    {
        printf("usage: %s <hostname> <portnum> <buf len> <Iterations>\n", strings[0]);
        exit(0);
    }
	hostname=strings[1];
	portnum=strings[2];
	buffer_len = atoi(strings[3]);
	iteration = atoi(strings[4]);

    ctx = InitCTX();
    SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256");
    int myctr = 0;
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);		/* create new SSL connection state */
    SSL_set_fd(ssl, server);	/* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )	/* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   
	while(1){
	    gettimeofday(&start, NULL);
       	    SSL_write(ssl, buf, buffer_len);
            SSL_read(ssl, buf, buffer_len);/* get reply & decrypt */
    	    gettimeofday(&end, NULL);

	    val = ((end.tv_sec * 1000000 + end.tv_usec)
                  - (start.tv_sec * 1000000 + start.tv_usec));

	    if (val < min)
		min = val;
	    if (val > max)
		max = val;

	    if(run++ >= iteration)
		break;
	}

	printf("RTT min %ld max:%ld \n",min,max); 
        SSL_free(ssl);	/* release connection state */
    }
    close(server);	/* close socket */
    SSL_CTX_free(ctx);	/* release context */
}

