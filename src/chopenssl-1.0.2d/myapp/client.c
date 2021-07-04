/*
 * copy the file here: openssl-1.0.2d/myapp
 * cc -g -ldl -I..  -I../include/ ssl_client.c ../libssl.a ../libcrypto.a -o ssl_client
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
    OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
    SSL_load_error_strings();			/* Bring in and register error messages */
    //method = SSLv2_client_method();		/* Create new client-method instance */
    method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);			/* Create new context */
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

    cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);							/* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);							/* free the malloc'ed string */
        X509_free(cert);					/* free the malloc'ed certificate copy */
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
    char datafile[25] = {0};
    int wtof = 1;
    if ( count < 3 || count > 4)
    {
        printf("usage: %s <hostname> <portnum> <outfile>\n", strings[0]);
        exit(0);
    }
	hostname=strings[1];
	portnum=strings[2];
	if (strings[3] != NULL)
		memcpy(datafile, strings[3], strlen(strings[3]));
	else
		wtof = 0;

    ctx = InitCTX();
    SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256");
    //SSL_CTX_set_cipher_list(ctx, "AES256-SHA");
    //SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-SHA384");
    int myctr = 0;
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);				/* create new SSL connection state */
    SSL_set_fd(ssl, server);			/* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )			/* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
#define PLAIN_READ 0 
#if PLAIN_READ
	bytes = recv(SSL_get_fd(ssl), buf, sizeof(buf), 0);
	printf("\nEncrypted TLS PDU: Hdr + IV + data + MAC + padding\n");
            int i =0;
            for(i = 0;i<bytes;i++)
            {
                if(i%8 == 0) printf("\n");
                printf("%2X   ",buf[i]& 0xFF);
            }

#else
	while(1){
        bytes = SSL_read(ssl, buf, sizeof(buf));/* get reply & decrypt */
#endif
	if (wtof && copy_buff_to_file(datafile, buf, bytes) < 1)
		break;
	read_bytes += bytes;
	if(bytes == 0)
		break;
	}
        SSL_free(ssl);	/* release connection state */
    }
    close(server);	/* close socket */
    SSL_CTX_free(ctx);	/* release context */
}

