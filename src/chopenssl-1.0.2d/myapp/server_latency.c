/* 
 * copy the file here: openssl-1.0.2d/myapp
 * cc -g -ldl -I..  -I../include/ server_latency.c ../libssl.a ../libcrypto.a -o ssl_server
 *
 * ./ssl_server <port number>
 * It will read a file ïnput.txt from current directory and send to the client
 * over ssl. It will use newreq.pem (in the same folder) for ssl handshake
 */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include<fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define BUFFSIZZ  50000

#define FAIL    -1

static long int copy_to_buff(char *f,char *b, long int startfrom, long int
			     readtill)
{

        int s; FILE *fp;
	long int i;
	memset(b, 0, BUFFSIZZ);
	fp = fopen(f, "r");
	if(!fp)
	{
		fprintf(stderr,"error opening the file \n");
		return 0;
	}
	fseek(fp, startfrom, SEEK_SET);
	fread(b, readtill, 1, fp);

	fclose(fp);
	return readtill;
}

long int file_size(char *f)
{
	FILE *fp;
	long int size;
	fp = fopen(f, "r");
	fseek(fp, 0L, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	return size;
}

int OpenListener(int port)
{
    int sd, j = 1;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *)&j, sizeof j);

    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        return -1;
    }
    if ( listen(sd, 128) != 0 )
    {
        perror("Can't configure listening port");
        return -1;
    }
    return sd;
}

SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx;
    SSL_library_init();
    OpenSSL_add_all_algorithms();	/* load & register all cryptos, etc. */
    SSL_load_error_strings();		/* load all error messages */
    method = TLSv1_2_server_method();	/* keep changing this */
    ctx = SSL_CTX_new(method);		/* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);/* Get certificates (if available) */
    if ( cert != NULL )
    {
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}

void Servlet(SSL* ssl, char *datafile, int bufflen)/* Serve the connection */
{
    char buf[BUFFSIZZ];
    char reply[BUFFSIZZ];
    int sd;
    struct timeval start, end;
    long int len = 0, bytes, filesize, copied =0, readtill = BUFFSIZZ,
	     remaining, written_bytes;
    filesize = file_size(datafile);
    if(filesize < readtill)
	readtill = filesize;
    if ( SSL_accept(ssl) == FAIL ) {
        printf("SSL_accept fail \n");
        ERR_print_errors_fp(stderr);
    } else {
	    while (1) {
	        SSL_read(ssl, buf, bufflen);
	        SSL_write(ssl,buf,bufflen);
	    }
    }

    sd = SSL_get_fd(ssl);	/* get socket connection */
    SSL_free(ssl);		/* release SSL state */
    shutdown(sd,2);
    close(sd);			/* close connection */
}

int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    char *portnum, choice;
    char datafile[25] = {0};
    int bufflen;

    if ( count != 4 )
    {
        printf("Usage: %s <portnum> <file> <buf len>\n", strings[0]);
        exit(0);
    }
    portnum = strings[1];
    memcpy(datafile, strings[2],(strlen(strings[2])));
    datafile[strlen(strings[2])] = '\0';
    bufflen = atoi(strings[3]);
    ctx = InitServerCTX();				/* initialize SSL */
    LoadCertificates(ctx, "newreq.pem", "newreq.pem");	/* load certs */
    SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256");	/* keep changing this */
    server = OpenListener(atoi(portnum));		/* create server socket */
    if (server < 0)
        exit(0);
    while (1)
    {   struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);
	if (fork() == 0) {
	        ssl = SSL_new(ctx);
	        SSL_set_fd(ssl, client);
	        Servlet(ssl, datafile, bufflen);
		exit(0);
	}
	close(client);
    }
done:
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}

