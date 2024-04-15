/*	srsh-server.c Copyright 2024 Srdjan Rajcevic <srdjan.rajcevic[OF]sectreme.com>
*/
#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/ssl.h>

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>

unsigned int 	cflag = 0,
		kflag = 0,
		pflag = 0; 

/* Default port if none is provided via -p */
char 		*port = "1982";

pthread_t 	th_id;
int 		th_running = 0;

/* Linux support - getprogname(3) is OpenBSDism */
#if __OpenBSD__
void usage(void);
#elif __linux__
void usage(char*);
#endif
void *shell(void*);

int
main(int argc, char *argv[])
{	
	int ch;
	char *cert_file = NULL;
	char *pkey_file = NULL;
	while ((ch = getopt(argc, argv, "c:k:p:")) != -1)
		switch (ch)
		{
		case 'c':
	       		cflag = 1;
			cert_file = optarg;
			break;
	 	case 'k':
			kflag = 1;
			pkey_file = optarg;
			break;
		case 'p':
			pflag = 1;
			port = optarg;
			break;
		case '?':
#if __OpenBSD__
			usage();
#elif __linux__
			usage(argv[0]);
#endif
			return 1;
		}
	if ((optind < 5) || !cflag || !kflag)
	{
#if __OpenBSD__
		usage();
#elif __linux__
		usage(argv[0]);
#endif
		return 1;
	}
	argc -= optind;
	argv += optind;
		
	int sockfd, newsockfd;
	const SSL_METHOD *method = TLS_method();
	SSL_CTX *ctx;
	ctx = SSL_CTX_new(method);
	if (ctx == NULL)
		errx(1, "%s", "Cannot create context");
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
	if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1)
		errx(1, "%s", "Could not load certificate file");
	if (SSL_CTX_use_PrivateKey_file(ctx, pkey_file, SSL_FILETYPE_PEM) != 1)
		errx(1, "%s", "Could not load private key file");
	SSL *connection = SSL_new(ctx);
	if (connection == NULL)
		errx(1, "%s", "Cannot create connection");
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		errx(1, "%s", "Cannot create socket");
	struct addrinfo hints, *res;
	memset (&hints, 0, sizeof(hints));
      	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE;
	int g_res = getaddrinfo(NULL, port, &hints, &res);
	if (g_res != 0)
		errx(1, "%s", "getaddrinfo failed");
	g_res = bind(sockfd, res->ai_addr, res->ai_addrlen);
	if (g_res != 0)
		errx(1, "%s", "Cannot bind");
	g_res = listen(sockfd, 5);
	printf("Listening on port %s...\n", port);
	if (g_res != 0)
		errx(1, "%s", "Cannot listen");
	struct sockaddr_storage conn_addr;
	socklen_t len = sizeof(conn_addr);
	newsockfd = accept(sockfd, (struct sockaddr *)&conn_addr, &len);
	if (newsockfd < 0)
		errx(1, "%s", "Cannot accept");
	SSL_set_fd(connection, newsockfd);
	g_res = SSL_accept(connection);
	if (g_res != 1)
		errx(1, "%s", "TLS handshake failed");	
	if (pthread_create(&th_id, NULL, shell, connection) != 0)
    		errx(1, "%s", "Cannot create thread");
	else th_running = 1;
	char in_ch;	
	while (th_running) {
		g_res = SSL_read(connection, (char*)&in_ch, sizeof(in_ch));
		if (g_res <= 0)
			break;
		putchar(in_ch);
	}
	SSL_free(connection);	
	SSL_CTX_free(ctx);
	close(newsockfd);
	close(sockfd);
	return 0;
}

#if __OpenBSD__
void
usage()
{
	printf("Usage: %s -c certfile -k keyfile [-p port]\n", getprogname());
}

#elif __linux__
void
usage(char *progname)
{
	printf("Usage: %s -c certfile -k keyfile [-p port]\n", progname);
}

#endif

void 
*shell(void *connection)
{
	int ret;
	char *ret_f;
	char *in_buff = calloc(256, sizeof(char));
	printf("New session started\n");
	while(strncmp(in_buff, "exit\n", sizeof("exit\n")) != 0) {
		fgets(in_buff, sizeof(in_buff), stdin);	
		ret = SSL_write((SSL*)connection, in_buff, sizeof(in_buff));
		if (ret <= 0)
			break;
	}
	th_running = 0;
	pthread_exit(ret_f);
}
