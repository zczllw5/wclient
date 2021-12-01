#ifndef _common_h
#define _common_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include <unistd.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#define CA_LIST "IncludedRootsPEM.pem"
#define HOST	"www.google.com"
//Client issues TCP connect to Server port 80 (or 443 for HTTPS).
#define PORT 443
#define BUFSIZZ 1024 //set a buffer size

int berr_exit (char *string);
int err_exit(char *string);

SSL_CTX *initialize_ctx();


#endif
