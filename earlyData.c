#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

//#include "test_common.h"
#define MSG1_REQ "GET /echo HTTP/1.1\r\nHOST: google.com\r\n\r\n"
#define MSG2_REQ "GET /main.html HTTP/1.1\r\nHOST: google.com\r\n\r\n"

#define CAFILE1 "./certs/ECC_Prime256_Certs/rootcert.pem"

void get_error()
{
    unsigned long error;
    const char *file = NULL, *func = "";
    int line= 0;
#ifdef WITH_OSSL_111
    error = ERR_get_error_line(&file, &line);
#elif defined WITH_OSSL_300
    error = ERR_get_error_all(&file, &line, &func, NULL, NULL);
#endif
    printf("Error reason=%d on [%s:%d:%s]\n", ERR_GET_REASON(error),
           file, line, func);
}

int do_tcp_connection(const char *server_ip, uint16_t port)
{
    struct sockaddr_in serv_addr;
    int count = 0;
    int fd;
    int ret;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("Socket creation failed\n");
        return -1;
    }
    printf("Client fd=%d created\n", fd);

    serv_addr.sin_family = AF_INET;
    if (inet_aton(server_ip, &serv_addr.sin_addr) == 0) {
        printf("inet_aton failed\n");
        goto err_handler;
    }
    serv_addr.sin_port = htons(port);

    printf("Connecting to %s:%d...\n", server_ip, port);
    do {
        ret = connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        if (ret) {
            printf("Connect failed, errno=%d\n", errno);
            goto err_handler;
        } else {
            break;
        }
        count++;
        usleep(2);
    } while (count < 20);

    printf("TLS connection succeeded, fd=%d\n", fd);
    return fd;
err_handler:
    close(fd);
    return -1;
}

SSL_CTX *create_context()
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        printf("SSL ctx new failed\n");
        return NULL;
    }

    printf("SSL context created\n");

    // if (SSL_CTX_load_verify_locations(ctx, CAFILE1, NULL) != 1) {
    //     printf("Load CA cert failed\n");
    //     goto err_handler;
    // }

    // printf("Loaded cert %s on context\n", CAFILE1);

    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // SSL_CTX_set_verify_depth(ctx, 5);

    printf("SSL context configurations completed\n");

    return ctx;
err_handler:
    SSL_CTX_free(ctx);
    return NULL;
}

SSL *create_ssl_object(SSL_CTX *ctx)
{
    SSL *ssl;
    int fd;

    fd = do_tcp_connection("142.250.200.46", 443);
    if (fd < 0) {
        printf("TCP connection establishment failed\n");
        return NULL;
    }

    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("SSL object creation failed\n");
        return NULL; 
    }

    SSL_set_fd(ssl, fd);
    printf("SSL object creation finished\n");
    return ssl;
}

void ssl_error_exit(SSL *ssl, int ret)
{
    switch(SSL_get_error(ssl,ret)){
        case SSL_ERROR_NONE:
            printf("The TLS/SSL I/O operation completed\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("peer has closed the connection for writing by sending the close_notify alert\n");
            goto end;
        case (SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE):
            printf("last operation was a read operation from a nonblocking BIO\n");
            goto end;
        case (SSL_ERROR_WANT_CONNECT | SSL_ERROR_WANT_ACCEPT):
            printf("underlying BIO was not connected yet to the peer\n");
            goto end;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again\n");
            goto end;
        case SSL_ERROR_WANT_ASYNC:
            printf("The operation did not complete because an asynchronous engine is still processing data\n");
            goto end;
        case SSL_ERROR_WANT_ASYNC_JOB:
            printf("The asynchronous job could not be started because there were no async jobs available in the pool \n");
            goto end;
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            printf("The operation did not complete because an application callback set by SSL_CTX_set_client_hello_cb() has asked to be called again\n");
            goto end;
        case SSL_ERROR_SYSCALL:
            fprintf(stderr, "errno = %s\n", strerror(errno));
            //printf("non-recoverable, fatal I/O error occurred\n");
            goto end;
        case SSL_ERROR_SSL:
            printf("non-recoverable, fatal error in the SSL library occurred, usually a protocol error.\n");
            goto end;
  }
  end:
    SSL_free(ssl);
    exit(0);
}

int do_early_data_transfer(SSL *ssl)
{
    char *msg_req = "Hello, I am client early data!";
    //char *msg_req = "Hello, I am client early data!";
    char buf[100000] = {0};
    size_t written;
    int ret;

    ret = SSL_write_early_data(ssl, MSG1_REQ, strlen(MSG1_REQ), &written);
    //ssl_error_exit(ssl,SSL_write_early_data(ssl, msg_req, strlen(msg_req), &written));
    if (ret <= 0) {
    	printf("SSL_write_early_data failed ret=%d\n", ret);
	return -1;
    }
    printf("Early data write sucessed\n");

    
    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    //ssl_error_exit(ssl,SSL_read(ssl, buf, sizeof(buf) - 1));
    if (ret <= 0) {
        printf("SSL_read read early data failed ret=%d\n", ret);
	return -1;
    }
    printf("Early data read '%s'\n", buf);

    return 0;
}

int do_data_transfer(SSL *ssl)
{
    const char *msg_req[] = {MSG1_REQ, MSG2_REQ};
    const char *req;
    char buf[10000] = {0};
    int ret, i;
    for (i = 0; i < sizeof(msg_req)/sizeof(msg_req[0]); i++) {
        req = msg_req[i];
        ret = SSL_write(ssl, req, strlen(req));
        if (ret <= 0) {
            printf("SSL_write failed ret=%d\n", ret);
            return -1;
        }
        printf("SSL_write[%d] sent %s\n", ret, req);

        ret = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (ret <= 0) {
            printf("SSL_read failed ret=%d\n", ret);
            return -1;
        }
        printf("SSL_read[%d] %s\n", ret, buf);
    }
    return 0;
}

int tls13_client(int con_count)
{
    SSL_CTX *ctx;
    SSL *ssl = NULL;
    SSL_SESSION *prev_sess = NULL;
    int ret_val = -1;
    int fd;
    int ret;
    int i;

    for (i = 0; i < con_count; i++) {
        ctx = create_context();
        if (!ctx) {
	    return -1;
    }

	if (i < 1) {
	    ret = SSL_CTX_set_max_early_data(ctx, SSL3_RT_MAX_PLAIN_LENGTH);
	    if (ret != 1) {
	    	printf("CTX set max early data failed\n");
		goto err_handler;
	    }
	}

        ssl = create_ssl_object(ctx);
        if (!ssl) {
	    goto err_handler;
        }

        fd = SSL_get_fd(ssl);

        if (prev_sess != NULL) {
            SSL_set_session(ssl, prev_sess);
            SSL_SESSION_free(prev_sess);
            prev_sess = NULL;
        }

	if (i >= 1) {
	    if (do_early_data_transfer(ssl)) {
	        printf("Early data transfer over TLS failed\n");
	        goto err_handler;
	    }
	    printf("Early data transfer over TLS suceeded\n");
        }

        ret = SSL_connect(ssl);
        if (ret != 1) {
            printf("SSL connect failed%d\n", ret);
	    get_error();
            goto err_handler;
        }
        printf("SSL connect succeeded\n");

        const char* version = SSL_get_version(ssl);
        printf("ssl protocol version: %s\n", version);

        if (do_data_transfer(ssl)) {
            printf("Data transfer over TLS failed\n");
            goto err_handler;
        }
        printf("Data transfer over TLS succeeded\n\n");

        prev_sess = SSL_get1_session(ssl);
        if (!prev_sess) {
            printf("SSL session is NULL\n");
            goto err_handler;
        }
        printf("SSL session backed up\n");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;
	SSL_CTX_free(ctx);
	ctx = NULL;
        close(fd);
        fd = -1;
    }

    ret_val = 0;
err_handler:
    SSL_free(ssl);
    SSL_SESSION_free(prev_sess);
    SSL_CTX_free(ctx);
    close(fd);
    return ret_val;
}

int main(int argc, char *argv[])
{
    printf("OpenSSL version: %s, %s\n", OpenSSL_version(OPENSSL_VERSION), OpenSSL_version(OPENSSL_BUILT_ON));
    if (tls13_client(2)) {
        printf("TLS13 client connection failed\n");
        return -1;
    }
    return 0;
}