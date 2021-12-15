#include <openssl/ssl.h>
#include <openssl/err.h>

#include <unistd.h>
 
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#define HOST    "www.google.com"
#define PORT "443"
#define BUFSIZZ 1024
#define CIPHER_LIST "TLS_AES_256_GCM_SHA384"

BIO *bio_err=0;

/* A simple error and exit routine*/ //[E. Rescorla]
int err_exit(char *string)
  {
    fprintf(stderr,"%s\n",string);
    exit(0);
  }

/* Print SSL errors and exit*/
int berr_exit(char *string)
  {
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
  }

int ssl_error_exit(SSL_CTX *ctx, SSL *myssl, int ret)
{
    switch(SSL_get_error(myssl,ret)){
        case SSL_ERROR_NONE:
            printf("The TLS/SSL I/O operation completed\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("peer has closed the connection for writing by sending the close_notify alert\n");
            goto end;
        case SSL_ERROR_WANT_READ:
            printf("last operation was a read operation from a nonblocking BIO\n");
        case SSL_ERROR_WANT_WRITE:
            printf("last operation was a write operation from a nonblocking BIO\n");
            goto end;
        case SSL_ERROR_WANT_CONNECT:
            printf("underlying BIO was not connected yet to the peer\n");
            goto end;
        case SSL_ERROR_WANT_X509_LOOKUP:
            printf("an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again\n");
            goto end;
        case SSL_ERROR_WANT_ASYNC:
            printf("1\n");
            goto end;
        case SSL_ERROR_WANT_ASYNC_JOB:
            printf("1\n");
            goto end;
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            printf("1\n");
            goto end;
        case SSL_ERROR_SYSCALL:
            printf("non-recoverable, fatal I/O error occurred\n");
            goto end;
        case SSL_ERROR_SSL:
            printf("non-recoverable, fatal error in the SSL library occurred, usually a protocol error.\n");
            goto end;
  }
  end:
    SSL_free(myssl);
    SSL_CTX_free(ctx);
    exit(0);
}

int hostname_to_ip(char *hostname, char *ip)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if((rv = getaddrinfo(hostname,"http",&hints,&servinfo)) != 0)
    {
        fprintf(stderr,"getaddrinfo: %s\n",gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL;p = p->ai_next)
    {
        h = (struct sockaddr_in*)p->ai_addr;
        strcpy(ip,inet_ntoa(h->sin_addr));
    }
    
    freeaddrinfo(servinfo); // all done with this structure
    return 0;
}

int main()
    {
        SSL *myssl; /*use SSL object to represent an SSL connection*/
        SSL_CTX *ctx;
        BIO *rbio;
     
        int socketfd,err,ret;
        char buf[BUFSIZZ];
        
        struct sockaddr_in socketaddr;
        
        char ip[100];
            
        hostname_to_ip(HOST, ip);
        printf("%s resolved to %s\n" ,HOST,ip);
        
        socketaddr.sin_family=AF_INET;
        socketaddr.sin_addr.s_addr=inet_addr(ip);
        socketaddr.sin_port=atoi(PORT);
        
        const SSL_METHOD *meth;
        meth = TLS_client_method();
        
        ctx = SSL_CTX_new(meth);
        if(!ctx){
            printf("Error SSL_CTX_new.\n");
            exit(0);
        }
        //printf("cipher %s.\n",OSSL_default_ciphersuites());
        
        if(SSL_CTX_set_ciphersuites(ctx,OSSL_default_ciphersuites()) <= 0)
            err_exit("Error setting the cipher list.\n");
        
//        if(!SSL_CTX_set_min_proto_version(ctx,0))
//            err_exit("set min version error\n");
//        if(!SSL_CTX_set_max_proto_version(ctx,0))
//            err_exit("set max version error");
    
        /*SSL_CTX_set_options(3): disable specific protocol versions*/
                
        /* Set for server verification*/
        //SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
        
        
        myssl=SSL_new(ctx);
        if(!myssl)
           err_exit("Error creating SSL structure.\n");
        
        socketfd=socket(AF_INET,SOCK_DGRAM,0);
        if(socketfd == -1)
            err_exit("socket error");
        
        err = connect(socketfd, (struct sockaddr *)&socketaddr, sizeof(socketaddr));
        if(err<0) {
            printf("Socket returned error #%i,program terminated\n",errno);
            SSL_free(myssl);
            SSL_CTX_free(ctx);
            exit(0);
        }
        else if(err ==0)
            printf("TCP/IP connect succeed!\n");
        
        /*BIO_s_connect() returns the connect BIO method, and BIO_new_ex() function returns a new BIO using method type  */
        rbio=BIO_new(BIO_s_connect());
        SSL_set0_rbio(myssl,rbio);
        printf("Prepare SSL connection on socket %x,Version: %s,ciphers:%s,bio:%s,file descriptor:%i\n",
               socketfd,
               SSL_get_version(myssl)
               ,SSL_get_ciphers(myssl)
               ,SSL_get_rbio(myssl)
               ,SSL_get_fd(myssl)
               );

        /*Bind the socket to the SSL structure*/
        err = SSL_set_fd(myssl,socketfd);
        if(err==0)
            err_exit("set_fd error\n");
        else if(err==1)
            printf("SSL_set_fd succeed\n");

        /*Connect to the server, SSL layer.*/
        ret = SSL_connect(myssl);
        switch(SSL_get_error(myssl,ret)){
            case SSL_ERROR_NONE:
                printf("The TLS/SSL I/O operation completed\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                printf("peer has closed the connection for writing by sending the close_notify alert\n");
                //goto end;
            case SSL_ERROR_WANT_READ:
                printf("last operation was a read operation from a nonblocking BIO\n");
            case SSL_ERROR_WANT_WRITE:
                printf("last operation was a write operation from a nonblocking BIO\n");
                //goto end;
            case SSL_ERROR_WANT_CONNECT:
                printf("underlying BIO was not connected yet to the peer\n");
                //goto end;
            case SSL_ERROR_WANT_X509_LOOKUP:
                printf("an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again\n");
                //goto end;
            case SSL_ERROR_WANT_ASYNC:
                printf("1\n");
                //goto end;
            case SSL_ERROR_WANT_ASYNC_JOB:
                printf("1\n");
                //goto end;
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:
                printf("1\n");
                //goto end;
            case SSL_ERROR_SYSCALL:
                printf("non-recoverable, fatal I/O error occurred\n");
                //goto end;
            case SSL_ERROR_SSL:
                printf("non-recoverable, fatal error in the SSL library occurred, usually a protocol error.\n");
                //goto end;
        }
                
//        if(ret!=1)
//            printf("SSL_connect not succeed");
        //printf("after SSL_connect\n");
        //ssl_error_exit(ctx,myssl,ret);
        printf("after SSL_conect\n");
        
//        if(err==-1)
//            printf("BIO is nonblocking\n");
//        else if(err==0)
//            SSL_get_error(myssl,err);
//            printf("SSL error #%d in accept,program terminated\n",err);
        
//        if (err<1) {
//           err=SSL_get_error(myssl,err);
//           err_exit("SSL error in accept,program terminated\n");
//
//           if(err==5){printf("sockerrno is:\n");}

        close(socketfd);
        SSL_free(myssl);
        SSL_CTX_free(ctx);
        exit(0);

}
