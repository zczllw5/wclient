#include <openssl/ssl.h>
#include <openssl/err.h>

#include <unistd.h>
 
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>

#include <regex.h> 

#define HOST    "www.google.com"
#define PORT 443
#define BUFSIZZ 1024
#define CIPHER_LIST1 "TLS_RSA_WITH_AES_256_CBC_SHA:TLS_NULL_WITH_NULL_NULL"
#define CIPHER_LIST2 "TLS_RSA_WITH_AES256-SHA256"


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

int get_the_nth_host_name(int index, char *host){
    FILE *fp;
    char *buff;
    char indexS[3];

    long lSize;
    size_t fileStream;             // represent the size of any object in bytes
    char *pch;
    /* get the host name pass it to host to ip funciton */
    fp = fopen("top-1h.csv", "r");
    if(fp == NULL) {
        err_exit("can't open file");
    }

    /*get all stream*/

    // obtain file size:
    fseek (fp, 0, SEEK_END); //Reposition stream position indicator
    lSize = ftell (fp);      //Get current position in stream
    rewind (fp);             //Set position of stream to the beginning

    // // allocate memory to contain the whole file:
    buff = (char*) malloc (sizeof(char)*lSize);
    if (buff == NULL) {err_exit("Memory error");}

    // copy the file into the buffer:
    fileStream = fread (buff,1,lSize,fp);  //Read block of data from stream return size_t
    if (fileStream != lSize) {
        err_exit("Reading error");
    }
    //printf("buff: %s\n",buff);

    /*get the host name by index*/
    
    //get the position by index
    sprintf(indexS, "%d", index);     
    pch = strstr(buff, indexS);                             //Locate substring
    //printf("pch: the %ith website: %s\n", index, (pch));


    //use sscanf() read one line  
    if(sscanf(pch, "%s", buff) ==0){
        err_exit("fscanf error");
    };
    //printf("First word = \n%s\n", buff);

    //slipt the line by ','  method1: strtok method2 split()
    char *tokens;
    tokens  = strtok(buff, ",");
    //printf("tokens: %s\n", tokens);

    tokens  = strtok(NULL, ",");
    //printf("second token which is host: %s\n", host);

    strcpy(host, tokens);
    
    fclose(fp);
    return 0;
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

int ip_connect_to_host(char *ip){
    int err;
    int socketfd;
    struct sockaddr_in socketaddr;

    socketaddr.sin_family=AF_INET;
    socketaddr.sin_addr.s_addr=inet_addr(ip);
    socketaddr.sin_port=htons(PORT); //host to network short

    socketfd=socket(AF_INET,SOCK_STREAM,0);
        if(socketfd == -1)
            err_exit("socket error");
        
    err = connect(socketfd, (struct sockaddr *)&socketaddr, sizeof(socketaddr));
        if(err<0) {
            printf("Socket returned error #%i,program terminated\n",errno);
            //SSL_free(myssl);
            //SSL_CTX_free(ctx);
            exit(0);
        }
        else if(err ==0)
            printf("TCP/IP connect succeed!\n");

    return socketfd;
}

SSL_CTX *initial_ctx(const SSL_METHOD *meth){
    int err;
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(meth);
    if(!ctx){
        printf("Error SSL_CTX_new.\n");
        exit(0);
    }
    return ctx;
}

void set_cipher_suites(SSL_CTX *ctx){
    int err;
    /*OSSL_default_ciphersuites() returns TLSv1.3 ciphersuites*/
    err = SSL_CTX_set_ciphersuites(ctx,CIPHER_LIST1);
    if(err == 0)
        err_exit("Error setting the cipher list.\n");
    else if(err == 1)
        printf("some ciher selected.\n");
}

SSL_CTX *set_protocol_version(SSL_CTX *ctx){
    int err;

    err = SSL_CTX_set_min_proto_version(ctx,0);             //0 will enable protocol versions down to the lowest version
        if(err==0)
            err_exit("set min version error\n");
    
    err = SSL_CTX_set_max_proto_version(ctx,TLS1_2_VERSION);
        if(err==1)
            printf("SSL_CTX_set_max_proto_version succeed: %d!\n",TLS1_2_VERSION);
        if(err==0)
            err_exit("SSL_CTX_set_max_proto_version error");
    
        /*SSL_CTX_set_options(3): disable specific protocol versions*/
                
        /* Set for server verification*/
        //SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);

    return ctx;
}

SSL *initialize_ssl_bio_propare_connection(SSL *myssl, SSL_CTX *ctx, int socketfd){
    int err;
    BIO *mybio;
    myssl=SSL_new(ctx);
    if(!myssl)
        err_exit("Error creating SSL structure.\n");
    
    /*BIO_s_connect() returns the connect BIO method, and BIO_new_ex() function returns a new BIO using method type  */
    mybio=BIO_new(BIO_s_connect());
    SSL_set_bio(myssl,mybio,mybio);
    printf("Prepare SSL connection on socket: %x, Version: %li, 1st cipher: %s, 2nd cipher: %s,3rd cipher: %s,4th cipher: %s,file descriptor:%i\n",
            socketfd
            ,SSL_CTX_get_max_proto_version(ctx)
            ,SSL_get_cipher_list(myssl,0)
            ,SSL_get_cipher_list(myssl,1)
            ,SSL_get_cipher_list(myssl,2)
            ,SSL_get_cipher_list(myssl,3)
            ,SSL_get_fd(myssl)
            );

    /*Bind the socket to the SSL structure*/
    err = SSL_set_fd(myssl,socketfd);
    if(err==0)
        err_exit("set_fd error\n");
    //else if(err==1)
        //printf("SSL_set_fd succeed\n");

    return myssl;
}

const char *get_session_cipher(SSL *ssl, const char *sessionCipher){
    int ret;
    SSL_SESSION *ses;

    /*Connect to the server, SSL layer.*/
    ret = SSL_connect(ssl);
    //ssl_error_exit(ctx,myssl,ret);
    
    ses = SSL_get1_session(ssl);
    sessionCipher = SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(ses));   
    printf("the session cipher chosed by server:%s\n", sessionCipher);    

    return sessionCipher;
}

void iteration100(){

}

int main()
    {
        SSL *ssl; /*use SSL object to represent an SSL connection*/
        SSL_CTX *ctx;
        const SSL_METHOD *meth;

        int socketfd;
        
        int err,ret;

        char host[15];
        char ip[100];
        const char *sessionCipher;
        
        get_the_nth_host_name(44,host);
        //printf("host found by index: %s\n", host);    

        hostname_to_ip(host, ip);
        printf("%s resolved to %s\n", host, ip);

        socketfd = ip_connect_to_host(ip);
        //printf("socketfd in main(): %i\n", socketfd); 
       
        meth = TLS_client_method();

        ctx = initial_ctx(meth);

        set_cipher_suites(ctx);

        set_protocol_version(ctx);

        ssl = initialize_ssl_bio_propare_connection(ssl, ctx, socketfd);

        get_session_cipher(ssl,sessionCipher);
        printf("the session cipher chosed by server in the main():%s\n", sessionCipher);
        //tell if the chosed cipher in the provided cipher list by the client

        /*get the session ciher and find weather if the server forced PSK*/
        if(strstr(CIPHER_LIST1, sessionCipher) != NULL){
            printf("session cipher in the CIPHER_LIST\n");
        } else {
            //printf("session cipher NOT in the CIPHER_LIST\n");
            if(strstr(sessionCipher,"ECDHE") != NULL){
                printf("forced PSK\n");
            }
        }

        /*print session in a file*/
        // fp = fopen("sessionInfo.txt", "r+");
        
        // err = SSL_SESSION_print_fp(fp,ses);  /*stdout to the console*/
        // if(err== 0)
        //     err_exit("SSL_SESSION_print_fp error\n");
        // else if(err==1)
        //     printf("SSL_SESSION_print_fp succeed\n");

        //fclose(fp);

        close(socketfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(0);
}