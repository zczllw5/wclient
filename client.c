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

#define PORT 443

BIO *bio_err=0;
int inTLS1_2 =0;
const char* cipher_list_tls1_3 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_CCM_SHA384:TLS_AES_128_CCM_SHA256";

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

void ssl_error_exit(SSL *ssl, int ret)
{
    switch(SSL_get_error(ssl,ret)){
        case SSL_ERROR_NONE:
            printf("The TLS/SSL I/O operation completed\n");
            break;
        case SSL_ERROR_ZERO_RETURN:
            printf("peer has closed the connection for writing by sending the close_notify alert\n");
        case (SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE):
            printf("last operation was a read operation from a nonblocking BIO\n");
        case (SSL_ERROR_WANT_CONNECT | SSL_ERROR_WANT_ACCEPT):
            berr_exit("underlying BIO was not connected yet to the peer\n");
        case SSL_ERROR_WANT_X509_LOOKUP:
            berr_exit("an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again\n");
        case SSL_ERROR_WANT_ASYNC:
            berr_exit("The operation did not complete because an asynchronous engine is still processing data\n");
        case SSL_ERROR_WANT_ASYNC_JOB:
            berr_exit("The asynchronous job could not be started because there were no async jobs available in the pool \n");
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            berr_exit("The operation did not complete because an application callback set by SSL_CTX_set_client_hello_cb() has asked to be called again\n");
        case SSL_ERROR_SYSCALL:
            berr_exit("non-recoverable, fatal I/O error occurred\n");
        case SSL_ERROR_SSL:
            berr_exit("non-recoverable, fatal error in the SSL library occurred, usually a protocol error.\n");
  }
}

char* get_host_name(int index){
    FILE *fp;
    char *buff;
    char indexS[10];

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

    /*get the host name by index*/
    
    //get the position by index
    sprintf(indexS, "%d", index);     
    pch = strstr(buff, indexS);                             //Locate substring

    //use sscanf() read one line  
    if(sscanf(pch, "%s", buff) ==0){
        err_exit("fscanf error");
    };

    //slipt the line by ','  method1: strtok method2 split()
    char *host=(char *)malloc(sizeof(char)*100);
    
    host = strtok(buff, ",");
    host  = strtok(NULL, ",");
    
    fclose(fp);
    return host;
}

void hostname_to_ip(char *hostname, char **ip)
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
        //return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL;p = p->ai_next)
    {
        h = (struct sockaddr_in*)p->ai_addr;
        *ip = inet_ntoa(h->sin_addr);
        //strcpy(ip,inet_ntoa(h->sin_addr));
    }
    
    freeaddrinfo(servinfo); // all done with this structure
    //return 0;
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
            exit(0);
        }
        //else if(err ==0)
            //printf("TCP/IP connected!\n");

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

void set_timeout(SSL_CTX *ctx){
    SSL_CTX_set_timeout(ctx, 2);
    long timeOut = SSL_CTX_get_timeout(ctx);
    printf("timeOut: %li. \n", timeOut);
}

SSL_CTX *set_protocol_version(SSL_CTX *ctx){
    /*SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION*/
    int err;
    int minVersion = TLS1_1_VERSION;

    err = SSL_CTX_set_min_proto_version(ctx,minVersion);
    if(err==0)
        err_exit("set min version error\n");
//     else if(err==1)
//         printf("min version is: %ld\n",SSL_CTX_get_min_proto_version(ctx));
    
    err = SSL_CTX_set_max_proto_version(ctx,maxVersion);
    if(err==0)
        err_exit("SSL_CTX_set_max_proto_version error");
//     else if(err==1)
//         printf("max version is: %ld\n",SSL_CTX_get_max_proto_version(ctx));

    /*use server's preference*/
    //long int serverList;
    // serverList = SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    // printf("this protocol is using server cipher list: %ld!\n", serverList);

    /*SSL_CTX_set_options(3): disable specific protocol versions*/
    //SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    
    /* Set for server verification*/
    //SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);

    return ctx;
}

void set_cipher_suites(SSL_CTX *ctx, const char *cipherList){

    int err;
    //printf("cipherlist in set_cipher_list(): %s\n", cipherList);
    //err = SSL_set_cipher_list(ssl, cipherList);
    err = SSL_CTX_set_cipher_list(ctx, cipherList);
    if(err == 0)
        err_exit("Error setting the cipher list.\n");
    // else if(err == 1)
    //     printf("some ciher selected.\n");
    
    err = SSL_CTX_set_ciphersuites(ctx, cipher_list_tls1_3);
    if(err == 0)
        err_exit("Error setting the TLS1.3 cipher list.\n");
    
}

void display_client_cipher_list(SSL *ssl){
    const char *clientCipherSuite;
    for(int i =0; i < 100; i++){
        //stack of available SSL_CIPHERs for ssl
        clientCipherSuite = SSL_get_cipher_list(ssl,i);
        //SSL_get1_supported_ciphers() returns the stack of enabled SSL_CIPHERs for ssl as would be sent in a ClientHello
        //clientCipherSuite = SSL_get1_supported_ciphers(ssl);
        
         printf("the client\'s %ith ciphersuite: %s\n", i+1, clientCipherSuite);
         if(clientCipherSuite == NULL){
             break;
         }
    }
}

SSL *initialize_ssl_bio_propare_connection(SSL_CTX *ctx, int socketfd){
    int err;
    BIO *mybio;
    SSL *ssl;
    
    ssl=SSL_new(ctx);
    if(!ssl)
        err_exit("Error creating SSL structure.\n");
    
    /*BIO_s_connect() returns the connect BIO method, and BIO_new_ex() function returns a new BIO using method type  */
    if(BIO_new(BIO_s_connect()) == NULL){
        berr_exit("BIO_new failed");
    } else{
        mybio=BIO_new(BIO_s_connect());
    }
    
    SSL_set_bio(ssl,mybio,mybio);

    /*Bind the socket to the SSL structure*/
    err = SSL_set_fd(ssl,socketfd);
    if(err==0)
        err_exit("set_fd error\n");
    //else if(err==1)
        //printf("SSL_set_fd succeed\n");

    return ssl;
}

SSL_SESSION *ssl_connet(SSL* ssl){

    int ret;
    SSL_SESSION *ses;

    /*Connect to the server, SSL layer.*/
    ret = SSL_connect(ssl);
    //ssl_error_exit(ssl,ret);
    
    if(SSL_get1_session(ssl) == NULL){
        err_exit("There is no session available in ssl");
    } else{
        ses = SSL_get1_session(ssl);
    }
    
    return ses;
}

void get_session_cipher(SSL_SESSION *ses, const char **sessionCipher){
    
    if(SSL_SESSION_get0_cipher(ses) == NULL){
        printf("SSL_CIPHER associated with the SSL_SESSION cannot be determined.\n");
        *sessionCipher = NULL;
        //SSL_SESSION_free(ses);
    } else {
            *sessionCipher = SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(ses));
    }
    //("the server choose :%s\n", *sessionCipher);

}

void counter(const  char* client_cipher_list, const char *sessionCipher){
    
    if(sessionCipher == NULL){
        printf("no cipher to compare");
        return;
    } else if(strstr(client_cipher_list, sessionCipher) != NULL){
        printf(" IN TLS1.2 cipher list\n");
        inTLS1_2++;
        //("inCount: %i", inCount);
    } else if(strstr(cipher_list_tls1_3, sessionCipher) != NULL){
        printf(" IN TLS1.3 cipher list\n");
        inTLS1_2++;
        //("inCount: %i", inCount);
    } else if(strstr(client_cipher_list, sessionCipher) == NULL){
        return;
    }

}

void get_shared_ciphers(SSL *ssl){
    int size = 100;
    char *buf;
    char *sharedCiphers = (char *)malloc(sizeof(char)*100);

    //char* copied_client_cipher_list = strcpy(copied_client_cipher_list, client_cipher_list);
    buf = (char *)malloc(sizeof(char)*1000);
    sharedCiphers = SSL_get_shared_ciphers(ssl, buf, size);
    if(sharedCiphers == NULL)
        printf("shared ciphers are: %s\n", sharedCiphers);
    else
        printf("NO shared ciphers. \n");
}

void get_server_cipher_list(){

}

void send_early_data(SSL *ssl, const SSL_SESSION *ses){
    if(SSL_is_init_finished(ssl) == 0){
        err_exit("SSL_is_init_finished(ssl) Not succeed.\n");
    } else {
        /*for 0-RTT, the session must be resumable, check it before send data */
        //uint32_t
        if(SSL_SESSION_is_resumable(ses) == 1){
            printf("can be used to resume a session");
            if(SSL_SESSION_get_max_early_data(ses) == 0){
                err_exit("session cannot be used\n");
            }
        } else {
            err_exit("can't be used to resume a session");
        }
    }
}


void iteration(const char* cipher_list){

    SSL_CTX *ctx;
    const SSL_METHOD *meth;

    char *ip = (char *)malloc(sizeof(char)*50);
    char *host = (char *)malloc(sizeof(char)*50);
    const char *sessionCipher = (char *)malloc(sizeof(char)*100);
    
    meth = TLS_client_method();
    ctx = initial_ctx(meth);
    /*set timeout*/
    //set_timeout(ctx);
    
    for(int i =1; i <=100; i++){
        
        host = get_host_name(i);

        hostname_to_ip(host, &ip);
        printf("%i. %s resolved to %s ",i, host, ip);
        
        int socketfd;
        socketfd = ip_connect_to_host(ip);
        printf("socketfd: %i\n", socketfd);
        
        set_protocol_version(ctx);
        
        set_cipher_suites(ctx, cipher_list);
        
        
        
        
        
        SSL *ssl;
        ssl = initialize_ssl_bio_propare_connection(ctx, socketfd);
        
        //display_client_cipher_list(ssl);
        
        SSL_SESSION *ses;
        ses = ssl_connet(ssl);

        get_session_cipher(ses, &sessionCipher);
        printf(" chosed :%s ", sessionCipher);
    
        counter(cipher_list,sessionCipher);
        
        //get_shared_ciphers(ssl);
        printf("\n");

        //get_server_cipher_list();
        
        /*O-RTT*/
        //ses = const ses;
        //send_early_data(ssl,ses);
        
        //SSL_SESSION_free(ses);
        close(socketfd);
        SSL_free(ssl);
    }

    printf("in: %i. notIn %i \n", inTLS1_2, 100-inTLS1_2);
    SSL_CTX_free(ctx);
      
}

int main()
    {
        
        const char* psk = "RSA-PSK-AES256-GCM-SHA384";
        
        const char* cipher_list_tls1_2 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:RSA-PSK-AES256-GCM-SHA384:DHE-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:AES256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-GCM-SHA256:AES128-GCM-SHA256:PSK-AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA:AES256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA:AES128-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA";
        const char* cipher_list_ssl3_0 = "";
        
        const char* cipher_list_Q1 = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384";
        const char* cipher_list_Q2 = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384";
        
        iteration(cipher_list_tls1_2);

        
        

        /*cipherList string rule:
            1. no NULL
            2. no same as the provided three
            3. TLS_AES_256_GCM_SHA384 and AES256-GCM-SHA384 are different, the later did not mention the authentication nor key exchange
        */
       
       /*machenims of how servere choosing a cipher:
            1. many vary each time
            2, may be none
        */

        //1. source for non foward secrecy.
        //2. time 0RTT-time to fisrt byte last byte come back
        //3. session resumption
        
        exit(0);
}
