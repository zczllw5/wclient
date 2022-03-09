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

BIO *bio_err = 0;
int inTLS1_2 = 0;
int inTLS1_3 = 0;
int inClientCipherList = 0;
int noSession = 0;
int unresumable = 0;

const char* cipher_list_tls1_3 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

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

void get_hosts(char host[100][50]){
    FILE *fp;
    char *buff;
    size_t fileStream;
    long lSize;
    
    fp = fopen("top_1h.txt", "r");
    
    if (!fp)
        exit(EXIT_FAILURE);
    
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
    char *piece = strtok(buff, " ");
    strcpy(host[0], piece);
    
    for(int i = 1; i < 100; i++){
        piece  = strtok(NULL, " ");
        strcpy(host[i], piece);
    }
    
    fclose(fp);
}

void hostname_to_ip(char hostname[100], char **ip)
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
    
    //printf("%s resolved to \n", hostname);
    
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
    SSL_CONF_CTX *cctx;
    
    ctx = SSL_CTX_new(meth);
    if(!ctx){
        printf("Error SSL_CTX_new.\n");
        exit(0);
    }
    
    /*set security level*/
    //SSL_CTX_set_security_level(ctx, 0);
    
//    cctx = SSL_CONF_CTX_new();
//    SSL_CONF_cmd(cctx, "MinProtocol", "SSL3_VERSION");
//    SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
//    if(!SSL_CONF_CTX_finish(cctx)) {
//            ERR_print_errors_fp(stderr);
//            err_exit("Finish error\n");
//    }
    
    return ctx;
}

SSL_CTX *set_protocol_version(SSL_CTX *ctx){
    /*SSL3_VERSION, 769:TLS1_VERSION, 770:TLS1_1_VERSION, 771:TLS1_2_VERSION, 772:TLS1_3_VERSION*/
    
    int err;
    int minVersion = TLS1_1_VERSION;
    int maxVersion = TLS1_3_VERSION;

    err = SSL_CTX_set_min_proto_version(ctx,minVersion);
    if(err==0)
        err_exit("set min version error\n");
     else if(err==1)
         printf("min version is: %ld\n",SSL_CTX_get_min_proto_version(ctx));
    
    err = SSL_CTX_set_max_proto_version(ctx,maxVersion);
    if(err==0)
        err_exit("SSL_CTX_set_max_proto_version error");
     else if(err==1)
         printf("max version is: %ld\n",SSL_CTX_get_max_proto_version(ctx));

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
    char buf[10000] = {0};
    size_t written;
    int ret;

    ret = SSL_write_early_data(ssl, msg_req, strlen(msg_req), &written);
    ssl_error_exit(ssl,ret);
    if (ret <= 0) {
    	printf("SSL_write_early_data failed ret=%d\n", ret);
	return -1;
    }
    printf("Early data write sucessed\n");

    ret = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        printf("SSL_read read early data failed ret=%d\n", ret);
	return -1;
    }
    printf("Early data read '%s'\n", buf);

    return 0;
}

SSL_SESSION *ssl_connect(SSL* ssl){

    int ret;
    SSL_SESSION *ses;

    /*Connect to the server, SSL layer.*/
    ret = SSL_connect(ssl);
    //ssl_error_exit(ssl,SSL_connect(ssl));
    
    const char* version = SSL_get_version(ssl);
    printf("ssl protocol version: %s\n", version);
    
    if(SSL_get1_session(ssl) == NULL){
        printf("There is no session available in ssl");
        noSession++;
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
        printf(" IN FS cipher list\n");
        inClientCipherList++;
        //("inCount: %i", inCount);
    } else if(strstr(cipher_list_tls1_3, sessionCipher) != NULL){
        printf(" IN TLS1.3 cipher list\n");
        inTLS1_3++;
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


void send_early_data(SSL *ssl){

    //shut down and reconnect
    // SSL_shutdown(ssl);
    // int ret;
    // SSL_SESSION *ses;
    // ret = SSL_connect(ssl);
    
    /*for 0-RTT, the session must be resumable, check it before send data */
    //uint32_t
    // if(SSL_SESSION_is_resumable(ses) == 1){
    //     printf("can be used to resume a session\n");
    //     if(SSL_SESSION_get_max_early_data(ses) == 0){
    //         err_exit("session cannot be used\n");
    //     }
    // } else {
    //     printf("can't be used to resume a session\n");
    //     unresumable++;
    // }
    
}



void iteration(const char* cipher_list){

    SSL_CTX *ctx;
    const SSL_METHOD *meth;

    char *ip = (char *)malloc(sizeof(char)*50);
    char host[100][50];
    char *hostname = (char *)malloc(sizeof(char)*50);
    const char *sessionCipher;
    SSL_SESSION *prev_sess = NULL;

    int ret = 0;
    
    meth = TLS_method();
    //ctx = initial_ctx(meth);
    
    get_hosts(host);
    
    for(int i = 0; i < 1; i++){
       int j;
        for (j = 0; j < 2; j++) {
            ctx =initial_ctx(meth);
        }

        if (i < 1) {
	        ret = SSL_CTX_set_max_early_data(ctx, SSL3_RT_MAX_PLAIN_LENGTH);
	        if (ret != 1) {
	    	    err_exit("CTX set max early data failed\n");
	        }
	    }

        hostname_to_ip(host[i], &ip);
        printf("%i. %s resolved to %s ", i, host[i], ip);
        
        int socketfd;
        socketfd = ip_connect_to_host(ip);
        printf("socketfd: %i\n", socketfd);
        
        set_protocol_version(ctx);
        
        set_cipher_suites(ctx, cipher_list);
        
        SSL *ssl;
        ssl = initialize_ssl_bio_propare_connection(ctx, socketfd);
        
        if (prev_sess != NULL) {
            SSL_set_session(ssl, prev_sess);
            SSL_SESSION_free(prev_sess);
            prev_sess = NULL;
        }        

        //display_client_cipher_list(ssl);
        if(j >= 1){
            if (do_early_data_transfer(ssl)) {
                err_exit("Early data transfer over TLS failed\n");
            }
	        printf("Early data transfer over TLS suceeded\n");
        }            

        if(i ==0 | i == 28 || i == 42 || i == 49 ||i == 51 || i == 53 ||i == 72 || i == 77 || i == 92 || i == 95){
            int err = SSL_set_tlsext_host_name(ssl, host[i]);
        } else  {
            char url[80];
            strcpy(url, "https://www.");
            strcat(url,host[i]);
            printf("url: %s\n", url);
            int err = SSL_set_tlsext_host_name(ssl,url);
            
            if(err == 1){
            printf("set hostname success\n");
                const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
                printf("servername: %s\n", servername);
            }
            else if(err == 0)
                err_exit("set hostname error");
        }
        
        SSL_SESSION *ses;
        ses = ssl_connect(ssl);
        
        get_session_cipher(ses, &sessionCipher);
        printf(" chosed :%s ", sessionCipher);
    
        counter(cipher_list,sessionCipher);
        
        //get_shared_ciphers(ssl);
        printf("\n");

        //get_server_cipher_list();
        
        /*O-RTT*/
//        size_t *len = 1000L;
//        const unsigned char *tick = (const unsigned char *)malloc(sizeof(char)*1000);
//
//        SSL_SESSION_get0_ticket(ses, &tick, len);
//        printf("session ticket :%s \n", tick);
        
        //ses = const ses;
        
        /*build connection and get the PSK */
        
        //SSL_set_psk_client_callback(ssl, SSL_psk_client_cb_func);
        
        send_early_data(ssl);
        
        //SSL_SESSION_free(ses);
        close(socketfd);
        SSL_free(ssl);
    }

    printf("in1.2: %i, in1.3 %i, inClientCipherList: %i, noSession: %i\n", inTLS1_2, inTLS1_3, inClientCipherList, noSession);
    //printf("unresumable server: %i\n", unresumable);
    SSL_CTX_free(ctx);
      
}

int main()
    {
        const char* ciphers_tls1_2 = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA";
        const char* ciphers_non_forward_secrecy = "ADH-AES256-GCM-SHA384:ADH-AES128-GCM-SHA256:ADH-AES256-SHA256:ADH-CAMELLIA256-SHA256:ADH-AES128-SHA256:ADH-CAMELLIA128-SHA256:AECDH-AES256-SHA:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:AECDH-AES128-SHA:ADH-AES128-SHA:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:RSA-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:RSA-PSK-ARIA256-GCM-SHA384:AES256-GCM-SHA384:AES256-CCM8:AES256-CCM:ARIA256-GCM-SHA384:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:PSK-AES256-CCM8:PSK-AES256-CCM:PSK-ARIA256-GCM-SHA384:RSA-PSK-AES128-GCM-SHA256:RSA-PSK-ARIA128-GCM-SHA256:AES128-GCM-SHA256:AES128-CCM8:AES128-CCM:ARIA128-GCM-SHA256:PSK-AES128-GCM-SHA256:PSK-AES128-CCM8:PSK-AES128-CCM:PSK-ARIA128-GCM-SHA256:AES256-SHA256:CAMELLIA256-SHA256:AES128-SHA256:CAMELLIA128-SHA256:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:SRP-AES-256-CBC-SHA:RSA-PSK-AES256-CBC-SHA384:RSA-PSK-AES256-CBC-SHA:RSA-PSK-CAMELLIA256-SHA384:AES256-SHA:CAMELLIA256-SHA:PSK-AES256-CBC-SHA384:PSK-AES256-CBC-SHA:PSK-CAMELLIA256-SHA384:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:SRP-AES-128-CBC-SHA:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES128-CBC-SHA:RSA-PSK-CAMELLIA128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA:PSK-CAMELLIA128-SHA256";
        const char* ciphers_forward_secrecy ="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-CCM:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-CCM:ECDHE-ECDSA-ARIA256-GCM-SHA384:ECDHE-ARIA256-GCM-SHA384:DHE-DSS-ARIA256-GCM-SHA384:DHE-RSA-ARIA256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-CCM:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-CCM:ECDHE-ECDSA-ARIA128-GCM-SHA256:ECDHE-ARIA128-GCM-SHA256:DHE-DSS-ARIA128-GCM-SHA256:DHE-RSA-ARIA128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:DHE-RSA-CAMELLIA256-SHA256:DHE-DSS-CAMELLIA256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-PSK-AES256-GCM-SHA384:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:DHE-PSK-AES256-CCM8:DHE-PSK-AES256-CCM:DHE-PSK-ARIA256-GCM-SHA384:DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-CCM8:DHE-PSK-AES128-CCM:DHE-PSK-ARIA128-GCM-SHA256:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA:ECDHE-PSK-CAMELLIA256-SHA384:DHE-PSK-CAMELLIA256-SHA384:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA:ECDHE-PSK-CAMELLIA128-SHA256:DHE-PSK-CAMELLIA128-SHA256:";
        
        iteration(ciphers_forward_secrecy);

        exit(0);
}


//2. time 0RTT-time to fisrt byte last byte come back
//3. session resumption
