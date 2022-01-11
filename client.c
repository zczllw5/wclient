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
#define CIPHER_LIST "TLS_RSA_WITH_AES_256_CBC_SHA:TLS_NULL_WITH_NULL_NULL"

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

int match_host_by_regex(char *fileBuff){
    regex_t    preg;
    //char       *fileStream = "a very simple simple simple string";
    char       *pattern = "\\(?<=,)[A-Za-z0-9_.]+";                
    int        rc;
    size_t     nmatch = 2;
    regmatch_t pmatch[2];
 
   if (0 != (rc = regcomp(&preg, pattern, 0))) {
      printf("regcomp() failed, returning nonzero (%d)\n", rc);
      exit(EXIT_FAILURE);
   }
 
   if (0 != (rc = regexec(&preg, fileBuff, nmatch, pmatch, 0))) {
      printf("Failed to match '%s' with '%s',returning %d.\n",
             fileBuff, pattern, rc);
   }
//    else {
//       printf("With the whole expression, "
//              "a matched substring \"%.*lld\" is found at position %d to %d.\n",
//              pmatch[0].rm_eo - pmatch[0].rm_so, &fileBuff[pmatch[0].rm_so],
//              pmatch[0].rm_so, pmatch[0].rm_eo - 1);
//       printf("With the sub-expression, "
//              "a matched substring \"%.*lld\" is found at position %d to %d.\n",
//              pmatch[1].rm_eo - pmatch[1].rm_so, &fileBuff[pmatch[1].rm_so],
//              pmatch[1].rm_so, pmatch[1].rm_eo - 1);
//    }
   regfree(&preg);
   return 0;
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
    
    /*read line by ling and store stream in ssize_t. Not easy to transfer sszie_t to string when compare stringf */
    // char *line = NULL;
    // size_t len = 0;
    // ssize_t read;
    // while ((read = getline(&line, &len, fp)) != -1) {
    //     //printf("Retrieved line of length %zu :\n", read);
    //     //printf("%s", line);
    //     //sprintf(indexS, "%d", index);     
    //     if(strstr(read, indexS) != NULL){
    //         pch = strstr(buff, indexS);
    //         printf("the hose name: %s", pch);
    //     };
    // }

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
    printf("tokens: %s\n", tokens);

    tokens  = strtok(NULL, ",");
    //printf("second token which is host: %s\n", host);

    strcpy(host, tokens);
    //scanf()
    // rewind(fp);
    // if(fscanf(fp, "%s", buff) ==0){
    //     err_exit("fscanf error");
    // };
    // printf("First word = \n%s\n", buff);

    //match_host_by_regex(buff);

    //strcpy(host,(pch));
    //printf("host: %s\n",host);

    //method: read one line  and slipt the line by ',' the later part is host 

    /*read one line*/
    // char * line = NULL;
    // size_t len = 0;
    // ssize_t read;
    // read = getline(&line, &len, &pch);
    // printf("Retrieved line of length %zu:\n", read);
    // printf("%s", line);


    //char *mystring;
    //mystring = (char*) malloc (sizeof(char)*lSize);
    //fgets(mystring, INT_MAX, fp);
    //puts (mystring);
    //printf("the current line: %s\n",mystring);

    //char current[]  = host.Split(' ');
 
    // while(index <= 100){
    //     fgets(buff, 255, fp);
    //     printf("the website: %s\n",buff);
    //     pch = strstr(buff, ",");
    //     printf("the %ith website: %s\n", index, (pch+1));
    //     //strcpy(host,buff);
    //     //printf("the website: %s\n",website);
    //     index++;
    // }
    
    fclose(fp);
    return 0;
}

void HostNametoSessionCipher(char *host, char *sessionCipher){
    char *result;

    
    strcpy(sessionCipher,result);
}

void iteration100(){

}

int main()
    {
        SSL *myssl; /*use SSL object to represent an SSL connection*/
        SSL_CTX *ctx;
        BIO *mybio;
        SSL_SESSION *ses;
     
        int socketfd,err,ret;
        char buf[BUFSIZZ];
        
        struct sockaddr_in socketaddr;

        char host[15];
        char ip[100];
        const char *sessionCipher;
        
        get_the_nth_host_name(84,host);
        printf("host found by index: %s\n", host);    

        hostname_to_ip(host, ip);
        printf("%s resolved to %s\n", host, ip);
        
        socketaddr.sin_family=AF_INET;
        socketaddr.sin_addr.s_addr=inet_addr(ip);
        socketaddr.sin_port=htons(PORT); //host to network short
        
        const SSL_METHOD *meth;
        meth = TLS_client_method();
        
        ctx = SSL_CTX_new(meth);
        if(!ctx){
            printf("Error SSL_CTX_new.\n");
            exit(0);
        }
        
        printf("CIPHER_LIST: %s.\n",CIPHER_LIST);
        /*OSSL_default_ciphersuites() returns TLSv1.3 ciphersuites*/
        if(SSL_CTX_set_ciphersuites(ctx,CIPHER_LIST) == 0)
            err_exit("Error setting the cipher list.\n");
        
        if(!SSL_CTX_set_min_proto_version(ctx,0))
            err_exit("set min version error\n");
        err = SSL_CTX_set_max_proto_version(ctx,TLS1_2_VERSION);
        if(err==1)
            printf("SSL_CTX_set_max_proto_version succeed: %d!\n",TLS1_2_VERSION);
        if(err==0)
            err_exit("SSL_CTX_set_max_proto_version error");
    
        /*SSL_CTX_set_options(3): disable specific protocol versions*/
                
        /* Set for server verification*/
        //SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
        
        myssl=SSL_new(ctx);
        if(!myssl)
           err_exit("Error creating SSL structure.\n");
        
        socketfd=socket(AF_INET,SOCK_STREAM,0);
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
        mybio=BIO_new(BIO_s_connect());
        SSL_set_bio(myssl,mybio,mybio);
        printf("Prepare SSL connection on socket: %x, Version: %li, first cipher: %s, file descriptor:%i\n",
               socketfd
               ,SSL_CTX_get_max_proto_version(ctx)
               ,SSL_get_cipher_list(myssl,0)
               //,SSL_get_rbio(myssl)
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
        //ssl_error_exit(ctx,myssl,ret);
        
        ses = SSL_get1_session(myssl);
        
        sessionCipher = SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(ses));   
        printf("%s\n", sessionCipher);

        /*get the session ciher and find weather if the server forced PSK*/
        if(strstr(CIPHER_LIST, sessionCipher) != NULL){
            printf("session cipher in the CIPHER_LIST\n");
        } else {
            printf("session cipher NOT in the CIPHER_LIST\n");
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
        SSL_free(myssl);
        SSL_CTX_free(ctx);
        exit(0);

}
