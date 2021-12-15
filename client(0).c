#include "common.h"
#include "read_write.h"

static char *REQUEST_TEMPLATE=
   "GET / HTTP/1.0\r\nUser-Agent:"
   "EKRClient\r\nHost: %s:%d\r\n\r\n";

static char *ciphers="PSK-AES128-CBC-SHA";

BIO *bio_err=0;

static char *pass;
static int password_cb(char *buf,int num,
  int rwflag,void *userdata);

/* A simple error and exit routine*/ //[E. Rescorla]
int err_exit(string)
  char *string;
  {
    fprintf(stderr,"%s\n",string);
    exit(0);
  }

/* Print SSL errors and exit*/
int berr_exit(string)
  char *string;
  {
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
  }

void destroy_ctx(ctx)
  SSL_CTX *ctx;
  {
    SSL_CTX_free(ctx);
    printf("ctx destroied!\n");
  }

//every thing build on TCP
int tcp_connect()
  {
    struct hostent *hp; // store information about a given host, such as host name, IPv4 address
    struct sockaddr_in addr; // a transport address and port for the AF_INET address family.
    int sock;
    
    if(!(hp=gethostbyname(HOST))) //gethoseby name is obsolete, tried getaddrinfo still ssl read problem
      berr_exit("Couldn't resolve host");
    printf("hp: %s and its ip address: %c\n",hp->h_name, hp->h_addr_list);
    memset(&addr,0,sizeof(addr)); //set the first num bytes of the block of memory pointed by addr to the specified value
    addr.sin_addr=*(struct in_addr*)hp->h_addr_list[0];
    //printf("addr.sin_addr: %i\n",);
    addr.sin_family=AF_INET; //the address family for IPv4.
    addr.sin_port=htons(PORT); //A transport protocol port number.
    if((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0)
      err_exit("Couldn't create socket");
    if(connect(sock,(struct sockaddr *)&addr,sizeof(addr))<0)
      err_exit("Couldn't connect socket");
    
    //printf("Sock: %i!\n",sock);
    //printf("hp: %s and its ip address: %i\n",hp->h_name, hp->h_addr_list);
    return sock;
  }

SSL_CTX *initialize_ctx()
  {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    if(!bio_err){
      /* Global system initialization*/
      //SSL_library_init();
      //SSL_load_error_strings();
      
      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }
    
    /* Create our context*/
    //meth = TLS_client_method();
    ctx=SSL_CTX_new(SSLv23_client_method());
    //printf("after SSL_CTX_new!\n");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx,
      CA_LIST,0)))
      berr_exit("Can't read CA list");
//#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx,1);
//#endif
    printf("ctx initiated!\n");
    return ctx;
  }

/* Check that the common name matches the host name*/
void check_cert(ssl,host)
  SSL *ssl;
  char *host;
  {
    X509 *peer;
    char peer_CN[256];
    //printf("SSL_get_verify_result(ssl): %li\n", SSL_get_verify_result(ssl));
    //if(SSL_get_verify_result(ssl)!=X509_V_OK) //returns the result of the verification of the X509 certificate
    //  berr_exit("Certificate doesn't verify");

    /*Check the cert chain. The chain length is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name againest host name*/
    peer=SSL_get_peer_certificate(ssl); //return a pointer to the X509 certificate the peer presented
      
    /*X509_NAME_get_text_by_NID() retrieve the "text" from the first entry in name which matches nid or obj, if no such entry exists -1 is returned*/
    int a;
    a = X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
    printf("result of X509_NAME_get_text_by_NID: %i!\n", a);
    if(strcasecmp(peer_CN,host))
      err_exit("Common name doesn't match host name");
      
    printf("end of check_cert!\n");
  }

void echo(ssl,sock)
    SSL *ssl;
    int sock;
    {
        printf("In the echo function\n");
        char buf[BUFSIZZ];
        int r,len,offset;

        while(1){
            printf("In the echo function loop\n");
            /*read data*/
            printf("r: %i",r);
            r = SSL_read(ssl,buf,BUFSIZZ);

            switch(SSL_get_error(ssl,r)){
                case SSL_ERROR_NONE:
                    len-=r;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    goto end;
                default:
                    berr_exit("SSL read problem");
            }

            /*now keep writing until we've written everything*/
            offset=0;

            while(len){
                r = SSL_write(ssl,buf+offset,len);
                switch(SSL_get_error(ssl,r)){
                    case SSL_ERROR_NONE:
                        len-=r;
                        offset +=r;
                        break;
                    default:
                        berr_exit("SSL write problem");
                }
            }
        }
    end:
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
    }

int main()
    {
        SSL *ssl; //use SSL object to represent an SSL connection
        SSL_CTX *ctx;
        BIO *sbio;
        int sock;
        char buf[BUFSIZZ];
    
        /* Build our SSL context by initiate a ctx*/
        ctx=initialize_ctx();
    
        sock = tcp_connect();//connect to the server
    
        /*need to implement Seed random number generator: Srng*/
    
        /*set cipher suites: could be set in ctx or pre-connection*/
//        if(ciphers){
//            SSL_CTX_set_cipher_list(ctx,ciphers);
//            berr_exit("Cipher suites error");
            //check for error about the return value 0/1.
            //printf("ciphers: %s\n",ciphers);
            //need to verify what is my default cipher
//        }
    
        ssl = SSL_new(ctx); //creat a new SSL structure to hold the TLS/SSL connection
    
        /*Do NOT directly attache SSL object to tcp connect, create a BIO object using the socket and then attach the SSL object to BIO. 1 BIO provide a layer of abstraction of I/O. 2 Allow OpenSSL do SSL handshakes on deviced that aren't socket at all */
        sbio=BIO_new_socket(sock,BIO_NOCLOSE);  //returns a socket BIO using sock and close_flag
        SSL_set_bio(ssl,sbio,sbio); //connects the rbio and the wbio, and transfers the ownership to ssl
        printf("after ssl_set_bio!\n");
        
        SSL_set_fd(ssl,sock);
        
        if (SSL_connect(ssl)<=0) //connected by blocking
            berr_exit("SSL connect error");
        //check_cert(ssl,HOST);
    
        /*read data*/
        echo(ssl,sock);
        //read_write(ssl,sock);
        
        
        /*make the HTTP request*/
        //http_request(ssl);
        //echo
        destroy_ctx(ctx);
}
