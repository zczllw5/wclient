#include "common.h"
#include <openssl/err.h>

#define KEYFILE "client.pem"
#define PASSWORD "password"


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

//every thing build on TCP
int tcp_connect(host,port)
  char *host;
  int port;
  {
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    
    if(!(hp=gethostbyname(host)))
      berr_exit("Couldn't resolve host");
    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr*)
      hp->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    if((sock=socket(AF_INET,SOCK_STREAM,
      IPPROTO_TCP))<0)
      err_exit("Couldn't create socket");
    if(connect(sock,(struct sockaddr *)&addr,
      sizeof(addr))<0)
      err_exit("Couldn't connect socket");
    
    printf("Sock created!\n");
    return sock;
  }

/*The password code is not thread safe*/
static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

static void sigpipe_handle(int x){
}

SSL_CTX *initialize_ctx(keyfile,password)
  char *keyfile;
  char *password;
  {
    //const struct SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();
      
      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);
    
    /* Create our context*/
    //meth= TLS_method();
    ctx=SSL_CTX_new(TLS_method());

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx,
      keyfile)))
      berr_exit("Can't read certificate file");

    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx,
      password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      keyfile,SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx,
      CA_LIST,0)))
      berr_exit("Can't read CA list");
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx,1);
#endif
    
    return ctx;
  }

int main(){
    
    SSL_CTX *ctx;
    

    //list my cipher suites
    
    printf("Begin the game!\n");
    
    int soc = tcp_connect(HOST,PORT);
    
    printf("What a socket looks like: %i!\n", soc);
    
    //initiate a ctx
    /* Build our SSL context*/
    ctx=initialize_ctx(KEYFILE,PASSWORD);
    printf("ctx initiated!\n");
    
    //1.send client_hello?
    //SSL_CTX_set_msg_callback()
    //to do that
    
    //BIO_socket(HOST,PORT);
    
    
    //STACK_OF() *sk;
    
//    struct stack_st_SSL_CIPHER *sk = SSL_get_ciphers(ssl);
//    _STACK st ;
//    while(1){
        //printf("%p\n", sk);
        //printf("Contents of structure %s are %_stack", sk, sk->data);
    
}
