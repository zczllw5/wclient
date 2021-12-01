#include "common.h"

void read_write(ssl, sock)
    SSL *ssl;
        {
            int width;
            int r,c2sl=0,c2s_offset=0;
            fd_set readfds,writefds;
            int shutdown_wait=0;
            char c2s[BUFSIZZ], s2c[BUFSIZZ];
            int ofcmode;

            /*First we make the socket nonblocking*/
            ofcmode=fcntl(sock,F_GETFL,0);
            ofcmode |=O_NDELAY;
            if(fcntl(sock, F_SETFL, ofcmode))
                err_exit("Couldn' t make socket nonblocking");

            width=sock+1;

            while(1){
                FD_ZERO(&readfds);//clears a set
                FD_ZERO(&writefds);

                FD_SET(sock, &readfds); //a fixed size buffer
                /*If we've got data to write do not try to read*/
                if(c2sl)
                    FD_SET(sock, &writefds);
                else
                    FD_SET(fileno(stdin),& readfds);

                r=select(width,&readfds,&writefds,0,0); //monitor multiple file descriptors, waiting until one or more of the file descriptors become "ready" for some class of I/O operation (e.g., input possible).
                if(r==0)
                    continue;

                /*now check if there's data to read*/
                if(FD_ISSET(sock,&readfds)){
                    do{
                        r =SSL_read(ssl,s2c,BUFSIZZ);
                        
                        switch(SSL_get_error(ssl,r)){
                            case SSL_ERROR_NONE:
                                fwrite (s2c, 1, r, stdout);
                                break;
                            case SSL_ERROR_ZERO_RETURN:
                                /*end of data*/
                                if(!shutdown_wait)
                                    SSL_shutdown(ssl);
                                goto end;
                                break;
                            case SSL_ERROR_WANT_READ:
                                break;
                            default:
                                berr_exit("SSL read problem");
                        }
                    }while(SSL_pending(ssl));
                }
                /*check for input on the console*/
                if(FD_ISSET(fileno(stdin),&readfds)){
                    c2sl=read(fileno(stdin),c2s,BUFSIZZ);
                    if(c2sl==0){
                        shutdown_wait=1;
                        if(SSL_shutdown(ssl))
                            return;
                    }
                    c2s_offset=0;
                }

                /*if got data write it*/
                if(c2sl && FD_ISSET(sock, &writefds)){
                    r=SSL_write(ssl,c2s+c2s_offset,c2sl);

                    switch(SSL_get_error(ssl,r)) {
                        /* We wrote something*/
                        case SSL_ERROR_NONE:
                            c2sl-=r;
                            c2s_offset+=r;
                            break;
                        /* We would have blocked */
                        case SSL_ERROR_WANT_WRITE:
                            break;
                        /* Some other error */
                        default:
                            berr_exit("SSL write problem");
                    }
                }
            }
        end:
            SSL_free(ssl);
            close(sock);
            return;
        }
