# wclient

A simple webclient try to figure out how servers choose ciphers by providing various cipher suites.

## Software

### Prerequisites

* Apple clang `12.0.0` 
* clang `1200.0.32.29`  
* openssl `3.0.1`  
* npm `8.3.1`  
* node `v16.14.0`  
* lighthouse `9.5.0`  

# Installation

* Macports    
* * `curl -O https://distfiles.macports.org/MacPorts/MacPorts-2.7.2.tar.bz2`  
* * `port search --name --glob 'openssl'`
* openssl3    `sudo port install openssl -preforkmpm +workermpm`  
* lighthouse  `npm install -g lighthouse`  

### Instructions

Use client.c for experiment 1 and experiment 2.  
    run `clang -g -o client -I/opt/local/include/openssl-3 client.c  -L/opt/local/lib/openssl-3 -lssl -lcrypto`  

Use earlyDate.c for experiment 3   
    run `clang -g -o earlyData -I/opt/local/include/openssl-3 earlyData.c  -L/opt/local/lib/openssl-3 -lssl -lcrypto`  

Use 0-rtt/lighthouse.js for experiment 4  
    run `node lighthouse.js`   

## Validation
For forward-secrecy secure cipher suites:   
    `openssl s_client -connect [host:443]  -server [server-name] -tls1_2  -cipher [FS]`  

For non-forward-secrecy secure cipher suites:  
    `openssl s_client -connect [host:443]  -server [server-name] -tls1_2 -cipher [nonFS]`  

For early data deplyment:  
    ```
    host=ssltest.louis.info  
    echo -e "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" > request.txt  
    openssl s_client -connect $host:443 -tls1_3 -sess_out session.pem -ign_eof < request.txt  
    openssl s_client -connect $host:443 -tls1_3 -sess_in session.pem -early_data request.txt  
    ```  

For FCP, LCP, and TTI:  
    `node lighthouse [url]`  



