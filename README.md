# wclient

A simple webclient try to figure out how servers choose ciphers by providing various cipher suites.

Use client.c for experiment 1 and experiment 2.  
    run clang -g -o client -I/opt/local/include/openssl-3 client.c  -L/opt/local/lib/openssl-3 -lssl -lcrypto
Use earlyDate.c for experiment 3   
    run clang -g -o earlyData -I/opt/local/include/openssl-3 earlyData.c  -L/opt/local/lib/openssl-3 -lssl -lcrypto
Use 0-rtt/lighthouse.js for experiment 4  
    run node lighthouse.js