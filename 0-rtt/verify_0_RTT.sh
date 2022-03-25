#!/bin/bash

while IFS=\= read var; do
    vars+=($var)
    #echo $var
done < "top_1h.csv"

echo $vars
echo "the last host is ${vars[99]}"

host1=${vars[0]}
echo pass the hostname to a variable:$host1

host2=google.com
echo $host2

echo -e "GET / HTTP/1.1\r\nHost: $host1\r\nConnection: close\r\n\r\n" > request.txt
openssl s_client -connect $host1:443 -tls1_3 -sess_out session.pem -ign_eof < request.txt
openssl s_client -connect $host1:443 -tls1_3 -sess_in session.pem -early_data request.txt

# host=ssltest.louis.info
# echo -e "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" > request.txt
# openssl s_client -connect $host:443 -tls1_3 -sess_out session.pem -ign_eof < request.txt
# openssl s_client -connect $host:443 -tls1_3 -sess_in session.pem -early_data request.txt

# echo -e "GET / HTTP/1.1\r\nHost: ${vars[4]}\r\nConnection: close\r\n\r\n" > 0-RTT/request.txt
# openssl s_client -connect youtube.com:443 -tls1_3 -sess_out session.pem -ign_eof < request.txt
# openssl s_client -connect ${vars[4]}:443 -tls1_3 -sess_in session.pem -early_data 0-RTT/request.txt

# for i in {0..1}
# do  
#   host=${vars[i]}
#   echo $host
#   echo -e "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n" > request.txt
#   openssl s_client -connect $host:443 -tls1_3 -sess_out session.pem -ign_eof < request.txt
#   # openssl s_client -connect $host:443 -tls1_3 -sess_in session.pem -early_data request.txt
# done



