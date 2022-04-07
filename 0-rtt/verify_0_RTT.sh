#!/bin/bash

function get_early_data(){
  echo -e "GET / HTTP/1.1\r\nHost: ${hosts[i]}\r\nConnection: close\r\n\r\n" > request.txt
  openssl s_client -connect ${hosts[i]}:443 -tls1_3 -sess_out session.pem -ign_eof < request.txt
  openssl s_client -connect ${hosts[i]}:443 -tls1_3 -sess_in session.pem -early_data request.txt
}

# hosts=(google.com youtube.com sina.com.cn canva.com google.com.hk google.com.br blogger.com google.co.in google.co.jp google.de walmart.com )
# for i in {0..10}
# do  
#   echo host: ${hosts[i]}
#   get_early_data 
# done

while IFS= read -r field1 
do
    echo $field1 
done < /Users/lian/Documents/UCL/Year4/FYP/topics/wclient/1_3_connected_output.csv

${field1[0]}