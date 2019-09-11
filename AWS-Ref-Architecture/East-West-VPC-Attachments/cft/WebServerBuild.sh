#
# Ubuntu Web Server Build
# Script can be placed into AWS UserData 
# Loops continuously waiting for firewall to intialise and then loads Apache and PHP
#
#!/bin/bash -ex
until resp=$(curl -s -S -g --max-time 3 --insecure "https://${FWIP}/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=LUFRPT1qS2xCRmZ6WVMrREtrK00yUGt4dVRna2lkY1U9cmgyaE93L3VoZ2U3WUgxeFpGVE1wOUNtdlM2S0Z5Z25ObG8wbmZoNXpuWT0=");do
if [[ $resp == *"[CDATA[yes"* ]] ; then
    break
  fi
  sleep 10s
done  
sudo apt-get update &&
sudo apt-get install -y apache2 php7.0 &&
sudo apt-get install -y libapache2-mod-php7. &&
sudo rm -f /var/www/html/index.html &&
sudo wget -O /var/www/html/index.php https://raw.githubusercontent.com/jasonmeurer/showheaders/master/showheaders.php &&
sudo service apache2 restart &&
sudo echo "done"