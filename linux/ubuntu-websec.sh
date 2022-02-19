sudo apt update && sudo apt install ufw -y
sudp ufw enable
sudo ufw allow 80 sudo charrt +i /etc/passwd && sudo chattr +i /etc/group
sudo service ssh stop
sudo echo "ServerSignature Off" >> /etc/apache2/conf-available/ccdc.conf
sudo echo "ServerTokens Prod" >> /etc/apache2/conf-available/ccdc.conf
sudo echo "Options all -Indexes" >> /etc/apache2/conf-available/ccdc.conf
sudo echo "SecServerSignature This is the CCDC signature!" >> /etc/apache2/conf-available/ccdc.conf
sudo a2enmod headers
sudo echo "Headers always unset X-Powered-By" >> /etc/apache2/conf-available/ccdc.conf

sudo apt install libapache2-modsecurity -y
sudo cp /etc/modsecurity/modsecurity{-recommended,}
sudo sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/g" /etc/modsecurity/modsecurity
sudo sed -i "s/SecRequestBodyAccess On/SecRequestBodyAccess Off/g" /etc/modsecurity/modsecurity
sudo apt install libapache2-mod-evasive -y
sudo mkdir /var/log/apache2/mod_evasive && sudo chmod 777 /var/log/apache2/mod_evasive
