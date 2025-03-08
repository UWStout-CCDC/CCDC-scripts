#!/bin/bash
# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No color

echo -e "${YELLOW}WARNING: THIS SCRIPT TAKES A LONG TIME TO RUN!${NC}"
echo -e "${YELLOW}DO NOT RUN IF YOU ARE IN A COMPETITION AND PRESSED FOR TIME.${NC}"
sleep 3

# Install the dependencies
echo -e "${GREEN}Installing Development Tools and Dependencies...${NC}"
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python-devel swig zlib-devel

# Download the old Bro (Zeek)
echo -e "${GREEN}Downloading Bro (Zeek) 2.6.4...${NC}"
cd /usr/local/src
sudo wget https://old.zeek.org/downloads/bro-2.6.4.tar.gz

# Unzip the tarball
echo -e "${GREEN}Extracting Bro (Zeek) 2.6.4...${NC}"
sudo tar -xvzf bro-2.6.4.tar.gz
cd bro-2.6.4

# Configure the build
echo -e "${GREEN}Configuring Bro (Zeek)...${NC}"
sudo ./configure --prefix=/opt/bro

# Compile and install
echo -e "${GREEN}Compiling Bro (Zeek), this may take a while...${NC}"
sudo make -j$(nproc)

echo -e "${GREEN}Installing Bro (Zeek)...${NC}"
sudo make install

# Set PATH
echo -e "${GREEN}Adding Bro (Zeek) to system PATH...${NC}"
echo 'export PATH=/opt/bro/bin:$PATH' | sudo tee -a /etc/profile
source /etc/profile

# Detect the correct network interface
INTERFACE=$(ip route | grep default | awk '{print $5}')
echo -e "${GREEN}Detected Network Interface: ${YELLOW}$INTERFACE${NC}"

# Replace interface setting in node.cfg
echo -e "${GREEN}Configuring Bro (Zeek) to use interface: ${YELLOW}$INTERFACE${NC}"
sudo sed -i "s/interface=eth0/interface=$INTERFACE/" /opt/bro/etc/node.cfg

# Start Bro (Zeek)
echo -e "${GREEN}Deploying Bro (Zeek) with BroControl...${NC}"
sudo /opt/bro/bin/broctl deploy

echo -e "${GREEN}Installation and configuration completed successfully!${NC}"

