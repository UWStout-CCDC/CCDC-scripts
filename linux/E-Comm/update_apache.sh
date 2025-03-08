# https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/feature/ecomm-hardening/linux/E-Comm/update_apache.sh
#######################################
#
#          UPDATE HTTPD TO 2.4.60
#
#######################################
# Check if the httpd version is already 2.4.60
if httpd -v | grep -q "2.4.60"
then
    echo "httpd version is already 2.4.60"
else
    echo "Updating httpd to 2.4.60..."
    # Ensure mod_ssl is installed
    # yum install mod_ssl -y

    # # Download pre-requisite packages
    yum install -y gcc pcre-devel mod_ssl openssl-devel expat expat-devel apr-devel apr-util-devel
    # yum install -y gcc make apr-devel apr-util-devel pcre-devel mod_ssl openssl-devel expat expat-devel

    cd /opt

    # Download the httpd 2.4.60 source code
    wget https://archive.apache.org/dist/httpd/httpd-2.4.60.tar.gz
    tar -xvf httpd-2.4.60.tar.gz
    cd httpd-2.4.60

    cd srclib

    sudo wget https://downloads.apache.org/apr/apr-1.7.5.tar.gz
    sudo tar -xvzf apr-1.7.5.tar.gz
    mv apr-1.7.5 apr
    sudo wget https://downloads.apache.org/apr/apr-util-1.6.3.tar.gz
    sudo tar -xvzf apr-util-1.6.3.tar.gz
    mv apr-util-1.6.3 apr-util
    rm -f apr-1.7.5.tar.gz apr-util-1.6.3.tar.gz

    cd ..

    # Run configure script with specified options
    ./configure --with-included-apr --with-included-apr-util --enable-ssl --enable-so --prefix=/etc/httpd
    make
    make install
    systemctl stop httpd
    # take a backup only if the /root/httpd.old does not exist
    if [ ! -f /root/httpd.old ]; then
        mv /usr/sbin/httpd /root/httpd.old
    fi
    mv httpd /usr/sbin/httpd
    cd ..
    # rm -rf httpd-2.4.60
    rm httpd-2.4.60.tar.gz
    cat <<-EOF > /etc/httpd/conf.modules.d/00-mpm.conf
# Select the MPM module which should be used by uncommenting exactly
# one of the following LoadModule lines. See the httpd.conf(5) man
# page for more information on changing the MPM.

# prefork MPM: Implements a non-threaded, pre-forking web server
# See: http://httpd.apache.org/docs/2.4/mod/prefork.html
#
# NOTE: If enabling prefork, the httpd_graceful_shutdown SELinux
# boolean should be enabled, to allow graceful stop/shutdown.
#
#LoadModule mpm_prefork_module modules/mod_mpm_prefork.so

# worker MPM: Multi-Processing Module implementing a hybrid
# multi-threaded multi-process web server
# See: http://httpd.apache.org/docs/2.4/mod/worker.html
#
#LoadModule mpm_worker_module modules/mod_mpm_worker.so

# event MPM: A variant of the worker MPM with the goal of consuming
# threads only for connections with active processing
# See: http://httpd.apache.org/docs/2.4/mod/event.html
#
#LoadModule mpm_event_module modules/mod_mpm_event.so
EOF

    systemctl start httpd
fi

#######################################
#
#          END HTTPD UPDATE
#
#######################################