#!/bin/bash
#
# System init for Redhat/Centos 6.x
#


# Install yum repo
#/bin/cp -a /etc/yum.repos.d /tmp/
#/bin/rm -rf /etc/yum.repos.d/*
#if ! rpm --force -Uvh http://mirrors.hust.edu.cn/epel//6/x86_64/epel-release-6-8.noarch.rpm
#then
#    echo "Install yum repo failed."
#    exit 1
#fi
#if ! rpm --force -Uvh http://rpms.famillecollet.com/enterprise/remi-release-6.rpm 
#then
#    echo "Install yum repo failed."
#    exit 1
#fi
#sed -i "s/enabled=0/enabled=1/g" /etc/yum.repos.d/remi.repo


# Install some packages.
packages="atop
vim
sed
awk
openssl
openssl-devel
pcre
pcre-devel
blktrace
expect
htop
iftop
iotop
nethogs
nload
numactl
openssl
popt-devel
python-argparse
python-devel
rpm-build
snmpd
syslog-ng
tcpstat
telnet
screen
tmux"
for i in $packages
do
    yum -y install $i
done


# Setting up on.
chkconfig_on="psacct microcode_ctl network crond lm_sensors openibd irqbalance sshd ipmi sendmail"
for i in ${chkconfig_on}
do
    /sbin/chkconfig --level 2345 $i on 2>/dev/null
done


# Setting up off.
chkconfig_off="NetworkManager acpid syslog anacron apmd arptables_jf atd auditd autofs avahi-daemon avahi-dnsconfd bluetooth conman cpuspeed cups dnsmasq dund firstboot gpm haldaemon hidd hpoj httpd ibmasm identd iiim ip6tables ipchains irda isdn kdump keytable kudzu linuxconf lm_sensors lpd mcstrans mdmonitor mdmpd messagebus microcode_ctl netconsole netfs netplugd nfs nfslock nscd ntpd oddjobd pand pcmcia pcscd portmap psacct random rawdevices rdisc restorecond rhnsd rpcgssd rpcidmapd rpcsvcgssd saslauthd setroubleshoot sgi_fam smartd smb sysstat vncserver winbind wpa_supplicant xfs xinetd ypbind yum-updatesd iptables snmpd"
for i in ${chkconfig_off}
do
    /sbin/chkconfig --level 2345 $i off 2>/dev/null
done


# Deny users command.
#for i in sz rz ftp lftp sftp rsync smbmount smbclient apt-get at mount yum wget rpm gcc make
for i in sz rz ftp lftp sftp smbmount smbclient apt-get at mount yum rpm gcc make
do
        /usr/bin/whereis $i | awk '{print $2}' | xargs chmod 750
done

for i in ftp-rfc lftp lftpget  pftp  rftp  sftp rcp rlogin  slogin ash  ash.static bsh csh
do
        /usr/bin/whereis $i | awk '{print $2}' | xargs rm -f
done

for i in sz rz ftp lftp sftp rsync smbmount smbclient scp apt-get at mount yum wget rpm gcc make
do
        /usr/bin/whereis $i | awk '{print $2}' | xargs chown root:root
done


# Delete not userful users
for i in adm lp sync shutdown halt news uucp games operator mail gopher ftp
do
        /usr/sbin/userdel $i
done


# Delete special groups
for i in adm lp news uucp games dip
do
        /usr/sbin/groupdel $i
done


# Set pasword lifetime
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   99999/g;s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   0/g;s/^PASS_MIN_LEN.*/PASS_MIN_LEN    20/g'  c/etc/login.defs


# Remove ctrlaltdel
# sed -i 's/ca::ctrlaltdel:/#ca::ctrlaltdel:/g' /etc/inittab


# Bash prompt
if ! grep 'source /etc/bashrc' /etc/profile >/dev/null
then
cat >> /etc/profile  <<EOF
if [ \$SHELL == /bin/bash ]; then
source /etc/bashrc
fi
EOF
fi


# Add serial tty
if ! grep 'ttyS0' /etc/securetty >/dev/null
then
    echo 'ttyS0' >> /etc/securetty;
fi


# Disable ipv6
if [ ! -f /etc/modprobe.d/net.conf ]
then
    touch /etc/modprobe.d/net.conf
fi

if ! grep 'options ipv6 disable=1' /etc/modprobe.d/net.conf >/dev/null
then
    echo "options ipv6 disable=1" >> /etc/modprobe.d/net.conf
fi

if ! grep 'alias net-pf-10 off' /etc/modprobe.d/net.conf >/dev/null
then
    echo "alias net-pf-10 off" >> /etc/modprobe.d/net.conf
fi


sed -i /NETWORKING_IPV6/cNETWORKING_IPV6=no /etc/sysconfig/network
#rm -rf /etc/udev/rules.d/70-persistent-net.rules


# Motd text
for i in motd issue issue.net
do
    if ! grep "Authorized users only.  All activity may be monitored and reported" /etc/"$i" >/dev/null
    then
        echo "Authorized users only.  All activity may be monitored and reported" >> /etc/"$i"
    fi
done


# Logrotate
sed -i 's/\#compress/compress/' /etc/logrotate.conf


# Add module ip_conntrack_ftp for iptables
sed -i /IPTABLES_MODULES/s/\"$/\ ip_conntrack_ftp\"/ /etc/sysconfig/iptables-config


# Add  ulimit for all user & root
cat >> /etc/security/limits.conf << EOF
root             soft   nofile          65536
root             hard   nofile          65536
*                soft   nofile          655360
*                hard   nofile          655360
root             soft   nproc           1024
root             hard   nproc           1024
*                soft   nproc           8192
*                hard   nproc           8192
EOF
sed -i "/*          soft    nproc/s/.*/*          soft    nproc     8192/g" /etc/security/limits.d/90-nproc.conf


# Raise nice
#echo 'root         -       nice            -20' >>/etc/security/limits.conf


# Set LANGUAGE
if ! grep 'LANGUAGE=en_US.UTF-8' /etc/profile >/dev/null
then
cat >> /etc/profile  <<EOF
export LANGUAGE=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
EOF
fi


# tune fstab
sed -i '/\ \/\ /s/defaults/defaults,data=ordered/g' /etc/fstab
#sed -i '/\ \/tmp\ /s/defaults/defaults,data=ordered,nodev,nosuid,noexec/g' /etc/fstab
sed -i '/\ \/tmp\ /s/defaults/defaults,data=ordered,nodev,nosuid/g' /etc/fstab
sed -i '/\ \/opt\ /s/defaults/defaults,data=ordered,nodev,nosuid/g' /etc/fstab
sed -i '/\ \/home\ /s/defaults/defaults,data=ordered,nodev,nosuid/g' /etc/fstab
sed -i '/\ \/var\ /s/defaults/defaults,data=ordered,nodev/g' /etc/fstab
sed -i '/\ \/usr\ /s/defaults/defaults,data=ordered,nodev/g' /etc/fstab
sed -i '/\ \/boot\ /s/defaults/defaults,data=ordered,nodev,nosuid,noexec/g' /etc/fstab


# change hashsize
echo 'echo 64000 > /sys/module/nf_conntrack/parameters/hashsize' >> /etc/rc.local


#sed -i '/splashimage/a password wandoujia.com'  /boot/grub/grub.conf


# Change the command history
sed -i '/^HISTSIZE=/c\HISTSIZE=10240' /etc/profile


# Add history date
if ! grep 'export HISTTIMEFORMAT="%F %T' /etc/bashrc >/dev/null
then
    echo 'export HISTTIMEFORMAT="%F %T "' >>/etc/bashrc
fi


# Change PS1
cat >> /etc/profile  <<EOF
export PS1='[\u@\H:\w]\\$ '
EOF


# Change lvm config
sed -i 's/umask = 077/umask = 022/g' /etc/lvm/lvm.conf


# Set up kernel
echo "# Kernel sysctl configuration file for Red Hat Linux
#
# For binary values, 0 is disabled, 1 is enabled.  See sysctl(8) and
# sysctl.conf(5) for more details.

# Controls IP packet forwarding
net.ipv4.ip_forward = 0

# Controls source route verification
net.ipv4.conf.default.rp_filter = 1

# Added by liningning
net.ipv4.conf.eth1.rp_filter = 0
net.ipv4.conf.em2.rp_filter = 0
net.ipv4.conf.p1p2.rp_filter = 0

# Do not accept source routing
net.ipv4.conf.default.accept_source_route = 0

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1

# Disable netfilter on bridges.
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0

# Controls the maximum size of a message, in bytes
kernel.msgmnb = 65536

# Controls the default maxmimum size of a mesage queue
kernel.msgmax = 65536

# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736

# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296

# Reboot a minute after an Oops
kernel.panic = 60

# Syncookies make SYN flood attacks ineffective
net.ipv4.tcp_syncookies = 1

# Ignore bad ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0

# Enable IP spoofing protection, turn on source route verification
net.ipv4.conf.all.rp_filter = 0

# Log Spoofed Packets, Source Routed Packets, Redirect Packets
net.ipv4.conf.all.log_martians = 1

# Reply to ARPs only from correct interface (required for DSR load-balancers)
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
fs.file-max = 1024000

net.ipv4.tcp_max_syn_backlog = 65536
net.core.netdev_max_backlog =  32768
net.core.somaxconn = 32768

#net.core.wmem_default = 8388608
#net.core.rmem_default = 8388608
#net.core.rmem_max = 16777216
#net.core.wmem_max = 16777216

net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2

net.ipv4.tcp_tw_recycle = 0
#net.ipv4.tcp_tw_len = 1
net.ipv4.tcp_tw_reuse = 1

net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_max_orphans = 3276800

#net.ipv4.tcp_fin_timeout = 30
#net.ipv4.tcp_keepalive_time = 120
net.ipv4.ip_local_port_range = 10000  65535

vm.swappiness = 0

#vulnerability from 2.6.37 till 3.8.8
perf_event_paranoid = 2

net.nf_conntrack_max = 655350
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 30
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30" > /etc/sysctl.conf
sysctl -p


# Set selinux off
sed -i "s/^SELINUX=.*/SELINUX=disabled/g"/etc/selinux/config
setenforce 0

# Config for sshd
sed -i "/^UseDNS/s/.*/UseDNS no/g" /etc/ssh/sshd_config
sed -i "/GSSAPIAuthentication/s/yes/no/g" /etc/ssh/ssh_config
/etc/init.d/sshd reload


# Iptables set
#> /etc/sysconfig/iptables
#/etc/init.d/iptables stop
echo '*filter
:INPUT DROP [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 10.0.0.0/8 -j ACCEPT
-A INPUT -s 172.0.0.0/8 -j ACCEPT
-A INPUT -s 192.0.0.0/8 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 0 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A INPUT -p udp -m udp --dport 161 -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
COMMIT' >/etc/sysconfig/iptables
/etc/init.d/iptables start
chkconfig iptables on


# Setup dmesg timestamp
echo "echo 1 > /sys/module/printk/parameters/time" >> /etc/rc.d/rc.local


# Disable mail
echo "unset MAILCHECK" >> /etc/profile

