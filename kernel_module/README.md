Linux module

# Illustration

```
$ make
$ sudo make install
$ sudo insmod epoll_reactor_module.ko
$ sudo rmmod epoll_reactor_module.ko
$ sudo dmesg -c

...
[20503.900377] Initialize epoll-reactor module...
[20503.900379] Ping message 0
[20503.900381] Ping message 1
[20503.900382] Ping message 2
[20503.900383] Ping message 3
[20503.900383] Ping message 4
[20503.900384] Ping message 5
[20503.900384] Ping message 6
[20503.900385] Ping message 7
[20503.900385] Ping message 8
[20503.900386] Ping message 9
[20503.900709] audit: type=1106 audit(1650367811.871:1538): pid=40289 uid=1000 auid=1000 ses=3 msg='op=PAM:session_close grantors=pam_systemd_home,pam_limits,pam_unix,pam_permit acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=success'
...
```
