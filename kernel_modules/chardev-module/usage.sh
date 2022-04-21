sudo insmod chardev.ko
dev="chardev"
# major="$(grep "$dev" /proc/devices | cut -d ' ' -f 1)"
major="511"
sudo mknod "/dev/$dev" c "$major" 0
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo rm /dev/chardev
sudo rmmod chardev
sudo dmesg -c
