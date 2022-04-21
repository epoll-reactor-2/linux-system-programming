sudo insmod chardev.ko
dev="chardev"
major="$(grep "$dev" /proc/devices | cut -d ' ' -f 1 | head -1)"
sudo mknod "/dev/$dev" c "$major" 0
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo rm /dev/chardev
sudo rmmod chardev
sudo dmesg -c

if ! grep -q "$dev" /proc/devices
then
	echo "Test is OK, device was removed"
else
	echo "Test failed, device was not removed"
fi
