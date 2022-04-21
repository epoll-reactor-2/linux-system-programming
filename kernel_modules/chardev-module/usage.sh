sudo insmod chardev.ko
dev="chardev"
major="$(grep "$dev" /proc/devices | cut -d ' ' -f 1 | head -1)"
sudo mknod "/dev/$dev" c "$major" 0

# Testing read
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo cat /dev/chardev
sudo cat /dev/chardev

# Testing write
# "/dev/chardev: Permission denied" message should emerge.
sudo echo "Hi" > /dev/chardev
sudo echo "Hi" > /dev/chardev
sudo echo "Hi" > /dev/chardev

sudo rmmod chardev
sudo rm /dev/chardev
sudo dmesg -c

if ! grep -q "$dev" /proc/devices
then
	echo "Test is OK, device was removed"
else
	echo "Test failed, device was not removed"
fi
