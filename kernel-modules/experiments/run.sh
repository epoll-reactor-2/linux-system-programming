make
sudo rmmod dev.ko
sudo insmod dev.ko
gcc userspace.c -o userspace
sudo ./userspace
echo "=== userspace exited with $? ==="
sudo dmesg | tail -20