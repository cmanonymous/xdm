#!/bin/bash

hadmpri
mkfs.ext3 -b 4096 /dev/hadm0
mount /dev/hadm0 /mnt
cp /boot/initrd.img-3.2.0-64-generic /mnt
sync

hadmctl fbsync hadm0 1
sleep 1
cp /etc/passwd /mnt
umount /mnt

exit $?
