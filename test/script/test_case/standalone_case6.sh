#!/bin/bash

create_and_delete()
{
    mount /dev/hadm0 /mnt
    dd if=/dev/urandom of=/mnt/4K bs=4K count=1
    rm -f /mnt/4K
    umount /mnt
}

for i in $(seq 1 10000); do
    echo "try write: $i"
    create_and_delete
done

exit $?
