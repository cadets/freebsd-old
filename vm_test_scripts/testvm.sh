#!/bin/sh

bhyvectl --destroy --vm=$1

bhyveload -d $1.img -m 1g $1
bhyve -A -H -P -s 0:0,hostbridge -s 1:0,lpc -s 2:0,virtio-blk,./$1.img -s 3:0,virtio-dtrace -l com1,stdio -c 2 -m 1g -t $1
