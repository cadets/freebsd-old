#!/bin/sh

bhyvectl --destroy --vm=test

bhyveload -d test.img -m 30g test
bhyve -A -H -P -s 0:0,hostbridge -s 1:0,lpc -s 2:0,virtio-blk,./test.img -s 3:0,virtio-dtrace -l com1,stdio -c 6 -m 30g -t test