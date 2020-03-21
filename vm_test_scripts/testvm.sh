#!/bin/sh

bhyvectl --destroy --vm=test

bhyveload -d test.img -m 1g test
bhyve -A -H -P -s 0:0,hostbridge -s 1:0,lpc -s 2:0,virtio-blk,./test.img -s 3:0,virtio-dtrace -l com1,stdio -c 2 -m 1g -t test
