#!/bin/sh
#
# Copyright (c) 2015-2018 Mark Johnston <markj@FreeBSD.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
#
# todo:
#   - support for incremental rebuilds of images
#   - ssh keys
#   - i386 images
#

usage()
{
    cat >&2 <<__EOF__
usage: $(basename $0) [-tkx] [-a <arch>] [-c <kernconf>] [-f <numfree>] [-p <pkgs>] [-s <size>] <img>
__EOF__
    exit 1
}

# Bootstrap packages.
bootstrap()
{
    local md mdir pfile pkgs

    pfile=$1
    pkgs=$2

    md=$(mdconfig -S $SECTORSIZE -f $pfile)
    mdir=$(mktemp -d)

    mount /dev/$md $mdir

    # Set up to install packages.
    #cp -f /etc/resolv.conf ${mdir}/etc/resolv.conf
    echo 'nameserver 8.8.8.8.' ${mdir}/etc/resolv.conf
    chroot ${mdir} env ASSUME_ALWAYS_YES=yes /usr/sbin/pkg -O OSVERSION=1200057 bootstrap -y

    # Do the thing.
    echo "$pkgs" | tr ',' ' ' | xargs chroot $mdir env ASSUME_ALWAYS_YES=yes \
        /usr/local/sbin/pkg -o OSVERSION=1200057 install

    # Clean up, clean up.
    umount $mdir
    rmdir $mdir
    mdconfig -d -u ${md#md}
}

cleanup()
{
    if [ $TMPFS ]; then
        umount $DESTDIR
    else
        rm -rf $DESTDIR || :
        chflags -R 0 $DESTDIR || :
        rm -rf $DESTDIR
    fi

    rm -f $PARTFILE
}

# Manually add a file to the image.
logfile()
{
    local file root size

    file=$1
    root=$2

    size=$(stat -f '%z' ${root}/${file})
    echo "./$file type=file uname=root gname=wheel mode=0644 size=$size" >> ${root}/METALOG
}

# Create custom system configuration files.
install_config()
{
    #local destdir fstab localtime rcconf srcconf
    local destdir fstab rcconf srcconf

    destdir=$1
    kernconfig=$2

    fstab=etc/fstab
    cat > ${destdir}/$fstab <<__EOF__
/dev/gpt/rootfs / ufs rw 1 1
/dev/gpt/swapfs none swap sw 0 0
none /proc procfs rw 0 0
none /dev/fd fdescfs rw 0 0
__EOF__

    if [ $NONET -eq 0 ]; then
        cat >> ${destdir}/$fstab <<__EOF__
${IPADDR}:$(pwd) /usr/src nfs ro 0 0
__EOF__
    fi

    #localtime=etc/localtime
    #cp -f /$localtime ${destdir}/$localtime

    rcconf=etc/rc.conf
    cat > ${destdir}/$rcconf <<__EOF__
ifconfig_vtnet0="DHCP"
ipv6_activate_all_interfaces="YES"
ipv6_cpe_wanif="vtnet0"
sendmail_enable="NONE"
sshd_enable="YES"
__EOF__

    srcconf=etc/src.conf
    cat > ${destdir}/$srcconf <<__EOF__
KERNCONF?= $kernconfig
__EOF__

    wallcmosclock=etc/wall_cmos_clock
    touch ${destdir}/$wallcmosclock

    logfile $fstab $destdir
    #logfile $localtime $destdir
    logfile $rcconf $destdir
    logfile $srcconf $destdir
    logfile $wallcmosclock $destdir
    echo 'ums_load="YES"' >> ${destdir}/boot/loader.conf
    echo 'fdescfs_load="YES"' >> ${destdir}/boot/loader.conf
    echo 'vmm_load="YES"' >> ${destdir}/boot/loader.conf
    echo 'dtraceall_load="YES"' >> ${destdir}/boot/loader.conf
}

#
# Execution begins here.
#

set -e

ARCH=$(uname -m)
IPADDR=
KERNCONFIG=
MKSRC=0
NONET=0
NUMFILES=
PARTSIZE=10g
PACKAGES=
SECTORSIZE=512
TMPFS=
while getopts a:c:f:i:k:p:S:s:tx o; do
    case "$o" in
    a)
        ARCH=$OPTARG
        ;;
    c)
        KERNCONFIG=$OPTARG
        ;;
    f)
        NUMFILES=$OPTARG
        ;;
    i)
        IPADDR=$OPTARG
        ;;
    k)
        MKSRC=1
	SRCDIR=$OPTARG
        ;;
    p)
        PACKAGES=$OPTARG
        ;;
    s)
        PARTSIZE=$OPTARG
        ;;
    S)
        SECTORSIZE=$OPTARG
        ;;
    t)
        TMPFS=1
        ;;
    x)
        NONET=1
	;;
    ?)
        usage
        ;;
    esac
    shift $((OPTIND-1))
done

if [ -n "$PACKAGES" -a $(id -u) -ne 0 ]; then
    echo "$(basename $0): must be root to install packages" >&2
    exit 1
elif [ "$TMPFS" -a $(id -u) -ne 0 ]; then
    echo "$(basename $0): must be root to use tmpfs" >&2
    exit 1
fi

if [ -z "$KERNCONFIG" ]; then
    KERNCONFIG=BHYVE
fi

if [ $NONET -eq 0 ]; then
    if [ -z "$IPADDR" ]; then
        ifconfig bridge0 >/dev/null || exit 1
        IPADDR=$(ifconfig bridge0 | grep -E '^[[:space:]]*inet' | head -n 1 | \
            awk '{print $2}')
    fi
fi

IMAGE=${1:-/tmp/vm.raw}
PARTFILE=$(mktemp)

DESTDIR=$(mktemp -d)
if [ $TMPFS ]; then
    mount -t tmpfs tmpfs $DESTDIR
fi

trap "cleanup; exit 1" EXIT SIGINT SIGHUP SIGTERM

make -j $(sysctl -n hw.ncpu) -s -DNO_ROOT DESTDIR=$DESTDIR KERNCONF=$KERNCONFIG \
    MACHINE=$ARCH TARGET_ARCH=$ARCH \
    DISTDIR= installworld installkernel distribution

install_config $DESTDIR $KERNCONFIG

if [ -z "$NUMFILES" ]; then
    NUMFILES=$(cat ${DESTDIR}/METALOG | wc -l)
fi

if [ $MKSRC -eq 1 ]; then
    echo "Installing source..."
    cp -R $SRCDIR/* $DESTDIR/usr/src
fi

makefs -B little -f $NUMFILES -o label=VM -M $PARTSIZE -S $SECTORSIZE \
    -F ${DESTDIR}/METALOG $PARTFILE $DESTDIR

if [ -n "$PACKAGES" ]; then
    bootstrap $PARTFILE $PACKAGES
fi

mkimg -s gpt -f raw -S $SECTORSIZE -b ${DESTDIR}/boot/pmbr \
    -p freebsd-boot/bootfs:=${DESTDIR}/boot/gptboot \
    -p freebsd-swap/swapfs::2G \
    -p freebsd-ufs/rootfs:=${PARTFILE} \
    -o $IMAGE

rm -f $PARTFILE
