#!/bin/sh

FEL=sunxi-fel
BDIR=arch/arm/boot
KERNEL=$BDIR/Image
DTB=$BDIR/dts/sun8i-v40-sharevdi-r1-256m.dtb

# NOTE: Arm default text offset is 0x8000, see  `linux/arch/arm/Makefile`
KER_ADDR=0x40008000
# 10 MB offset for DTB
DTB_ADDR=0x40c08000

echo Chip ID:
$FEL sid
$FEL sid
$FEL sid

echo Transfer binary, takes ~60 seconds...
$FEL write $KER_ADDR $KERNEL
sleep 1
echo Transfer DTB...
$FEL write $DTB_ADDR $DTB
echo Run
$FEL exec $KER_ADDR
echo Done.
