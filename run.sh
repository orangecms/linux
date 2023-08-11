#!/bin/sh

FEL=sunxi-fel
KERNEL=arch/arm/boot/Image
BIN=head.bin
# NOTE: Arm default text offset is 0x8000, see  `linux/arch/arm/Makefile`
ADDR=0x40008000

ONE_AND_A_HALF_MB=1572864
TWO_MB=2097152

# for testing around to decrease the transfer time
head -c $TWO_MB $KERNEL > $BIN

BIN=$KERNEL

echo Chip ID:
$FEL sid
$FEL sid
$FEL sid

echo Transfer binary...
$FEL write $ADDR $BIN
echo Run
$FEL exec $ADDR
echo Done.
