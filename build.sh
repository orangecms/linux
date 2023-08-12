#!/bin/sh

ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- make -j32

ls -l arch/arm/boot/Image
