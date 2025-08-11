/*****************************************************************************
 * Copyright (C), 2002-2014, TP-LINK TECHNOLOGIES CO., LTD.
 *
 * File Name:   pm8019_ext.c
 * Version:     1.0
 * Description: Export some PM8019 software interfaces to sysfs.
 *
 * Author:      LuoWei
 * Create Date: 2014-04-10
 *
 * History:
 * 01    10Apr14     LuoWei         Create file
 *****************************************************************************/
#include <linux/kobject.h>
#include <mach/msm_smem.h>
#include <linux/gpio.h>
#include <linux/stat.h>
#include "pm8019_ext.h"

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned long long uint64;

/* [ouyangyi] add power on info */

char int_to_hex_char(int v)
{
	if (v >= 0 && v < 10)
	{
		return ('0' + v);
	}
	else if (v >= 10 && v < 16)
	{
		return ('A' + v - 10);
	}
	else
	{
		return 0;
	}
}

#define PMIC_PON_INFO_HEX_BITS 16

static ssize_t pmic_pon_info_show(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf)
{
	uint64 pon_info = 0;
	unsigned int size = 0;
	int i = 0;

	pon_info = *(uint64 *)smem_get_entry(SMEM_POWER_ON_STATUS_INFO, &size);

	if (!size || !pon_info) {
		pr_err("%s: Cannot get the pon_info\n", __func__);
		return sprintf(buf, "0000000000000000\n");
	}

	for (i = 0; i < PMIC_PON_INFO_HEX_BITS; i++) {
		buf[PMIC_PON_INFO_HEX_BITS - i - 1] =
			int_to_hex_char((int)(pon_info & 0xF));
		pon_info = pon_info >> 4;
	}

	buf[PMIC_PON_INFO_HEX_BITS] = '\n';

	return (PMIC_PON_INFO_HEX_BITS + 1);

}

static struct kobj_attribute pmic_pon_info_attr = {
	.attr = {
		.name = "pon_info",
		.mode = S_IRUGO,
	},
	.show = &pmic_pon_info_show,
};

static struct attribute *pmic_pon_info_attrs[] = {
	&pmic_pon_info_attr.attr,
	NULL
};

static struct attribute_group pmic_pon_info_attr_group = {
	.attrs = pmic_pon_info_attrs,
};
/* [ouyangyi] add end */

#define PM_TRIGGER_BIT_START 1
#define PM_TRIGGER_BIT_END   9

/*
 The function shows one byte of power on reason for User Level.
 The power on reason struct is :
 typedef struct
{
  unsigned hard_reset : 1;     //Hard reset event trigger
  unsigned smpl : 1;           //SMPL trigger
  unsigned rtc : 1;            //RTC trigger
  unsigned dc_chg : 1;         //DC Charger trigger
  unsigned usb_chg : 1;        //USB Charger trigger
  unsigned pon1 : 1;           //PON1 trigger
  unsigned cblpwr : 1;         //CBL_PWR1_N trigger
  unsigned kpdpwr : 1;         //KPDPWR_N trigger
}pm_pon_pon_reason_type;

buf[0]     buf[1]       buf[2]   ...   buf[8]
is reset   hard_reset   smpl     ...   kpdpwr
*/

static ssize_t pmic_pon_trigger_show(struct kobject *kobj,
			struct kobj_attribute *attr, char *buf)
{
	static int first_time = 1;
	static uint64 reason = 0;
	static unsigned int size = 0;
	uint8 pon_reason = 0;
	uint16 warm_reset_reason = 0;
	uint16 soft_reset_reason = 0;
	int i = 0;

	if (first_time) {
		first_time = 0;

		/*
		 * There are 8 bytes in field SMEM_POWER_ON_STATUS_INFO, which contains
		 * reasons for Power On(1 byte), Warm Reset(2 bytes), Power Off(2 bytes)
		 * , Soft Reset(2 bytes) and reserved byte(1 byte).
		 * The system is Litter-Endian, the last byte is power on reason.
		 */
		reason = *(uint64 *)smem_get_entry(SMEM_POWER_ON_STATUS_INFO,
			&size);
	}

	if (!size || !reason) {
		pr_err("%s: Cannot get the reasons\n", __func__);
		return sprintf(buf, "000000000\n");
	}

	pon_reason = (reason & 0xFF);
	warm_reset_reason = (reason >> (1 * 8)) & 0xFFFF;
	soft_reset_reason = (reason >> ((1 + 2 + 2) * 8)) & 0xFFFF;

	if (warm_reset_reason || soft_reset_reason) {
		buf[0] = '1';
	} else {
		buf[0] = '0';
	}

	for (i = PM_TRIGGER_BIT_START; i < PM_TRIGGER_BIT_END; i++) {
		if (pon_reason & (1 << (i - PM_TRIGGER_BIT_START))) {
			buf[i] = '1';
		} else {
			buf[i] = '0';
		}
	}

	buf[PM_TRIGGER_BIT_END] = '\n';

	return PM_TRIGGER_BIT_END + 1;
}

/*
 * Export sysfs interface.
 * "cat /sys/pmic/pon_trigger" shows the power-on reason
*/
static struct kobj_attribute pmic_trigger_attr = {
	.attr = {
		.name = "pon_trigger",
		.mode = S_IRUGO,
	},
	.show = &pmic_pon_trigger_show,
};

static struct attribute *pmic_trigger_attrs[] = {
	&pmic_trigger_attr.attr,
	NULL
};

static struct attribute_group pmic_trigger_attr_group = {
	.attrs = pmic_trigger_attrs,
};

void export_pmic_interface(void)
{
	struct kobject* kobj;
	int ret;

	kobj = kobject_create_and_add("pmic", NULL);
	if (!kobj) {
		pr_err("%s: failed to export PMIC interface\n", __func__);
		return;
	}

	ret = sysfs_create_group(kobj, &pmic_trigger_attr_group);
	if (!kobj || ret) {
		pr_err("%s: failed to export PMIC trigger interface\n", __func__);
	}

	ret = sysfs_create_group(kobj, &pmic_pon_info_attr_group);
	if (!kobj || ret) {
		pr_err("%s: failed to export PMIC pon_info interface\n", __func__);
	}

}

