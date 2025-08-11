/*****************************************************************************
 * Copyright (C), 2002-2014, TP-LINK TECHNOLOGIES CO., LTD.
 *
 * File Name:   pm8019_ext.h
 * Version:     1.0
 * Description: Export some PM8019 software interfaces to sysfs.
 *
 * Author:      LuoWei
 * Create Date: 2014-04-10
 *
 * History:
 * 01    10Apr14     LuoWei         Create file
 *****************************************************************************/

#ifndef __PM8019_EXT_H__
#define __PM8019_EXT_H__

#ifdef CONFIG_TPLINK_PMIC_EXT
void export_pmic_interface(void);
#else
void export_pmic_interface(void){}
#endif

#endif /* __PM8019_EXT_H__ */

