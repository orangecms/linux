/*******************************************************************************
  Copyright (C), 2014, TP-LINK TECHNOLOGIES CO., LTD.
  File name : oled_display.h
  Description : Header file of oled sysfs interface.
  Author : Luowei

  History:
------------------------------
V0.1, 2014-05-13, Luowei create file.
*******************************************************************************/

#ifndef __OLED_DISPLAY_H__
#define __OLED_DISPLAY_H__

#include <linux/types.h>

enum oled_display_property {
	DISPLAY_PROP_BUFFER = 0,
	DISPLAY_PROP_BACKLIGHTON,
	DISPLAY_PROP_PANELON,
	DISPLAY_PROP_NUMBER
};

struct oled_display {
	const char *name;
	enum oled_display_property *properties;
	size_t num_properties;

	ssize_t (*show_property[DISPLAY_PROP_NUMBER]) (struct device *dev,
	struct device_attribute *attr, char *buf);
	ssize_t (*store_property[DISPLAY_PROP_NUMBER]) (struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count);

	struct device *dev;
	spinlock_t lock;
};

int oled_display_register(struct device *parent, struct oled_display *display);

#endif