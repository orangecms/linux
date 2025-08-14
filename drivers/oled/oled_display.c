/*******************************************************************************
  Copyright (C), 2014, TP-LINK TECHNOLOGIES CO., LTD.
  File name : oled_display.h
  Description : oled sysfs interface.
  Author : Luowei

  History:
------------------------------
V0.1, 2014-05-13, Luowei create file.
*******************************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/err.h>
#include "oled_display.h"

struct class *oled_display_class;
EXPORT_SYMBOL_GPL(oled_display_class);

static struct device_type oled_display_dev_type;

#define DISPLAY_ATTR(_name)                 \
{                                           \
	.attr = { .name = #_name },             \
	.show = oled_display_show_property,          \
	.store = oled_display_store_property,        \
}

static struct device_attribute oled_display_attrs[];

static ssize_t oled_display_show_property(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct oled_display *display = dev_get_drvdata(dev);
	const ptrdiff_t off = attr - oled_display_attrs;
	ssize_t ret = 0;

	if (!display)
		goto show_failed;

	if ((off >= DISPLAY_PROP_BUFFER && off < DISPLAY_PROP_NUMBER)
		&& display->show_property[off])
			ret = display->show_property[off](dev, attr, buf);

	return ret;
show_failed:
	return 0;
}

static ssize_t oled_display_store_property(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	struct oled_display *display = dev_get_drvdata(dev);
	const ptrdiff_t off = attr - oled_display_attrs;
	ssize_t ret = 0;

	if (!display)
		goto show_failed;

	if ((off >= DISPLAY_PROP_BUFFER && off < DISPLAY_PROP_NUMBER)
		&& display->store_property[off])
		ret = display->store_property[off](dev, attr, buf, count);

	return ret;
show_failed:
	return 0;
}

static struct device_attribute oled_display_attrs[] = {
	DISPLAY_ATTR(oled_buffer),
	DISPLAY_ATTR(backlight_on),
	DISPLAY_ATTR(panel_on),
};

static struct attribute *__oled_display_attrs[ARRAY_SIZE(oled_display_attrs) + 1];

static umode_t oled_display_attr_is_visible(struct kobject *kobj,
					   struct attribute *attr,
					   int attrno)
{
	return (S_IRUGO | S_IWUGO);
}

static struct attribute_group oled_display_attr_group = {
	.attrs = __oled_display_attrs,
	.is_visible = oled_display_attr_is_visible,
};

static const struct attribute_group *oled_display_attr_groups[] = {
	&oled_display_attr_group,
	NULL,
};

static void oled_display_init_attrs(struct device_type *dev_type)
{
	int i;

	dev_type->groups = oled_display_attr_groups;

	for (i = 0; i < ARRAY_SIZE(oled_display_attrs); i++)
		__oled_display_attrs[i] = &oled_display_attrs[i].attr;
}

static void oled_display_dev_release(struct device *dev)
{
	pr_debug("device: '%s': %s\n", dev_name(dev), __func__);
	kfree(dev);
}

int oled_display_register(struct device *parent, struct oled_display *display)
{
	struct device *dev;
	int rc;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	device_initialize(dev);

	dev->class = oled_display_class;
	dev->type = &oled_display_dev_type;
	dev->parent = parent;
	dev->release = oled_display_dev_release;
	dev_set_drvdata(dev, display);
	display->dev = dev;

	rc = kobject_set_name(&dev->kobj, "%s", display->name);
	if (rc)
		goto kobject_set_name_failed;

	rc = device_add(dev);
	if (rc)
		goto device_add_failed;

	spin_lock_init(&display->lock);

	return 0;

kobject_set_name_failed:
	put_device(dev);
	kfree(dev->p);
	kfree(dev);
	return rc;
device_add_failed:
	device_del(dev);
	put_device(dev);
	return rc;
}
EXPORT_SYMBOL_GPL(oled_display_register);

void oled_display_unregister(struct oled_display *display)
{
	device_unregister(display->dev);
}
EXPORT_SYMBOL_GPL(oled_display_unregister);

static int __init oled_display_class_init(void)
{
	oled_display_class = class_create(THIS_MODULE, "display");

	if (IS_ERR(oled_display_class))
		return PTR_ERR(oled_display_class);

	oled_display_init_attrs(&oled_display_dev_type);

	return 0;
}

static void __exit oled_display_class_exit(void)
{
	class_destroy(oled_display_class);
}

subsys_initcall(oled_display_class_init);
module_exit(oled_display_class_exit);

MODULE_DESCRIPTION("Universal display class");
MODULE_AUTHOR("LuoWei <luoweisj@tp-link.net>");
MODULE_LICENSE("GPL");
