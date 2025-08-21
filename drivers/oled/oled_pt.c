/*******************************************************************************
  Copyright (C), 1996-2012, TP-LINK TECHNOLOGIES CO., LTD.
  File name	: oled_pt.c
  Description	: Driver for OLED s90319.
  Author	: linyunfeng

  History:
------------------------------
V0.1, 2011-08-16, linyunfeng    create file.
*******************************************************************************/
#include <linux/module.h>
#include <linux/platform_device.h>
#include <mach/board.h>
#include <linux/device.h>
#include <linux/wakelock.h>

#include "oled_pt.h"
#include "oled_display.h"

//#define OLED_DEBUG

struct mutex oled_mutex;
struct wake_lock oled_wlock;

static struct oled_panel_data *oled_pdata;

#ifdef CONFIG_OLED_SSD1306_PT
extern uint8_t oled_ssd1306_buf[];
extern struct oled_panel_data oled_ssd1306_panel_data;
#endif

#ifdef CONFIG_OLED_S90319_PT
extern uint8_t oled_s90319_buf[];
extern struct oled_panel_data oled_s90319_panel_data;
#endif

static uint32_t oled_buf_size = 0;

/*******************************************************************************
  Function	: oled_buffer_show
  Description	: Print the oled buffer data, hex
  Input		: None
  Output	: buf: Command line buffer
  Return	: The number of characters will display in command
                 line.
  Others	: None
*******************************************************************************/
static ssize_t oled_buffer_show(struct device *dev, struct device_attribute *attr,
	char *buf)
{
	return oled_pdata->oled_print_buffer(buf);
}

/*******************************************************************************
  Function	: oled_buffer_store
  Description	: Write data to oled buffer.
  Input		: buf: Input format is: x,y,width,height,data.
               count: Length of input.
  Output	: None
  Return	: Length of input or error number.
  Others	: None
*******************************************************************************/
static ssize_t oled_buffer_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t count)
{
	uint32_t data_length = 0;
	uint8_t x = buf[0];
	uint8_t y = buf[1];
	uint8_t width = buf[2];
	uint8_t height = buf[3];

	if ('\n' == *(buf + count - 1)) {
		data_length = count - 5;
	} else {
		data_length = count - 4;
	}

	if (data_length > oled_buf_size) {
		printk("%s, data_length=%d, oled_buf_size=%d, oled buffer overflow!\n",
			__func__, data_length, oled_buf_size);
		mutex_unlock(&oled_mutex);
		return -1;
	}

	mutex_lock(&oled_mutex);

#ifdef CONFIG_OLED_SSD1306_PT
	memcpy(oled_ssd1306_buf, buf + 4, data_length);
	oled_pdata->oled_fill_with_pic(oled_ssd1306_buf, x, y, width, height);
#endif

#ifdef CONFIG_OLED_S90319_PT
	memcpy(oled_s90319_buf, buf + 4, width * height * 2);
	oled_pdata->oled_fill_with_pic(oled_s90319_buf, x, y, width, height);
#endif

	mutex_unlock(&oled_mutex);

	return count;
}

/*******************************************************************************
  Function	: backlight_on_store
  Description	: Control backlight.
  Input		: buf: 0: off, 1: on.
               count: Length of input.
  Output	: None
  Return	: Length of input.
  Others	: None
*******************************************************************************/
static ssize_t backlight_on_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t count)
{
	uint8_t on = simple_strtoul(buf, NULL, 10);

#if defined(OLED_DEBUG)
	printk("%s, buf=%s\n", __func__, buf);
#endif

	oled_pdata->oled_set_backlight(on);
	return count;
}

/*******************************************************************************
  Function	: panel_on_store
  Description	: Control panel.
  Input		: buf: 0: off, 1: on.
               count: Length of input.
  Output	: None
  Return	: Length of input.
  Others	: None
*******************************************************************************/
static ssize_t panel_on_store(struct device *dev, struct device_attribute *attr,
	const char *buf, size_t count)
{
	uint8_t on = simple_strtoul(buf, NULL, 10);

#if defined(OLED_DEBUG)
	printk("%s, buf=%s\n", __func__, buf);
#endif

	if (0 == on) {
		oled_pdata->oled_panel_off();

		if (wake_lock_active(&oled_wlock)) {
			wake_unlock(&oled_wlock);
		}
	} else {
		if (!wake_lock_active(&oled_wlock)) {
			wake_lock(&oled_wlock);
		}

		oled_pdata->oled_panel_on();
	}

#if defined(OLED_DEBUG)
	printk("%s end\n", __func__);
#endif

	return count;
}

static enum oled_display_property oled_display_prop[] = {
	DISPLAY_PROP_BUFFER,
	DISPLAY_PROP_BACKLIGHTON,
	DISPLAY_PROP_PANELON
};

static struct oled_display oled_display = {
	.name = "oled",
	.properties = oled_display_prop,
	.num_properties = ARRAY_SIZE(oled_display_prop),
	.show_property = {oled_buffer_show},
	.store_property = {oled_buffer_store, backlight_on_store, panel_on_store}
};

/* Function to load the device */
static int __devinit oled_probe(struct platform_device *pdev)
{
	int ret = 0;
	struct device *dev = &(pdev->dev);
	printk("%s\n", __func__);

	ret = of_platform_populate(pdev->dev.of_node, NULL, NULL, &pdev->dev);
	if (ret)
		pr_err("%s: of_platform_populate failed %d\n", __func__, ret);

#ifdef CONFIG_OLED_SSD1306_PT
	pdev->dev.platform_data = &oled_ssd1306_panel_data;
#endif

#ifdef CONFIG_OLED_S90319_PT
	pdev->dev.platform_data = &oled_s90319_panel_data;
#endif

	oled_pdata = pdev->dev.platform_data;

	oled_buf_size = oled_pdata->panel_width * oled_pdata->panel_height * 2;

	oled_display.dev = dev;
	ret = oled_display_register(dev, &oled_display);

	if (ret < 0) {
		dev_err(dev, "%s: oled_display_register failed, ret=%d\n",
						__func__, ret);
		return ret;
	}

	mutex_init(&oled_mutex);

	wake_lock_init(&oled_wlock, WAKE_LOCK_SUSPEND, "oled");

	return ret;
}

static int __devexit oled_remove(struct platform_device *pdev)
{
#if defined(OLED_DEBUG)
	printk("%s\n", __func__);
#endif

	wake_lock_destroy(&oled_wlock);

	return 0;
}

static struct of_device_id tp_oled_pt_table[] = {
	{ .compatible = "tp,oled_pt",},
	{ },
};

static struct platform_driver oled_device_driver = {
	.probe = oled_probe,
	.remove = __devexit_p(oled_remove),
	.driver = {
		   .name = "oled",
		   .owner = THIS_MODULE,
		   .of_match_table = tp_oled_pt_table,
	},
};

static int __init oled_init(void)
{
	int rc = 0;
#if defined(OLED_DEBUG)
	printk("%s\n", __func__);
#endif

	rc =  platform_driver_register(&oled_device_driver);

	if (!rc)
		printk("oled init success!\n");

	return rc;
}

static void __exit oled_exit(void)
{
#if defined(OLED_DEBUG)
	printk("%s\n", __func__);
#endif
	platform_driver_unregister(&oled_device_driver);
}

module_init(oled_init);
module_exit(oled_exit);

MODULE_AUTHOR("Lin Yunfeng");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("OLED display driver");

