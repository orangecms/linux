/*******************************************************************************
  Copyright (C), 1996-2012, TP-LINK TECHNOLOGIES CO., LTD.
  File name	: oled_ssd1306_pt.c
  Description	: Driver for OLED SSD1306.
  Author	: linyunfeng

  History:
------------------------------
V0.2, 2014-04-16, zhangtao		modified oled_ssd1306_pt driver for dts of the new kernel.
V0.1, 2011-08-16, linyunfeng    create file.
*******************************************************************************/

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <mach/gpio.h>
#include <mach/pmic.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <mach/board.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_i2c.h>
#include <linux/of_gpio.h>
#include <mach/board.h>
#include <mach/gpiomux.h>

#include "oled_ssd1306_pt.h"
#include "oled_pt.h"

//#define OLED_SSD1306_DEBUG

typedef unsigned int boolean;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

uint8_t oled_ssd1306_buf[COLUMN_NUM * PAGE_NUM] = {0};
static uint8_t frame_data[COLUMN_NUM * PAGE_NUM + 1] ={0};
static uint8_t oled_ssd1306_image[COLUMN_NUM * PAGE_NUM] = {0};

struct ssd1306_state_type{
	boolean disp_initialized;
	boolean display_on;
	boolean disp_powered_up;
};

struct ssd1306_work_t {
	struct work_struct work;
};

struct ssd1306_i2c_reg_conf {
	unsigned short waddr;
	unsigned short wdata;
};

static struct ssd1306_state_type ssd1306_state = {0};
struct oled_panel_data oled_ssd1306_panel_data;
static struct oled_panel_data *oled_ssd1306_pdata;

static DECLARE_WAIT_QUEUE_HEAD(ssd1306_wait_queue);
static struct ssd1306_work_t *ssd1306_sensorw;
static struct i2c_client *ssd1306_client;
static struct mutex flush_mutex;
static struct mutex oled_panel_mutex;

/* Data/Command flag, 0: Command, 1: Data */
static int oled_ssd1306_sa0;

/* Chip select, always 0 in I2C mode */
static int oled_ssd1306_cs;

/* [ZhangTao start] for getting the gpio number configered in the dts file */
enum ENUM_OLED_SSD1306_GPIO {
	GPIO_OLED_CS = 0,
	GPIO_OLED_A0,
	GPIO_OLED_RES,
	GPIO_OLED_BOOST_EN,

	GPIO_OLED_END
};

/* enum the gpio name defined in the dts config file */
static const char *dts_gpio_name[] = {
	[GPIO_OLED_CS]       = "qcom,oled-cs-gpio",
	[GPIO_OLED_A0] 		 = "qcom,oled-a0-gpio",
	[GPIO_OLED_RES] 	 = "qcom,oled-res-gpio",
	[GPIO_OLED_BOOST_EN] = "qcom,oled-boost-en-gpio",

	[GPIO_OLED_END] 	 = "",
};

/* Store oled ssd1306 gpio pin number, will be filled by get_gpio_by_dtsname() */
static int oled_ssd1306_gpio[GPIO_OLED_END] = {0};

/*******************************************************************************
  Function		: get_gpio_by_dtsname
  Description	: get gpio pin number by name defined in dts config file.
  Input			: @node, the device node defined in dts which we get the gpio pin number form
				  @gpio_name[], the string array which store the gpio name defined in dts file
				  @gpio_num, we will store the gpio pin number getted from dts file in the int array gpio_num point to
				  @len, the numbers of gpio we will get
  Output		: gpio_num: the request gpios pin number which gpio_num point to
  Return		: void
  Others		: None
*******************************************************************************/
static void get_gpio_by_dtsname(struct device_node *node, const char *gpio_name[], u32 *gpio_num, int len)
{
	int i;
	for (i = 0; i < len; ++ i)
	{
		gpio_num[i] = of_get_named_gpio(node, gpio_name[i], 0);
	}
}

/*******************************************************************************
  Function		: oled_ssd1306_config_gpios
  Description	: request/free for specific gpio
  Input			: @enable, 0: free gpios, 1: request gpios
  Output		: request or free the specific gpio stored in oled_ssd1306_gpio[]
  Return		: void
  Others		: None
*******************************************************************************/
static void oled_ssd1306_config_gpios(int enable)
{
	int i, rc = 0;

	for (i = 0; i < GPIO_OLED_END; ++ i)
	{
		if (enable) {
			rc = gpio_request(oled_ssd1306_gpio[i], dts_gpio_name[i]);
			if (rc)
			{
				pr_err("request gpio %s failed, rc=%d\n", dts_gpio_name[i], rc);
				gpio_free(oled_ssd1306_gpio[i]);
				return;
			}

		} else {
			gpio_free(oled_ssd1306_gpio[i]);
		}
	}

	return;
}

/*******************************************************************************
  Function		: oled_ssd1306_power_save
  Description	: power on/off the oled
  Input			: @on, 0: power off, 1: power on
  Output		:
  Return		: None
  Others		: None
*******************************************************************************/
static int oled_ssd1306_power_save(int on)
{
	int rc = 0;

	if (on) {
		gpio_direction_output(oled_ssd1306_gpio[GPIO_OLED_RES], 0);
		mdelay(1);

		gpio_direction_output(oled_ssd1306_gpio[GPIO_OLED_BOOST_EN], 1);
		mdelay(1);

		__gpio_set_value(oled_ssd1306_gpio[GPIO_OLED_RES], 1);
		mdelay(1);
	} else {
		gpio_direction_output(oled_ssd1306_gpio[GPIO_OLED_BOOST_EN], 0);
		mdelay(1);

		gpio_direction_output(oled_ssd1306_gpio[GPIO_OLED_RES], 0);
		mdelay(1);
	}

	return rc;
}
/* [ZhangTao end]*/

static int ssd1306_i2c_txdata(const uint16_t saddr,
		uint8_t *txdata, const uint16_t length)
{
	struct i2c_msg msg[] = {
		{
			.addr = saddr,
			.flags = 0,
			.len = length,
			.buf = txdata,
		},
	};

	if (i2c_transfer(ssd1306_client->adapter, msg, 1) < 0) {
		printk("ssd1306_i2c_txdata faild 0x%x\n", saddr);
		return -EIO;
	}

	return 0;
}

/*******************************************************************************
  Function	: oled_ssd1306_print_buffer
  Description	: print the oled buffer data, hex
  Input		: None
  Output	: buf: Command line buffer
  Return	: The number of characters will display in command
                 line.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_print_buffer(char *buf)
{
	int i = 0;
	int j = 0;

	for (i = 0; i < PAGE_NUM; i++){
		for (j = 0; j < COLUMN_NUM; j++) {
			sprintf(buf + 3 *(i * (COLUMN_NUM + 1) + j), "%02x ",
				*(oled_ssd1306_image
				+ (i << COLUMN_NUM_EXP) + j));
		}
		sprintf(buf + (i + 1) * 3 * (COLUMN_NUM + 1) - 3, "  \n" );
	}

	return (COLUMN_NUM + 1) * 3 * PAGE_NUM;
}

/*******************************************************************************
  Function	: ssd1306_i2c_write_cmd
  Description	: Send command by I2C
  Input		: data: Command will be send
                  len: The length of Command
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int ssd1306_i2c_write_cmd(const uint8_t *data, const uint16_t len)
{
	int rc = 0;

#ifdef OLED_SSD1306_DEBUG
	int i = 0;
	printk("%s, data = 0x%x, len = %d\n", __func__, *data, len);
#endif

	if (TRUE == ssd1306_state.disp_powered_up) {

		*frame_data = OLED_CONTROL_CMDS;
		memcpy(frame_data + 1, data, len);

#ifdef OLED_SSD1306_DEBUG
		for (i = 0; i < len + 1; i++){
			printk("0x%x ", *(frame_data+i));
		}
		printk("\n");
#endif

		rc = ssd1306_i2c_txdata(ssd1306_client->addr, frame_data, len + 1);

		if (rc < 0) {
			printk("%s fail, data = 0x%x, len = %d\n",
				__func__, *data, len);
		}
	}
	return rc;
}

/*******************************************************************************
  Function	: ssd1306_i2c_write_data
  Description	: Send data by I2C
  Input		: data: Data will be send
               len: The length of data
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int ssd1306_i2c_write_data(const uint8_t *data, const uint16_t len)
{
	int rc = -EFAULT;

#ifdef OLED_SSD1306_DEBUG
	printk("%s, data = 0x%x, len = %d\n", __func__, *data, len);
#endif

	if (TRUE == ssd1306_state.disp_powered_up) {

		*frame_data = OLED_CONTROL_DATAS;
		memcpy(frame_data + 1, data, len);

		rc = ssd1306_i2c_txdata((ssd1306_client->addr),
			frame_data, len + 1);
		if (rc < 0) {
			printk("%s fail, data = 0x%x, len = %d\n",
				__func__, *data, len);
		}
	}
	return rc;
}

static void oled_ssd1306_pin_assign(void)
{
	/* Setting the Default GPIO's */
	oled_ssd1306_sa0 = oled_ssd1306_gpio[GPIO_OLED_A0];
	oled_ssd1306_cs  = oled_ssd1306_gpio[GPIO_OLED_CS];
}

static int oled_ssd1306_area_check(const uint8_t x, const uint8_t y,
	const uint8_t width, const uint8_t height)
{
	if ((x < 0) || (y < 0) || (width <= 0) || (height <= 0)
		|| (x + width > COLUMN_NUM) || (y + height > PAGE_NUM)){
		printk("%s error, row_start=%d, col_start=%d, width=%d, height=%d",
			__func__, x, y, width, height);
		return -EINVAL;
	}

	return 0;
}


/* [wuzhong start] */
#ifdef __ENABLE_OLED_SH1106_AND_SSD1306__

static int oled_sh1106_and_ssd1306_fill_with_pic(const uint8_t *pic, const uint8_t x,
	const uint8_t y, const uint8_t width, const uint8_t height)
{
	int i = 0;

#if defined(OLED_SSD1306_DEBUG)
	printk("%s,width=%d, height=%d\n", __func__, width, height);
#endif

	if (oled_ssd1306_area_check(x, y, width, height)) {
		return -EINVAL;
	}

	if (TRUE == ssd1306_state.disp_initialized) {
		mutex_lock(&flush_mutex);

		for (i = 0; i < height; i++)
		{
			oled_sh1106_flush_cmd[1] = 0xb0 + y + i;
			oled_sh1106_flush_cmd[2] = (x + SH1106_OFFSET) & 0x0f;
			oled_sh1106_flush_cmd[3] = (((x + SH1106_OFFSET) & 0xf0) >> 4) | 0x10;

			ssd1306_i2c_write_cmd(oled_sh1106_flush_cmd, sizeof(oled_sh1106_flush_cmd));
			ssd1306_i2c_write_data(pic + i * width, width);
		}

		for (i = y; i < y + height; i++) {
			memcpy(oled_ssd1306_image + (i << COLUMN_NUM_EXP) + x,
				pic + width * (i - y), width);
		}

		mutex_unlock(&flush_mutex);
	}

	return 0;
}

#else /* __ENABLE_OLED_SH1106_AND_SSD1306__ */

/*******************************************************************************
  Function	: oled_ssd1306_fill_with_pic
  Description	: Fill and flush certain area with picture.
  Input		: pic: Picture to fill
                x: Start point, x coordinate, 0 ~ COLUMN_NUM - 1
                y: Start point, y coordiante, 0 ~ PAGE_NUM - 1
                width: Area width
                height: Area height
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_fill_with_pic(const uint8_t *pic, const uint8_t x,
	const uint8_t y, const uint8_t width, const uint8_t height)
{
	int i = 0;

#if defined(OLED_SSD1306_DEBUG)
	printk("%s,width=%d, height=%d\n", __func__, width, height);
#endif

	if (oled_ssd1306_area_check(x, y, width, height)) {
		return -EINVAL;
	}

	if (TRUE == ssd1306_state.disp_initialized) {
		mutex_lock(&flush_mutex);
		*(oled_ssd1306_flush_cmd_config.col_addr_start) = x;
		*(oled_ssd1306_flush_cmd_config.col_addr_end) = x + width - 1;
		*(oled_ssd1306_flush_cmd_config.page_addr_start) = y;
		*(oled_ssd1306_flush_cmd_config.page_addr_end) = y + height - 1;

		ssd1306_i2c_write_cmd(oled_ssd1306_flush_cmd, sizeof(oled_ssd1306_flush_cmd));

		ssd1306_i2c_write_data(pic, width * height);

		for (i = y; i < y + height; i++) {
			memcpy(oled_ssd1306_image + (i << COLUMN_NUM_EXP) + x,
				pic + width * (i - y), width);
		}

		mutex_unlock(&flush_mutex);
	}

	return 0;
}


#endif /* __ENABLE_OLED_SH1106_AND_SSD1306__ */
/* [wuzhong end] */


/*******************************************************************************
  Function	: oled_ssd1306_fill_with_value
  Description	: Fill and flush certain area with value.
  Input		: value: Value to fill
                x: Start point, x coordinate, 0 ~ COLUMN_NUM - 1
                y: Start point, y coordiante, 0 ~ PAGE_NUM - 1
                width: Area width
                height: Area height
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_fill_with_value(const uint8_t value, const uint8_t x,
	const uint8_t y, const uint8_t width, const uint8_t height)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif

	if (oled_ssd1306_area_check(x, y, width, height)) {
		return -EINVAL;
	}

	memset(oled_ssd1306_buf, value, width * height);

/* [wuzhong start] */
#ifdef __ENABLE_OLED_SH1106_AND_SSD1306__
	return oled_sh1106_and_ssd1306_fill_with_pic(oled_ssd1306_buf, x, y, width, height);
#else
	return oled_ssd1306_fill_with_pic(oled_ssd1306_buf, x, y, width, height);
#endif
/* [wuzhong end] */
}

/*******************************************************************************
  Function	: oled_ssd1306_fade_blink
  Description	: Fade out or blink.
  Input		: mode: 0: Disable Fade Out / Blinking Mode.
                       2: Enable Fade Out mode.
                       3: Enable Blinking mode.
                 t_interval_scroll: Set time interval for each fade step, 0~7,
                       (8 * t_interval_scroll + 1))frames
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_fade_blink(const uint8_t mode, const uint8_t t_interval_scroll)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif

	if ((mode < 0) || (t_interval_scroll < 0) || (mode > 3)
		|| (1 == mode) || (t_interval_scroll > 15)) {
		printk("%s error, mode=%d, t_interval_scroll=%d",
			__func__, mode, t_interval_scroll);
		return -EINVAL;
	}

	*(oled_ssd1306_fade_blink_cmd_config.fade_blink_parameter)
		= (mode << 4) | t_interval_scroll;

	return ssd1306_i2c_write_cmd(oled_ssd1306_fade_blink_cmd, sizeof(oled_ssd1306_fade_blink_cmd));
}

/*******************************************************************************
  Function	: oled_ssd1306_scroll_stop
  Description	: Stop scroll.
  Input		: None
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_scroll_stop(void)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif

	return ssd1306_i2c_write_cmd(oled_ssd1306_scroll_stop_cmd, sizeof(oled_ssd1306_scroll_stop_cmd));
}

/*******************************************************************************
  Function	: oled_ssd1306_horizontal_scroll
  Description	: Horizontal scroll.
  Input		: y: Start point, y coordiante, 0 ~ PAGE_NUM - 1
                 height: Scroll area height
                 t_interval_scroll: 0: 5 frame, 1: 64, 2: 128, 3: 256,
                            4: 3, 5: 4, 6: 25, 7: 2
                direction: 0: Left->Right, 1:Right->Left
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_horizontal_scroll(const uint8_t y, const uint8_t height,
	const uint8_t t_interval_scroll, const uint8_t direction)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif

	if ((y < 0) || (height < 0) || (y + height > PAGE_NUM)
		|| (t_interval_scroll < 0) || (t_interval_scroll > 7)
		|| (direction < 0) || (direction > 1)) {
		printk("%s error, y=%d, height=%d, t_interval_scroll=%d, direction=%d",
			__func__, y, height, t_interval_scroll, direction);
		return -EINVAL;
	}

	oled_ssd1306_scroll_stop();
	mdelay(1);

	*(oled_ssd1306_h_scroll_cmd_config.horizontal_scroll_direction) = CMD_HORIZONTAL_SCROLL_ARRAY[direction];
	*(oled_ssd1306_h_scroll_cmd_config.page_addr_start) = y;
	*(oled_ssd1306_h_scroll_cmd_config.time_interval_scroll) = t_interval_scroll;
	*(oled_ssd1306_h_scroll_cmd_config.page_addr_end) = y + height - 1;

	return ssd1306_i2c_write_cmd(oled_ssd1306_h_scroll_cmd, sizeof(oled_ssd1306_h_scroll_cmd));
}

/*******************************************************************************
  Function	: oled_ssd1306_set_backlight
  Description	: Set backlight on or off.
  Input		: on: 0: off, 1: on.
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_set_backlight(const uint8_t on)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s, on =%u\n", __func__, on);
#endif

	if (0 == on) {
		oled_ssd1306_backlight_cmd[0] = CMD_DISPLAY_OFF_ON(0);
	} else {
		oled_ssd1306_backlight_cmd[0] = CMD_DISPLAY_OFF_ON(1);
	}

	return ssd1306_i2c_write_cmd(oled_ssd1306_backlight_cmd, sizeof(oled_ssd1306_backlight_cmd));
}

/*******************************************************************************
  Function	: ssd1306_disp_on
  Description	: initial oled.
  Input		: None
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static void ssd1306_disp_on(void)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif

	if (ssd1306_state.disp_powered_up && !ssd1306_state.display_on) {
		ssd1306_i2c_write_cmd(oled_ssd1306_init_cmd, sizeof(oled_ssd1306_init_cmd));

		ssd1306_state.display_on = TRUE;
	}
}

/*******************************************************************************
  Function	: ssd1306_disp_powerup
  Description	: Power and initial.
  Input		: None
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static void ssd1306_disp_powerup(void)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif

	if (!ssd1306_state.disp_powered_up && !ssd1306_state.display_on) {
		/* Reset the hardware first */
		ssd1306_state.disp_powered_up = TRUE;
		if (oled_ssd1306_pdata->oled_power_save)
			oled_ssd1306_pdata->oled_power_save(1);

		gpio_direction_output(oled_ssd1306_cs, 0);
		gpio_direction_output(oled_ssd1306_sa0, 0);
		mdelay(5);

		/* CS will be always 0 in I2C mode */
		__gpio_set_value(oled_ssd1306_cs, 0);
		/* SA0 is used to determine the I2C address in I2C mode */
		__gpio_set_value(oled_ssd1306_sa0, 0);
		mdelay(3);
	}
}

/*******************************************************************************
  Function	: oled_ssd1306_panel_on
  Description	: Power and initial oled SSD1306.
  Input		: None
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_panel_on(void)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif
	mutex_lock(&oled_panel_mutex);
	if (!ssd1306_state.disp_initialized) {
		/* Configure reset GPIO that drives DAC */
		if (oled_ssd1306_pdata->oled_gpio_config)
			oled_ssd1306_pdata->oled_gpio_config(1);
		ssd1306_disp_powerup();
		ssd1306_disp_on();
		ssd1306_state.disp_initialized = TRUE;
	}
	mutex_unlock(&oled_panel_mutex);
	return 0;
}

/*******************************************************************************
  Function	: oled_ssd1306_panel_off
  Description	: Power down oled SSD1306.
  Input		: None
  Output	: None
  Return	: 0: OK, Others: Error.
  Others	: None
*******************************************************************************/
static int oled_ssd1306_panel_off(void)
{
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif
	mutex_lock(&oled_panel_mutex);
	if (ssd1306_state.disp_powered_up && ssd1306_state.display_on) {
		/* Main panel power off (Deep standby in) */
		ssd1306_i2c_write_cmd(oled_ssd1306_panel_off_cmd,
			sizeof(oled_ssd1306_panel_off_cmd));
		mdelay(100);	/* Typical 100ms */

		if (oled_ssd1306_pdata->oled_power_save)
			oled_ssd1306_pdata->oled_power_save(0);

		if (oled_ssd1306_pdata->oled_gpio_config)
			oled_ssd1306_pdata->oled_gpio_config(0);
		ssd1306_state.disp_powered_up = FALSE;
		ssd1306_state.display_on = FALSE;
		ssd1306_state.disp_initialized = FALSE;
	}
	mutex_unlock(&oled_panel_mutex);
	return 0;
}

static int __devinit oled_ssd1306_probe(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	if (!node)
	{
		dev_err(&pdev->dev, "%s: device tree information missing\n", __func__);
		return -ENODEV;
	}

	printk("%s\n", __func__);

	pdev->dev.platform_data = &oled_ssd1306_panel_data;
	oled_ssd1306_pdata = pdev->dev.platform_data;

	/* get gpios' number by name defined in the dts config file and store them in oled_ssd1306_gpio array */
	get_gpio_by_dtsname(node, dts_gpio_name, oled_ssd1306_gpio, GPIO_OLED_END);

	oled_ssd1306_pin_assign();

	/* [ZhangTao start] */
	oled_ssd1306_pdata->oled_gpio_config = oled_ssd1306_config_gpios;
	oled_ssd1306_pdata->oled_power_save = oled_ssd1306_power_save;
	/* [ZhangTao end] */

	oled_ssd1306_pdata->oled_panel_on = oled_ssd1306_panel_on;
	oled_ssd1306_pdata->oled_panel_off = oled_ssd1306_panel_off;
	oled_ssd1306_pdata->oled_horizontal_scroll = oled_ssd1306_horizontal_scroll;
	oled_ssd1306_pdata->oled_scroll_stop = oled_ssd1306_scroll_stop;
	oled_ssd1306_pdata->oled_fade_blink = oled_ssd1306_fade_blink;

/* [wuzhong start] */
#ifdef __ENABLE_OLED_SH1106_AND_SSD1306__
	oled_ssd1306_pdata->oled_fill_with_pic = oled_sh1106_and_ssd1306_fill_with_pic;
#else
	oled_ssd1306_pdata->oled_fill_with_pic = oled_ssd1306_fill_with_pic;
#endif
/* [wuzhong end] */

	oled_ssd1306_pdata->oled_fill_with_value = oled_ssd1306_fill_with_value;
	oled_ssd1306_pdata->oled_print_buffer = oled_ssd1306_print_buffer;
	oled_ssd1306_pdata->oled_set_backlight = oled_ssd1306_set_backlight;
	oled_ssd1306_pdata->panel_width = COLUMN_NUM;
	oled_ssd1306_pdata->panel_height = PAGE_NUM;

	mutex_init(&flush_mutex);
	mutex_init(&oled_panel_mutex);

	return 0;
}

static int __devexit oled_ssd1306_remove(struct platform_device *pdev)
{
	return 0;
}

static int __devexit ssd1306_i2c_remove(struct i2c_client *client)
{
	struct ssd1306_work_t *ssd1306 = i2c_get_clientdata(client);
	free_irq(client->irq, ssd1306);
	ssd1306_client = NULL;
	kfree(ssd1306);
	return 0;
}

static int ssd1306_init_client(struct i2c_client *client)
{
	/* Initialize the MSM_CAMI2C Chip */
	init_waitqueue_head(&ssd1306_wait_queue);
	return 0;
}

static int ssd1306_i2c_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	int rc = 0;
	printk("%s called!\n", __func__);

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		printk("i2c_check_functionality failed\n");
		goto probe_failure;
	}

	ssd1306_sensorw = kzalloc(sizeof(struct ssd1306_work_t), GFP_KERNEL);
	if (!ssd1306_sensorw) {
		printk("kzalloc failed.\n");
		rc = -ENOMEM;
		goto probe_failure;
	}

	i2c_set_clientdata(client, ssd1306_sensorw);
	ssd1306_init_client(client);
	ssd1306_client = client;

	msleep(50);

	printk("%s successed! rc = %d\n", __func__, rc);
	return 0;

probe_failure:
	printk("%s failed! rc = %d\n", __func__, rc);
	return rc;
}

static struct of_device_id qcom_ssd1306_i2c_table[] = {
	{ .compatible = "qcom,ssd1306",},
	{ },
};

static const struct i2c_device_id ssd1306_i2c_id[] = {
	{"ssd1306", 0},
	{ }
};

static struct i2c_driver ssd1306_i2c_driver = {
	.id_table = ssd1306_i2c_id,
	.probe  = ssd1306_i2c_probe,
	.remove = __exit_p(ssd1306_i2c_remove),
	.driver = {
		.name = "ssd1306",
		.of_match_table = qcom_ssd1306_i2c_table,
	},
};

static struct of_device_id qcom_ssd1306_pt_table[] = {
	{ .compatible = "qcom,oled_ssd1306_pt",},
	{ },
};

static struct platform_driver this_driver = {
	.probe  = oled_ssd1306_probe,
	.remove = __devexit_p(oled_ssd1306_remove),
	.driver = {
		.name   = "oled_ssd1306_pt",
		.of_match_table = qcom_ssd1306_pt_table,
	},
};

static int __init oled_ssd1306_panel_init(void)
{
	int ret = 0;
#if defined(OLED_SSD1306_DEBUG)
	printk("%s\n", __func__);
#endif
	ret = platform_driver_register(&this_driver);
	if (ret)
		return ret;

	ret = i2c_add_driver(&ssd1306_i2c_driver);

	if (ret < 0 || ssd1306_client == NULL) {
		ret = -ENOTSUPP;
		printk("I2C add driver failed");
		goto fail_driver;
	}

	return ret;

fail_driver:
	platform_driver_unregister(&this_driver);
	return ret;
}

device_initcall(oled_ssd1306_panel_init);

MODULE_AUTHOR("Lin Yunfeng");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("OLED SSD1306 driver");

