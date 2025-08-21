/*******************************************************************************
  Copyright (C), 1996-2014, TP-LINK TECHNOLOGIES CO., LTD.
  File name	: oled_s90319_pt.c
  Description	: Driver for OLED s90319.
  Author	: xiongsizhe

  History:
------------------------------
V0.1, 2014-03-28, xiongsizhe    create file.
*******************************************************************************/

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <mach/gpio.h>
#include <mach/pmic.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <mach/board.h>
#include <linux/gpio.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <mach/board.h>
#include <mach/gpiomux.h>
#include <linux/device.h>
#include "oled_pt.h"
#include "oled_s90319_pt.h"

//#define OLED_S90319_DEBUG

typedef unsigned int boolean;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

static int s90319_spi_write_cmd(const uint8_t *data, const uint16_t len);
static int s90319_spi_write_data(const uint8_t *data, const uint16_t len);

uint8_t oled_s90319_buf[COLUMN_NUM * ROW_NUM * 2] = {0};
static uint8_t frame_data[COLUMN_NUM * ROW_NUM * 2] ={0};

static uint8_t frame_data_buf[COLUMN_NUM * ROW_NUM * 2] ={0};

struct s90319_state_type{
	boolean disp_initialized;
	boolean display_on;
	boolean disp_powered_up;
};

static struct s90319_state_type s90319_state = {0};

struct oled_panel_data oled_s90319_panel_data;
static struct oled_panel_data *oled_s90319_pdata;

static struct mutex flush_mutex;
static struct mutex oled_panel_mutex;

#define BUFFER_SIZE 4 << 10
struct spi_message spi_msg;
//struct spi_transfer spi_xfer;
unsigned char *tx_buf;

struct s90319_work_t {
	struct work_struct work;
};
static DECLARE_WAIT_QUEUE_HEAD(s90319_wait_queue);

static struct s90319_work_t *s90319_sensorw;
static struct spi_device *s90319_spi;

static int oled_s90319_rsx;

static int oled_s90319_cs;
static int oled_s90319_boost_en;

enum GPIO_OLED_S90319 {
	GPIO_OLED_CS = 0,
	GPIO_OLED_RESET,
	GPIO_OLED_BOOST_EN,
	GPIO_OLED_RSX,
	GPIO_OLED_VDD0,
	GPIO_OLED_VDD1,

	GPIO_OLED_END,
};

static const char *dts_gpio_name[] = {
	[GPIO_OLED_CS] = "qcom,oled-cs-gpio",
	[GPIO_OLED_RESET] = "qcom,oled-reset-gpio",
	[GPIO_OLED_BOOST_EN] = "qcom,oled-boost-en-gpio",
	[GPIO_OLED_RSX] = "qcom,oled-rsx-gpio",
	[GPIO_OLED_VDD0] = "qcom,oled-vdd0-gpio",
	[GPIO_OLED_VDD1] = "qcom,oled-vdd1-gpio",

	[GPIO_OLED_END] = "",
};

static int oled_s90319_gpio[GPIO_OLED_END] = {0};

/************************************************************
  Function   : wr_comm
  Description: transfer command to oled
  Input	     : commond
  Return     :
************************************************************/
void wr_comm(uint8_t cmd)
{
	s90319_spi_write_cmd(&cmd, 1);
}

/************************************************************
  Function   : wr_dat
  Description: transfer data to oled
  Input	     : data
  Return     :
************************************************************/
void wr_dat(uint8_t data)
{
	s90319_spi_write_data(&data, 1);
}

/************************************************************
  Function   : Delay
  Description: delay time
  Input	     : t
  Return     :
************************************************************/
void  Delay(unsigned int t)
{
	mdelay(t);
}

/************************************************************
  Function   : get_gpio_by_dtsname
  Description: get gpio number by dtsname
  Input	     :
  Return     :
************************************************************/
static void get_gpio_by_dtsname(struct device_node *node, const char *gpio_name[], u32 *gpio_num, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
	{
		gpio_num[i] = of_get_named_gpio(node, gpio_name[i], 0);
	}
}

/************************************************************
  Function   : oled_s90319_config_gpios
  Description: config gpio
  Input	     :
  Return     :
************************************************************/
static void oled_s90319_config_gpios(int enable)
{
	int i, rc = 0;
	for (i = 0; i < GPIO_OLED_END; i++)
	{
		if (enable)
		{
			rc = gpio_request(oled_s90319_gpio[i], dts_gpio_name[i]);
			if (rc)
			{
				pr_err("request gpio %s failed, rc=%d\n", dts_gpio_name[i], rc);
				gpio_free(oled_s90319_gpio[i]);
				return;
			}
		}
		else
		{
			gpio_free(oled_s90319_gpio[i]);
		}
	}
	return;
}

/************************************************************
  Function   : oled_s90319_power_save
  Description: open or close power supply
  Input	     :
  Return     :
************************************************************/
static int oled_s90319_power_save(int on)
{
	int rc = 0;
	if (on)
	{
		gpio_direction_output(oled_s90319_gpio[GPIO_OLED_RESET], 0);
		mdelay(1);

		gpio_direction_output(oled_s90319_gpio[GPIO_OLED_VDD0], 1);
		mdelay(1);
		gpio_direction_output(oled_s90319_gpio[GPIO_OLED_VDD1], 1);
		mdelay(1);

		gpio_set_value_cansleep(oled_s90319_gpio[GPIO_OLED_RESET], 1);
		mdelay(1);
	}
	else
	{
		gpio_direction_output(oled_s90319_gpio[GPIO_OLED_BOOST_EN], 0);
		mdelay(1);
		gpio_direction_output(oled_s90319_gpio[GPIO_OLED_VDD1], 0);
		mdelay(1);
		gpio_direction_output(oled_s90319_gpio[GPIO_OLED_VDD0], 0);
		mdelay(1);
		gpio_direction_output(oled_s90319_gpio[GPIO_OLED_RESET], 0);
		mdelay(1);
	}
	return rc;
}

/************************************************************
  Function   : s90319_spi_txdata
  Description: transfer data by spi
  Input	     : txdata: data to transfer
		   length: length of txdata
  Return     :
************************************************************/
static int s90319_spi_txdata(uint8_t *txdata, const uint16_t length)
{
	struct spi_transfer spi_xfer = {
		.tx_buf = txdata,
		.len = length,
    };
	spi_message_init(&spi_msg);

	spi_message_add_tail(&spi_xfer, &spi_msg);

	return spi_sync(s90319_spi, &spi_msg);
}

/************************************************************
  Function   : s90319_spi_write_cmd
  Description: transfer cmd by spi
  Input	     : data: cmd to transfer
		   len: length of cmd
  Return     :
************************************************************/
static int s90319_spi_write_cmd(const uint8_t *data, const uint16_t len)
{
	int rc = 0;

#ifdef OLED_S90319_DEBUG
	int i = 0;
	printk("%s, data = 0x%x, len = %d\n", __func__, *data, len);
#endif

	if (TRUE == s90319_state.disp_powered_up) {

		memcpy(frame_data, data, len);

#ifdef OLED_S90319_DEBUG
		for (i = 0; i < len; i++){
			printk("0x%x ", *(frame_data+i));
		}
		printk("\n");
#endif

		gpio_set_value_cansleep(oled_s90319_rsx, 0);

		rc = s90319_spi_txdata(frame_data, len);
		if (rc < 0) {
			printk("%s fail, data = 0x%x, len = %d, rc = %d\n",
				__func__, *data, len, rc);
		}
	}
	return rc;
}

/************************************************************
  Function   : s90319_spi_write_data
  Description: data need to be write
  Input	     : data: data need to be write
		   len: length of data
  Return     :
************************************************************/
static int s90319_spi_write_data(const uint8_t *data, const uint16_t len)
{
	int rc = -EFAULT;

#ifdef OLED_S90319_DEBUG
	printk("%s, data = 0x%x, len = %d\n", __func__, *data, len);
#endif

	if (TRUE == s90319_state.disp_powered_up) {

		memcpy(frame_data, data, len);

		gpio_set_value_cansleep(oled_s90319_rsx, 1);

		rc = s90319_spi_txdata(frame_data, len);
		if (rc < 0) {
			printk("%s fail, data = 0x%x, len = %d, rc = %d\n",
				__func__, *data, len, rc);
		}
	}
	return rc;
}

/************************************************************
  Function   : oled_s90319_area_check
  Description: check data area bigger than oled area or not
  Input	     :
  Return     :
************************************************************/
static int oled_s90319_area_check(const uint8_t x, const uint8_t y,
	const uint8_t width, const uint8_t height)
{
	if ((x < 0) || (y < 0) || (width <= 0) || (height <= 0)
		|| (x + width > COLUMN_NUM) || (y + height > ROW_NUM)){
		printk("%s error, row_start=%d, col_start=%d, width=%d, height=%d",
			__func__, x, y, width, height);
		return -EINVAL;
	}

	return 0;
}

/************************************************************
  Function   : oled_s90319_fill_with_pic
  Description: write pic data on location assign
  Input	     :
  Return     :
************************************************************/
static int oled_s90319_fill_with_pic(const uint8_t *pic, const uint8_t x,
	const uint8_t y, const uint8_t width, const uint8_t height)
{
	int i = 0;
#if defined(OLED_S90319_DEBUG)
	printk("%s,width=%d, height=%d\n", __func__, width, height);
#endif

	if (oled_s90319_area_check(x, y, width, height)) {
		return -EINVAL;
	}

	oled_s90319_set_col_addr[1] = x + X_OFFSET;
	oled_s90319_set_col_addr[3] = x + width - 1 + X_OFFSET;
	oled_s90319_set_row_addr[1] = y + Y_OFFSET;
	oled_s90319_set_row_addr[3] = y + height - 1 + Y_OFFSET;

	for (i = 0; i < width * height * 2; i++)
	{
		frame_data_buf[i] = *pic;
		pic++;
	}

	if (TRUE == s90319_state.disp_initialized) {
		mutex_lock(&flush_mutex);

		s90319_spi_write_cmd(oled_set_col_cmd, sizeof(oled_set_col_cmd));
		s90319_spi_write_data(oled_s90319_set_col_addr, sizeof(oled_s90319_set_col_addr));

		s90319_spi_write_cmd(oled_set_row_cmd, sizeof(oled_set_row_cmd));
		s90319_spi_write_data(oled_s90319_set_row_addr, sizeof(oled_s90319_set_row_addr));

		s90319_spi_write_cmd(oled_write_data_cmd, sizeof(oled_write_data_cmd));
		s90319_spi_write_data(frame_data_buf, width * height * 2);

		mutex_unlock(&flush_mutex);
	}

	return 0;
}

static int oled_s90319_print_buffer(char* buf)
{
	return 0;
}

/************************************************************
  Function   : oled_s90319_set_backlight
  Description: backlight on/off
  Input	     :
  Return     :
************************************************************/
static int oled_s90319_set_backlight(const uint8_t on)
{
#if defined(OLED_S90319_DEBUG)
	printk("%s, on =%u\n", __func__, on);
#endif

	if (0 == on) {
		gpio_direction_output(oled_s90319_boost_en, 0);
	} else {
		gpio_direction_output(oled_s90319_boost_en, 1);
	}

	return 0;
}

/************************************************************
  Function   : oled_s90319_panel_init
  Description: init panel
  Input	     :
  Return     :
************************************************************/
static void oled_s90319_panel_init(void)
{
	/* End Reset Sequence */
	wr_comm(0x11); //Sleep out
	Delay (120); //Delay 120ms
	/* Frame Rate */
	wr_comm(0xB1);
	wr_dat(0x05);
	wr_dat(0x3A);
	wr_dat(0x3A);
	wr_comm(0xB2);
	wr_dat(0x05);
	wr_dat(0x3A);
	wr_dat(0x3A);
	wr_comm(0xB3);
	wr_dat(0x05);
	wr_dat(0x3A);
	wr_dat(0x3A);
	wr_dat(0x05);
	wr_dat(0x3A);
	wr_dat(0x3A);
	/* End Frame Rate */
	wr_comm(0xB4); //Column inversion
	wr_dat(0x07);
	/* Power Sequence */
	wr_comm(0xC0);
	wr_dat(0xC8);
	wr_dat(0x08);
	wr_dat(0x84);
	wr_comm(0xC1);
	wr_dat(0XC5);
	wr_comm(0xC2);
	wr_dat(0x0A);
	wr_dat(0x00);
	wr_comm(0xC3);
	wr_dat(0x8A);
	wr_dat(0x2A);
	wr_comm(0xC4);
	wr_dat(0x8A);
	wr_dat(0xEE);
	/* End Power Sequence*/
	wr_comm(0xC5); //VCOM
	wr_dat(0x0C);
	wr_comm(0x36); //MX, MY, RGB mode
	wr_dat(0xc8);
	/* Gamma Sequence */
	wr_comm(0xE0);
	wr_dat(0x05);
	wr_dat(0x1A);
	wr_dat(0x0C);
	wr_dat(0x0E);
	wr_dat(0x3A);
	wr_dat(0x34);
	wr_dat(0x2D);
	wr_dat(0x2F);
	wr_dat(0x2D);
	wr_dat(0x2A);
	wr_dat(0x2F);
	wr_dat(0x3C);
	wr_dat(0x00);
	wr_dat(0x01);
	wr_dat(0x02);
	wr_dat(0x10);
	wr_comm(0xE1);
	wr_dat(0x04);
	wr_dat(0x1B);
	wr_dat(0x0D);
	wr_dat(0x0E);
	wr_dat(0x2D);
	wr_dat(0x29);
	wr_dat(0x24);
	wr_dat(0x29);
	wr_dat(0x28);
	wr_dat(0x26);
	wr_dat(0x31);
	wr_dat(0x3B);
	wr_dat(0x00);
	wr_dat(0x00);
	wr_dat(0x03);
	wr_dat(0x12);
	/* End Gamma Sequence */
	wr_comm(0x3A); //65k mode
	wr_dat(0x05);

	wr_comm(0x2a);
	wr_dat(0x00);
	wr_dat(0x02);
	wr_dat(0x00);
	wr_dat(0x81);

	wr_comm(0x2b);
	wr_dat(0x00);
	wr_dat(0x03);
	wr_dat(0x00);
	wr_dat(0x82);

	wr_comm(0x29); //Display on
	wr_comm(0x2C);
}

/************************************************************
  Function   : s90319_disp_on
  Description: init oled and display on
  Input	     :
  Return     :
************************************************************/
static void s90319_disp_on(void)
{
#if defined(OLED_S90319_DEBUG)
	printk("%s\n", __func__);
#endif

	if (s90319_state.disp_powered_up && !s90319_state.display_on) {
		oled_s90319_panel_init();
		s90319_state.display_on = TRUE;
	}
}

/************************************************************
  Function   : s90319_disp_powerup
  Description: power on
  Input	     :
  Return     :
************************************************************/
static void s90319_disp_powerup(void)
{
#if defined(OLED_S90319_DEBUG)
	printk("%s\n", __func__);
#endif

	if (!s90319_state.disp_powered_up && !s90319_state.display_on) {
		/* Reset the hardware first */
		s90319_state.disp_powered_up = TRUE;
		if (oled_s90319_pdata->oled_power_save)
			oled_s90319_pdata->oled_power_save(1);

		gpio_direction_output(oled_s90319_cs, 0);
		/* 1 data, 0 command*/
		gpio_direction_output(oled_s90319_rsx, 0);
		mdelay(5);

		gpio_set_value_cansleep(oled_s90319_cs, 0);

		mdelay(3);
	}
}

/************************************************************
  Function   : oled_s90319_panel_on
  Description: init oled and power on
  Input	     :
  Return     :
************************************************************/
static int oled_s90319_panel_on(void)
{
#if defined(OLED_S90319_DEBUG)
	printk("%s\n", __func__);
#endif
	mutex_lock(&oled_panel_mutex);
	if (!s90319_state.disp_initialized) {
		gpio_direction_output(oled_s90319_boost_en, 0);
		s90319_disp_powerup();
		s90319_disp_on();

		s90319_state.disp_initialized = TRUE;

	}
	mutex_unlock(&oled_panel_mutex);
	return 0;
}

/************************************************************
  Function   : oled_s90319_panel_off
  Description: panel off
  Input	     :
  Return     :
************************************************************/
static int oled_s90319_panel_off(void)
{
#if defined(OLED_S90319_DEBUG)
	printk("%s\n", __func__);
#endif
	mutex_lock(&oled_panel_mutex);
	if (s90319_state.disp_powered_up && s90319_state.display_on) {
		/* Main panel power off (Deep standby in) */
		s90319_spi_write_cmd(oled_s90319_panel_off_cmd,
			sizeof(oled_s90319_panel_off_cmd));
		mdelay(100);	/* Typical 100ms */

		if (oled_s90319_pdata->oled_power_save)
			oled_s90319_pdata->oled_power_save(0);

		//if (oled_s90319_pdata->oled_gpio_config)
			//oled_s90319_pdata->oled_gpio_config(0);
		s90319_state.disp_powered_up = FALSE;
		s90319_state.display_on = FALSE;
		s90319_state.disp_initialized = FALSE;
	}
	mutex_unlock(&oled_panel_mutex);
	return 0;
}

static struct of_device_id s90319__spi_table[] = {
	{ .compatible = "tplink,oled",},
	{ },
};

static int s90319_init_spi(struct spi_device *spi)
{
	/* Initialize the MSM_CAMI2C Chip */
	init_waitqueue_head(&s90319_wait_queue);
	return 0;
}

/************************************************************
  Function   : s90319_spi_probe
  Description: spi driver probe
  Input	     :
  Return     :
************************************************************/
static int __devinit s90319_spi_probe(struct spi_device *spi)
{
	tx_buf = kmalloc(BUFFER_SIZE, GFP_ATOMIC);
	if (tx_buf == NULL)
	{
		printk("kmalloc failed.\n");
		return -ENOMEM;
	}

	s90319_sensorw = kzalloc(sizeof(struct s90319_work_t), GFP_KERNEL);
	if (!s90319_sensorw) {
		printk("kzalloc failed.\n");
		return -ENOMEM;
	}

	spi_set_drvdata(spi, s90319_sensorw);
	s90319_init_spi(spi);
	s90319_spi = spi;

	msleep(50);

	printk("%s successed!\n", __func__);

	return 0;
}

/************************************************************
  Function   : oled_s90319_pin_assign
  Description: assign gpio number
  Input	     :
  Return     :
************************************************************/
static void oled_s90319_pin_assign(void)
{
	/* Setting the Default GPIO's */
	oled_s90319_cs = oled_s90319_gpio[GPIO_OLED_CS];
	oled_s90319_rsx  = oled_s90319_gpio[GPIO_OLED_RSX];
	oled_s90319_boost_en = oled_s90319_gpio[GPIO_OLED_BOOST_EN];
}

/************************************************************
  Function   : oled_s90319_probe
  Description: platform device driver probe
  Input	     :
  Return     :
************************************************************/
static int __devinit oled_s90319_probe(struct platform_device *pdev)
{
  const uint8_t pic[32] = {
    255, 127, 255, 0, 255, 0, 255, 0,
    255, 0, 255, 127, 255, 0, 255, 0,
    0, 255, 0, 255, 127, 255, 0, 255,
    0, 255, 0, 255, 0, 255, 127, 255,
  };
  uint8_t i = 0;

	struct device_node *node = pdev->dev.of_node;
	if (!node)
	{
		 dev_err(&pdev->dev, "%s: device tree information missing\n", __func__);
		 return -ENODEV;
	}

	printk("%s\n", __func__);

	pdev->dev.platform_data = &oled_s90319_panel_data;
	oled_s90319_pdata = pdev->dev.platform_data;

	get_gpio_by_dtsname(node, dts_gpio_name, oled_s90319_gpio, GPIO_OLED_END);
	oled_s90319_pin_assign();

	oled_s90319_pdata->oled_gpio_config = oled_s90319_config_gpios;
	oled_s90319_pdata->oled_power_save = oled_s90319_power_save;
	oled_s90319_pdata->oled_panel_on = oled_s90319_panel_on;
	oled_s90319_pdata->oled_panel_off = oled_s90319_panel_off;
	oled_s90319_pdata->oled_fill_with_pic = oled_s90319_fill_with_pic;
	oled_s90319_pdata->oled_set_backlight = oled_s90319_set_backlight;
	oled_s90319_pdata->oled_print_buffer = oled_s90319_print_buffer;
	oled_s90319_pdata->panel_width = COLUMN_NUM;
	oled_s90319_pdata->panel_height = ROW_NUM;

	oled_s90319_config_gpios(ENABLE);

	mutex_init(&flush_mutex);
	mutex_init(&oled_panel_mutex);

  // Indicator that our kernel is running, budget loading animation.
	msleep(50);
  oled_s90319_panel_on();
  oled_s90319_set_backlight(1);
  for (i=0; i<15; i++) {
    oled_s90319_fill_with_pic(pic, 4 + 8*i, 4, 4, 4);
    oled_s90319_fill_with_pic(pic, 4 + 8*i, 120, 4, 4);
    msleep(80);
  }

	return 0;
}

static int __devexit oled_s90319_remove(struct platform_device *pdev)
{
	return 0;
}

static struct spi_driver s90319_spi_driver = {
	.driver = {
		.name = "oleds90319",
		.owner = THIS_MODULE,
		.of_match_table = s90319__spi_table,
	},
	.probe = s90319_spi_probe,
};

static struct of_device_id qcom_s90319_pt_table[] = {
	{ .compatible = "qcom,oled_s90319_pt",},
	{},
};

static struct platform_driver this_driver = {
	.probe  = oled_s90319_probe,
	.remove = __devexit_p(oled_s90319_remove),
	.driver = {
		.name   = "oled_s90319_pt",
		.of_match_table = qcom_s90319_pt_table,
	},
};

/************************************************************
  Function   : oled_90319_panel_init
  Description: init function
  Input	     :
  Return     :
************************************************************/
static int __init oled_90319_panel_init(void)
{
	int ret = 0;

	ret = platform_driver_register(&this_driver);
	if (ret)
		return ret;

	ret =  spi_register_driver(&s90319_spi_driver);
	if (ret < 0 || s90319_spi == NULL)
	{
		ret = -ENOTSUPP;
		printk("SPI add driver failed.\n");
		goto fail_driver;
	}
	printk("oled_90319_panel_init success.\n");
	return ret;

fail_driver:
	platform_driver_unregister(&this_driver);
	return ret;
}

device_initcall(oled_90319_panel_init);

MODULE_AUTHOR("Xiong Sizhe");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("OLED 90319 driver");
