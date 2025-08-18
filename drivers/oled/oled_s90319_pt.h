/*******************************************************************************
  Copyright (C), 1996-2012, TP-LINK TECHNOLOGIES CO., LTD.
  File name	: oled_s90319_pt.h
  Description	: Driver for OLED S90319.
  Author	: xiongsizhe

  History:
------------------------------
V0.1, 2014-03-30, xiongsizhe    create file.
*******************************************************************************/

#ifndef __OLED_S90319_PT_H__
#define __OLED_S90319_PT_H__

typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef	int		int32_t;
typedef	unsigned int	uint32_t;

#define ROW_NUM 		128	/* 0~7 */
#define PAGE_NUM		128
#define COLUMN_NUM		128

#define ENABLE	1
#define DISABLE	0

#define COLUMN_NUM_EXP		7	/* 2^7 = 128 */

/*
 * Four Formats:
 * 1. CMD_CONTROL BYTE . CMD . CMD . CMD бнбн
 * 2. CMD_CONTROL BYTE . CMD . CMD_CONTROL_BYTE . CMD бнбн
 * 3. DAT_CONTROL BYTE . DATA . DATA . DATA бнбн
 * 4. DAT_CONTROL BYTE . DATA . DAT_CONTROL_BYTE . DATA бнбн
 */
#define OLED_CONTROL_CMDS			0x00
#define OLED_CONTROL_CMD_PAIRS			0x80
#define OLED_CONTROL_DATAS			0x40
#define OLED_CONTROL_DATA_PAIRS			0xC0

/* SINGLE CMDS */
#define CMD_DUMMY_BYTE_ZERO			0x00
#define CMD_DUMMY_BYTE_FF			0xFF
#define CMD_GRAM_IGNORE(bit) 			(0xA4|(bit))	/* 0: No, 1: Yes */
#define CMD_DISPLAY_OFF_ON(bit) 		(0xAE|(bit))	/* v: 0|1 */
#define CMD_SCAN_DIRECTION_0_TO_N		0xC0
#define CMD_SCAN_DIRECTION_N_TO_0		0xC8
#define CMD_LOWER_COL_ADDR(addr)		(0x00|(addr))	/* addr: 0~F */
#define CMD_HIGHER_COL_ADDR(addr)		(0x10|(addr))	/* addr: 0~F */
#define CMD_SEGMENT_REMAP(dir)			(0xA0|(dir))	/* dir:0 normal direction, dir:1 reverse direction */
#define CMD_START_LINE(line)			(0x40|(line))	/* line: 0 ~ 63 */
#define CMD_NORMAL_REV_DISPLAY(bit)		(0xA6|(bit))	/* bit:0 normal display, bit:1 reverse display */
#define CMD_HORIZONTAL_SCROLL(dir)		(0x26|(dir))	/* 0: L->R, 1:R->L */
#define CMD_SCROLL_ENABLE(ena)			(0x2E|(ena))	/* 0:Disable, 1:Enable */

/* DOUBLE CMDS */
#define CMD_DOUBLE_CLOCK_DIVIDE_RATIO		0xD5
#define CMD_DOUBLE_MULTIPLEX_RATIO		0xA8
#define CMD_DOUBLE_PRECHARGE_PERIOD		0xD9
#define CMD_DOUBLE_PADS_HW_CONFIG		0xDA	/* Sequence: 0x02; Alternative: 0x12*/
#define CMD_DOUBLE_CONTRAST_CONTROL		0x81
#define CMD_DOUBLE_DISPLAY_OFFSET		0xD3	/* 0x00 ~ 3f */
#define CMD_DOUBLE_VCOM_HLEVEL			0xDB	/* 0x00 ~ 0xff */
#define CMD_DOUBLE_SET_CHARGE_PUMP		0x8D	/* Enable: 0x14, Disable: 0x10*/
#define CMD_DOUBLE_MEMORY_ADDRESSING_MODE	0x20	/* 00: Horizontal 01: Vertial 10: Page 11: Invalid*/
#define CMD_DOUBLE_FADE_BLINK_MODE		0x23	/* Fade out or blinking mode */

/* TRIPLE CMDS */
#define CMD_TRIPE_COLUMN_ADDRESS		0x21	/* 0~127, 0~127 */
#define CMD_TRIPE_PAGE_ADDRESS			0x22	/* 0~7, 0~7 */

#define OLED_MATREIAL_STANDARD_CONTRAST		0xAF
#define OLED_MATREIAL_LOW_CONTRAST      	0x0F

#define OLED_SET_COL_CMD		0x2A
#define OLED_SET_ROW_CMD		0x2B
#define OLED_WRITE_DATA_CMD		0x2C

#define X_OFFSET	2
#define Y_OFFSET	3

uint8_t CMD_HORIZONTAL_SCROLL_ARRAY[] = {CMD_HORIZONTAL_SCROLL(0), CMD_HORIZONTAL_SCROLL(1)};
uint8_t CMD_BACKLIGHT_ARRAY[] = {
	CMD_DISPLAY_OFF_ON(0), 				/* Backlight off */
	CMD_DISPLAY_OFF_ON(1)				/* Backlight oN */
};

/* set col command */
uint8_t oled_set_col_cmd[] = {
	OLED_SET_COL_CMD,
};

/* set row command */
uint8_t oled_set_row_cmd[] = {
	OLED_SET_ROW_CMD,
};

/* write data command */
uint8_t oled_write_data_cmd[] = {
	OLED_WRITE_DATA_CMD,
};

/* set backlight command */
uint8_t oled_s90319_backlight_cmd[] = {
	CMD_DISPLAY_OFF_ON(0)
};

/* panel on/off command */
uint8_t oled_s90319_panel_off_cmd[] = {
	CMD_DISPLAY_OFF_ON(0),				/* manual display on */
	CMD_DOUBLE_SET_CHARGE_PUMP, 0x10		/* set charge pump enable*/
};

uint8_t oled_s90319_scroll_stop_cmd[] = {
	CMD_SCROLL_ENABLE(0)
};

/* Fade out or blinking mode */
uint8_t oled_s90319_fade_blink_cmd[] = {
	CMD_DOUBLE_FADE_BLINK_MODE,
	0
};

/*
 * fade_blink_parameter:
 * A[5:4] = 00b	Disable Fade Out / Blinking Mode
 * A[5:4] = 10b	Enable Fade Out mode
 * A[5:4] = 11b	Enable Blinking mode
 * A[3:0] : Set time interval for each fade step, (8 * (A[3:0] + 1))frames
 */
struct oled_s90319_fade_blink_cmd_config_struct {
	uint8_t *fade_blink_parameter;
};

uint8_t oled_s90319_set_col_addr[] = {
	0x00, 0x00, 0x00, 0x00
};

uint8_t oled_s90319_set_row_addr[] = {
	0x00, 0x00, 0x00, 0x00
};

#endif	/* __OLED_S90320_PT__ */
