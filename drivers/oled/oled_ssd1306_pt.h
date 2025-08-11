/*******************************************************************************
  Copyright (C), 1996-2012, TP-LINK TECHNOLOGIES CO., LTD.
  File name	: oled_ssd1306_pt.h
  Description	: Driver for OLED SSD1306.
  Author	: linyunfeng

  History:
------------------------------
V0.1, 2011-08-16, linyunfeng    create file.
*******************************************************************************/

#ifndef __OLED_SSD1306_PT_H__
#define __OLED_SSD1306_PT_H__

/* [wuzhong start] 2012-11-29 */
#define __ENABLE_OLED_SH1106_AND_SSD1306__
/* [wuzhong end] */


#define PAGE_NUM 		8	/* 0~7 */

/* [wuzhong start] 2012-11-29 */
#ifdef __ENABLE_OLED_SH1106_AND_SSD1306__
#define COLUMN_NUM		132
#else
#define COLUMN_NUM		128
#endif
/* [wuzhong end] */

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

uint8_t CMD_HORIZONTAL_SCROLL_ARRAY[] = {CMD_HORIZONTAL_SCROLL(0), CMD_HORIZONTAL_SCROLL(1)};
uint8_t CMD_BACKLIGHT_ARRAY[] = {
	CMD_DISPLAY_OFF_ON(0), 				/* Backlight off */
	CMD_DISPLAY_OFF_ON(1)				/* Backlight oN */
};


/* [wuzhong start] 2012-11-29 */
#ifdef __ENABLE_OLED_SH1106_AND_SSD1306__
#define CMD_DC_DC_CONTROL 0xad
#define CMD_DC_DC_ON 0x8b    /* POR */
#define CMD_DC_DC_OFF 0x8a
#endif
/* [wuzhong end] */


uint8_t oled_ssd1306_init_cmd[] = {
#if 0
	CMD_DISPLAY_OFF_ON(0),
	CMD_LOWER_COL_ADDR(0),
	CMD_HIGHER_COL_ADDR(0),
	CMD_START_LINE(0),
	CMD_DOUBLE_CONTRAST_CONTROL,
	OLED_MATREIAL_STANDARD_CONTRAST,
	CMD_SEGMENT_REMAP(1),				/* left-right */
	CMD_NORMAL_REV_DISPLAY(0),
	CMD_SCAN_DIRECTION_N_TO_0,			/* up-down */
	CMD_DOUBLE_MULTIPLEX_RATIO, 0x3F,		/* something influence */
	CMD_DOUBLE_DISPLAY_OFFSET, 0x00,
	CMD_DOUBLE_CLOCK_DIVIDE_RATIO, 0xF0,		/* something influence */
	CMD_DOUBLE_PRECHARGE_PERIOD, 0x22,		/* something influence */
	CMD_DOUBLE_PADS_HW_CONFIG, 0x12,
	CMD_DOUBLE_VCOM_HLEVEL, 0x40,			/* something influence */
	CMD_DOUBLE_SET_CHARGE_PUMP, 0x14,		/* set charge pump enable*/
	CMD_DISPLAY_OFF_ON(1) 				/* manual display on */
#else	/* From vendor */

/* [wuzhong start] */
#ifdef __ENABLE_OLED_SH1106_AND_SSD1306__

	CMD_DISPLAY_OFF_ON(0),
	CMD_DOUBLE_CLOCK_DIVIDE_RATIO, 0x80,	/* something influence */
	CMD_DOUBLE_MULTIPLEX_RATIO, 0x3f,		/* something influence */
	CMD_DOUBLE_DISPLAY_OFFSET, 0x00,
	CMD_START_LINE(0),
	//CMD_DC_DC_CONTROL, CMD_DC_DC_ON,     /* same with POR in sh1106,  no this command in ssd1306 */
	CMD_DOUBLE_SET_CHARGE_PUMP, 0x14,		/* set charge pump enable for ssd1306, no this command in sh1106 */
	//CMD_DOUBLE_MEMORY_ADDRESSING_MODE, 0x10, /* POR in ssd1306 , no this command in sh1106 */
	CMD_SEGMENT_REMAP(1),				/* left-right */
	CMD_SCAN_DIRECTION_N_TO_0,
	CMD_DOUBLE_PADS_HW_CONFIG, 0x12,
	CMD_DOUBLE_CONTRAST_CONTROL,OLED_MATREIAL_STANDARD_CONTRAST,  /*   0x40 was given in sh1106 init code(0x80 is recommended in sh1106 datasheet ), while SSD1306 use 0xaf */
	CMD_DOUBLE_PRECHARGE_PERIOD, 0xF1,      /* TODO:  */
	CMD_DOUBLE_VCOM_HLEVEL, 0x40,			/* something influence */
	CMD_GRAM_IGNORE(0),
	CMD_NORMAL_REV_DISPLAY(0),
	//CMD_DISPLAY_OFF_ON(1) 			/* Backlight on */

#else /* __ENABLE_OLED_SH1106_AND_SSD1306__ */

	CMD_DISPLAY_OFF_ON(0),
	CMD_DOUBLE_CLOCK_DIVIDE_RATIO, 0x80,		/* something influence */
	CMD_DOUBLE_MULTIPLEX_RATIO, 0x3f,		/* something influence */
	CMD_DOUBLE_DISPLAY_OFFSET, 0x00,
	CMD_START_LINE(0),
	CMD_DOUBLE_SET_CHARGE_PUMP, 0x14,		/* set charge pump enable*/
	CMD_DOUBLE_MEMORY_ADDRESSING_MODE, 0x00,
	CMD_SEGMENT_REMAP(1),				/* left-right */
	CMD_SCAN_DIRECTION_N_TO_0,
	CMD_DOUBLE_PADS_HW_CONFIG, 0x12,
	CMD_DOUBLE_CONTRAST_CONTROL,
	OLED_MATREIAL_STANDARD_CONTRAST,
	CMD_DOUBLE_PRECHARGE_PERIOD, 0xF1,		/* something influence */
	CMD_DOUBLE_VCOM_HLEVEL, 0x40,			/* something influence */
	CMD_GRAM_IGNORE(0),
	CMD_NORMAL_REV_DISPLAY(0),
	//CMD_DISPLAY_OFF_ON(1) 			/* Backlight on */

#endif /* __ENABLE_OLED_SH1106_AND_SSD1306__ */
/* [wuzhong end] */

#endif /* From vendor */
};

uint8_t oled_ssd1306_backlight_cmd[] = {
	CMD_DISPLAY_OFF_ON(0)
};

uint8_t oled_ssd1306_panel_off_cmd[] = {
	CMD_DISPLAY_OFF_ON(0),				/* manual display on */
	CMD_DOUBLE_SET_CHARGE_PUMP, 0x10		/* set charge pump enable*/
};

uint8_t oled_ssd1306_scroll_stop_cmd[] = {
	CMD_SCROLL_ENABLE(0)
};

/* Fade out or blinking mode */
uint8_t oled_ssd1306_fade_blink_cmd[] = {
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
struct oled_ssd1306_fade_blink_cmd_config_struct {
	uint8_t *fade_blink_parameter;
};

static struct oled_ssd1306_fade_blink_cmd_config_struct oled_ssd1306_fade_blink_cmd_config = {
	.fade_blink_parameter = &oled_ssd1306_fade_blink_cmd[1],
};

/* [wuzhong start] */
#ifdef __ENABLE_OLED_SH1106_AND_SSD1306__

// sh1106 is  4  pixel widder then ssd1306
#define SH1106_OFFSET 2

//struct oled_sh1106_flush_cmd {
//    uint8_t* line_start;
//    uint8_t* low_column;
//    uint8_t* high_column;
//    uint8_t* page_number;
//};

// line: 0x40 as default
// page: range 0xb0~0xb7
// low column: range 0x00~0x0f
// high column: range 0x10~0x1f
uint8_t oled_sh1106_flush_cmd[] = {
	0x40, 0xb0, 0x00, 0x10
};

#else /* __ENABLE_OLED_SH1106_AND_SSD1306__ */

/* Flush the screen */
uint8_t oled_ssd1306_flush_cmd[] = {
	CMD_DOUBLE_MEMORY_ADDRESSING_MODE, 0,
	CMD_TRIPE_COLUMN_ADDRESS, 0, (COLUMN_NUM - 1),
	CMD_TRIPE_PAGE_ADDRESS, 0, (PAGE_NUM - 1)
};

struct oled_ssd1306_flush_cmd_config_struct {
	uint8_t *col_addr_start;
	uint8_t *col_addr_end;
	uint8_t *page_addr_start;
	uint8_t *page_addr_end;
};

static struct oled_ssd1306_flush_cmd_config_struct oled_ssd1306_flush_cmd_config = {
	.col_addr_start = &oled_ssd1306_flush_cmd[3],	/* Start column address, 0~127 */
	.col_addr_end = &oled_ssd1306_flush_cmd[4],	/* End column address, 0~127 */
	.page_addr_start = &oled_ssd1306_flush_cmd[6],	/* Start page address, 0~7 */
	.page_addr_end = &oled_ssd1306_flush_cmd[7],	/* End page address, 0~7 */
};

#endif  /* __ENABLE_OLED_SH1106_AND_SSD1306__ */
/* [wuzhong end] */

/* Horizontal scroll */
uint8_t oled_ssd1306_h_scroll_cmd[] = {
	CMD_HORIZONTAL_SCROLL(0),	/* Direction, 0: L->R, 1:R->L */
	CMD_DUMMY_BYTE_ZERO,
	0,				/* Start page address */
	0,				/* Frames interval between each scroll,
					 * 0: 5 frame, 1: 64, 2: 128, 3: 256,
					 * 4: 3, 5: 4, 6: 25, 7: 2 */
	(PAGE_NUM - 1),			/* End page address */
	CMD_DUMMY_BYTE_ZERO,
	CMD_DUMMY_BYTE_FF,
	CMD_SCROLL_ENABLE(1)
};

struct oled_ssd1306_h_scroll_cmd_config_struct {
	uint8_t *horizontal_scroll_direction;
	uint8_t *page_addr_start;
	uint8_t *time_interval_scroll;
	uint8_t *page_addr_end;
};

static struct oled_ssd1306_h_scroll_cmd_config_struct oled_ssd1306_h_scroll_cmd_config = {
	.horizontal_scroll_direction = &oled_ssd1306_h_scroll_cmd[0],
	.page_addr_start = &oled_ssd1306_h_scroll_cmd[2],
	.time_interval_scroll = &oled_ssd1306_h_scroll_cmd[3],
	.page_addr_end = &oled_ssd1306_h_scroll_cmd[4],
};

#endif	/* __OLED_SSD1306_PT__ */

