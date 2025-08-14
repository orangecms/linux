/*******************************************************************************
Copyright (C), 2014, TP-LINK TECHNOLOGIES CO., LTD.
File name	: oled_pt.h
Description	: Driver for OLED.
Author	: Zhang Tao<zhangtao@tp-link.net>

History:
------------------------------
V0.1, 2014-04-14, ZhangTao create file.
*******************************************************************************/

#ifndef _OLED_PT_H
#define _OLED_PT_H

#ifdef CONFIG_OLED_SSD1306_PT
struct oled_panel_data {
    void (*oled_gpio_config)(int on);
    int (*oled_power_save)(int);
    int (*oled_panel_on)(void);
    int (*oled_panel_off)(void);
    int (*oled_horizontal_scroll)(const uint8_t y, const uint8_t height,
    const uint8_t t_interval_scroll, const uint8_t direction);
    int (*oled_scroll_stop)(void);
    int (*oled_fade_blink)(const uint8_t mode, const uint8_t t_interval_scroll);
    int (*oled_fill_with_pic)(const uint8_t *pic, const uint8_t x,
    const uint8_t y, const uint8_t width, const uint8_t height);
    int (*oled_fill_with_value)(const uint8_t value, const uint8_t x,
    const uint8_t y, const uint8_t width, const uint8_t height);
    int (*oled_print_buffer)(char *buf);
    int (*oled_set_backlight)(const uint8_t on);
    int panel_width;
    int panel_height;
    int *gpio_num;
};
#endif

#ifdef CONFIG_OLED_S90319_PT
struct oled_panel_data {
    void (*oled_gpio_config)(int on);
    int (*oled_power_save)(int);
    int (*oled_panel_on)(void);
    int (*oled_panel_off)(void);
    int (*oled_fill_with_pic)(const uint8_t *pic, const uint8_t x,
    const uint8_t y, const uint8_t width, const uint8_t height);
    int (*oled_set_backlight)(const uint8_t on);
    int (*oled_print_buffer)(char *buf);
    int panel_width;
    int panel_height;
    int *gpio_num;
};

#endif

#endif //end of _OLED_PT_H
