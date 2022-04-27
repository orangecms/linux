// SPDX-License-Identifier: GPL-2.0-only
//
// Copyright (C) 2022 Samuel Holland <samuel@sholland.org>
//

#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

static const struct of_device_id sun50i_r329_mbus_of_match[] = {
	{ .compatible = "allwinner,sun20i-d1-mbus" },
	{ .compatible = "allwinner,sun50i-r329-mbus" },
	{ },
};
MODULE_DEVICE_TABLE(of, sun50i_r329_mbus_of_match);

static struct platform_driver sun50i_r329_mbus_driver = {
	.driver	= {
		.name		= "sun50i-r329-mbus",
		.of_match_table	= sun50i_r329_mbus_of_match,
	},
};
module_platform_driver(sun50i_r329_mbus_driver);

MODULE_AUTHOR("Samuel Holland <samuel@sholland.org>");
MODULE_DESCRIPTION("Allwinner R329 MBUS DEVFREQ Driver");
MODULE_LICENSE("GPL v2");
