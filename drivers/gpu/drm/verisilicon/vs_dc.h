/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 VeriSilicon Holdings Co., Ltd.
 */

#ifndef __VS_DC_H__
#define __VS_DC_H__

#include <linux/clk.h>
#include <linux/mm_types.h>
#include <linux/reset.h>
#include <linux/version.h>

#include <drm/drm_fourcc.h>
#include <drm/drm_modes.h>

#include "vs_crtc.h"
#include "vs_dc_hw.h"
#include "vs_plane.h"

#define fourcc_mod_vs_get_type(val) \
			(((val) & DRM_FORMAT_MOD_VS_TYPE_MASK) >> 54)

struct vs_dc_plane {
	enum dc_hw_plane_id id;
};

enum vout_clk {
	CLK_VOUT_NOC_DISP = 0,
	CLK_VOUT_PIX0,
	CLK_VOUT_PIX1,
	CLK_VOUT_AXI,
	CLK_VOUT_CORE,
	CLK_VOUT_AHB,
	CLK_VOUT_HDMI_PIX,
	CLK_VOUT_SOC_PIX,
	CLK_VOUT_NUM
};

enum rst_vout {
	RST_VOUT_AXI = 0,
	RST_VOUT_AHB,
	RST_VOUT_CORE,
	RST_VOUT_NUM
};

struct vs_dc {
	struct vs_crtc		*crtc[DC_DISPLAY_NUM];
	struct dc_hw		hw;
	void __iomem        *dss_reg;
	bool			    first_frame;

	struct vs_dc_plane  planes[PLANE_NUM];
	struct clk_bulk_data clk_vout[CLK_VOUT_NUM];
	int nclks;
	struct reset_control_bulk_data rst_vout[RST_VOUT_NUM];
	int nrsts;
};

extern struct platform_driver dc_platform_driver;

#endif /* __VS_DC_H__ */
