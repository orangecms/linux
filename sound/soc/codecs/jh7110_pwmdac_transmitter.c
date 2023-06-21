// SPDX-License-Identifier: GPL-2.0
/*
 * Dummy PWM-DAC transmitter driver for the StarFive JH7110 SoC
 *
 * Copyright (C) 2021-2023 StarFive Technology Co., Ltd.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <sound/initval.h>
#include <sound/pcm.h>
#include <sound/soc.h>

#define DRV_NAME "pwmdac-dit"

static const struct snd_soc_dapm_widget dit_widgets[] = {
	SND_SOC_DAPM_OUTPUT("pwmdac-out"),
};

static const struct snd_soc_dapm_route dit_routes[] = {
	{ "pwmdac-out", NULL, "Playback" },
};

static const struct snd_soc_component_driver soc_codec_pwmdac_dit = {
	.dapm_widgets		= dit_widgets,
	.num_dapm_widgets	= ARRAY_SIZE(dit_widgets),
	.dapm_routes		= dit_routes,
	.num_dapm_routes	= ARRAY_SIZE(dit_routes),
	.idle_bias_on		= 1,
	.use_pmdown_time	= 1,
	.endianness		= 1,
};

static struct snd_soc_dai_driver dit_stub_dai = {
	.name		= "pwmdac-dit-hifi",
	.playback	= {
		.stream_name	= "Playback",
		.channels_min	= 1,
		.channels_max	= 384,
		.rates		= SNDRV_PCM_RATE_8000_48000,
		.formats	= SNDRV_PCM_FMTBIT_S16_LE,
	},
};

static int pwmdac_dit_probe(struct platform_device *pdev)
{
	return devm_snd_soc_register_component(&pdev->dev,
					       &soc_codec_pwmdac_dit,
					       &dit_stub_dai, 1);
}

#ifdef CONFIG_OF
static const struct of_device_id pwmdac_dit_dt_ids[] = {
	{ .compatible = "starfive,jh7110-pwmdac-dit", },
	{ }
};
MODULE_DEVICE_TABLE(of, pwmdac_dit_dt_ids);
#endif

static struct platform_driver pwmdac_dit_driver = {
	.probe		= pwmdac_dit_probe,
	.driver		= {
		.name	= DRV_NAME,
		.of_match_table = of_match_ptr(pwmdac_dit_dt_ids),
	},
};

module_platform_driver(pwmdac_dit_driver);

MODULE_DESCRIPTION("StarFive JH7110 dummy PWM-DAC transmitter driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" DRV_NAME);
