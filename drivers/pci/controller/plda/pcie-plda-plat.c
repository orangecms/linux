// SPDX-License-Identifier: GPL-2.0
/*
 * PLDA XpressRich PCIe platform driver
 *
 * Authors: Minda Chen <minda.chen@starfivetech.com>
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/of_device.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/resource.h>
#include <linux/types.h>

#include "pcie-plda.h"

static struct pci_ops plda_default_ops = {
	.map_bus	= plda_pcie_map_bus,
	.read		= pci_generic_config_read,
	.write		= pci_generic_config_write,
};

static int plda_plat_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct plda_pcie *pci;
	int ret;

	pci = devm_kzalloc(dev, sizeof(*pci), GFP_KERNEL);
	if (!pci)
		return -ENOMEM;

	pci->dev = dev;

	ret = plda_pcie_host_init(pci, &plda_default_ops);
	if (ret) {
		dev_err(dev, "Failed to initialize host\n");
		return ret;
	}

	platform_set_drvdata(pdev, pci);

	return ret;
}

static const struct of_device_id plda_plat_pcie_of_match[] = {
	{ .compatible = "plda,xpressrich-pcie-host"},
	{ /* sentinel */ }
};

static struct platform_driver plda_plat_pcie_driver = {
	.driver = {
		.name	= "plda-xpressrich-pcie",
		.of_match_table = plda_plat_pcie_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = plda_plat_pcie_probe,
};
builtin_platform_driver(plda_plat_pcie_driver);
