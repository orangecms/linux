// SPDX-License-Identifier: GPL-2.0-only
/*
 * RISC-V specific functions to support DMA for non-coherent devices
 *
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 */

#include <linux/dma-direct.h>
#include <linux/dma-iommu.h>
#include <linux/dma-map-ops.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <asm/cacheflush.h>

static unsigned int riscv_cbom_block_size = L1_CACHE_BYTES;

void arch_sync_dma_for_device(phys_addr_t paddr, size_t size, enum dma_data_direction dir)
{
	switch (dir) {
	case DMA_TO_DEVICE:
		ALT_CMO_OP(CLEAN, (unsigned long)phys_to_virt(paddr), size, riscv_cbom_block_size);
		break;
	case DMA_FROM_DEVICE:
		break;
	case DMA_BIDIRECTIONAL:
		ALT_CMO_OP(FLUSH, (unsigned long)phys_to_virt(paddr), size, riscv_cbom_block_size);
		break;
	default:
		break;
	}
}

void arch_sync_dma_for_cpu(phys_addr_t paddr, size_t size, enum dma_data_direction dir)
{
	switch (dir) {
	case DMA_TO_DEVICE:
		break;
	case DMA_FROM_DEVICE:
		ALT_CMO_OP(INVAL, (unsigned long)phys_to_virt(paddr), size, riscv_cbom_block_size);
		break;
	case DMA_BIDIRECTIONAL:
		ALT_CMO_OP(FLUSH, (unsigned long)phys_to_virt(paddr), size, riscv_cbom_block_size);
		break;
	default:
		break;
	}
}

void arch_dma_prep_coherent(struct page *page, size_t size)
{
	void *flush_addr = page_address(page);

	ALT_CMO_OP(FLUSH, (unsigned long)flush_addr, size, riscv_cbom_block_size);
}

void arch_setup_dma_ops(struct device *dev, u64 dma_base, u64 size,
		const struct iommu_ops *iommu, bool coherent)
{
	/* If a specific device is dma-coherent, set it here */
	dev->dma_coherent = coherent;

	if (iommu)
		iommu_setup_dma_ops(dev, dma_base, dma_base + size - 1);
}

void riscv_init_cbom_blocksize(void)
{
	struct device_node *node;
	int ret;
	u32 val;

	for_each_of_cpu_node(node) {
		int hartid = riscv_of_processor_hartid(node);
		int cbom_hartid;

		if (hartid < 0)
			continue;

		/* set block-size for cbom extension if available */
		ret = of_property_read_u32(node, "riscv,cbom-block-size", &val);
		if (ret)
			continue;

		if (!riscv_cbom_block_size) {
			riscv_cbom_block_size = val;
			cbom_hartid = hartid;
		} else {
			if (riscv_cbom_block_size != val)
				pr_warn("cbom-block-size mismatched between harts %d and %d\n",
					cbom_hartid, hartid);
		}
	}
}
