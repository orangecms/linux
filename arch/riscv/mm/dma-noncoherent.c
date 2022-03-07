// SPDX-License-Identifier: GPL-2.0-only
/*
 * RISC-V specific functions to support DMA for non-coherent devices
 *
 * Copyright (c) 2021 Western Digital Corporation or its affiliates.
 */

#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/libfdt.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_fdt.h>

void arch_sync_dma_for_device(phys_addr_t paddr, size_t size, enum dma_data_direction dir)
{
	switch (dir) {
	case DMA_TO_DEVICE:
		ALT_CMO_OP(CLEAN, (unsigned long)phys_to_virt(paddr), size);
		break;
	case DMA_FROM_DEVICE:
		ALT_CMO_OP(INVAL, (unsigned long)phys_to_virt(paddr), size);
		break;
	case DMA_BIDIRECTIONAL:
		ALT_CMO_OP(FLUSH, (unsigned long)phys_to_virt(paddr), size);
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
	case DMA_BIDIRECTIONAL:
		ALT_CMO_OP(INVAL, (unsigned long)phys_to_virt(paddr), size);
		break;
	default:
		break;
	}
}

void arch_dma_prep_coherent(struct page *page, size_t size)
{
	void *flush_addr = page_address(page);

	memset(flush_addr, 0, size);
	ALT_CMO_OP(FLUSH, (unsigned long)flush_addr, size);
}

void arch_setup_dma_ops(struct device *dev, u64 dma_base, u64 size,
		const struct iommu_ops *iommu, bool coherent)
{
	/* If a specific device is dma-coherent, set it here */
	dev->dma_coherent = coherent;
}
