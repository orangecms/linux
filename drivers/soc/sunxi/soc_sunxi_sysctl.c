// SPDX-License-Identifier: GPL-2.0-or-later

#include <asm/pgtable-bits.h>
#include <asm/soc.h>

static void __init thead_init(void)
{
	/*
	__riscv_custom_pte.cache = 0x7000000000000000;
	__riscv_custom_pte.mask  = 0xf800000000000000;
	__riscv_custom_pte.io    = BIT(63);
	__riscv_custom_pte.wc    = 0;
	*/

	__riscv_pbmt.mask	= 0xf800000000000000;
	__riscv_pbmt.mt[MT_PMA]	= 0x7000000000000000;
	__riscv_pbmt.mt[MT_NC]	= 0;
	__riscv_pbmt.mt[MT_IO]	= BIT(63);

}

static void __init sun20i_d1_soc_early_init(const void *fdt)
{
	thead_init();
}

SOC_EARLY_INIT_DECLARE(sun20i_d1_soc, "allwinner,sun20i-d1",
		       sun20i_d1_soc_early_init);
