// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Heiko Stuebner <heiko@sntech.de>
 */

#include <linux/bug.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/alternative.h>
#include <asm/cacheflush.h>
#include <asm/errata_list.h>
#include <asm/patch.h>
#include <asm/sbi.h>
#include <asm/vendorid_list.h>

struct errata_info {
	char name[ERRATA_STRING_LENGTH_MAX];
	bool (*check_func)(unsigned long arch_id, unsigned long impid);
	unsigned int stage;
};

static bool errata_mt_check_func(unsigned long  arch_id, unsigned long impid)
{
  sbi_console_putchar('c');
	if (arch_id != 0 || impid != 0)
		return false;
  sbi_console_putchar('t');
	return true;
}

static const struct errata_info errata_list[ERRATA_THEAD_NUMBER] = {
	{
		.name = "memory-types",
		.stage = RISCV_ALTERNATIVES_EARLY_BOOT,
		.check_func = errata_mt_check_func
	},
	{
		.name = "cache-management",
		.stage = RISCV_ALTERNATIVES_BOOT,
		.check_func = errata_mt_check_func
	},
};

static u32 thead_errata_probe(unsigned int stage, unsigned long archid, unsigned long impid)
{
	const struct errata_info *info;
	u32 cpu_req_errata = 0;
	int idx;

  sbi_console_putchar('5');
	for (idx = 0; idx < ERRATA_THEAD_NUMBER; idx++) {
    sbi_console_putchar('6');
		info = &errata_list[idx];
    sbi_console_putchar('p');
    sbi_console_putchar(idx);
    sbi_console_putchar(archid);
    sbi_console_putchar(impid);
		if (stage == RISCV_ALTERNATIVES_MODULE || info->stage == stage) {
      sbi_console_putchar('x');
      // sbi_console_putchar(((void*) &info->check_func) );
      // sbi_console_putchar(((void*) &info->check_func) >> 8);
      // sbi_console_putchar(((void*) &info->check_func) >> 16);
      // sbi_console_putchar(((void*) &info->check_func) >> 24);
      sbi_console_putchar('o');
      // PROBLEM HERE!
      // if (info->check_func(archid, impid)) {
      bool doit;
      // doit = info->check_func(archid, impid); // THIS CAUSES AN EXCEPTION
      doit = errata_mt_check_func(archid, impid);
      // doit = !(archid != 0 || impid != 0);
      if (doit) {
        sbi_console_putchar('a');
        cpu_req_errata |= (1U << idx);
      }
    }
    sbi_console_putchar('b');
	}

	return cpu_req_errata;
}

void __init_or_module thead_errata_patch_func(struct alt_entry *begin, struct alt_entry *end,
					      unsigned long archid, unsigned long impid,
					      unsigned int stage)
{
	struct alt_entry *alt;
  sbi_console_putchar('P');
	u32 cpu_req_errata = thead_errata_probe(stage, archid, impid);
	u32 tmp;

  sbi_console_putchar('C');
  sbi_console_putchar(begin);
  sbi_console_putchar(end);
  if (end - begin > 10) {
    sbi_console_putchar('X');
  }
	for (alt = begin; alt < end; alt++) {
		if (alt->vendor_id != THEAD_VENDOR_ID) {
      sbi_console_putchar('T');
			continue;
    }
		if (alt->errata_id >= ERRATA_THEAD_NUMBER) {
      sbi_console_putchar('N');
			continue;
    }
    sbi_console_putchar('Y');

		tmp = (1U << alt->errata_id);
		if (cpu_req_errata & tmp) {
      sbi_console_putchar('E');

			/* On vm-alternatives, the mmu isn't running yet */
			if (stage == RISCV_ALTERNATIVES_EARLY_BOOT) {
        sbi_console_putchar('V');

				memcpy((void *)__pa_symbol(alt->old_ptr),
				       (void *)__pa_symbol(alt->alt_ptr), alt->alt_len);
      } else {
        sbi_console_putchar('S');

				patch_text_nosync(alt->old_ptr, alt->alt_ptr, alt->alt_len);
      }
		}
	}

	if (stage == RISCV_ALTERNATIVES_EARLY_BOOT)
		local_flush_icache_all();
}
