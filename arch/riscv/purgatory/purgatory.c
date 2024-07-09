// SPDX-License-Identifier: GPL-2.0-only
/*
 * purgatory: Runs between two kernels
 *
 * Copyright (C) 2022 Huawei Technologies Co, Ltd.
 *
 * Author: Li Zhengyu (lizhengyu3@huawei.com)
 *
 */

#include <linux/purgatory.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/string.h>

u8 purgatory_sha256_digest[SHA256_DIGEST_SIZE] __section(".kexec-purgatory");

struct kexec_sha_region purgatory_sha_regions[KEXEC_SEGMENT_MAX] __section(".kexec-purgatory");

// Special simplified implementation
void sbi_console_putchar(int ch);

void sbi_console_putchar(int ch)
{
	register uintptr_t a0 asm ("a0") = (uintptr_t)(ch);
	register uintptr_t a7 asm ("a7") = (uintptr_t)(1);
	asm volatile ("ecall" : "+r" (a0) : "r" (a7) : "memory");
}

static int verify_sha256_digest(void)
{
	struct kexec_sha_region *ptr, *end;
	struct sha256_state ss;
	u8 digest[SHA256_DIGEST_SIZE];

	sha256_init(&ss);
	end = purgatory_sha_regions + ARRAY_SIZE(purgatory_sha_regions);
	for (ptr = purgatory_sha_regions; ptr < end; ptr++)
		sha256_update(&ss, (uint8_t *)(ptr->start), ptr->len);
	sha256_final(&ss, digest);
	if (memcmp(digest, purgatory_sha256_digest, sizeof(digest)) != 0)
		return 1;
	return 0;
}

/* workaround for a warning with -Wmissing-prototypes */
void purgatory(void);

void purgatory(void)
{
	if (verify_sha256_digest())
		for (;;)
			/* loop forever */
			;
}
