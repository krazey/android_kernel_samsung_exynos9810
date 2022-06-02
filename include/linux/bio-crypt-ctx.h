/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2019 Google LLC
 */
#ifndef __LINUX_BIO_CRYPT_CTX_H
#define __LINUX_BIO_CRYPT_CTX_H

enum blk_crypto_mode_num {
	BLK_ENCRYPTION_MODE_INVALID,
	BLK_ENCRYPTION_MODE_AES_256_XTS,
	BLK_ENCRYPTION_MODE_AES_128_CBC,
	BLK_ENCRYPTION_MODE_ADIANTUM,
	BLK_ENCRYPTION_MODE_MAX,
};

#ifdef CONFIG_BLOCK
#include <linux/blk_types.h>

#ifdef CONFIG_BLK_INLINE_ENCRYPTION

#define BLK_CRYPTO_MAX_KEY_SIZE		64

/**
 * struct blk_crypto_key - an inline encryption key
 * @crypto_mode: encryption algorithm this key is for
 * @data_unit_size: the data unit size for all encryption/decryptions with this
 *	key.  This is the size in bytes of each individual plaintext and
 *	ciphertext.  This is always a power of 2.  It might be e.g. the
 *	filesystem block size or the disk sector size.
 * @data_unit_size_bits: log2 of data_unit_size
 * @size: size of this key in bytes (determined by @crypto_mode)
 * @hash: hash of this key, for keyslot manager use only
 * @raw: the raw bytes of this key.  Only the first @size bytes are used.
 *
 * A blk_crypto_key is immutable once created, and many bios can reference it at
 * the same time.  It must not be freed until all bios using it have completed.
 */
struct blk_crypto_key {
	enum blk_crypto_mode_num crypto_mode;
	unsigned int data_unit_size;
	unsigned int data_unit_size_bits;
	unsigned int size;
	unsigned int hash;
	u8 raw[BLK_CRYPTO_MAX_KEY_SIZE];
};

#endif /* CONFIG_BLK_INLINE_ENCRYPTION */
#endif /* CONFIG_BLOCK */
#endif /* __LINUX_BIO_CRYPT_CTX_H */
