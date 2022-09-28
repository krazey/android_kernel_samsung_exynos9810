/*
 * fscrypt_private.h
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * Originally written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar.
 * Heavily modified since then.
 */

#ifndef _FSCRYPT_PRIVATE_H
#define _FSCRYPT_PRIVATE_H

#include <linux/fscrypt.h>
#include <crypto/hash.h>

#define CONST_STRLEN(str)	(sizeof(str) - 1)

#define FS_KEY_DERIVATION_NONCE_SIZE	16

#define FSCRYPT_MIN_KEY_SIZE		16

/**
 * Encryption context for inode
 *
 * Protector format:
 *  1 byte: Protector format (1 = this version)
 *  1 byte: File contents encryption mode
 *  1 byte: File names encryption mode
 *  1 byte: Flags
 *  8 bytes: Master Key descriptor
 *  16 bytes: Encryption Key derivation nonce
 */
struct fscrypt_context {
	u8 format;
	u8 contents_encryption_mode;
	u8 filenames_encryption_mode;
	u8 flags;
	u8 master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
	u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
} __packed;

#define FS_ENCRYPTION_CONTEXT_FORMAT_V1		1

/**
 * For encrypted symlinks, the ciphertext length is stored at the beginning
 * of the string in little-endian format.
 */
struct fscrypt_symlink_data {
	__le16 len;
	char encrypted_path[1];
} __packed;

/*
 * fscrypt_info - the "encryption key" for an inode
 *
 * When an encrypted file's key is made available, an instance of this struct is
 * allocated and stored in ->i_crypt_info.  Once created, it remains until the
 * inode is evicted.
 */
struct fscrypt_info {

	/* The actual crypto transform used for encryption and decryption */
	struct crypto_skcipher *ci_ctfm;

	/*
	 * Cipher for ESSIV IV generation.  Only set for CBC contents
	 * encryption, otherwise is NULL.
	 */
	struct crypto_cipher *ci_essiv_tfm;

	/*
	 * Encryption mode used for this inode.  It corresponds to either
	 * ci_data_mode or ci_filename_mode, depending on the inode type.
	 */
	struct fscrypt_mode *ci_mode;

	/* Back-pointer to the inode */
	struct inode *ci_inode;

	/*
	 * The master key with which this inode was unlocked (decrypted).  This
	 * will be NULL if the master key was found in a process-subscribed
	 * keyring rather than in the filesystem-level keyring.
	 */
	struct key *ci_master_key;

	/*
	 * Link in list of inodes that were unlocked with the master key.
	 * Only used when ->ci_master_key is set.
	 */
	struct list_head ci_master_key_link;

	/*
	 * If non-NULL, then encryption is done using the master key directly
	 * and ci_ctfm will equal ci_direct_key->dk_ctfm.
	 */
	struct fscrypt_direct_key *ci_direct_key;

	/* fields from the fscrypt_context */
	u8 ci_data_mode;
	u8 ci_filename_mode;
	u8 ci_flags;
	u8 ci_master_key_descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE];
	u8 ci_nonce[FS_KEY_DERIVATION_NONCE_SIZE];
};

typedef enum {
	FS_DECRYPT = 0,
	FS_ENCRYPT,
} fscrypt_direction_t;

#define FS_CTX_REQUIRES_FREE_ENCRYPT_FL		0x00000001

static inline bool fscrypt_valid_enc_modes(u32 contents_mode,
					   u32 filenames_mode)
{
	if (contents_mode == FSCRYPT_MODE_AES_128_CBC &&
	    filenames_mode == FSCRYPT_MODE_AES_128_CTS)
		return true;

	if (contents_mode == FSCRYPT_MODE_AES_256_XTS &&
	    filenames_mode == FSCRYPT_MODE_AES_256_CTS)
		return true;

	if (contents_mode == FSCRYPT_MODE_ADIANTUM &&
	    filenames_mode == FSCRYPT_MODE_ADIANTUM)
		return true;

	return false;
}

/* crypto.c */
extern struct kmem_cache *fscrypt_info_cachep;
extern int fscrypt_initialize(unsigned int cop_flags);
extern int fscrypt_crypt_block(const struct inode *inode,
			       fscrypt_direction_t rw, u64 lblk_num,
			       struct page *src_page, struct page *dest_page,
			       unsigned int len, unsigned int offs,
			       gfp_t gfp_flags);
extern struct page *fscrypt_alloc_bounce_page(gfp_t gfp_flags);
extern const struct dentry_operations fscrypt_d_ops;

extern void __printf(3, 4) __cold
fscrypt_msg(const struct inode *inode, const char *level, const char *fmt, ...);

#define fscrypt_warn(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_WARNING, fmt, ##__VA_ARGS__)
#define fscrypt_err(inode, fmt, ...)		\
	fscrypt_msg((inode), KERN_ERR, fmt, ##__VA_ARGS__)

#define FSCRYPT_MAX_IV_SIZE	32

union fscrypt_iv {
	struct {
		/* logical block number within the file */
		__le64 lblk_num;

		/* per-file nonce; only set in DIRECT_KEY mode */
		u8 nonce[FS_KEY_DERIVATION_NONCE_SIZE];
	};
	u8 raw[FSCRYPT_MAX_IV_SIZE];
};

void fscrypt_generate_iv(union fscrypt_iv *iv, u64 lblk_num,
			 const struct fscrypt_info *ci);

/* fname.c */
extern int fname_encrypt(struct inode *inode, const struct qstr *iname,
			 u8 *out, unsigned int olen);
extern bool fscrypt_fname_encrypted_size(const struct inode *inode,
					 u32 orig_len, u32 max_len,
					 u32 *encrypted_len_ret);

/* hkdf.c */

struct fscrypt_hkdf {
	struct crypto_shash *hmac_tfm;
};

extern int fscrypt_init_hkdf(struct fscrypt_hkdf *hkdf, const u8 *master_key,
			     unsigned int master_key_size);

extern int fscrypt_hkdf_expand(struct fscrypt_hkdf *hkdf, u8 context,
			       const u8 *info, unsigned int infolen,
			       u8 *okm, unsigned int okmlen);

extern void fscrypt_destroy_hkdf(struct fscrypt_hkdf *hkdf);

/* keyring.c */

/*
 * fscrypt_master_key_secret - secret key material of an in-use master key
 */
struct fscrypt_master_key_secret {

	/* Size of the raw key in bytes */
	u32			size;

	/* The raw key */
	u8			raw[FSCRYPT_MAX_KEY_SIZE];

} __randomize_layout;

/*
 * fscrypt_master_key - an in-use master key
 *
 * This represents a master encryption key which has been added to the
 * filesystem and can be used to "unlock" the encrypted files which were
 * encrypted with it.
 */
struct fscrypt_master_key {

	/*
	 * The secret key material.  After FS_IOC_REMOVE_ENCRYPTION_KEY is
	 * executed, this is wiped and no new inodes can be unlocked with this
	 * key; however, there may still be inodes in ->mk_decrypted_inodes
	 * which could not be evicted.  As long as some inodes still remain,
	 * FS_IOC_REMOVE_ENCRYPTION_KEY can be retried, or
	 * FS_IOC_ADD_ENCRYPTION_KEY can add the secret again.
	 *
	 * Locking: protected by key->sem.
	 */
	struct fscrypt_master_key_secret	mk_secret;

	/* Arbitrary key descriptor which was assigned by userspace */
	struct fscrypt_key_specifier		mk_spec;

	/*
	 * Length of ->mk_decrypted_inodes, plus one if mk_secret is present.
	 * Once this goes to 0, the master key is removed from ->s_master_keys.
	 * The 'struct fscrypt_master_key' will continue to live as long as the
	 * 'struct key' whose payload it is, but we won't let this reference
	 * count rise again.
	 */
	refcount_t		mk_refcount;

	/*
	 * List of inodes that were unlocked using this key.  This allows the
	 * inodes to be evicted efficiently if the key is removed.
	 */
	struct list_head	mk_decrypted_inodes;
	spinlock_t		mk_decrypted_inodes_lock;

} __randomize_layout;

static inline bool
is_master_key_secret_present(const struct fscrypt_master_key_secret *secret)
{
	/*
	 * The READ_ONCE() is only necessary for fscrypt_drop_inode() and
	 * fscrypt_key_describe().  These run in atomic context, so they can't
	 * take key->sem and thus 'secret' can change concurrently which would
	 * be a data race.  But they only need to know whether the secret *was*
	 * present at the time of check, so READ_ONCE() suffices.
	 */
	return READ_ONCE(secret->size) != 0;
}

static inline const char *master_key_spec_type(
				const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return "descriptor";
	}
	return "[unknown]";
}

static inline int master_key_spec_len(const struct fscrypt_key_specifier *spec)
{
	switch (spec->type) {
	case FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR:
		return FSCRYPT_KEY_DESCRIPTOR_SIZE;
	}
	return 0;
}

extern struct key *
fscrypt_find_master_key(struct super_block *sb,
			const struct fscrypt_key_specifier *mk_spec);

extern int __init fscrypt_init_keyring(void);

/* keysetup.c */

struct fscrypt_mode {
	const char *friendly_name;
	const char *cipher_str;
	int keysize;
	int ivsize;
	bool logged_impl_name;
	bool needs_essiv;
};

static inline bool
fscrypt_mode_supports_direct_key(const struct fscrypt_mode *mode)
{
	return mode->ivsize >= offsetofend(union fscrypt_iv, nonce);
}

extern struct crypto_skcipher *
fscrypt_allocate_skcipher(struct fscrypt_mode *mode, const u8 *raw_key,
			  const struct inode *inode);

extern int fscrypt_set_derived_key(struct fscrypt_info *ci,
				   const u8 *derived_key);

/* keysetup_v1.c */

extern void fscrypt_put_direct_key(struct fscrypt_direct_key *dk);

extern int fscrypt_setup_v1_file_key(struct fscrypt_info *ci,
				     const u8 *raw_master_key);

extern int fscrypt_setup_v1_file_key_via_subscribed_keyrings(
					struct fscrypt_info *ci);

#endif /* _FSCRYPT_PRIVATE_H */
