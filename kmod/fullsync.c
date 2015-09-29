#include <linux/module.h>
#include <linux/blkdev.h>
#include <crypto/hash.h>

#include "hadm_def.h"
#include "hadm_config.h"
#include "bio_handler.h"
#include "hadm_device.h"
#include "bwr.h"
#include "hadm_node.h"
#include "fullsync.h"
#include "dbm.h"

/*
 * taken from http://www.youback.net/kernel/linux%E5%86%85%E6%A0%B8%E5%86%85%E4%BD%BF%E7%94%A8md5%E5%8A%A0%E5%AF%86%E5%87%BD%E6%95%B0.html
 *
 * str 要加密的字符串
 * len 字符串的长度
 * hash 保存md5的内存大于等于16
 *
 * 成功返回0 否则返回-1
 */
int fullsync_md5_hash(const char *str, u32 len, u8 *hash)
{
	u32 size=0;
	struct shash_desc *sdescmd5;
	int err = 0;
	struct crypto_shash *md5 = crypto_alloc_shash("md5", 0, 0);
	if (IS_ERR(md5))
		return -1;
	size = sizeof(struct shash_desc) + crypto_shash_descsize(md5);
	sdescmd5 = kmalloc(size, GFP_KERNEL);
	if (!sdescmd5) {
		err = -1;
		goto malloc_err;
	}
	sdescmd5->tfm = md5;
	sdescmd5->flags = 0x0;

	err = crypto_shash_init(sdescmd5);
	if (err) {
		err = -1;
		goto hash_err;
	}
	crypto_shash_update(sdescmd5, str, len);
	err = crypto_shash_final(sdescmd5, hash);

hash_err:
	kfree(sdescmd5);
malloc_err:
	crypto_free_shash(md5);

	return err;
}
