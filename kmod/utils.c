#include "utils.h"

struct node_config *get_node_by_id(int id, struct config *cfg)
{
        int idx;

        for (idx = 0; idx < cfg->node_num; idx++) {
                if (cfg->nodes[idx].id == id)
                        return &cfg->nodes[idx];
        }

        return NULL;
}

uint64_t get_disk_size(struct dbm *dbm)
{
	return (uint64_t)(dbm->disk_size);
}

uint64_t n_bits(char *data, uint64_t beg, uint64_t end)
{
	uint64_t i, j, n;
	int byte_per_bit;

	n = 0;
	byte_per_bit = 1 << BYTE_SHIFT;
	for (i = beg; i < end; i++) {
		for (j = 0; j < byte_per_bit; j++) {
			n += !!(data[i] & (1<<j));
		}
	}

	return n;
}

void pr_content(void *addr, unsigned int size)
{
	int i;
	if (!addr) {
		return;
	}

	for (i=0; i< size/sizeof(char); i++) {
		printk("%02X ", ((char *)addr)[i]);
	}
	printk("\n");
}

void pr_c_content(void *addr, unsigned int size)
{
	int i;
	if (!addr) {
		return;
	}

	printk("pr_c_conte:\n");
	for (i=0; i< size/sizeof(char); i++) {
		printk("%c", ((char *)addr)[i]);
	}
	printk("\n");
}

#define GET_SIGN(a) (((a) < 0) ? (-1) : ((a) > 0))
int sector_in_area(sector_t target, sector_t start, sector_t end)
{
	int result;

	if (start == end)
		result = start == target ? 1 : -1;
	else
		result = GET_SIGN((int64_t)(end - target))
			* GET_SIGN((int64_t)(end - start))
			* GET_SIGN((int64_t)(target - start));
	return result >= 0;
}

static int bits_char(unsigned char n)
{
	int nr_bit = 0;

	while (n) {
		n &= n - 1;
		nr_bit++;
	}

	return nr_bit;
}

uint64_t nr_bits(char *data, uint64_t begin, uint64_t len)
{
#define UCHAR_MAX ((unsigned char)~0)
	int i;
	uint64_t nr = 0;
	unsigned char data_iter;
	static int char_bit[UCHAR_MAX];

	for (i = begin; i < len; i++) {
		data_iter = (unsigned char)data[i];
		if (!char_bit[data_iter])
			char_bit[data_iter] = bits_char(data_iter);
		nr += char_bit[data_iter];
	}

	return nr;
}

char *md5_print(char *out, u8 *in)
{
	snprintf(out, 33, MD5_FORMAT, MD5_ARGS(in));
	return out;
}
