#

参考
http://www.ibm.com/developerworks/cn/linux/l-devmapper/index.html

代码位置 linux/drivers/md

Kconfig 
```
--snip--
config BLK_DEV_DM_BUILTIN
	bool

config BLK_DEV_DM
	tristate "Device mapper support"
	select BLK_DEV_DM_BUILTIN
--snip--
config DM_VERITY
	tristate "Verity target support"
	depends on BLK_DEV_DM
	select CRYPTO
	select CRYPTO_HASH
	select DM_BUFIO
--snip--
```

Makefile
```
--snip--
dm-mod-y	+= dm.o dm-table.o dm-target.o dm-linear.o dm-stripe.o \
		   dm-ioctl.o dm-io.o dm-kcopyd.o dm-sysfs.o dm-stats.o
--snip--
obj-$(CONFIG_BLK_DEV_DM)	+= dm-mod.o
obj-$(CONFIG_BLK_DEV_DM_BUILTIN) += dm-builtin.o
--snip--
obj-$(CONFIG_DM_VERITY)		+= dm-verity.o
--snip--
```

dm.c
将自己注册成块设备

dm-verity.c 
将自己注册成DM的一个目标设备，注册相应的函数
供DM使用

```c
module_init(dm_verity_init);
module_exit(dm_verity_exit);
```
dm_verity_init 将自己注册成为一个DM目标设备
提供指针
+ verity_ctr 构造函数，指明算法
+ verity_map 将验证函数挂在bio上


Linux默认好像是不启用DM-Verity的

MD 中几个关键的数据结构
```c
// linux/drivers/md/dm.c

/*
 * For bio-based dm.
 * One of these is allocated per bio.
 */
struct dm_io {
	struct mapped_device *md;
	int error;
	atomic_t io_count;
	struct bio *bio;
	unsigned long start_time;
	spinlock_t endio_lock;
	struct dm_stats_aux stats_aux;
};

/*
 * For request-based dm.
 * One of these is allocated per request.
 */
struct dm_rq_target_io {
	struct mapped_device *md;
	struct dm_target *ti;
	struct request *orig, *clone;
	struct kthread_work work;
	int error;
	union map_info info;
	struct dm_stats_aux stats_aux;
	unsigned long duration_jiffies;
	unsigned n_sectors;
};

/*
 * For request-based dm - the bio clones we allocate are embedded in these
 * structs.
 *
 * We allocate these with bio_alloc_bioset, using the front_pad parameter when
 * the bioset is created - this means the bio has to come at the end of the
 * struct.
 */
struct dm_rq_clone_bio_info {
	struct bio *orig;
	struct dm_rq_target_io *tio;
	struct bio clone;
};
 


/*
 * Work processed by per-device workqueue.
 */
struct mapped_device {
	struct srcu_struct io_barrier;
	struct mutex suspend_lock;
	atomic_t holders;
	atomic_t open_count;

	/*
	 * The current mapping.
	 * Use dm_get_live_table{_fast} or take suspend_lock for
	 * dereference.
	 */
	struct dm_table __rcu *map;

	struct list_head table_devices;
	struct mutex table_devices_lock;

	unsigned long flags;

	struct request_queue *queue;
	unsigned type;
	/* Protect queue and type against concurrent access. */
	struct mutex type_lock;

	struct target_type *immutable_target_type;

	struct gendisk *disk;
	char name[16];

	void *interface_ptr;

	/*
	 * A list of ios that arrived while we were suspended.
	 */
	atomic_t pending[2];
	wait_queue_head_t wait;
	struct work_struct work;
	struct bio_list deferred;
	spinlock_t deferred_lock;

	/*
	 * Processing queue (flush)
	 */
	struct workqueue_struct *wq;

	/*
	 * io objects are allocated from here.
	 */
	mempool_t *io_pool;
	mempool_t *rq_pool;

	struct bio_set *bs;

	/*
	 * Event handling.
	 */
	atomic_t event_nr;
	wait_queue_head_t eventq;
	atomic_t uevent_seq;
	struct list_head uevent_list;
	spinlock_t uevent_lock; /* Protect access to uevent_list */

	/*
	 * freeze/thaw support require holding onto a super block
	 */
	struct super_block *frozen_sb;
	struct block_device *bdev;

	/* forced geometry settings */
	struct hd_geometry geometry;

	/* kobject and completion */
	struct dm_kobject_holder kobj_holder;

	/* zero-length flush that will be cloned and submitted to targets */
	struct bio flush_bio;

	/* the number of internal suspends */
	unsigned internal_suspend_count;

	struct dm_stats stats;

	struct kthread_worker kworker;
	struct task_struct *kworker_task;

	/* for request-based merge heuristic in dm_request_fn() */
	unsigned seq_rq_merge_deadline_usecs;
	int last_rq_rw;
	sector_t last_rq_pos;
	ktime_t last_rq_start_time;

	/* for blk-mq request-based DM support */
	struct blk_mq_tag_set tag_set;
	bool use_blk_mq;
};

/*
 * For mempools pre-allocation at the table loading time.
 */
struct dm_md_mempools {
	mempool_t *io_pool;
	mempool_t *rq_pool;
	struct bio_set *bs;
};

struct table_device {
	struct list_head list;
	atomic_t count;
	struct dm_dev dm_dev;
};

```

```c
// linux/include/linux/device-mapper.h

// 定义目标设备类型，及操作接口指针
struct target_type {
	uint64_t features;
	const char *name;
	struct module *module;
	unsigned version[3];
	dm_ctr_fn ctr; // 构造函数
	dm_dtr_fn dtr; // 析构函数
	dm_map_fn map; // 
	dm_map_request_fn map_rq;
	dm_clone_and_map_request_fn clone_and_map_rq;
	dm_release_clone_request_fn release_clone_rq;
	dm_endio_fn end_io;
	dm_request_endio_fn rq_end_io;
	dm_presuspend_fn presuspend;
	dm_presuspend_undo_fn presuspend_undo;
	dm_postsuspend_fn postsuspend;
	dm_preresume_fn preresume;
	dm_resume_fn resume;
	dm_status_fn status; //
	dm_message_fn message;
	dm_prepare_ioctl_fn prepare_ioctl; //
	dm_busy_fn busy;
	dm_iterate_devices_fn iterate_devices; //
	dm_io_hints_fn io_hints; // 

	/* 供内部使用 */
	/* For internal device-mapper use. */
	struct list_head list;
}
// 定义目标设备特性
struct dm_target {
	struct dm_table *table;
	struct target_type *type;

	/* target limits */
	sector_t begin;
	sector_t len;

	/* If non-zero, maximum size of I/O submitted to a target. */
	uint32_t max_io_len;

	/*
	 * A number of zero-length barrier bios that will be submitted
	 * to the target for the purpose of flushing cache.
	 *
	 * The bio number can be accessed with dm_bio_get_target_bio_nr.
	 * It is a responsibility of the target driver to remap these bios
	 * to the real underlying devices.
	 */
	unsigned num_flush_bios;

	/*
	 * The number of discard bios that will be submitted to the target.
	 * The bio number can be accessed with dm_bio_get_target_bio_nr.
	 */
	unsigned num_discard_bios;

	/*
	 * The number of WRITE SAME bios that will be submitted to the target.
	 * The bio number can be accessed with dm_bio_get_target_bio_nr.
	 */
	unsigned num_write_same_bios;

	/*
	 * The minimum number of extra bytes allocated in each bio for the
	 * target to use.  dm_per_bio_data returns the data location.
	 */
	unsigned per_bio_data_size;

	/*
	 * If defined, this function is called to find out how many
	 * duplicate bios should be sent to the target when writing
	 * data.
	 */
	dm_num_write_bios_fn num_write_bios;

	/* target specific data */
	void *private;

	/* Used to provide an error string from the ctr */
	char *error;

	/*
	 * Set if this target needs to receive flushes regardless of
	 * whether or not its underlying devices have support.
	 */
	bool flush_supported:1;

	/*
	 * Set if this target needs to receive discards regardless of
	 * whether or not its underlying devices have support.
	 */
	bool discards_supported:1;

	/*
	 * Set if the target required discard bios to be split
	 * on max_io_len boundary.
	 */
	bool split_discard_bios:1;

	/*
	 * Set if this target does not return zeroes on discarded blocks.
	 */
	bool discard_zeroes_data_unsupported:1;
};

/*
 * For bio-based dm.
 * One of these is allocated for each bio.
 * This structure shouldn't be touched directly by target drivers.
 * It is here so that we can inline dm_per_bio_data and
 * dm_bio_from_per_bio_data
 */
struct dm_target_io {
	struct dm_io *io;
	struct dm_target *ti;
	unsigned target_bio_nr;
	unsigned *len_ptr;
	struct bio clone;
};
```

```c
struct dm_verity {
	struct dm_dev *data_dev;
	struct dm_dev *hash_dev;
	struct dm_target *ti;
	struct dm_bufio_client *bufio;
	char *alg_name;
	struct crypto_shash *tfm;
	u8 *root_digest;	/* digest of the root block */
	u8 *salt;		/* salt: its size is salt_size */
	unsigned salt_size;
	sector_t data_start;	/* data offset in 512-byte sectors */
	sector_t hash_start;	/* hash start in blocks */
	sector_t data_blocks;	/* the number of data blocks */
	sector_t hash_blocks;	/* the number of hash blocks */
	unsigned char data_dev_block_bits;	/* log2(data blocksize) */
	unsigned char hash_dev_block_bits;	/* log2(hash blocksize) */
	unsigned char hash_per_block_bits;	/* log2(hashes in hash block) */
	unsigned char levels;	/* the number of tree levels */
	unsigned char version;
	unsigned digest_size;	/* digest size for the current hash algorithm */
	unsigned shash_descsize;/* the size of temporary space for crypto */
	int hash_failed;	/* set to 1 if hash of any block failed */
	enum verity_mode mode;	/* mode for handling verification errors */
	unsigned corrupted_errs;/* Number of errors for corrupted blocks */

	struct workqueue_struct *verify_wq;

	/* starting blocks for each tree level. 0 is the lowest level. */
	sector_t hash_level_block[DM_VERITY_MAX_LEVELS];
};
//
struct dm_verity_io {
	struct dm_verity *v;

	/* original values of bio->bi_end_io and bio->bi_private */
	bio_end_io_t *orig_bi_end_io;
	void *orig_bi_private;

	sector_t block;
	unsigned n_blocks;

	struct bvec_iter iter;

	struct work_struct work;

	/*
	 * Three variably-size fields follow this struct:
	 *
	 * u8 hash_desc[v->shash_descsize];
	 * u8 real_digest[v->digest_size];
	 * u8 want_digest[v->digest_size];
	 *
	 * To access them use: io_hash_desc(), io_real_digest() and io_want_digest().
	 */
};

struct dm_verity_prefetch_work {
	struct work_struct work;
	struct dm_verity *v;
	sector_t block;
	unsigned n_blocks;
};

static struct target_type verity_target = {
	.name		= "verity",
	.version	= {1, 2, 0},
	.module		= THIS_MODULE,
	.ctr		= verity_ctr,
	.dtr		= verity_dtr,
	.map		= verity_map,
	.status		= verity_status,
	.prepare_ioctl	= verity_prepare_ioctl,
	.iterate_devices = verity_iterate_devices,
	.io_hints	= verity_io_hints,
};

```


初步印象应该是修改其它地方

