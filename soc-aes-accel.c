#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/interrupt.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/padlock.h>
#include <linux/scatterlist.h>

#include <linux/highmem.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>

#include <linux/delay.h>
#include <linux/jiffies.h>

#include <linux/kdev_t.h>
#include "netdma.h"

#define AES_BLOCK_SIZE 16
#define FPGA_AUXDATA    8
#define AES_KEY_SIZE   (32 * 4 / 8)

struct aes_regs {
	u32 main_ctrl;
	u32 key[4];
	u32 iv[4];
	u32 block_counter;
} __attribute__ ((__packed__));

#define NETDMA_CSR_SIZE 32

struct netdma_regs {
	u32 control;
	u32 status;
	u32 tx_status;
	u32 rx_report;

	u32 src_desc;
	u32 dst_desc;
} __attribute__ ((packed, aligned(NETDMA_CSR_SIZE)));

struct sg_meta_info {
	void *from;
	struct page *to_page;
	ssize_t to_offset;
	ssize_t len;
	bool last;
};

/* This structure holds everypthing that is necessary to access an instance of
 * hardware crypto accelerator.  It it instantiated twise for encryption and
 * decryption. */
struct aes_priv_hwinfo {
	struct aes_regs __iomem *aes_regs;
	struct netdma_regs __iomem *dma_regs;

	int irq;
};

struct aes_priv {
	uint32_t old_seq;
	struct device *dev;

	/* These fields are used by both encryption and decryption functions.
	 * Looks like kernel crypto subsystem doesn't call them simultaneously
	 * so sharing fields is ok. */
	wait_queue_head_t irq_queue;
	int irq_done;

	struct aes_priv_hwinfo enc, dec;

	struct sg_table dst_table;
	struct page *dst_page;
	dma_addr_t dst_dma;
	void *dst;

	struct sg_table dst_orig_table;

	struct sg_table src_table;
	struct page *src_page;
	dma_addr_t src_dma;
	void *src;

	struct sg_meta_info *meta;
};

struct aes_priv *priv;

static int write_fpga_desc(struct netdma_regs __iomem *regs,
		u32 dma_address, u16 length, u8 irq_is_en, u8 is_dst)
{
	u32 control_field;

	control_field = (length << DESC_BYTECOUNT_OFFSET) |
	    (!irq_is_en << DESC_DISABLE_IRQ_OFFSET);

	while (ioread32(&regs->status) & STAT_TX_DESC_BUFFER_FULL);

	if (is_dst) {
		iowrite32(dma_address, &regs->dst_desc);
		iowrite32(control_field, &regs->dst_desc);
	} else {
		iowrite32(dma_address, &regs->src_desc);
		iowrite32(control_field, &regs->src_desc);
	}

	wmb();
	return 0;
}

static int fpga_set_key(struct crypto_tfm *tfm, const u8 *in_key,
			unsigned int key_len)
{
	int i;
	const uint32_t *w_buf;

	if (key_len != AES_KEY_SIZE) {
		printk(KERN_ERR "Provided key of length %u when %u expected\n",
		       (unsigned int)key_len, (unsigned int)AES_KEY_SIZE);
		return -EINVAL;
	}

	w_buf = (const uint32_t *)in_key;

	for (i = 3; i >= 0; i--)
		iowrite32(w_buf[i], priv->dec.aes_regs->key + i);

	for (i = 3; i >= 0; i--)
		iowrite32(w_buf[i], priv->enc.aes_regs->key + i);

	return 0;
}

static int fpga_write_iv(const u8 *iv, struct aes_priv_hwinfo *hw)
{
	int i;
	const uint32_t *w_buf;

	w_buf = (const uint32_t *)iv;

	for (i = 3; i >= 0; i--)
		iowrite32(w_buf[i], hw->aes_regs->iv + i);

	return 0;
}

static int fpga_aes_init(struct crypto_tfm *tfm)
{
	return 0;
}

static void fpga_aes_exit(struct crypto_tfm *tfm)
{
}

static void sg_copy_back(struct sg_meta_info *meta)
{
	int i;

	for (i = 0; !meta[i].last; ++i) {
		void *to;

		to = kmap_atomic(meta[i].to_page);

		memcpy(to + meta[i].to_offset, meta[i].from, meta[i].len);

		kunmap_atomic(to);
	}
}

static void set_meta(struct sg_meta_info *meta, struct page *to_page,
		ssize_t to_offset, void *from, ssize_t len)
{
	meta->to_page = to_page;
	meta->to_offset = to_offset;
	meta->from = from;
	meta->len = len;
}

static void sg_split_to_aligned(void *buff, struct page *page,
				struct scatterlist *from, struct scatterlist *to,
				struct sg_meta_info *meta)
{
	struct scatterlist *sg;
	struct scatterlist *old_to;
	ssize_t buff_offset;
	int meta_idx;

	old_to = NULL;

	buff_offset = 0;
	meta_idx = 0;

	for (sg = from; sg; sg = sg_next(sg)) {

		if (!sg->length)
			continue;

		if (sg->length % AES_BLOCK_SIZE) {
			unsigned int first_len, second_len, third_len;
			struct scatterlist *sgn;
			void *sgn_page_ptr, *sg_page_ptr;

			sgn = sg_next(sg);
			sgn_page_ptr = kmap_atomic(sg_page(sgn));
			BUG_ON(!sgn_page_ptr);

			sg_page_ptr = kmap_atomic(sg_page(sg));
			BUG_ON(!sg_page_ptr);

			first_len = sg->length & ~0xf;
			second_len = sg->length & 0xf;
			third_len = AES_BLOCK_SIZE - second_len;

			if (first_len) {
				sg_set_page(to, sg_page(sg), first_len, sg->offset);
				old_to = to;
				to = sg_next(to);
			}

			if (meta) {
				set_meta(&meta[meta_idx++], sg_page(sg), sg->offset + first_len, buff + buff_offset, second_len);
				set_meta(&meta[meta_idx++], sg_page(sgn), sgn->offset, buff + buff_offset + second_len, third_len);
			} else {
				memcpy(buff + buff_offset, sg_page_ptr + sg->offset + first_len, second_len);
				memcpy(buff + buff_offset + second_len, sgn_page_ptr + sgn->offset, third_len);
			}

			sg_set_page(to, page, AES_BLOCK_SIZE, buff_offset);
			old_to = to;
			to = sg_next(to);

			buff_offset += AES_BLOCK_SIZE;

			sgn->offset += third_len;
			sgn->length -= third_len;

			kunmap_atomic(sg_page_ptr);
			kunmap_atomic(sgn_page_ptr);
		} else {
			sg_set_page(to, sg_page(sg), sg->length, sg->offset);
			old_to = to;
			to = sg_next(to);
		}
	}

	if (meta)
		meta[meta_idx].last = 1;
	sg_mark_end(old_to);
}

static void sg_map_all(struct device *dev, struct scatterlist *sg,
		       enum dma_data_direction dir)
{
	struct scatterlist *i;

	for (i = sg; i; i = sg_next(i)) {
		i->dma_address = dma_map_page(dev, sg_page(i), i->offset, i->length, dir);
		BUG_ON(dma_mapping_error(dev, i->dma_address));
	}
}

static void sg_unmap_all(struct device *dev, struct scatterlist *sg,
			 enum dma_data_direction dir)
{
	struct scatterlist *i;

	for (i = sg; i; i = sg_next(i))
		dma_unmap_page(dev, i->dma_address, i->length, dir);
}

static void sg_feed_all(struct scatterlist *src, struct scatterlist *dst,
		struct aes_priv_hwinfo *hw)
{
	struct scatterlist *i, *j;
	ssize_t src_fed, dst_fed;
	int err;

	src_fed = dst_fed = 0;

	i = src;
	j = dst;
	while (i || j) {
		bool irq_en;
		bool is_dst;
		struct scatterlist *sg;

		if (src_fed < dst_fed) {
			sg = i;
			i = sg_next(i);
			is_dst = false;
			src_fed += sg->length;
		} else {
			sg = j;
			j = sg_next(j);
			is_dst = true;
			dst_fed += sg->length;
		}

		irq_en = sg_is_last(sg) && is_dst;

		err = write_fpga_desc(hw->dma_regs, sg->dma_address, sg->length,
				irq_en, is_dst);
		if (err)
			pr_err("write_dst_desc failed: %d\n", err);
	}
}

#define SG_MAX_SIZE 200

static int fpga_crypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes,
			struct aes_priv_hwinfo *hw)
{
	int err;
	struct scatterlist *i;
	struct scatterlist *src_sg;
	struct scatterlist *dst_sg;
	struct scatterlist *dst_orig_sg;
	struct scatterlist *old_dst_orig_sg;

	BUG_ON(nbytes % AES_BLOCK_SIZE != 0);

	src_sg = priv->src_table.sgl;
	dst_sg = priv->dst_table.sgl;
	dst_orig_sg = priv->dst_orig_table.sgl;

	fpga_write_iv(desc->info, hw);

	priv->irq_done = 0;

	sg_init_table(src_sg, SG_MAX_SIZE);
	sg_init_table(dst_sg, SG_MAX_SIZE);
	sg_init_table(dst_orig_sg, SG_MAX_SIZE);

	old_dst_orig_sg = dst;

	for (i = dst; i; i = sg_next(i)) {
		sg_set_page(dst_orig_sg, sg_page(i), i->length, i->offset);
		old_dst_orig_sg = dst_orig_sg;
		dst_orig_sg = sg_next(dst_orig_sg);
	}

	sg_mark_end(old_dst_orig_sg);

	dst_orig_sg = priv->dst_orig_table.sgl;

	dma_sync_single_for_cpu(priv->dev, priv->src_dma, PAGE_SIZE, DMA_TO_DEVICE);

	/* Align scatterlists provided to us */
	sg_split_to_aligned(priv->src, priv->src_page, src, src_sg, NULL);
	sg_split_to_aligned(priv->dst, priv->dst_page, dst_orig_sg, dst_sg, priv->meta);

	dma_sync_single_for_device(priv->dev, priv->src_dma, PAGE_SIZE, DMA_TO_DEVICE);

	/* Map memory chunk for passing to DMA controller */
	sg_map_all(priv->dev, src_sg, DMA_TO_DEVICE);
	sg_map_all(priv->dev, dst_sg, DMA_FROM_DEVICE);

	/* Start decryption by writing descriptors */
	sg_feed_all(src_sg, dst_sg, hw);

	/* Wait for completion interrupt */
	err = wait_event_interruptible(priv->irq_queue, priv->irq_done == 1);
	if (err) {
		printk(KERN_ERR "wait_event_interruptible failed.\n");
		return err;
	}

	/* Unmap chunks back */
	sg_unmap_all(priv->dev, src_sg, DMA_TO_DEVICE);
	sg_unmap_all(priv->dev, dst_sg, DMA_FROM_DEVICE);

	dma_sync_single_for_cpu(priv->dev, priv->dst_dma, PAGE_SIZE, DMA_FROM_DEVICE);

	sg_copy_back(priv->meta);

	dma_sync_single_for_device(priv->dev, priv->dst_dma, PAGE_SIZE, DMA_FROM_DEVICE);

	return err;
}


static int fpga_encrypt(struct blkcipher_desc *desc,
			struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes)
{
	return fpga_crypt(desc, dst, src, nbytes, &priv->enc);
}


static int fpga_decrypt(struct blkcipher_desc *desc,
			struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes)
{
	return fpga_crypt(desc, dst, src, nbytes, &priv->dec);
}


struct crypto_alg fpga_alg = {
	.cra_name = "cbc(aes)",
	.cra_driver_name = "cbc(aes-fpga)",
	.cra_priority = 1000,
	.cra_flags = CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct aes_priv),
	.cra_type = &crypto_blkcipher_type,
	.cra_alignmask = 15,
	.cra_module = THIS_MODULE,
	.cra_init = fpga_aes_init,
	.cra_exit = fpga_aes_exit,
	.cra_blkcipher = {
		.min_keysize = AES_KEY_SIZE,
		.max_keysize = AES_KEY_SIZE,
		.ivsize = AES_BLOCK_SIZE,
		.setkey = fpga_set_key,
		.encrypt = fpga_encrypt,
		.decrypt = fpga_decrypt,
	}
};

static irqreturn_t fpga_isr(int irq, void *dev_id)
{
	struct aes_priv *priv = dev_id;

	priv->irq_done = 1;
	wake_up_interruptible(&priv->irq_queue);

	return IRQ_HANDLED;
}

static void aes_reset(struct aes_priv_hwinfo *hw)
{
	/* These three writes reset the aes hardware */
	iowrite32(0, &hw->aes_regs->main_ctrl);
	iowrite32(1, &hw->aes_regs->main_ctrl);
	iowrite32(0, &hw->aes_regs->main_ctrl);

	/* WTF? What does 6 mean? */
	iowrite32(6, &hw->dma_regs->control);
}

/* aes_parse_of_resources - Parse `reg` and `interrupts` DT properties and also
 * ioremap registers.
 *
 * Be aware that this function doesn't request_irq for you
 */
static void aes_parse_of_resources(struct device *dev, struct aes_priv_hwinfo *dec,
		struct aes_priv_hwinfo *enc, struct device_node *of_node)
{
	struct resource res;

	dec->irq = irq_of_parse_and_map(of_node, 0);
	BUG_ON(!dec->irq);

	enc->irq = irq_of_parse_and_map(of_node, 1);
	BUG_ON(!enc->irq);

	BUG_ON(of_address_to_resource(of_node, 0, &res));
	dec->aes_regs = devm_ioremap_resource(dev, &res);
	BUG_ON(IS_ERR(dec->aes_regs));

	BUG_ON(of_address_to_resource(of_node, 1, &res));
	dec->dma_regs = devm_ioremap_resource(dev, &res);
	BUG_ON(IS_ERR(dec->dma_regs));

	BUG_ON(of_address_to_resource(of_node, 2, &res));
	enc->aes_regs = devm_ioremap_resource(dev, &res);
	BUG_ON(IS_ERR(enc->aes_regs));

	BUG_ON(of_address_to_resource(of_node, 3, &res));
	enc->dma_regs = devm_ioremap_resource(dev, &res);
	BUG_ON(IS_ERR(enc->dma_regs));
}

static int aes_probe(struct platform_device *pdev)
{
	int err;

	dev_info(&pdev->dev, "probing");

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	BUG_ON(!priv);

	priv->meta = devm_kzalloc(&pdev->dev, sizeof(struct sg_meta_info) * SG_MAX_SIZE * 2, GFP_KERNEL);
	BUG_ON(!priv->meta);

	priv->dev = &pdev->dev;

	aes_parse_of_resources(priv->dev, &priv->dec, &priv->enc, pdev->dev.of_node);
	dev_info(&pdev->dev, "decrypt irq = %d", priv->dec.irq);
	dev_info(&pdev->dev, "encrypt irq = %d", priv->enc.irq);

	priv->src = (void *)devm_get_free_pages(priv->dev, GFP_KERNEL, 0);
	priv->dst = (void *)devm_get_free_pages(priv->dev, GFP_KERNEL, 0);

	priv->src_page = virt_to_page(priv->src);
	priv->dst_page = virt_to_page(priv->dst);

	priv->src_dma = dma_map_page(priv->dev, priv->src_page, 0, PAGE_SIZE,
			DMA_TO_DEVICE);
	priv->dst_dma = dma_map_page(priv->dev, priv->dst_page, 0, PAGE_SIZE,
			DMA_FROM_DEVICE);

	err = sg_alloc_table(&priv->src_table, SG_MAX_SIZE, GFP_KERNEL);
	BUG_ON(err);
	err = sg_alloc_table(&priv->dst_table, SG_MAX_SIZE, GFP_KERNEL);
	BUG_ON(err);
	err = sg_alloc_table(&priv->dst_orig_table, SG_MAX_SIZE, GFP_KERNEL);
	BUG_ON(err);

	aes_reset(&priv->dec);
	aes_reset(&priv->enc);

	init_waitqueue_head(&priv->irq_queue);

	err = devm_request_irq(priv->dev, priv->dec.irq, fpga_isr, IRQF_SHARED,
			"fpga-aes-decrypt", priv);
	BUG_ON(err);

	err = devm_request_irq(priv->dev, priv->enc.irq, fpga_isr, IRQF_SHARED,
			"fpga-aes-encrypt", priv);
	BUG_ON(err);

	err = crypto_register_alg(&fpga_alg);
	BUG_ON(err);

	return 0;
}

static int aes_remove(struct platform_device *pdev)
{
	/* This must be done before anything else to be sure that no users call
	 * us when some resuorces are not initialized
	 */
	crypto_unregister_alg(&fpga_alg);

	/* Although devres may free IRQs for us, we free them implicitly before
	 * any other resources to make sure that interrupt handler won't access
	 * any of them.
	 */
	devm_free_irq(priv->dev, priv->dec.irq, priv);
	devm_free_irq(priv->dev, priv->enc.irq, priv);

	sg_free_table(&priv->src_table);
	sg_free_table(&priv->dst_table);
	sg_free_table(&priv->dst_orig_table);

	dma_unmap_page(priv->dev, priv->src_dma, PAGE_SIZE, DMA_TO_DEVICE);
	dma_unmap_page(priv->dev, priv->dst_dma, PAGE_SIZE, DMA_FROM_DEVICE);

	dev_info(&pdev->dev, "device removed");

	return 0;
}

static const struct of_device_id aes_id_table[] = {
	{.compatible = "stcmtk,aes"},
	{}
};

MODULE_DEVICE_TABLE(of, aes_id_table);

static struct platform_driver aes_drv = {
	.probe = aes_probe,
	.remove = aes_remove,
	.driver = {
		.name = "aes",
		.of_match_table = aes_id_table,
	}
};

module_platform_driver(aes_drv);

MODULE_AUTHOR("Denis Gabidullin");
MODULE_AUTHOR("Ivan Oleynikov");
MODULE_LICENSE("GPL");
