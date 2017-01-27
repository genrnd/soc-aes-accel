#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <linux/of_irq.h>
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

#define FPGASLAVES (0xC0000000)

#define DMA_BASE (FPGASLAVES)
#define DMA_SIZE (0x18)

#define AES_BASE  (FPGASLAVES + 0x2000)
#define AES_SIZE  (10 * 4)

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
	int           sg_idx;
	ssize_t       size;
	ssize_t       sg_offset;
	ssize_t       buff_offset;
	bool          last;
};

struct aes_priv {
	uint32_t old_seq;
	struct device *dev;
	struct aes_regs __iomem *aes_regs;
	struct netdma_regs __iomem *dma_regs;
	wait_queue_head_t irq_queue;
	int irq_done;

	int irq_decrypt;
	int irq_encrypt;

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

static int write_fpga_desc(struct aes_priv *priv, u32 dma_address, u16 length,
			   u8 irq_is_en, u8 is_dst)
{
	struct netdma_regs __iomem *regs = priv->dma_regs;

	u32 control_field;

	control_field = (length << DESC_BYTECOUNT_OFFSET) |
	    (!irq_is_en << DESC_DISABLE_IRQ_OFFSET);

	if (ioread32(&regs->status) & STAT_TX_DESC_BUFFER_FULL) {
		pr_err("%s descriptor buffer full bit is set. Address = 0x%x\n",
		       is_dst ? "rx" : "tx", dma_address);
		return -ENOMEM;
	}

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
		iowrite32(w_buf[i], priv->aes_regs->key + i);

	return 0;
}

static int fpga_write_iv(const u8 *iv)
{
	int i;
	const uint32_t *w_buf;

	w_buf = (const uint32_t *)iv;

	for (i = 3; i >= 0; i--)
		iowrite32(w_buf[i], priv->aes_regs->iv + i);

	return 0;
}

static int fpga_aes_init(struct crypto_tfm *tfm)
{
	return 0;
}

static void fpga_aes_exit(struct crypto_tfm *tfm)
{
}

static int fpga_encrypt(struct blkcipher_desc *desc,
			struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes)
{
	printk(KERN_INFO "fpga_aes_enc\n");
	return 0;
}

static void sg_copy_back(struct sg_meta_info *meta, struct scatterlist *sg, void *buff)
{
	struct scatterlist *i;
	int idx;
	int sg_idx;
	void *sg_page_ptr;

	idx = 0;
	sg_idx = 0;

	for (i = sg; i; i = sg_next(i)) {
		sg_page_ptr = kmap_atomic(sg_page(i));
		BUG_ON(!sg_page_ptr);

		while (meta[idx].sg_idx == sg_idx) {
			memcpy(sg_page_ptr + i->offset + meta[idx].sg_offset, buff + meta[idx].buff_offset, meta[idx].size);

			if (meta[idx].last)
				break;

			idx++;
		}

		sg_idx++;
		kunmap_atomic(sg_page_ptr);
	}
}

static void set_meta(struct sg_meta_info *meta, int idx, ssize_t size, ssize_t sg_offset, ssize_t buff_offset)
{
	meta->sg_idx      = idx;
	meta->size        = size;
	meta->sg_offset   = sg_offset;
	meta->buff_offset = buff_offset;
	meta->last        = 0;
}

static void sg_split_to_aligned(void *buff, struct page *page,
				struct scatterlist *from, struct scatterlist *to, bool is_dst, struct sg_meta_info *meta)
{
	struct scatterlist *sg;
	struct scatterlist *old_to;
	ssize_t buff_offset;
	int sg_idx;
	int meta_idx;

	old_to = NULL;

	buff_offset = 0;
	meta_idx = 0;
	sg_idx = 0;

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

			if (is_dst) {
				set_meta(&meta[meta_idx++], sg_idx++, second_len, first_len, buff_offset);
				set_meta(&meta[meta_idx++], sg_idx, third_len, 0, buff_offset + second_len);
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

	meta[meta_idx - 1].last = 1;
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

static void sg_feed_all(struct aes_priv *priv, struct scatterlist *sg, bool is_dst)
{
	struct scatterlist *i;
	int err;

	for (i = sg; i; i = sg_next(i)) {
		bool irq_en;

		irq_en = sg_is_last(i) && is_dst;

		err = write_fpga_desc(priv, i->dma_address, i->length, irq_en, is_dst);
		if (err)
			pr_err("write_dst_desc failed: %d\n", err);
	}
}

#define SG_MAX_SIZE 20

static int fpga_decrypt(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes)
{
	int err;
	struct scatterlist *i;
	struct scatterlist *src_sg;
	struct scatterlist *dst_sg;
	struct scatterlist *dst_orig_sg;
	struct scatterlist *old_dst_orig_sg;

	BUG_ON(nbytes > PAGE_SIZE);

	src_sg = priv->src_table.sgl;
	dst_sg = priv->dst_table.sgl;
	dst_orig_sg = priv->dst_orig_table.sgl;

	fpga_write_iv(desc->info);

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

	/* Align scatterlists provided to us */
	sg_split_to_aligned(priv->src, priv->src_page, src, src_sg, 0, priv->meta);
	sg_split_to_aligned(priv->dst, priv->dst_page, dst_orig_sg, dst_sg, 1, priv->meta);

	/* Map memory chunk for passing to DMA controller */
	sg_map_all(priv->dev, src_sg, DMA_TO_DEVICE);
	sg_map_all(priv->dev, dst_sg, DMA_FROM_DEVICE);

	/* Start decryption by writing descriptors */
	sg_feed_all(priv, dst_sg, 1);
	sg_feed_all(priv, src_sg, 0);

	/* Wait for completion interrupt */
	err = wait_event_interruptible(priv->irq_queue, priv->irq_done == 1);
	if (err) {
		printk(KERN_ERR "wait_event_interruptible failed.\n");
		return err;
	}

	sg_copy_back(priv->meta, dst, priv->dst);

	/* Unmap chunks back */
	sg_unmap_all(priv->dev, src_sg, DMA_TO_DEVICE);
	sg_unmap_all(priv->dev, dst_sg, DMA_FROM_DEVICE);

	return err;
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

static void fpga_read_rx_report(struct netdma_rx_report *report)
{
	unsigned int rx_report;

	rx_report = ioread32(&priv->dma_regs->rx_report);
	report->actual_bytes_transferred =
		(rx_report >> RX_REPORT_ACTUAL_BYTES_OFFSET) &
		RX_REPORT_ACTUAL_BYTES_MASK;
}

static irqreturn_t fpga_isr(int irq, void *dev_id)
{
	struct netdma_rx_report report;

	while (!
	       (ioread32(&priv->dma_regs->status) &
		STAT_RX_REPORT_BUFFER_EMPTY))
		fpga_read_rx_report(&report);

	iowrite32(0, &priv->dma_regs->control);
	iowrite32(6, &priv->dma_regs->control);

	priv->irq_done = 1;
	wake_up_interruptible(&priv->irq_queue);

	return IRQ_HANDLED;
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

	priv->irq_decrypt = irq_of_parse_and_map(pdev->dev.of_node, 0);
	BUG_ON(!priv->irq_decrypt);

	priv->irq_encrypt = irq_of_parse_and_map(pdev->dev.of_node, 1);
	BUG_ON(!priv->irq_encrypt);

	dev_info(&pdev->dev, "decrypt irq = %d", priv->irq_decrypt);
	dev_info(&pdev->dev, "encrypt irq = %d", priv->irq_encrypt);

	priv->aes_regs = ioremap(AES_BASE, AES_SIZE);
	priv->dma_regs = ioremap(DMA_BASE, DMA_SIZE);

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

	iowrite32(0, &priv->aes_regs->main_ctrl);
	iowrite32(1, &priv->aes_regs->main_ctrl);
	iowrite32(0, &priv->aes_regs->main_ctrl);

	iowrite32(6, &priv->dma_regs->control);

	init_waitqueue_head(&priv->irq_queue);

	err = request_irq(priv->irq_decrypt, fpga_isr, IRQF_SHARED, "fpga-aes-decrypt", priv);
	if (err) {
		dev_err(&pdev->dev, "request_irq for encrypt failed!");
		return -ENOMEM;
	}

	err = request_irq(priv->irq_encrypt, fpga_isr, IRQF_SHARED, "fpga-aes-encrypt", priv);
	if (err) {
		dev_err(&pdev->dev, "request_irq for encrypt failed!");
		return -ENOMEM;
	}

	err = crypto_register_alg(&fpga_alg);
	BUG_ON(err);

	return 0;
}

static int aes_remove(struct platform_device *pdev)
{
	crypto_unregister_alg(&fpga_alg);

	free_irq(priv->irq_decrypt, priv);
	free_irq(priv->irq_encrypt, priv);

	sg_free_table(&priv->src_table);
	sg_free_table(&priv->dst_table);
	sg_free_table(&priv->dst_orig_table);

	dma_unmap_page(priv->dev, priv->src_dma, PAGE_SIZE, DMA_TO_DEVICE);
	dma_unmap_page(priv->dev, priv->dst_dma, PAGE_SIZE, DMA_FROM_DEVICE);

	iounmap(priv->aes_regs);
	iounmap(priv->dma_regs);

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
