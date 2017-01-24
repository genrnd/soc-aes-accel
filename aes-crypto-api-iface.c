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
#include <crypto/scatterwalk.h>

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

struct aes_priv {
	uint32_t old_seq;
	struct device *dev;
	struct aes_regs __iomem *aes_regs;
	struct netdma_regs __iomem *dma_regs;
	wait_queue_head_t irq_queue;
	int irq_done;
	int irq;

	struct page *dst_page;
	dma_addr_t dst_dma;
	void *dst;

	struct page *src_page;
	dma_addr_t src_dma;
	void *src;

	struct scatterlist *sg;
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

static int write_dst_desc(struct aes_priv *priv, u32 dma_address, u16 length,
			  u8 irq_is_en)
{
	return write_fpga_desc(priv, dma_address, length, irq_is_en, 1);
}

static int write_src_desc(struct aes_priv *priv, u32 dma_address, u16 length,
			  u8 irq_is_en)
{
	return write_fpga_desc(priv, dma_address, length, irq_is_en, 0);
}

static int fpga_set_key(struct crypto_tfm *tfm, const u8 *in_key,
			unsigned int key_len)
{
	int i;
	const uint32_t *w_buf;

	if (key_len != AES_KEY_SIZE) {
		printk("Provided key of length %u when %u expected\n",
		       (unsigned int)key_len, (unsigned int)AES_KEY_SIZE);
		return -EINVAL;
	}

	w_buf = (const uint32_t *)in_key;

	for (i = 3; i >= 0; i--) {
		//printk("key[ %d ] = 0x%x\n", i, w_buf[i] );
		iowrite32(w_buf[i], priv->aes_regs->key + i);
	}

	//printk("key written successfully\n");
	return 0;
}

static int fpga_write_iv(const u8 *iv)
{
	int i;
	const uint32_t *w_buf;

	w_buf = (const uint32_t *)iv;

	for (i = 3; i >= 0; i--) {
		//printk("iv[ %d ] = 0x%x\n", i, w_buf[i]);
		iowrite32(w_buf[i], priv->aes_regs->iv + i);
	}

	//printk("iv written successfully\n");
	return 0;
}

static int fpga_aes_init(struct crypto_tfm *tfm)
{
	//printk("fpga_aes_init\n");
	return 0;
}

static void fpga_aes_exit(struct crypto_tfm *tfm)
{
	//printk("fpga_aes_exit\n");
}

static int fpga_encrypt(struct blkcipher_desc *desc,
			struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes)
{
	printk("fpga_aes_enc\n");
	return 0;
}

static void sg_split_to_aligned(void *buff, struct page *page,
		struct scatterlist *from, struct scatterlist *to)
{
	struct scatterlist *sg;
	struct scatterlist *old_to;
	ssize_t buff_offset;

	buff_offset = 0;

	for (sg = from; sg; sg = sg_next(sg)) {
		if (!sg->length)
			continue;

		if (sg->length % 16) {
			unsigned int first_len, second_len, third_len;
			struct scatterlist *sgn;
			void *sgn_page, *sg_page;

			sgn = sg_next(sg);
			sgn_page = kmap_atomic(sg_page(sgn));
			BUG_ON(!sgn_page);

			sg_page = kmap_atomic(sg_page(sg));
			BUG_ON(!sg_page);

			first_len = sg->length & ~0xf;
			second_len = sg->length & 0xf;
			third_len = 0x10 - second_len;

			if (first_len) {
				sg_set_page(to, sg_page(sg), first_len, sg->offset);
				old_to = to;
				to = sg_next(to);
			}

			memcpy(buff + buff_offset, sg_page + sg->offset + first_len, second_len);
			memcpy(buff + buff_offset + first_len, sgn_page + sgn_offset, third_len);

			sg_set_page(to, page, 0x10, buff_offset);
			old_to = to;
			to = sg_next(to);

			sgn->offset += third_len;
			sgn->length -= third_len;

			kunmap(sg_page);
			kunmap(sgn_page);
		} else {
			sg_set_page(to, sg_page(sg), sg->length, sg->offset);
			old_to = to;
			to = sg_next(to);
		}
	}

	sg_mark_end(old_to);
}

#define MAX_DESC_CNT 16

static int fpga_decrypt(struct blkcipher_desc *desc,
			struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes)
{
	int err;
	struct scatterlist *i;
	void *curr_ptr;

	BUG_ON(nbytes > PAGE_SIZE);

	fpga_write_iv(desc->info);

	priv->irq_done = 0;

	/* Write ciphertext to be fetched by the hardware */
	dma_sync_single_for_cpu(priv->dev, priv->src_dma, PAGE_SIZE,
				DMA_TO_DEVICE);
	curr_ptr = priv->src;
	for (i = src; i; i = scatterwalk_sg_next(i)) {
		void *ptr = kmap_atomic(sg_page(i)) + i->offset;

		memcpy(curr_ptr, ptr, i->length);
		curr_ptr += i->length;

		kunmap_atomic(ptr - i->offset);
	}
	dma_sync_single_for_device(priv->dev, priv->src_dma, PAGE_SIZE,
				   DMA_TO_DEVICE);

	/* Start decryption by writing descriptors */
	err = write_dst_desc(priv, priv->dst_dma, nbytes, 1);
	if (err)
		return pr_err("write_dst_desc failed: %d\n", err), err;
	err = write_src_desc(priv, priv->src_dma, nbytes, 0);
	if (err)
		return pr_err("write_sr_desc failed: %d\n", err), err;

	/* Wait for completion interrupt */
	err = wait_event_interruptible(priv->irq_queue, priv->irq_done == 1);
	if (err) {
		printk("wait_event_interruptible failed.\n");
		return err;
	}

	/* Get the result returned from hardware */
	dma_sync_single_for_cpu(priv->dev, priv->dst_dma, PAGE_SIZE,
				DMA_FROM_DEVICE);
	curr_ptr = priv->dst;
	for (i = dst; i; i = scatterwalk_sg_next(i)) {
		void *ptr = kmap_atomic(sg_page(i)) + i->offset;

		memcpy(ptr, curr_ptr, i->length);
		curr_ptr += i->length;

		kunmap_atomic(ptr - i->offset);
	}
	dma_sync_single_for_device(priv->dev, priv->dst_dma, PAGE_SIZE,
				   DMA_FROM_DEVICE);

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

	//printk( "IRQ2!\n" );

	while (!
	       (ioread32(&priv->dma_regs->status) &
		STAT_RX_REPORT_BUFFER_EMPTY))
		fpga_read_rx_report(&report);

	iowrite32(0, &priv->dma_regs->control);
	iowrite32(6, &priv->dma_regs->control);

	priv->irq_done = 1;
	wake_up_interruptible(&priv->irq_queue);

	//printk( "IRQ2 end\n" );

	return IRQ_HANDLED;
}

static int aes_probe(struct platform_device *pdev)
{
	int err;

	dev_info(&pdev->dev, "probing");

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	BUG_ON(!priv);

	priv->dev = &pdev->dev;

	priv->irq = irq_of_parse_and_map(pdev->dev.of_node, 0);
	BUG_ON(!priv->irq);

	printk("irq = %d\n", priv->irq);

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

	priv->sg = sg_kmalloc(20, GFP_KERNEL);

	iowrite32(0, &priv->aes_regs->main_ctrl);
	iowrite32(1, &priv->aes_regs->main_ctrl);
	iowrite32(0, &priv->aes_regs->main_ctrl);

	iowrite32(6, &priv->dma_regs->control);

	init_waitqueue_head(&priv->irq_queue);

	err = request_irq(priv->irq, fpga_isr, IRQF_SHARED, "fpga-aes", priv);
	if (err) {
		printk("request_irq failed!");
		return -ENOMEM;
	}

	err = crypto_register_alg(&fpga_alg);
	BUG_ON(err);

	return 0;
}

static int aes_remove(struct platform_device *pdev)
{
	crypto_unregister_alg(&fpga_alg);

	free_irq(priv->irq, priv);

	sg_kfree(priv->sg, 20);

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
