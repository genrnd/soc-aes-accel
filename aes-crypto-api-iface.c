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
} __attribute__((__packed__));

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
};

struct aes_priv *priv;



static int write_fpga_desc(struct aes_priv *priv, u32 dma_address, u16 length, u8 irq_is_en, u8 is_dst )
{
	struct netdma_regs __iomem *regs = priv->dma_regs;

	u32 control_field;
	control_field = (length << DESC_BYTECOUNT_OFFSET) |
		(!irq_is_en << DESC_DISABLE_IRQ_OFFSET);

	if (ioread32(&regs->status) & STAT_TX_DESC_BUFFER_FULL) {
		pr_err("%s descriptor buffer full bit is set. Address = 0x%x\n", is_dst ? "rx" : "tx", dma_address);
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


static int write_dst_desc(struct aes_priv *priv, u32 dma_address, u16 length, u8 irq_is_en )
{
	return write_fpga_desc(priv, dma_address, length, irq_is_en, 1 );
}

static int write_src_desc(struct aes_priv *priv, u32 dma_address, u16 length, u8 irq_is_en )
{
	return write_fpga_desc(priv, dma_address, length, irq_is_en, 0 );
}


static int fpga_set_key(struct crypto_tfm *tfm, const u8 *in_key, unsigned int key_len)
{
	int i;
	const uint32_t *w_buf;

	if (key_len != AES_KEY_SIZE) {
		printk("Provided key of length %u when %u expected\n",
			(unsigned int) key_len, (unsigned int) AES_KEY_SIZE);
		return -EINVAL;
	}

	w_buf = (const uint32_t *)in_key;

	for( i = 3; i >= 0; i-- ) {
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

	for( i = 3; i >= 0; i-- ) {
		//printk("iv[ %d ] = 0x%x\n", i, w_buf[i] );
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
		struct scatterlist *src,
		unsigned int nbytes)
{
	printk("fpga_aes_enc\n");
	return 0;
}

#define MAX_DESC_CNT 16

static int fpga_decrypt(struct blkcipher_desc *desc,
		struct scatterlist *dst,
		struct scatterlist *src,
		unsigned int nbytes)
{
	struct blkcipher_walk walk;
	int err;
	int i;
	int size[ MAX_DESC_CNT ];
	dma_addr_t dma_dst[ MAX_DESC_CNT ], dma_src[ MAX_DESC_CNT ];
	int desc_cnt;

	//printk("fpga_aes_dec start\n");

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_phys(desc, &walk);

	fpga_write_iv(walk.iv);

	desc_cnt = 0;

	while ((nbytes = walk.nbytes)) {

		size[ desc_cnt ] = nbytes / 16 * 16;

		dma_src[ desc_cnt ] = dma_map_page(priv->dev, walk.src.phys.page,
				walk.src.phys.offset, size[ desc_cnt ], DMA_TO_DEVICE);
		dma_dst[ desc_cnt ] = dma_map_page(priv->dev, walk.dst.phys.page,
				walk.dst.phys.offset, size[ desc_cnt ], DMA_FROM_DEVICE);

		write_dst_desc(priv, dma_dst[ desc_cnt ], size[ desc_cnt ], 1);
		write_src_desc(priv, dma_src[ desc_cnt ], size[ desc_cnt ], 0);

		priv->irq_done = 0;
		err = wait_event_interruptible(priv->irq_queue, priv->irq_done == 1);
		if( err ) {
			printk( "wait_event_interruptible failed.\n" );
			return err;
		}

		err = blkcipher_walk_done(desc, &walk, nbytes - size[ desc_cnt ]);

		desc_cnt++;

		if( desc_cnt > MAX_DESC_CNT ) {
			printk( "Error: too many descriptors on decrypt\n" );
			return -EINVAL;
		}
	}

	//for( i = 0; i < desc_cnt; i++ ) {
	//  printk( "%d:\n", i );
	//  printk( "  src dma = 0x%x\n", dma_src[ i ]  );
	//  printk( "  dst dma = 0x%x\n", dma_dst[ i ]  );
	//  printk( "  cnt     = %d\n", size[ i ] );
	//}

	//for( i = 0; i < 10; i++ )
	//  mdelay(5);

	for( i = 0; i < desc_cnt; i++ ) {
		dma_unmap_page(priv->dev, dma_dst[ i ], size[ i ], DMA_FROM_DEVICE);
		dma_unmap_page(priv->dev, dma_src[ i ], size[ i ], DMA_TO_DEVICE);
	}

	//printk("fpga_aes_dec end %d\n", err);
	return err;
}



struct crypto_alg fpga_alg = {
	.cra_name        = "cbc(aes)",
	.cra_driver_name = "cbc(aes-fpga)",
	.cra_priority    = 1000,
	.cra_flags       = CRYPTO_ALG_TYPE_BLKCIPHER,
	.cra_blocksize   = AES_BLOCK_SIZE,
	.cra_ctxsize     = sizeof(struct aes_priv),
	.cra_type        = &crypto_blkcipher_type,
	.cra_alignmask   = 15,
	.cra_module      = THIS_MODULE,
	.cra_init        = fpga_aes_init,
	.cra_exit        = fpga_aes_exit,
	.cra_blkcipher = {
		.min_keysize = AES_KEY_SIZE,
		.max_keysize = AES_KEY_SIZE,
		.ivsize      = AES_BLOCK_SIZE,
		.setkey      = fpga_set_key,
		.encrypt     = fpga_encrypt,
		.decrypt     = fpga_decrypt,
	}
};

static void fpga_read_rx_report(struct netdma_rx_report *report)
{
	unsigned int rx_report;

	rx_report = ioread32(&priv->dma_regs->rx_report);
	report->actual_bytes_transferred =
		(rx_report >> RX_REPORT_ACTUAL_BYTES_OFFSET) & RX_REPORT_ACTUAL_BYTES_MASK;
}


static irqreturn_t fpga_isr(int irq, void *dev_id)
{
	struct netdma_rx_report report;

	//printk( "IRQ2!\n" );

	while (!(ioread32(&priv->dma_regs->status) & STAT_RX_REPORT_BUFFER_EMPTY))
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

	printk( "irq = %d\n", priv->irq);

	err = request_irq(priv->irq, fpga_isr, IRQF_SHARED, "fpga-aes", priv);
	if (err) {
		printk( "request_irq failed!" );
		return -ENOMEM;
	}

	priv->aes_regs = ioremap(AES_BASE, AES_SIZE);
	priv->dma_regs = ioremap(DMA_BASE, DMA_SIZE);

	iowrite32(0, &priv->aes_regs->main_ctrl);
	iowrite32(1, &priv->aes_regs->main_ctrl);
	iowrite32(0, &priv->aes_regs->main_ctrl);

	iowrite32(6, &priv->dma_regs->control);

	init_waitqueue_head(&priv->irq_queue);

	err = crypto_register_alg(&fpga_alg);
	BUG_ON(err);

	return 0;
}

static int aes_remove(struct platform_device *pdev)
{
	crypto_unregister_alg(&fpga_alg);

	free_irq(priv->irq, priv);

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
	.probe  = aes_probe,
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
