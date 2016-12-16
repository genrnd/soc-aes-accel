#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/device.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>
#include <crypto/padlock.h>

#include <linux/dma-mapping.h>
#include <linux/slab.h>

#include <linux/delay.h>
#include <linux/jiffies.h>

#include <linux/kdev_t.h>

#define FPGASLAVES (0xC0000000)

#define AES_BASE  FPGASLAVES
#define AES_SIZE  (7 * 4)

#define AES_BLOCK_SIZE 16
#define FPGA_AUXDATA    8
#define AES_KEY_SIZE   (32 * 4 / 8)

struct aes_regs {
	u32 main_ctrl;
	u32 dma_read;
	u32 dma_write;
	u32 key[4];
	u32 block_counter;
} __attribute__((__packed__));

struct aes_priv {
        uint32_t old_seq;
	struct device *dev;
	struct aes_regs __iomem *regs;

	char *cipher_buf, *plain_buf;

	dma_addr_t cipher_dma, plain_dma;
};

struct aes_priv *priv;

static int fpga_setkey(struct crypto_tfm *tfm, const u8 *in_key, unsigned int key_len)
{
	const uint32_t *w_buf;

	if (key_len != AES_KEY_SIZE) {
		printk("Provided key of length %u when %u expected\n",
			(unsigned int) key_len, (unsigned int) AES_KEY_SIZE);
		return -EINVAL;
	}

	w_buf = (const uint32_t *)in_key;

	iowrite32(w_buf[0], priv->regs->key);
	iowrite32(w_buf[1], priv->regs->key + 1);
	iowrite32(w_buf[2], priv->regs->key + 2);
	iowrite32(w_buf[3], priv->regs->key + 3);

	iowrite32(0x4, &priv->regs->main_ctrl);
	iowrite32(0x0, &priv->regs->main_ctrl);

        return 0;
}

static void fpga_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
        //struct aes_priv *priv = crypto_tfm_ctx(tfm);
        //
	//printk("fpga_encrypt\n");

}

static void fpga_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
        //struct aes_priv *priv = crypto_tfm_ctx(tfm);
        unsigned long start;
        uint32_t *seq;

	//printk("fpga_decrypt\n");

	memcpy(priv->cipher_buf, src, AES_BLOCK_SIZE);
	dma_sync_single_for_device(priv->dev, priv->cipher_dma, AES_BLOCK_SIZE, DMA_TO_DEVICE);

	iowrite32(0x1, &priv->regs->main_ctrl);

        seq = (uint32_t *) (priv->plain_buf + AES_BLOCK_SIZE);

        start = jiffies;
        while (1) {
          dma_sync_single_for_cpu(priv->dev, priv->plain_dma, AES_BLOCK_SIZE, DMA_FROM_DEVICE);
          if (*seq != priv->old_seq)
            break;
          BUG_ON(time_is_before_jiffies(start + HZ));
        }

        priv->old_seq = *seq;

	memcpy(dst, priv->plain_buf, AES_BLOCK_SIZE);
}


static struct crypto_alg fpga_alg = {
	.cra_name   = "aes",
	.cra_driver_name  = "aes-fpga",

	// XXX:
	//   Larger number -- higher priority :)
	.cra_priority   = 1000,
	.cra_flags      = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize  = AES_BLOCK_SIZE,
	.cra_ctxsize    = sizeof (struct aes_priv),
	.cra_alignmask  = 0,
	.cra_module     = THIS_MODULE,
	.cra_u         = {
		.cipher = {
			.cia_min_keysize  = AES_KEY_SIZE,
			.cia_max_keysize  = AES_KEY_SIZE,
			.cia_setkey   =   fpga_setkey,
			.cia_encrypt    = fpga_encrypt,
			.cia_decrypt    = fpga_decrypt
		}
	}
};


static int aes_probe(struct platform_device *pdev)
{
	int err;
	//struct aes_priv *priv;

	dev_info(&pdev->dev, "probing");

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	BUG_ON(!priv);

	priv->dev = &pdev->dev;
	platform_set_drvdata(pdev, priv);

	/* Allocate both buffers */
	priv->cipher_buf = kzalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	BUG_ON(!priv->cipher_buf);
	priv->plain_buf = kzalloc(AES_BLOCK_SIZE + FPGA_AUXDATA, GFP_KERNEL);
	BUG_ON(!priv->plain_buf);

        priv->old_seq = -1;
        *(uint32_t *)(priv->plain_buf + AES_BLOCK_SIZE) = -1;

	priv->regs = ioremap(AES_BASE, AES_SIZE);

	/* Map ciphertext buffer */
	priv->cipher_dma = dma_map_single(&pdev->dev,
				priv->cipher_buf, AES_BLOCK_SIZE, DMA_TO_DEVICE);
	BUG_ON(dma_mapping_error(&pdev->dev, priv->cipher_dma));

	iowrite32(priv->cipher_dma, &priv->regs->dma_read);

	/* Map plaintext buffer */
	priv->plain_dma = dma_map_single(&pdev->dev,
				priv->plain_buf, AES_BLOCK_SIZE, DMA_FROM_DEVICE);
	BUG_ON(dma_mapping_error(&pdev->dev, priv->plain_dma));

	iowrite32(priv->plain_dma, &priv->regs->dma_write);

        err = crypto_register_alg(&fpga_alg);
	BUG_ON(err);

	return 0;
}

static int aes_remove(struct platform_device *pdev)
{
	struct aes_priv *priv;

	priv = platform_get_drvdata(pdev);

        crypto_unregister_alg(&fpga_alg);

	iounmap(priv->regs);

	dma_unmap_single(&pdev->dev, priv->cipher_dma, AES_BLOCK_SIZE, DMA_TO_DEVICE);
	dma_unmap_single(&pdev->dev, priv->plain_dma, AES_BLOCK_SIZE, DMA_FROM_DEVICE);

	kfree(priv->cipher_buf);
	kfree(priv->plain_buf);

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

static int aes_init(void)
{
	int err;

	err = platform_driver_register(&aes_drv);
	BUG_ON(err);

	return 0;
}
module_init(aes_init);

static void aes_exit(void)
{
	platform_driver_unregister(&aes_drv);
	pr_info("class destroyed\n");
}
module_exit(aes_exit);

MODULE_AUTHOR("Denis Gabidullin");
MODULE_AUTHOR("Ivan Oleynikov");
MODULE_LICENSE("GPL");
