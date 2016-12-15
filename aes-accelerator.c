#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/device.h>

#include <linux/dma-mapping.h>
#include <linux/slab.h>

#include <linux/delay.h>

#include <linux/kdev_t.h>

#define FPGASLAVES (0xC0000000)

#define AES_BASE  FPGASLAVES
#define AES_SIZE  (7 * 4)

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   (32 * 4 / 8)

static struct class *encryptor_class;

struct aes_regs {
	u32 main_ctrl;
	u32 dma_read;
	u32 dma_write;
	u32 key[4];
	u32 block_counter;
} __attribute__((__packed__));

struct aes_priv {
	struct device *dev;
	struct aes_regs __iomem *regs;

	char *cipher_buf, *plain_buf;

	dma_addr_t cipher_dma, plain_dma;
};

static ssize_t key_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct aes_priv *priv;
	const uint32_t *w_buf;

	priv = dev_get_drvdata(dev);

	dev_info(dev, "key = %s", buf);

	if (count != AES_KEY_SIZE) {
		dev_warn(dev, "Provided key of length %u when %u expected",
			(unsigned int) count, (unsigned int) AES_KEY_SIZE);
		return -EINVAL;
	}

	w_buf = (const uint32_t *)buf;

	iowrite32(w_buf[0], priv->regs->key);
	iowrite32(w_buf[1], priv->regs->key + 1);
	iowrite32(w_buf[2], priv->regs->key + 2);
	iowrite32(w_buf[3], priv->regs->key + 3);

	iowrite32(0x4, &priv->regs->main_ctrl);
	iowrite32(0x0, &priv->regs->main_ctrl);

	dev_info(dev, "key written successfully");

	return count;
}
DEVICE_ATTR_WO(key);

static ssize_t ciphertext_store(struct device *dev, struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct aes_priv *priv;

	priv = dev_get_drvdata(dev);

	dev_info(dev, "ciphertext = %s", buf);

	if (count != AES_BLOCK_SIZE) {
		dev_warn(dev, "Got %u bytes of ciphertext when expected %u",
			(unsigned int) count, (unsigned int) AES_BLOCK_SIZE);
		return -EINVAL;
	}

	dma_sync_single_for_cpu(priv->dev, priv->cipher_dma, AES_BLOCK_SIZE, DMA_TO_DEVICE);

	memcpy(priv->cipher_buf, buf, AES_BLOCK_SIZE);

	dma_sync_single_for_device(priv->dev, priv->cipher_dma, AES_BLOCK_SIZE, DMA_TO_DEVICE);

	return count;
}
DEVICE_ATTR_WO(ciphertext);

static ssize_t plaintext_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct aes_priv *priv;

	priv = dev_get_drvdata(dev);

	iowrite32(0x1, &priv->regs->main_ctrl);

	//msleep(1);

	dma_sync_single_for_cpu(priv->dev, priv->plain_dma, AES_BLOCK_SIZE, DMA_FROM_DEVICE);

	memcpy(buf, priv->plain_buf, AES_BLOCK_SIZE);

	dma_sync_single_for_device(priv->dev, priv->plain_dma, AES_BLOCK_SIZE, DMA_FROM_DEVICE);

	return AES_BLOCK_SIZE;
}
DEVICE_ATTR_RO(plaintext);

static const struct attribute *aes_attrs[] = {
	&dev_attr_key.attr,
	&dev_attr_ciphertext.attr,
	&dev_attr_plaintext.attr,
	NULL
};

static const struct attribute_group aes_attr_group = {
	.attrs = (struct attribute **) aes_attrs,
};

static int aes_probe(struct platform_device *pdev)
{
	int err;
	struct aes_priv *priv;
	struct device *dev;

	dev_info(&pdev->dev, "probing");

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	BUG_ON(!priv);

	dev = device_create(encryptor_class, &pdev->dev, MKDEV(0, 0), NULL,
			"aes");
	BUG_ON(IS_ERR(priv->dev));

	priv->dev = dev;
	dev_set_drvdata(dev, priv);
	platform_set_drvdata(pdev, priv);

	dev_info(dev, "device created");

	/* Allocate both buffers */
	priv->cipher_buf = kzalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	BUG_ON(!priv->cipher_buf);
	priv->plain_buf = kzalloc(AES_BLOCK_SIZE, GFP_KERNEL);
	BUG_ON(!priv->plain_buf);

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

	err = sysfs_create_group(&dev->kobj, &aes_attr_group);
	BUG_ON(err);

	dev_info(dev, "files created");

	return 0;
}

static int aes_remove(struct platform_device *pdev)
{
	struct aes_priv *priv;

	priv = platform_get_drvdata(pdev);

	device_unregister(priv->dev);

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

	encryptor_class = class_create(THIS_MODULE, "encryptor");
	BUG_ON(IS_ERR(encryptor_class));
	pr_info("class created\n");

	err = platform_driver_register(&aes_drv);
	BUG_ON(err);

	return 0;
}
module_init(aes_init);

static void aes_exit(void)
{
	platform_driver_unregister(&aes_drv);

	class_destroy(encryptor_class);
	pr_info("class destroyed\n");
}
module_exit(aes_exit);

MODULE_AUTHOR("Ivan Oleynikov");
MODULE_LICENSE("GPL");
