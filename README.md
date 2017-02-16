aes-crypto-api-iface
====================

This project contains the driver that we use to test FPGA firmware
providing AES decryption hardware accelerator.

It uses the standard kernel Crypto-API interface. See:
  https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html


FILES
-----

 * `aes-crypto-api-iface.c` -- the driver source code
 * `socfpga_cyclone5_etln.dts` -- sample DTS file containing description of
   platform device handled by the driver

BUILD
-----

This project is built with the command commonly used for building kernel
modules:

```shell
make KDIR=path/to/prebuilt/kernel
```

Here KDIR is the directory containing the kernel sources.

In addition, one may want to pass `CROSS_COMPILE` parameter to `make` to change
cross compilation toolchain prefix. The default `CROSS_COMPILE` value is
`arm-linux-gnueabihf-`. Make sure you build the module with the same toolchain
that was used to build a kernel.

INSTALL
-------

After building the project `aes-crypto-api-iface.ko` shall appear in the
current directory. It is commonly placed in `/usr/lib/modules/<kernel-version>/`
on the target machine; then one should run `depmod` so that the module is loaded
automatically once the kernel finds appropriate platform device. Alternatively,
it's possible to place the file anywhere on the target machine and then simply
run `insmod` with its full path manually.

The module provides a platform device driver that handles devices having
`compatible` property equal to `stcmtk,aes`. For example, such device can be
described in dts as such:

```dts
my-aes-decryptor {
	compatible = "stcmtk,aes";

	reg = < 0x0 0x20            /* Decryptor AES regs base */
		0x100 0x30          /* Decryptor DMA regs base */
		0x200 0x20          /* Encryptor AES regs base */
		0x300 0x30>;        /* Encryptor DMA regs base */

	interrupts = <0x0 0x1 0x2   /* decryption irq */
		      0x0 0x1 0x3>; /* encryption irq */
};
```
Note that:

 * the `compatible` property must be exactly `stcmtk,aes`.
 * the `interrupts` property must describe two interrupts that are issued by
   decryption and encryption accelerators' DMA controllers in the FPGA; the
   interrupts must be listed in this order.
 * the `reg` property must describe four address ranges:
   * decryption core registers
   * decryption DMA core registers
   * encryption core registers
   * encryption DMA core registers
 * the `reg-names` property is optional. You may set it to influence the
   contents of /proc/iomem, it has no effect on driver behaviour.

STC Metortek's SoC-based devices are shipped with custom FPGA manager driver
(`etn-fpga-mgr.ko`) installed while the upstream Altera's FPGA manager (called
`altera.ko` or `socfpga.ko`) device's node is disabled in dts. The Metrotek's
FPGA manager driver requires the FPGA firmware to have a special capability
called 'features'.

At the moment of writing `aes-crypto-api-iface` the firmware providing hardware
AES decryption accelerator device did not have 'features'. In order to run the
firmware properly one has to disable the device handled by Metrotek's FPGA
manager and enable Altera FPGA manager's device.

The `socfpga_cyclone5_etln.dts` file provided here enables Altera's FPGA
manager and describes the device tree node for the device handled by
`aes-crypto-api-iface`. It is applicable for ETL-N and can be used as a
reference for writing other device tree specifications.

USAGE
-----

Once you have compiled, installed `aes-crypto-api-iface` and the proper
FPGA firmware, and booted the machine with the proper DTS you may load the
`aes-crypto-api-iface` module and start having fun.

Once loaded, the module registers an in-kernel cipher that can be used by
various consumers which are mostly in kernel. Userspace can access our
hardware cipher through interfaces like `AF_ALG` socket family [2] or
`cryptodev.ko` out-of-tree module [1].

Minimal usage example of our module is presented below. It uses openssl in
conjunction with `cryptodev.ko` to decrypt using hardware acceleration and
compare with reference result. The openssl must be compiled with cryptodev
engine support:
  http://forum.doozan.com/read.php?2,18152

```shell
# Ensure that our Crypto device is registered:
cat /proc/crypto | grep -A 10 fpga

# Make tmpfs
mkdir tmpfs
mount -t tmpfs -o size=300m,nr_inodes=100,mode=0700 tmpfs tmpfs/
cf tmpfs

# Genarate random ciphertext, key and initialization vector
dd bs=16000 count=1000 if=/dev/urandom of=ciphertext
dd bs=1 count=16 if=/dev/urandom of=key
dd bs=1 count=16 if=/dev/urandom of=iv

# Decrypt ciphertext without FPGA acceleration (make sure that
# `aes-crypto-api-iface` and `cryptodev` modules are not loaded)
time openssl aes-128-cbc -d -in ciphertext -out nofpga_plaintext -K $(xxd -p key) -nopad -iv $(xxd -p iv)

# Load modules
insmod <your-path>/cryptodev.ko
insmod <your-path>/aes-crypto-api-iface.ko

# Decrypt ciphertext with FPGA acceleration
time openssl aes-128-cbc -d -in ciphertext -out fpga_plaintext -K $(xxd -p key) -nopad -iv $(xxd -p iv)

# Compare results
diff fpga_plaintext nofpga_plaintext
```

The example above `insmod`s and `rmmod`s modules to switch between hardware and
software implementations of encryption. We hope that there is a more convenient
way to achieve this, but it is unknown to us.

SEE ALSO
--------

 1. https://github.com/cryptodev-linux/cryptodev-linux
 2. https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html
