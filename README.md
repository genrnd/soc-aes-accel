aes-crypto-api-iface
====================

This directory contains sources of driver that we use to test FPGA firware
providing AES decryption hardware accelerator.

It uses standard kernel Crypto-API interface. See:
  https://kernel.readthedocs.io/en/sphinx-samples/crypto-API.html


FILES
-----

 * `aes-crypto-api-iface.c` -- the driver source code
 * `socfpga_cyclone5_etln.dts` -- sample DTS file containing decription of
   platform device handled by the driver

BUILD
-----

Building the module is straingtforward:

```shell
make KDIR=path/to/prebuilt/kernel
```

KDIR must contain a path to kernel sources.

In addition, one may want to pass `CROSS_COMPILE` parameter to `make` to change
cross compilation toolchain prefix. The default `CROSS_COMPILE` value is
`arm-linux-gnueabihf-`. Make sure you build the module with the same toolchain
that was used to build a kernel.

INSTALL
-------

After running the `make` described in the previous section you will obtain
`aes-crypto-api-iface.ko` in the current directory. You may want to place it in
`/usr/lib/modules/<kernel-version>/` on target machine and run `depmod` making
the module load automatically once the kernel finds appropriate platform
device. Or instead you can simply copy it to whatever directory on the target
machine and `insmod` by hand.

The module provides a platform device driver that handles devices having
`compatible` property equal to `stcmtk,aes`. For example, such device can be
described in dts by the following lines:

```dts
my-aes-decryptor {
	compatible = "stcmtk,aes";
};
```

Currently all the device properties (register addresses, block size) are
hardcoded in the driver, so no properties except `compatible` can be specified
in DTS.

STC Metortek's SoC-based devices are shipped with custom fpga manager driver
(`etn-fpga-mgr.ko`) installed while the upstream Altera's fpga manager (called
`altera.ko` or `socfpga.ko`) device's node is disabled in dts. The Metrotek's
fpga manager driver requires the FPGA firmware to have special capability
called 'features'.

At the moment of writing `aes-crypto-api-iface` driver the firmware providing
hardware AES decryption accelerator device did not have 'features'. In order to
run the firmware properly you have to disable the device handled by Metrotek's
FPGA manager and enable Altera FPGA manager's device.

The task of enabling proper FPGA manager and disabling the other as well as
describing device tree node for the device handled by `aes-crypto-api-iface` are
solved in `socfpga_cyclone5_etln.dts` DTS for ETLN that can be found in this
directory. Make sure you boot with proper DTS.

USAGE
-----

Once you have compiled and installed the `aes-crypto-api-iface`, installed the
proper FPGA firmware and booted the machine with proper DTS you may load the
`aes-crypto-api-iface` module and start having fun.

Once loaded the module registers an in-kernel cryptographic cipher that can be
used by various consumers mostly in kernel. Userspace use our hardware cipher
through interfaces like `AF_ALG` socket family or `cryptodev.ko` out-of-tree
module.

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

