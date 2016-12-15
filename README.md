aes-accelerator
===============

This directory contains sources of driver that we use to test FPGA firware
providing AES decryption hardware accelerator.

FILES
-----

 * `aes-accelerator.c` -- the driver source code
 * `socfpga_cyclone5_etln.dts` -- sample DTS file containing decription of
   platform device handled by the driver

BUILD
-----

Building the module providing driver is straingtforward:

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
`aes-accelerator.ko` in the current directory. You may want to place it in
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

At the moment of writing `aes-accelerator` driver the firmware providing
hardware AES decryption accelerator device did not have 'features'. In order to
run the firmware properly you have to disable the device handled by Metrotek's
FPGA manager and enable Altera FPGA manager's device.

The task of enabling proper FPGA manager and disabling the other as well as
describing device tree node for the device handled by `aes-accelerator` are
solved in `socfpga_cyclone5_etln.dts` DTS for ETLN that can be found in this
directory. Make sure you boot with proper DTS.

USAGE
-----

Once you have compiled and installed the `aes-accelerator`, installed the
proper FPGA firmware and booted the machine with proper DTS you may load the
`aes-accelerator` module and start having fun.

Once the module is loaded (manually by running `insmod ./aes-accelerator.ko` or
automatically by the kernel if you installed the module into
`/lib/firmware/<kernel-verison>/`) it creates new directory
`/sys/class/encryptor/aes` with the following files in it:

 * `key` -- Key that will be used for decryption (Write-only).
 * `ciphertext` -- Ciphertext to decrypt (Write-only).
 * `plaintext` -- Plaintext that was obtained by decrypting `ciphertext` using
   `key` (Read-only).

The hardware implements AES-128 so you must write exactly 16 bytes into
`ciphertext` and `key`.

The typical usage of the drvier could look like this:

```shell
# Genarate random ciphertext and key
dd bs=1 count=16 if=/dev/urandom of=ciphertext
dd bs=1 count=16 if=/dev/urandom of=key

# Pass them to the device
cat ciphertext > /sys/class/encryptor/aes/ciphertext
cat key > /sys/class/encryptor/aes/key

# Get the resulting plaintext
cat /sys/class/encryptor/aes/plaintext > hardware_plaintext

# Obtain the reference result
openssl aes-128-ecb -d -in ciphertext -out openssl_plaintext -K $(xxd -p key) -nopad

# Make sure the hardware decrypts the data correctly
diff openssl_plaintext hardware_plaintext
```

Note that each read of `plaintext` file triggers hardware decryption even when
the `ciphertext` and `key` weren't changed since the last decryption.
