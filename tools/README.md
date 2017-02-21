tools
=====

Userspace utilities for testing and benchmarking the `soc-aes-accel` driver.

FILES
-----

 * `openssl_benchmark.c` -- encrypts specified amount od data specified number
   of times through `libcrypto`
 * `collect_benchmarks.py` -- script to execute `openssl_benchmark` multiple
   times for different buffer length values
