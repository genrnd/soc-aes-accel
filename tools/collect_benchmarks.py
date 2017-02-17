#!/usr/bin/env python3

import subprocess
from sys import argv

run_count = 1000

def main():
    for operation in ['encrypt', 'decrypt']:
        print(operation, ': ')
        with open(argv[1] + operation + '.data', 'w') as output:
            for length in range(4096, 4096 * 110, 4096 * 5):
                print('  len = ', str(length))
                p = subprocess.Popen(['./openssl_benchmark', str(length), str(run_count), operation, 'aligned'], stdout = subprocess.PIPE)
                delay = float(p.stdout.read().decode())
                throughput = length * run_count * 8 / delay
                print("    delay      = ", delay)
                print("    throughput = ", throughput)
                output.write("%d %f %f\n" % (length, delay, throughput))


if __name__ == "__main__":
    main()
