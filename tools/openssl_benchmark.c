/* This program is based on examples from libcrypto tutorial at
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
		unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
		unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

void *allocate(int size, bool aligned)
{
	void *result;
	int err;
	const int PAGE_SIZE = getpagesize();

	err = posix_memalign(&result, PAGE_SIZE, size + PAGE_SIZE);
	if (err)
		fprintf(stderr, "posix_memalign: %s\n", strerror(err)), exit(1);

	result = aligned ? result : result + PAGE_SIZE - 1;

	memset(result, 0, size);

	return result;
}

void help(char *prog)
{
	fprintf(stderr, "%s <buffer size> (aligned|unaligned)\n", prog);
}

int main (int argc, char **argv)
{
	bool align;
	int size;

	/* Following code parses commandline arguments */
	if (argc != 3)
		return help(argv[0]), 1;

	size = strtoll(argv[1], NULL, 0);
	if (size == LONG_MAX || size == LONG_MIN || size < 0)
		return perror("Something is wrong with first argument"), 1;

	if (!strcmp(argv[2], "aligned"))
		align = true;
	else if (!strcmp(argv[2], "unaligned"))
		align = false;
	else
		return fprintf(stderr, "The second argument must be exactly `aligned` on `unaligned`\n"), 1;

	/* Set up the key and iv. Do I need to say to not hard code these in a
	 * real application? :-)
	 */

	/* A 256 bit key */
	unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"01234567890123456";

	/* Message to be encrypted */
	unsigned char *plaintext = allocate(size, align);

	/* Buffer for ciphertext. Ensure the buffer is long enough for the
	 * ciphertext which may be longer than the plaintext, dependant on the
	 * algorithm and mode
	 */
	unsigned char *ciphertext = allocate(size + 16, align);

	/* Buffer for the decrypted text */
	unsigned char *decryptedtext = allocate(size, align);;

	int decryptedtext_len, ciphertext_len;

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	/* Encrypt the plaintext */
	ciphertext_len = encrypt (plaintext, size, key, iv, ciphertext);

	/* Do something useful with the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
			decryptedtext);

	/* Show the decrypted text */
	printf("Decrypted text is:\n");
	BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);

	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();

	return 0;
}
