#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

bool generate_key()
{
	int				ret = 0;
	RSA				*r = NULL;
	BIGNUM			*bne = NULL;
	BIO				*bp_public = NULL, *bp_private = NULL;

	int				bits = 2048;
	unsigned long	e = RSA_F4;

    // char buffer[32];
    // int written = get_random_bytes(buffer, sizeof(buffer));
    // RAND_seed(buffer, 32);

    // int read = RAND_load_file("/home/osboxes/cpp/openssl/test/prng.seed", -1);
    // if(read <= 0) printf("Rand load failed\n");

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	// 2. save public key
	bp_public = BIO_new_file("public.pem", "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if(ret != 1){
		goto free_all;
	}

	// 3. save private key
	bp_private = BIO_new_file("private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);

	return (ret == 1);
}

// int main(int argc, char* argv[]) 
// {
// 	generate_key();
//         return 0;
// }