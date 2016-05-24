
#include "Tcm_crypto.h"

int nTCM_Crypto;

int fnTCM_Crypto(void);

#include <assert.h>
#include <memory.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sms4.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>
#include <openssl/obj_mac.h>

//unsigned char *key,			/* 16字节 */
//unsigned char *plaintext,		/* 明文 */
//unsigned short plaintextlen,	/* 明文长度 */
//unsigned char *ciphertext,	/* 密文输出 */
//unsigned short *ciphertextlen, /* 长度是16的整数倍,最多比明文长度多16字节 ( plaintextlen /16 +1) * 16 */
//unsigned char *IV				/* 初始向量 16字节 */
//
unsigned char SMS4_Encryption(unsigned char *key, 
							  unsigned char *plaintext, unsigned short plaintextlen, 
							  unsigned char *ciphertext, unsigned short *ciphertextlen, 
							  unsigned char *IV)
{
	assert(key && plaintext && ciphertext && ciphertextlen && IV);

	sms4_key_t pkey;
	sms4_set_encrypt_key(&pkey, key);

	int pad = 16 - plaintextlen % 16;
	*ciphertextlen = plaintextlen  + pad;
	memcpy(ciphertext, plaintext, plaintextlen);
	memset(ciphertext + plaintextlen, pad, pad);

	sms4_cbc_encrypt(ciphertext, ciphertext, *ciphertextlen, 
		&pkey, IV, 1);

	return 0;
}

// 解密
unsigned char SMS4_Decryption(unsigned char *key, 
							  unsigned char *ciphertext, unsigned short ciphertextlen, 
							  unsigned char *plaintext,	unsigned short *plaintextlen, 
							  unsigned char *IV)
{
	assert(key && ciphertext && plaintext && plaintextlen && IV);

	sms4_key_t pkey;
	sms4_set_decrypt_key(&pkey, key);

	sms4_cbc_encrypt(ciphertext, ciphertext, ciphertextlen, &pkey, IV, 0);
	int pad = ciphertext[ciphertextlen - 1];
	for (int i = 1; i <= pad; ++ i) {
		if (ciphertext[ciphertextlen - i] != pad)
			return 1; // 补齐出错
	}
	*plaintextlen = ciphertextlen - pad;
	memcpy(plaintext, ciphertext, *plaintextlen);
	return 0;
}

// unsigned char *pM      输出,明文
// unsigned char *pPDKey  私钥
// unsigned char *pC      密文
// unsigned long Clen     密文长度
unsigned char eccDecrypt(unsigned char *pM, unsigned char *pPDKey, unsigned char *pC, unsigned long Clen)
{
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

	KDF_FUNC kdf = KDF_get_x9_63(EVP_sm3());

	// 设置私钥
	BIGNUM *pri_key = BN_new();
	BN_bin2bn(pPDKey, 32, pri_key);
	EC_KEY_set_private_key(ec_key, pri_key);

	int ret = 1;
	EC_POINT *point = NULL;
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BN_CTX *bn_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	unsigned char mac[EVP_MAX_MD_SIZE];
	unsigned int maclen;
	int nbytes;
	size_t size;
	size_t i;

	if (!ec_group || !pri_key) {
		goto end;
	}
	if (!kdf) {
		goto end;
	}

	EC_POINT *ephem_point = EC_POINT_new(ec_group);
	EC_POINT_oct2point(ec_group, ephem_point, pC, 65, NULL);

	/* init vars */
	point = EC_POINT_new(ec_group);
	n = BN_new();
	h = BN_new();
	bn_ctx = BN_CTX_new();
	md_ctx = EVP_MD_CTX_create();
	if (!point || !n || !h || !bn_ctx || !md_ctx) {
		goto end;
	}

	/* init ec domain parameters */
	if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
		goto end;
	}
	if (!EC_GROUP_get_cofactor(ec_group, h, bn_ctx)) {
		goto end;
	}
	nbytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;

	/* B2: check [h]C1 != O */
	if (!EC_POINT_mul(ec_group, point, NULL, ephem_point, h, bn_ctx)) {
		goto end;
	}
	if (EC_POINT_is_at_infinity(ec_group, point)) {
		goto end;
	}

	/* B3: compute ECDH [d]C1 = (x2, y2) */	
	if (!EC_POINT_mul(ec_group, point, NULL, ephem_point, pri_key, bn_ctx)) {
		goto end;
	}
	if (!(size = EC_POINT_point2oct(ec_group, point,
		POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
			goto end;
	}
	OPENSSL_assert(size == 1 + nbytes * 2);

	/* B4: compute t = KDF(x2 || y2, clen) */

	size_t len = 0;
	size_t *outlen = &len;
	*outlen = Clen - 97; //FIXME: duplicated code
	unsigned char *out = (unsigned char *)OPENSSL_malloc(*outlen);
	kdf(buf + 1, size - 1, out, outlen);

	unsigned char *ciphertext = pC + 65;

	/* B5: compute M = C2 xor t */
	for (i = 0; i < len; i++) {
		out[i] ^= ciphertext[i];
	}
	*outlen = len;

	if (1) {

		/* B6: check Hash(x2 || M || y2) == C3 */
		if (!EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL)) {
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1, nbytes)) {
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, out, *outlen)) {
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)) {
			goto end;
		}
		if (!EVP_DigestFinal_ex(md_ctx, mac, &maclen)) {
			goto end;
		}

		/* GmSSL specific */
		if (memcmp(mac, pC + 129, 32)) {
			goto end;
		}
	}

	for (i = 0; i < len; i++) {
		pM[i] = out[i] ;
	}

	ret = 0;
end:
	if (point) EC_POINT_free(point);
	if (n) BN_free(n);	
	if (h) BN_free(h);
	if (bn_ctx) BN_CTX_free(bn_ctx);
	if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

	return ret;
}

// unsigned char *pC      输出，密文
// unsigned char *pPxKey, unsigned char *pPyKey  公钥
// unsigned char *pM      明文
// unsigned long MLen     明文长度
unsigned char eccEncrypt(unsigned char *pC, 
						 unsigned char *pPxKey, unsigned char *pPyKey, 
						 unsigned char *pM, unsigned long MLen)
{
	// NID_sm2p256v1
	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	//// 相当于
	//EC_KEY *ret = EC_KEY_new();
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

	KDF_FUNC kdf = KDF_get_x9_63(EVP_sm3());;

	EC_POINT *point = NULL;
	//// 设置私钥
	//BIGNUM *d = NULL;
	//BN_hex2bn(&d, pPDKey);
	//EC_KEY_set_private_key(ec_key, d);
	int ret = 1;

	BIGNUM *x = BN_new();;
	BIGNUM *y = BN_new();;
	if (!BN_bin2bn(pPxKey, 32, x)) {
		goto end;
	}
	if (!BN_bin2bn(pPyKey, 32, y)) {
		goto end;
	}
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		goto end;
	}
	const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
	/* init ec domain parameters */
	BIGNUM *n = NULL;
	BIGNUM *h = NULL;
	BIGNUM *k = NULL;
	n = BN_new();
	h = BN_new();
	k = BN_new();
	BN_CTX *bn_ctx = NULL;
	bn_ctx = BN_CTX_new();
	if (!EC_GROUP_get_order(ec_group, n, bn_ctx)) {
		goto end;
	}
	if (!EC_GROUP_get_cofactor(ec_group, h, bn_ctx)) {
		goto end;
	}
	int nbytes = (EC_GROUP_get_degree(ec_group) + 7) / 8;

	EC_POINT *ec_point = EC_POINT_new(ec_group);
	point = EC_POINT_new(ec_group);
	unsigned char buf[(OPENSSL_ECC_MAX_FIELD_BITS + 7)/4 + 1];
	size_t len;
	char *ciphertext = (char *)OPENSSL_malloc(MLen);
	size_t ciphertext_size = MLen;
	do
	{
		/* A1: rand k in [1, n-1] */
		do {
			BN_rand_range(k, n);
		} while (BN_is_zero(k));

		/* A2: C1 = [k]G = (x1, y1) */
		if (!EC_POINT_mul(ec_group, ec_point, k, NULL, NULL, bn_ctx)) {
			goto end;
		}
#if 1
		if (!(len = EC_POINT_point2oct(ec_group, ec_point,
			POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
				goto end;
		}
		BN_bin2bn(buf, 65, n);
		printf(BN_bn2hex(n));
		printf("\n");
		printf(BN_bn2hex(k));
#endif
		/* A3: check [h]P_B != O */
		if (!EC_POINT_mul(ec_group, point, NULL, pub_key, h, bn_ctx)) {
			goto end;
		}
		if (EC_POINT_is_at_infinity(ec_group, point)) {
			goto end;
		}

		/* A4: compute ECDH [k]P_B = (x2, y2) */
		if (!EC_POINT_mul(ec_group, point, NULL, pub_key, k, bn_ctx)) {
			goto end;
		}
		if (!(len = EC_POINT_point2oct(ec_group, point,
			POINT_CONVERSION_UNCOMPRESSED, buf, sizeof(buf), bn_ctx))) {
				goto end;
		}
		OPENSSL_assert(len == nbytes * 2 + 1);

		/* A5: t = KDF(x2 || y2, klen) */
		kdf(buf + 1, len - 1, (unsigned char *)ciphertext, &ciphertext_size);

		// 防止全0
		size_t i = 0;
		for (i = 0; i < ciphertext_size; i++) {
			if (ciphertext[i]) {
				break;
			}
		}
		if (i == ciphertext_size) {
			continue;
		}
		break;
	} while (1);


	/* A6: C2 = M xor t */
	for (size_t i = 0; i < MLen; i++) {
		ciphertext[i] ^= pM[i];
	}

	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
	if (1) {

		/* A7: C3 = Hash(x2 || M || y2) */
		if (!EVP_DigestInit_ex(md_ctx, EVP_sm3(), NULL)) {
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1, nbytes)) {
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, pM, MLen)) {
			goto end;
		}
		if (!EVP_DigestUpdate(md_ctx, buf + 1 + nbytes, nbytes)) {
			goto end;
		}
		if (!EVP_DigestFinal_ex(md_ctx, dgst, &dgstlen)) {
			goto end;
		}
	}

	EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_UNCOMPRESSED, pC, 65, NULL);
	memcpy(&pC[65], ciphertext, MLen);
	memcpy(&pC[65 + MLen], dgst, dgstlen);
ret = 0;
end:

	if (point) EC_POINT_free(point);
	if (n) BN_free(n);
	if (h) BN_free(h);
	if (k) BN_free(k);
	if (bn_ctx) BN_CTX_free(bn_ctx);
	if (md_ctx) EVP_MD_CTX_destroy(md_ctx);

	return ret;
}

// unsigned char *pHV  计算所得的哈希值
// unsigned char *pSV  要计算其哈希值的输入。
// unsigned short SLen 输入的字节数。
void eccHash(unsigned char *pHV, 
			 unsigned char *pSV, unsigned short SLen)
{
	sm3(pSV, SLen, pHV);
}

// unsigned char *pDKey 私钥数据
// unsigned char *pPxKey 公钥数据
// unsigned char *pPyKey 公钥数据
unsigned char eccKeyGen(unsigned char *pDKey, 
						unsigned char *pPxKey, unsigned char *pPyKey)
{
	int rv;
	EC_KEY *ec_key = NULL;
	EVP_PKEY *pkey = NULL;
	// NID_sm2p256v1
	ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime192v1);
	OPENSSL_assert(ec_key);
	rv = EC_KEY_generate_key(ec_key);
	OPENSSL_assert(rv == 1);

	// 私钥
	const BIGNUM *key = EC_KEY_get0_private_key(ec_key);

	// 公钥
	const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
	const EC_GROUP *group = EC_KEY_get0_group(ec_key);

#define ECDH_SIZE 65
	unsigned char pubkey[ECDH_SIZE];
	EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, pubkey, ECDH_SIZE, NULL);
	memcpy (pPxKey, pubkey + 1, 32);
	memcpy (pPyKey, pubkey + 33, 32);

	BN_bn2bin(key, pDKey);

	return 0;
}

//unsigned char hash_start(unsigned int *maxinlen)
//{
//	return 0;
//}
//
//unsigned char hash_updata(
//						  unsigned char *pText,		/* SM3 的输入信息 */
//						  unsigned short TextLength	/* SM3输入信息长度 */
//						  )
//{
//	return 0;
//}
//
//unsigned char hash_complete(  
//							unsigned char *pText,		/* SM3 的输入信息 */
//							unsigned short TextLength,	/* SM3输入信息长度 */
//							unsigned char *pOutputData,
//							unsigned int *outputlen
//							)
//{
//	return 0;
//}


// unsigned char *pAPriKey, A 的私钥
// unsigned char *pARxPoint, unsigned char *pArx, A 随机的一个点
// unsigned char *pIDA, unsigned short ulenIDA, 身份信息
// unsigned char tag, 
//unsigned char *pBPubKey, B 的公钥
// unsigned char *pBRxPoint, B 的点
//unsigned char *pIDB,unsigned short ulenIDB, 身份信息
//unsigned char *pKA, 输出的对称密钥
// unsigned char *pS1, unsigned char *pSA
unsigned char eccGetKeyExchange(unsigned char *pAPriKey, unsigned char *pARxPoint, unsigned char *pArx, 
								unsigned char *pIDA, unsigned short ulenIDA, 
								unsigned char tag, 
								unsigned char *pBPubKey, unsigned char *pBRxPoint, 
								unsigned char *pIDB,unsigned short ulenIDB, 
								unsigned char *pKA, unsigned char *pS1, unsigned char *pSA)
{
	//// only for vtcs

	//BN_CTX *bn_ctx = BN_CTX_new();
	//BIGNUM *order = BN_new();

	//EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	//const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);

	//if (!EC_GROUP_get_order(ec_group, order, bn_ctx)) {
	//	SM2err(SM2_F_SM2_KAP_CTX_INIT, ERR_R_EC_LIB);
	//	goto err;
	//}

	//// w
	//int w = (BN_num_bits(order) + 1) / 2 - 1;
	//// A 的私钥
	//BIGNUM *Dax = BN_new();;
	//if (!BN_bin2bn(pAPriKey, 32, Dax)) {
	//	goto err;
	//}
	//if (!EC_KEY_set_private_key(ec_key, Dax)) {
	//	goto err;
	//}
	//EC_KEY_generate_key(ec_key);
	//// 根据A私钥推导公钥
	//const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
	//BIGNUM *x = BN_new();
	//BIGNUM *y = BN_new();
	//if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
	//	if (!EC_POINT_get_affine_coordinates_GFp(ec_group, pub_key, x, y, bn_ctx)) {
	//		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
	//		goto err;
	//	}
	//} else /* NID_X9_62_characteristic_two_field */ {
	//	if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, pub_key, x, y, bn_ctx)) {
	//		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
	//		goto err;
	//	}
	//}
	//unsigned char xA[32], yA[32];
	//BN_bn2bin(x, xA);
	//BN_bn2bin(y, yA);

	//// A 随机点
	//EC_POINT *Rax = EC_POINT_new(ec_group);
	//EC_POINT_oct2point(ec_group, Rax, pARxPoint, 65, bn_ctx);
	//BIGNUM *Rda = BN_new();
	//BN_bin2bn(pArx, 32, Rda);

	//// Za
	//unsigned char za[32];
	////Z_Gen(za, ulenIDA, pIDA, x, y);

	//BIGNUM *two_pow_w = BN_new();
	//BN_one(two_pow_w);
	//BN_lshift(two_pow_w, two_pow_w, w);
	//BN_nnmod(x, x, two_pow_w, bn_ctx);
	//BN_add(x, x, two_pow_w);

	//// A5
	//BIGNUM *t = BN_new();
	//BN_mod_mul(t, x, Rda, order, bn_ctx);
	//BN_mod_add(t, t, Dax, order, bn_ctx);

	//BIGNUM *h = BN_new();
	//EC_GROUP_get_cofactor(ec_group, h, bn_ctx);
	//BN_mul(t, t, h, bn_ctx);

	//EC_POINT_point2oct(ec_group, point, POINT_CONVERSION_UNCOMPRESSED, 
	//	buf, &buf_len, bn_ctx);
	//EC_POINT_is_at_infinity()


err:
	return 0;
}

void eccSetUserMessageData(unsigned long ulUserIDSize, unsigned char *rgbUserID, 
						   unsigned long ulMessageSize, unsigned char *rgbMessage, 
						   unsigned char *x, unsigned char *y, 
						   unsigned char *rgbHashData)
{
	// Tsp 需要
	unsigned char z[32];
	Z_Gen(z, ulUserIDSize, rgbUserID, x, y);

	sm3_ctx_t ctx2;

	sm3_init(&ctx2);
	sm3_update(&ctx2, z, sizeof(z));
	sm3_update(&ctx2, rgbMessage, ulMessageSize);

	sm3_final(&ctx2, rgbHashData);
}

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

/* k in [1, n-1], (x, y) = kG */
static int sm2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx_in, BIGNUM **kp, BIGNUM **xp)
{
	int ret = 0;
	const EC_GROUP *ec_group;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL;
	BIGNUM *x = NULL;
	BIGNUM *order = NULL;
	EC_POINT *point = NULL;

	if (ec_key == NULL || (ec_group = EC_KEY_get0_group(ec_key)) == NULL) {
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	if (ctx_in == NULL)  {
		if ((ctx = BN_CTX_new()) == NULL) {
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_MALLOC_FAILURE);
			return 0;
		}
	}
	else {
		ctx = ctx_in;
	}

	k = BN_new();	
	x = BN_new();
	order = BN_new();
	if (!k || !x || !order) {
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
		goto err;
	}

	if ((point = EC_POINT_new(ec_group)) == NULL) {
		ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
		goto err;
	}

	do {
		/* get random k */	
		do {
			if (!BN_rand_range(k, order)) {
				ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,
					ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);	
				goto err;
			}

		} while (BN_is_zero(k));

		/* compute r the x-coordinate of generator * k */
		if (!EC_POINT_mul(ec_group, point, k, NULL, NULL, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_EC_LIB);
			goto err;
		}

		if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
			if (!EC_POINT_get_affine_coordinates_GFp(ec_group, point, x, NULL, ctx)) {
				ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		} else /* NID_X9_62_characteristic_two_field */ {
			if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, x, NULL, ctx)) {
				ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP,ERR_R_EC_LIB);
				goto err;
			}
		}

		//FIXME: do we need this?
		if (!BN_nnmod(x, x, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_SIGN_SETUP, ERR_R_BN_LIB);
			goto err;
		}

	} while (BN_is_zero(x));

	/* clear old values if necessary */
	if (*kp != NULL)
		BN_clear_free(*kp);
	if (*xp != NULL)
		BN_clear_free(*xp);

	/* save the pre-computed values  */
	*kp = k;
	*xp = x;
	ret = 1;

err:
	if (!ret) {
		if (k) BN_clear_free(k);
		if (x) BN_clear_free(x);
	}
	if (ctx_in == NULL) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (point) EC_POINT_free(point);

	return(ret);
}

// unsigned char *rgbHashData, 哈希
// unsigned char *rgbKeyDb, 私钥
// unsigned char *rs             签名
void eccHashSign(unsigned char *rgbHashData, unsigned char *rgbKeyDb, unsigned char *rs)
{
	int ok = 0;
	const EC_GROUP *ec_group;
	BIGNUM *priv_key;
	const BIGNUM *ck;
	BIGNUM *k = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *bn = NULL;
	int i;
	BIGNUM *r= BN_new(), *s = BN_new();


	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	ec_group = EC_KEY_get0_group(ec_key);
	priv_key = BN_new();
	BN_bin2bn(rgbKeyDb, 32, priv_key);
	EC_KEY_set_private_key(ec_key, priv_key);
	if (!ec_group || !priv_key) {
	}

	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	bn = BN_new();
	if (!ctx || !order || !e || !bn) {
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_EC_LIB);
		goto err;
	}

	/* convert dgst to e */
	i = BN_num_bits(order);
#if 0
	if (8 * dgst_len > i) {
		dgst_len = (i + 7)/8;
	}
#endif
	if (!BN_bin2bn(rgbHashData, 32, e)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}

#if 0
	if ((8 * dgst_len > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
		ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
		goto err;
	}
#endif

	do {
		/* use or compute k and (kG).x */
			if (!sm2_sign_setup(ec_key, ctx, &k, &r)) {
				ECDSAerr(ECDSA_F_ECDSA_DO_SIGN,ERR_R_ECDSA_LIB);
				goto err;
			}
			ck = k;


		/* r = e + x (mod n) */	
		if (!BN_mod_add(r, r, e, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}


		if (!BN_mod_add(bn, r, ck, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

		/* check r != 0 && r + k != n */
		if (BN_is_zero(r) || BN_is_zero(bn)) {
				continue;
		}

		/* s = ((1 + d)^-1 * (k - rd)) mod n */
		if (!BN_one(bn)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_add(s, priv_key, bn, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_inverse(s, s, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

		if (!BN_mod_mul(bn, r, priv_key, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_sub(bn, ck, bn, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}
		if (!BN_mod_mul(s, s, bn, order, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_SIGN, ERR_R_BN_LIB);
			goto err;
		}

		/* check s != 0 */
		if (!BN_is_zero(s)) 
			break;

	} while (1);

	ok = 1;
	BN_bn2bin(r, rs);
	BN_bn2bin(s, rs + 32);

err:
	if (k) BN_free(k);	
	if (ctx) BN_CTX_free(ctx);
	if (order) BN_free(order);
	if (e) BN_free(e);
	if (bn) BN_free(bn);	

}

// unsigned char *rgbHashData, 哈希数值
// unsigned char *rgbKeyPb, SM2公钥数据，Px Py 不含标志位 point_conversion_form_t
// unsigned char *rs 待验证的签名数据
unsigned char eccVerifySignature(unsigned char *rgbHashData, unsigned char *rgbKeyPb, unsigned char *rs)
{
	int ret = SM2_VERIFY_INNER_ERROR;
	EC_POINT *point = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL;
	BIGNUM *e = NULL;
	BIGNUM *t = NULL;
	int i;

	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);

	BIGNUM *x = BN_new();;
	BIGNUM *y = BN_new();;
	if (!BN_bin2bn(rgbKeyPb, 32, x)) {
		goto err;
	}
	if (!BN_bin2bn(rgbKeyPb + 32, 32, y)) {
		goto err;
	}
	if (!EC_KEY_set_public_key_affine_coordinates(ec_key, x, y)) {
		goto err;
	}
	const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);

	BIGNUM *r= BN_new(), *s = BN_new();
	BN_bin2bn(rs, 32, r);
	BN_bin2bn(rs + 32, 32, s);

	//// 相当于
	//EC_KEY *ret = EC_KEY_new();
	EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);

	ctx = BN_CTX_new();
	order = BN_new();
	e = BN_new();
	t = BN_new();

	if (!ctx || !order || !e || !t) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_GROUP_get_order(ec_group, order, ctx)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}

	/* check r, s in [1, n-1] and r + s != 0 (mod n) */ 
	if (BN_is_zero(r) ||
		BN_is_negative(r) ||
		BN_ucmp(r, order) >= 0 || 
		BN_is_zero(s) ||
		BN_is_negative(s) || 
		BN_ucmp(s, order) >= 0) {

			ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ECDSA_R_BAD_SIGNATURE);
			ret = 0;
			goto err;
	}

	/* check t = r + s != 0 */
	if (!BN_mod_add(t, r, s, order, ctx)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	if (BN_is_zero(t)) {
		ret = 0;
		goto err;
	}

	/* convert digest to e */
	i = BN_num_bits(order);
#if 0
	if (8 * dgstlen > i) {
		dgstlen = (i + 7)/8;
	}
#endif
	if (!BN_bin2bn(rgbHashData, 32, e)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
#if 0
	if ((8 * dgstlen > i) && !BN_rshift(e, e, 8 - (i & 0x7))) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
#endif

	/* compute (x, y) = sG + tP, P is pub_key */
	if (!(point = EC_POINT_new(ec_group))) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if (!EC_POINT_mul(ec_group, point, s, pub_key, t, ctx)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
		goto err;
	}
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group)) == NID_X9_62_prime_field) {
		if (!EC_POINT_get_affine_coordinates_GFp(ec_group, point, t, NULL, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	} else /* NID_X9_62_characteristic_two_field */ { 
		if (!EC_POINT_get_affine_coordinates_GF2m(ec_group, point, t, NULL, ctx)) {
			ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_EC_LIB);
			goto err;
		}
	}
	if (!BN_nnmod(t, t, order, ctx)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}

	/* check (sG + tP).x + e  == sig.r */
	if (!BN_mod_add(t, t, e, order, ctx)) {
		ECDSAerr(ECDSA_F_ECDSA_DO_VERIFY, ERR_R_BN_LIB);
		goto err;
	}
	if (BN_ucmp(t, r) == 0) {
		ret = SM2_VERIFY_SUCCESS;
	} else {
		ret = SM2_VERIFY_FAILED;
	}

err:
	if (point) EC_POINT_free(point);
	if (order) BN_free(order);
	if (e) BN_free(e);
	if (t) BN_free(t);
	if (ctx) BN_CTX_free(ctx);
	return 0;
}

void Z_Gen(unsigned char *z, unsigned int klen, unsigned char *ID, unsigned char *x, unsigned char *y)
{
	// Tsp 需要
	// ZA=H256(ENTLA || IDA || a || b || xG || yG || xA || yA)。

	BN_CTX *ctx = NULL;
	ctx = BN_CTX_new();

	EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2p256v1);
	const EC_GROUP *ec_group = EC_KEY_get0_group(ec_key);


	BIGNUM *p = NULL, *a = NULL, *b = NULL, *gen = NULL,
		*order = NULL, *cofactor = NULL;

	if ((p = BN_new()) == NULL || (a = BN_new()) == NULL ||
		(b = BN_new()) == NULL || (order = BN_new()) == NULL ||
		(cofactor = BN_new()) == NULL) {
			goto err;
	}

	int is_char_two = 0;
	int tmp_nid = EC_METHOD_get_field_type(EC_GROUP_method_of(ec_group));

	if (tmp_nid == NID_X9_62_characteristic_two_field)
		is_char_two = 1;

#ifndef OPENSSL_NO_EC2M
	if (is_char_two) {
		if (!EC_GROUP_get_curve_GF2m(ec_group, p, a, b, ctx)) {
			goto err;
		}
	} else  /* prime field */
#endif
	{
		if (!EC_GROUP_get_curve_GFp(ec_group, p, a, b, ctx)) {
			goto err;
		}
	}

	const EC_POINT *generator = EC_GROUP_get0_generator(ec_group);

	unsigned char g[65];
	EC_POINT_point2oct(ec_group, generator, POINT_CONVERSION_UNCOMPRESSED, g, ECDH_SIZE, NULL);

	sm3_ctx_t ctx2;

	sm3_init(&ctx2);
	unsigned char entla[2];
	entla[0] = (klen / 32);
	entla[1] = (klen * 8);
	sm3_update(&ctx2, entla, sizeof(entla));
	sm3_update(&ctx2, ID, klen);

	unsigned char buffer[32];
	BN_bn2bin(a, buffer);
	sm3_update(&ctx2, buffer, 32);
	BN_bn2bin(b, buffer);
	sm3_update(&ctx2, buffer, 32);

	sm3_update(&ctx2, g + 1, 64);
	sm3_update(&ctx2, x, 32);
	sm3_update(&ctx2, y, 32);
	sm3_final(&ctx2, z);

err:
	return;
}
