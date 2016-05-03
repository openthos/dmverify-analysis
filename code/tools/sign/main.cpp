
#include "apps.h"

#include "xsign.h"


static const char *ca_usage[] = {
	"usage: ca args\n",
	"\n",
	" -keyfile arg    - private key file\n",
	" -key arg        - key to decode the private key if it is encrypted\n",
	" -cert file      - The CA certificate\n",
	" -in file        - The input PEM encoded certificate request(s)\n",
	" -out file       - Where to put the output file(s)\n",
	NULL
};

int main(int argc, char *argv[])
{
	char *keyfile;
	char *certfile;
	char *infile;
	char *outfile;
	char *key = 0;
	int badops;

	do { 
		setup_ui_method();
		CRYPTO_malloc_init(); 
		ERR_load_crypto_strings(); 
		OpenSSL_add_all_algorithms(); 
	} while(0);


	BIO *bio_err;
#if defined WIN32
	bio_err = BIO_new_fd(2, BIO_NOCLOSE);
#else
	bio_err = BIO_new_fd(stderr, BIO_NOCLOSE);
#endif


	argc--;
	argv++;
	while (argc >= 1) {
		if (strcmp(*argv, "-keyfile") == 0) {
			if (--argc < 1)
				goto bad;
			keyfile = *(++argv);
		}
		else if (strcmp(*argv, "-key") == 0) {
			if (--argc < 1)
				goto bad;
			key = *(++argv);
		}
		else if (strcmp(*argv, "-cert") == 0) {
			if (--argc < 1)
				goto bad;
			certfile = *(++argv);
		}
		else if (strcmp(*argv, "-in") == 0) {
			if (--argc < 1)
				goto bad;
			infile = *(++argv);
		} else if (strcmp(*argv, "-out") == 0) {
			if (--argc < 1)
				goto bad;
			outfile = *(++argv);

		}
		else {
bad:
			BIO_printf(bio_err, "unknown option %s\n", *argv);
			break;
		}
		argc--;
		argv++;
	}

	if (badops) {
		const char **pp2;

		for (pp2 = ca_usage; (*pp2 != NULL); pp2++)
			BIO_printf(bio_err, "%s", *pp2);
		return 0;
	}


	EVP_PKEY *pkey = load_key(bio_err, keyfile, FORMAT_PEM, 0, key, "key");

	//if (EVP_PKEY_RSA == EVP_PKEY_type(pkey->type)) {
	//	return 0;
	//}

	X509 *x509 = load_cert(bio_err, certfile, FORMAT_PEM, NULL, "server certificate");

	// 验证证书与私钥是否匹配
	if (!X509_check_private_key(x509, pkey)) {
		BIO_printf(bio_err,
			"CA certificate and CA private key do not match\n");
		return 0;
	}

	XSign *xsign = XSign_new();

	ASN1_INTEGER_set(xsign->version, 1);

	xsign->origin = ASN1_PRINTABLESTRING_new();

	ASN1_STRING_set(xsign->origin, "zImage", 6);

	xsign->cert = x509;

	xsign->alg = x509->cert_info->signature;

	xsign->alg = X509_ALGOR_new();
	// NID_sm3WithSM2
	xsign->alg ->algorithm = OBJ_nid2obj(NID_sha1WithRSA);

	xsign->signature = ASN1_BIT_STRING_new();
	//ASN1_STRING_set(xsign->signature, "0123456789abcdef", 16);

	const EVP_MD *md = NULL;
	EVP_MD_CTX ctx;

	EVP_MD_CTX_init(&ctx);

	md = EVP_get_digestbyname("md5");

	EVP_PKEY_CTX *pctx = NULL;
	if (1 != EVP_SignInit_ex(&ctx, md, NULL)) {
		return 0;
	}

	BIO     *b=NULL;
	int     len=0,n1=0;
	char    *out=NULL;

	b=BIO_new_file(infile,"rb");
	len= 1024;
	out=(char *)OPENSSL_malloc(len);
	do 
	{     
		n1 = BIO_read(b, out, len);

		if (1 != EVP_SignUpdate(&ctx, out, n1)) {
			return 0;
		}
	} while(n1>0);
	BIO_free(b);
	OPENSSL_free(out);


	unsigned char digist[1024];
	int len2 = 1024;
	if (EVP_SignFinal(&ctx, digist,
		(size_t *)&len2, pkey) <= 0) {
			return -1;
	}
	ASN1_STRING_set(xsign->signature, digist, len2);

	int n = i2d_XSign(xsign, 0);
	unsigned char *buf = (unsigned char *)OPENSSL_malloc(n);
	unsigned char *ptr = buf;
	n = i2d_XSign(xsign, &buf);


	FILE *fp = fopen(outfile, "wb");
	fwrite(ptr, n, 1, fp);
	fclose(fp);

	OPENSSL_free(ptr);
	XSign_free(xsign);

	do { 
		CONF_modules_unload(1); 
		OBJ_cleanup(); 
		EVP_cleanup(); 
		CRYPTO_cleanup_all_ex_data(); 
		ERR_remove_thread_state(NULL); 
		RAND_cleanup(); 
		ERR_free_strings(); 
	} while(0);
	return 0;

}