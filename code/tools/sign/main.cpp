
#include "apps.h"

#include "xsign.h"

//
//#include "d:\thtfpc\gmssl\crypto\cpk\cpk.h"
//
static const char *ca_usage[] = {
	"usage: ca args\n",
	"\n",
	" -keyfile arg    - private key file\n",
	" -key arg        - key to decode the private key if it is encrypted\n",
	" -cert file      - The CA certificate\n",
	" -in file        - The input file\n",
	" -out file       Where-  to put the output file(s)\n",
	" -md arg         - md to use, one of md2, md5, sha, sha1 or sm3\n",
	NULL
};

int main(int argc, char *argv[])
{
	char *keyfile = 0;
	char *certfile = 0;
	char *infile = 0;
	char *outfile = 0;
	char *key = 0;
	const char *md = "default";
	int badops = 0;

	do { 
		setup_ui_method();
		//CRYPTO_malloc_init(); 
		ERR_load_crypto_strings(); 
		OpenSSL_add_all_algorithms(); 
	} while(0);


	BIO *bio_err;
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);


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
		else if (strcmp(*argv, "-md") == 0) {
			if (--argc < 1)
				goto bad;
			md = *(++argv);
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
			badops = 1;
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

	if (keyfile == 0) {
		BIO_printf(bio_err, "lookup failed for private key");
		return 0;
	}

	if (certfile == 0) {
		BIO_printf(bio_err, "lookup failed for cert file");
		return 0;
	}

	if (infile == 0) {
		BIO_printf(bio_err, "lookup failed for input file");
		return 0;
	}

	if (outfile == 0) {
		outfile = (char *)OPENSSL_malloc(strlen(infile) + 6);
		strcpy(outfile, infile);
		strcat(outfile, ".sign");
	}

	EVP_PKEY *pkey = load_key(bio_err, keyfile, FORMAT_PEM, 0, key, "key");
	if (pkey == NULL) {
		BIO_printf(bio_err, "bad key file");
		return 0;
	}
	else {
		//const char *name = OBJ_nid2sn(EVP_PKEY_type(pkey->type));
	}

	if (!strcmp(md, "default")) {
		int def_nid;
		if (EVP_PKEY_get_default_digest_nid(pkey, &def_nid) <= 0) {
			BIO_puts(bio_err, "no default digest\n");
			return 0;
		}
		md = (char *)OBJ_nid2sn(def_nid);
	}

	X509 *x509 = load_cert(bio_err, certfile, FORMAT_PEM, NULL, "server certificate");

	// 验证证书与私钥是否匹配
	if (!X509_check_private_key(x509, pkey)) {
		BIO_printf(bio_err,
			"CA certificate and CA private key do not match\n");
		return 0;
	}

	int sigid;
#if 0
	if (1 != OBJ_find_sigid_by_algs(&sigid, OBJ_sn2nid(md), EVP_PKEY_type(pkey->type))) {
#else
	if (1 != OBJ_find_sigid_by_algs(&sigid, OBJ_sn2nid(md), EVP_PKEY_id(pkey))) {
#endif
		BIO_printf(bio_err,
			"assign the sign alg\n");
		return 0;
	}

	XSign *xsign = XSign_new();

	ASN1_INTEGER_set(xsign->version, 1);

	xsign->origin = ASN1_PRINTABLESTRING_new();

	ASN1_STRING_set(xsign->origin, infile, strlen(infile));

	xsign->cert = x509;

	xsign->alg = X509_ALGOR_new();
	xsign->alg ->algorithm = OBJ_nid2obj(sigid);
	xsign->alg->parameter = ASN1_TYPE_new();
	xsign->alg->parameter->type = V_ASN1_NULL;

	xsign->signature = ASN1_BIT_STRING_new();
	//ASN1_STRING_set(xsign->signature, "0123456789abcdef", 16);

	const EVP_MD *dgst = NULL;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	EVP_MD_CTX_init(ctx);
	dgst = EVP_get_digestbyname(md);
	fprintf(stderr, "Using client alg %s\n", EVP_MD_name(dgst));

	// EVP_PKEY_CTX *pctx = NULL;
	if (!EVP_SignInit_ex(ctx, dgst, NULL)) {
		ERR_print_errors(bio_err);
		return 0;
	}

	BIO     *b=NULL;
	char    *out=NULL;
#define BUF_SIZE 1024
	b=BIO_new_file(infile,"rb");
	out=(char *)OPENSSL_malloc(BUF_SIZE);
	int n1 = 0;
	do 
	{     
		n1 = BIO_read(b, out, BUF_SIZE);

		if (1 != EVP_SignUpdate(ctx, out, n1)) {
			return 0;
		}
	} while(n1>0);
	BIO_free(b);
	OPENSSL_free(out);


	unsigned char digist[BUF_SIZE];
	int len2 = BUF_SIZE;
	if (EVP_SignFinal(ctx, digist,
		(unsigned int *)&len2, pkey) <= 0) {
			return -1;
	}
	ASN1_STRING_set(xsign->signature, digist, len2);

	int n = i2d_XSign(xsign, 0);
	unsigned char *buf = (unsigned char *)OPENSSL_malloc(n);
	unsigned char *ptr = buf;
	n = i2d_XSign(xsign, &buf);

	EVP_MD_CTX_free(ctx);

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

