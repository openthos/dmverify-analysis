#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
//#include <openssl/sm2.h>
//#include <openssl/sm3.h>
//#include <openssl/sms4.h>

#include <openssl/ui.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#pragma comment(lib, "libeay32")
#pragma comment(lib, "ssleay32")

# define FORMAT_UNDEF    0
# define FORMAT_ASN1     1
# define FORMAT_PEM      3
# define FORMAT_NETSCAPE 4
# define FORMAT_PKCS12   5
# define FORMAT_SMIME    6
# define FORMAT_ENGINE   7
# define FORMAT_IISSGC   8      /* XXX this stupid macro helps us to avoid
                                 * adding yet another param to load_*key() */
# define FORMAT_PEMRSA   9      /* PEM RSAPubicKey format */
# define FORMAT_ASN1RSA  10     /* DER RSAPubicKey format */
# define FORMAT_MSBLOB   11     /* MS Key blob format */
# define FORMAT_PVK      12     /* MS PVK file format */

# define EXT_COPY_NONE   0
# define EXT_COPY_ADD    1
# define EXT_COPY_ALL    2

# define NETSCAPE_CERT_HDR       "certificate"


int setup_ui_method(void);


EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
				   const char *pass, const char *key_descrip);


EVP_PKEY *load_pubkey(BIO *err, const char *file, int format, int maybe_stdin,
					  const char *pass, const char *key_descrip);

X509 *load_cert(BIO *err, const char *file, int format,
				const char *pass, const char *cert_descrip);

