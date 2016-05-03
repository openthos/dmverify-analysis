
typedef struct xsign_st {
	ASN1_INTEGER *version;      /* [ 0 ] default of v1 */
	ASN1_PRINTABLESTRING *origin;
	X509 *cert;
	X509_ALGOR *alg;
	ASN1_BIT_STRING *signature;
} XSign;


ASN1_SEQUENCE(XSign) = {
	ASN1_SIMPLE(XSign, version, ASN1_INTEGER),
	ASN1_SIMPLE(XSign, origin, ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(XSign, cert, X509),
	ASN1_SIMPLE(XSign, alg, X509_ALGOR),
	ASN1_SIMPLE(XSign, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(XSign)

IMPLEMENT_ASN1_FUNCTIONS(XSign)
