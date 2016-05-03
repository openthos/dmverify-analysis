

#include "apps.h"


# define PW_MIN_LENGTH 4
typedef struct pw_cb_data {
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;

BIO *bio_err = NULL;

#define OPENSSL_NO_ENGINE

static UI_METHOD *ui_method = NULL;


static int ui_open(UI *ui)
{
	return UI_method_get_opener(UI_OpenSSL())(ui);
}

static int ui_read(UI *ui, UI_STRING *uis)
{
	if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
		&& UI_get0_user_data(ui)) {
			switch (UI_get_string_type(uis)) {
		case UIT_PROMPT:
		case UIT_VERIFY:
			{
				const char *password =
					(const char *)((PW_CB_DATA *)UI_get0_user_data(ui))->password;
				if (password && password[0] != '\0') {
					UI_set_result(ui, uis, password);
					return 1;
				}
			}
		default:
			break;
			}
	}
	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}

static int ui_write(UI *ui, UI_STRING *uis)
{
	if (UI_get_input_flags(uis) & UI_INPUT_FLAG_DEFAULT_PWD
		&& UI_get0_user_data(ui)) {
			switch (UI_get_string_type(uis)) {
		case UIT_PROMPT:
		case UIT_VERIFY:
			{
				const char *password =
					(const char *)((PW_CB_DATA *)UI_get0_user_data(ui))->password;
				if (password && password[0] != '\0')
					return 1;
			}
		default:
			break;
			}
	}
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}

static int ui_close(UI *ui)
{
	return UI_method_get_closer(UI_OpenSSL())(ui);
}

int setup_ui_method(void)
{
	ui_method = UI_create_method("OpenSSL application user interface");
	UI_method_set_opener(ui_method, ui_open);
	UI_method_set_reader(ui_method, ui_read);
	UI_method_set_writer(ui_method, ui_write);
	UI_method_set_closer(ui_method, ui_close);
	return 0;
}


int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp)
{
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data) {
		if (cb_data->password)
			password = (const char *)cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}

	if (password) {
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}

	ui = UI_new_method(ui_method);
	if (ui) {
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);
		if (!prompt) {
			BIO_printf(bio_err, "Out of memory\n");
			UI_free(ui);
			return 0;
		}

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui, prompt, ui_flags, buf,
			PW_MIN_LENGTH, bufsiz - 1);
		if (ok >= 0 && verify) {
			buff = (char *)OPENSSL_malloc(bufsiz);
			if (!buff) {
				BIO_printf(bio_err, "Out of memory\n");
				UI_free(ui);
				OPENSSL_free(prompt);
				return 0;
			}
			ok = UI_add_verify_string(ui, prompt, ui_flags, buff,
				PW_MIN_LENGTH, bufsiz - 1, buf);
		}
		if (ok >= 0)
			do {
				ok = UI_process(ui);
			}
			while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

			if (buff) {
				OPENSSL_cleanse(buff, (unsigned int)bufsiz);
				OPENSSL_free(buff);
			}

			if (ok >= 0)
				res = strlen(buf);
			if (ok == -1) {
				BIO_printf(bio_err, "User interface error\n");
				ERR_print_errors(bio_err);
				OPENSSL_cleanse(buf, (unsigned int)bufsiz);
				res = 0;
			}
			if (ok == -2) {
				BIO_printf(bio_err, "aborted!\n");
				OPENSSL_cleanse(buf, (unsigned int)bufsiz);
				res = 0;
			}
			UI_free(ui);
			OPENSSL_free(prompt);
	}
	return res;
}

static int load_pkcs12(BIO *err, BIO *in, const char *desc,
					   pem_password_cb *pem_cb, void *cb_data,
					   EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
	const char *pass;
	char tpass[PEM_BUFSIZE];
	int len, ret = 0;
	PKCS12 *p12;
	p12 = d2i_PKCS12_bio(in, NULL);
	if (p12 == NULL) {
		BIO_printf(err, "Error loading PKCS12 file for %s\n", desc);
		goto die;
	}
	/* See if an empty password will do */
	if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
		pass = "";
	else {
		if (!pem_cb)
			pem_cb = (pem_password_cb *)password_callback;
		len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
		if (len < 0) {
			BIO_printf(err, "Passpharse callback error for %s\n", desc);
			goto die;
		}
		if (len < PEM_BUFSIZE)
			tpass[len] = 0;
		if (!PKCS12_verify_mac(p12, tpass, len)) {
			BIO_printf(err,
				"Mac verify error (wrong password?) in PKCS12 file for %s\n",
				desc);
			goto die;
		}
		pass = tpass;
	}
	ret = PKCS12_parse(p12, pass, pkey, cert, ca);
die:
	if (p12)
		PKCS12_free(p12);
	return ret;
}

EVP_PKEY *load_key(BIO *err, const char *file, int format, int maybe_stdin,
				   const char *pass, const char *key_descrip)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	key = BIO_new(BIO_s_file());
	if (key == NULL) {
		ERR_print_errors(err);
		goto end;
	}

	if (BIO_read_filename(key, file) <= 0) {
		BIO_printf(err, "Error opening %s %s\n", key_descrip, file);
		ERR_print_errors(err);
		goto end;
	}

	if (format == FORMAT_ASN1) {
		pkey = d2i_PrivateKey_bio(key, NULL);
	} else if (format == FORMAT_PEM) {
		pkey = PEM_read_bio_PrivateKey(key, NULL,
			(pem_password_cb *)password_callback,
			&cb_data);
	}
	else if (format == FORMAT_PKCS12) {
		if (!load_pkcs12(err, key, key_descrip,
			(pem_password_cb *)password_callback, &cb_data,
			&pkey, NULL, NULL))
			goto end;
	}
	else if (format == FORMAT_MSBLOB)
		pkey = b2i_PrivateKey_bio(key);
	else {
		BIO_printf(err, "bad input format specified for key file\n");
		goto end;
	}
end:
	if (key != NULL)
		BIO_free(key);
	if (pkey == NULL) {
		BIO_printf(err, "unable to load %s\n", key_descrip);
		ERR_print_errors(err);
	}
	return (pkey);
}

EVP_PKEY *load_pubkey(BIO *err, const char *file, int format, int maybe_stdin,
					  const char *pass, const char *key_descrip)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	key = BIO_new(BIO_s_file());
	if (key == NULL) {
		ERR_print_errors(err);
		goto end;
	}
	if (BIO_read_filename(key, file) <= 0) {
		BIO_printf(err, "Error opening %s %s\n", key_descrip, file);
		ERR_print_errors(err);
		goto end;
	}
	if (format == FORMAT_ASN1) {
		pkey = d2i_PUBKEY_bio(key, NULL);
	}
#ifndef OPENSSL_NO_RSA
	else if (format == FORMAT_ASN1RSA) {
		RSA *rsa;
		rsa = d2i_RSAPublicKey_bio(key, NULL);
		if (rsa) {
			pkey = EVP_PKEY_new();
			if (pkey)
				EVP_PKEY_set1_RSA(pkey, rsa);
			RSA_free(rsa);
		} else
			pkey = NULL;
	} else if (format == FORMAT_PEMRSA) {
		RSA *rsa;
		rsa = PEM_read_bio_RSAPublicKey(key, NULL,
			(pem_password_cb *)password_callback,
			&cb_data);
		if (rsa) {
			pkey = EVP_PKEY_new();
			if (pkey)
				EVP_PKEY_set1_RSA(pkey, rsa);
			RSA_free(rsa);
		} else
			pkey = NULL;
	}
#endif
	else if (format == FORMAT_PEM) {
		pkey = PEM_read_bio_PUBKEY(key, NULL,
			(pem_password_cb *)password_callback,
			&cb_data);
	}
	else if (format == FORMAT_MSBLOB) {
		pkey = b2i_PublicKey_bio(key);
	}
	else {
		BIO_printf(err, "bad input format specified for key file\n");
		goto end;
	}
end:
	if (key != NULL)
		BIO_free(key);
	if (pkey == NULL)
		BIO_printf(err, "unable to load %s\n", key_descrip);
	return (pkey);
}

X509 *load_cert(BIO *err, const char *file, int format,
				const char *pass, const char *cert_descrip)
{

	X509 *x = NULL;
	BIO *cert;

	if ((cert = BIO_new(BIO_s_file())) == NULL) {
		ERR_print_errors(err);
		goto end;
	}

	if (BIO_read_filename(cert, file) <= 0) {
		BIO_printf(err, "Error opening %s %s\n", cert_descrip, file);
		ERR_print_errors(err);
		goto end;
	}

	if (format == FORMAT_ASN1) {
		x = d2i_X509_bio(cert, NULL);
	} 
	else if (format == FORMAT_PEM) {
		x = PEM_read_bio_X509_AUX(cert, NULL,
			(pem_password_cb *)password_callback, NULL);
	}
	else if (format == FORMAT_PKCS12) {
		if (!load_pkcs12(err, cert, cert_descrip, NULL, NULL, NULL, &x, NULL))
			goto end;
	} else {
		BIO_printf(err, "bad input format specified for %s\n", cert_descrip);
		goto end;
	}
end:
	if (x == NULL) {
		BIO_printf(err, "unable to load certificate\n");
		ERR_print_errors(err);
	}
	if (cert != NULL)
		BIO_free(cert);
	return (x);
}