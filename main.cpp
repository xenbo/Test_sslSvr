#include <iostream>
//openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes

#include <stdio.h>
#include <signal.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define CERT_FILE    "/home/dongbo/Desktop/openssl/server.pem"
#define  KEY         "/home/dongbo/Desktop/openssl/server.pem"

BIO *in = NULL;

int main(int argc, char **argv) {
    char *port = NULL;
    BIO *ssl_bio, *tmp;
    SSL_CTX *ctx;
    SSL *ssl;
    char buf[512];
    int ret = 1, i;

    if (argc <= 1)
        port = (char*)"*:4442";
    else
        port = argv[1];


    SSL_load_error_strings();


/* Add ciphers and message digests */
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new(SSLv23_server_method());

    //SSL_CTX_set_ex_data(ctx,)

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

    const char* ssl_cipher_list = "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-SHA384:"
            "HIGH:!aNULL:!eNULL:!EXPORT:"
            "!DES:!MD5:!PSK:!RC4:!HMAC_SHA1:"
            "!SHA1:!DHE-RSA-AES128-GCM-SHA256:"
            "!DHE-RSA-AES128-SHA256:"
            "!AES128-GCM-SHA256:"
            "!AES128-SHA256:"
            "!DHE-RSA-AES256-SHA256:"
            "!AES256-GCM-SHA384:"
            "!AES256-SHA256";
    SSL_CTX_set_cipher_list(ctx,ssl_cipher_list);


    /* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
     * We just hardcode a single curve which is reasonably decent.
     * See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh (ctx, ecdh);


    if (! SSL_CTX_load_verify_locations(ctx, CERT_FILE, NULL))
        goto err;
    if (!SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_use_PrivateKey_file(ctx, KEY, SSL_FILETYPE_PEM))
        goto err;
    if (!SSL_CTX_check_private_key(ctx))
        goto err;


/* Setup server side SSL bio */
    ssl = SSL_new(ctx);
    ssl_bio = BIO_new_ssl(ctx, 0);

    if ((in = BIO_new_accept(port)) == NULL) goto err;

/* This means that when a new connection is acceptede on 'in',
 * The ssl_bio will be 'dupilcated' and have the new socket
 * BIO push into it.  Basically it means the SSL BIO will be
 * automatically setup */
    BIO_set_accept_bios(in, ssl_bio);

    again:
/* The first call will setup the accept socket, and the second
 * will get a socket.  In this loop, the first actual accept
 * will occur in the BIO_read() function. */

    if (BIO_do_accept(in) <= 0) goto err;

    for (;;) {
        i = BIO_read(in, buf, 512);
        if (i == 0) {
/* If we have finished, remove the underlying
 * BIO stack so the next time we call any function
 * for this BIO, it will attempt to do an
 * accept */
            printf("Done\n");
            tmp = BIO_pop(in);
            BIO_free_all(tmp);
            goto again;
        }
        if (i < 0) goto err;
        fwrite(buf, 1, i, stdout);
        fflush(stdout);
    }

    ret = 0;
    err:
    if (ret) {
        ERR_print_errors_fp(stderr);
    }
    if (in != NULL) BIO_free(in);
    exit(ret);
    return (!ret);
}