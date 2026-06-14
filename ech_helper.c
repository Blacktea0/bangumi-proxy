#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>

/* Connect with GREASE ECH, return retry-config binary via out params.
   Returns: 1 = got retry-config, 0 = failed. */
int ech_get_retry_config(
    const char *host, int port,
    const char *outer_sni,
    unsigned char **out_config, size_t *out_len)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 0;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(ctx, (uint64_t)1 << 37); /* SSL_OP_ECH_GREASE */

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return 0; }

    char hostname[256];
    snprintf(hostname, sizeof(hostname), "%s:%d", host, port);

    BIO *bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, hostname);

    SSL *ssl2 = NULL;
    BIO_get_ssl(bio, &ssl2);
    if (!ssl2) { BIO_free_all(bio); SSL_CTX_free(ctx); return 0; }

    SSL_set_tlsext_host_name(ssl2, outer_sni);

    int ret = 0;
    if (BIO_do_connect(bio) > 0) {
        int st = SSL_ech_get1_status(ssl2, NULL, NULL);
        if (st != 1) {
            /* ECH didn't succeed - try to get retry config */
            unsigned char *ec = NULL;
            size_t eclen = 0;
            if (SSL_ech_get1_retry_config(ssl2, &ec, &eclen) == 1 && ec && eclen > 0) {
                *out_config = (unsigned char *)malloc(eclen);
                if (*out_config) {
                    memcpy(*out_config, ec, eclen);
                    *out_len = eclen;
                    ret = 1;
                }
                OPENSSL_free(ec);
            }
        }
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    return ret;
}

void ech_free(void *p) { free(p); }
