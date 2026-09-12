#include "transport_tls.h"

#include <openssl/pem.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#ifndef _WIN32
#include <sys/stat.h>
#endif

static const uint16_t insecure_verify_algorithms[] = {
    PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    PTLS_SIGNATURE_RSA_PKCS1_SHA256, UINT16_MAX};

static int verify_any_certificate(
    ptls_verify_certificate_t *self, ptls_t *tls, const char *server_name,
    int (**verify_sign)(void *verify_ctx, uint16_t algorithm, ptls_iovec_t data,
                        ptls_iovec_t signature),
    void **verify_data, ptls_iovec_t *certificates, size_t certificate_count) {
  (void)self;
  (void)tls;
  (void)server_name;
  (void)verify_sign;
  (void)verify_data;
  (void)certificates;
  (void)certificate_count;
  return 0;
}

int transport_tls_load_certificate_and_key(
    ptls_context_t *tls, ptls_openssl_sign_certificate_t *signer,
    const char *certificate_file, const char *key_file) {
  if (!tls || !signer || !certificate_file || !key_file) {
    fprintf(stderr, "certificate file and key file are required\n");
    return -1;
  }
#ifndef _WIN32
  struct stat key_stat;
  if (stat(key_file, &key_stat) != 0) {
    fprintf(stderr, "failed to inspect private key file\n");
    return -1;
  }
  if ((key_stat.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) != 0) {
    fprintf(stderr,
            "private key permissions are unsafe; remove group write/execute "
            "and all access for other users\n");
    return -1;
  }
#endif
  if (ptls_load_certificates(tls, (char *)certificate_file) != 0) {
    fprintf(stderr, "failed to load certificates\n");
    return -1;
  }

  FILE *file = fopen(key_file, "r");
  if (!file) {
    fprintf(stderr, "failed to open private key file\n");
    return -1;
  }
  EVP_PKEY *key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
  fclose(file);
  if (!key) {
    fprintf(stderr, "failed to load private key\n");
    return -1;
  }
  const unsigned char *der =
      tls->certificates.count != 0 ? tls->certificates.list[0].base : NULL;
  X509 *leaf = der ? d2i_X509(NULL, &der, tls->certificates.list[0].len) : NULL;
  bool matches = leaf && X509_check_private_key(leaf, key) == 1;
  X509_free(leaf);
  if (!matches) {
    EVP_PKEY_free(key);
    fprintf(stderr, "certificate and private key do not match\n");
    return -1;
  }
  if (ptls_openssl_init_sign_certificate(signer, key) != 0) {
    EVP_PKEY_free(key);
    fprintf(stderr, "failed to initialize certificate signer\n");
    return -1;
  }
  EVP_PKEY_free(key);
  tls->sign_certificate = &signer->super;
  return 0;
}

void transport_tls_init_insecure_verifier(
    ptls_openssl_verify_certificate_t *verifier) {
  if (!verifier)
    return;
  verifier->super.cb = verify_any_certificate;
  verifier->super.algos = insecure_verify_algorithms;
}
