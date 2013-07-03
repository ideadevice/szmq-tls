/* This example code is placed in the public domain. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "examples.h"


static const char *
bin2hex (const void *bin, size_t bin_size)
{
  static char printable[110];
  const unsigned char *_bin = bin;
  char *print;
  size_t i;

  if (bin_size > 50)
    bin_size = 50;

  print = printable;
  for (i = 0; i < bin_size; i++)
    {
      sprintf (print, "%.2x ", _bin[i]);
      print += 2;
    }

  return printable;
}

/* This function will print some details of the
 * given session.
 */
int
print_info (gnutls_session_t session)
{
  const char *tmp;
  gnutls_credentials_type_t cred;
  gnutls_kx_algorithm_t kx;
  int dhe, ecdh;

  dhe = ecdh = 0;

  /* print the key exchange's algorithm name
   */
  kx = gnutls_kx_get (session);
  tmp = gnutls_kx_get_name (kx);
  printf ("- Key Exchange: %s\n", tmp);

  /* Check the authentication type used and switch
   * to the appropriate.
   */
  cred = gnutls_auth_get_type (session);
  switch (cred)
    {
    case GNUTLS_CRD_IA:
      printf ("- TLS/IA session\n");
      break;


#ifdef ENABLE_SRP
    case GNUTLS_CRD_SRP:
      printf ("- SRP session with username %s\n",
              gnutls_srp_server_get_username (session));
      break;
#endif

    case GNUTLS_CRD_PSK:
      /* This returns NULL in server side.
       */
      if (gnutls_psk_client_get_hint (session) != NULL)
        printf ("- PSK authentication. PSK hint '%s'\n",
                gnutls_psk_client_get_hint (session));
      /* This returns NULL in client side.
       */
      if (gnutls_psk_server_get_username (session) != NULL)
        printf ("- PSK authentication. Connected as '%s'\n",
                gnutls_psk_server_get_username (session));

      if (kx == GNUTLS_KX_ECDHE_PSK)
        ecdh = 1;
      else if (kx == GNUTLS_KX_DHE_PSK)
        dhe = 1;
      break;

    case GNUTLS_CRD_ANON:      /* anonymous authentication */

      printf ("- Anonymous authentication.\n");
      if (kx == GNUTLS_KX_ANON_ECDH)
        ecdh = 1;
      else if (kx == GNUTLS_KX_ANON_DH)
        dhe = 1;
      break;

    case GNUTLS_CRD_CERTIFICATE:       /* certificate authentication */

      /* Check if we have been using ephemeral Diffie-Hellman.
       */
      if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS)
        dhe = 1;
      else if (kx == GNUTLS_KX_ECDHE_RSA || kx == GNUTLS_KX_ECDHE_ECDSA)
        ecdh = 1;

      /* if the certificate list is available, then
       * print some information about it.
       */
      print_x509_certificate_info (session);

    }                           /* switch */

  if (ecdh != 0)
    printf ("- Ephemeral ECDH using curve %s\n",
            gnutls_ecc_curve_get_name (gnutls_ecc_curve_get (session)));
  else if (dhe != 0)
    printf ("- Ephemeral DH using prime of %d bits\n",
            gnutls_dh_get_prime_bits (session));

  /* print the protocol's name (ie TLS 1.0) 
   */
  tmp = gnutls_protocol_get_name (gnutls_protocol_get_version (session));
  printf ("- Protocol: %s\n", tmp);

  /* print the certificate type of the peer.
   * ie X.509
   */
  tmp =
    gnutls_certificate_type_get_name (gnutls_certificate_type_get (session));

  printf ("- Certificate Type: %s\n", tmp);

  /* print the compression algorithm (if any)
   */
  tmp = gnutls_compression_get_name (gnutls_compression_get (session));
  printf ("- Compression: %s\n", tmp);

  /* print the name of the cipher used.
   * ie 3DES.
   */
  tmp = gnutls_cipher_get_name (gnutls_cipher_get (session));
  printf ("- Cipher: %s\n", tmp);

  /* Print the MAC algorithms name.
   * ie SHA1
   */
  tmp = gnutls_mac_get_name (gnutls_mac_get (session));
  printf ("- MAC: %s\n", tmp);

  return 0;
}

void
print_x509_certificate_info (gnutls_session_t session)
{
  char serial[40];
  char dn[256];
  size_t size;
  unsigned int algo, bits;
  time_t expiration_time, activation_time;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size = 0;
  gnutls_x509_crt_t cert;
  gnutls_datum_t cinfo;

  /* This function only works for X.509 certificates.
   */
  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
    return;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);

  printf ("Peer provided %d certificates.\n", cert_list_size);

  if (cert_list_size > 0)
    {
      int ret;

      /* we only print information about the first certificate.
       */
      gnutls_x509_crt_init (&cert);

      gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER);

      printf ("Certificate info:\n");

      /* This is the preferred way of printing short information about
         a certificate. */

      ret = gnutls_x509_crt_print (cert, GNUTLS_CRT_PRINT_ONELINE, &cinfo);
      if (ret == 0)
        {
          printf ("\t%s\n", cinfo.data);
          gnutls_free (cinfo.data);
        }

      /* If you want to extract fields manually for some other reason,
         below are popular example calls. */

      expiration_time = gnutls_x509_crt_get_expiration_time (cert);
      activation_time = gnutls_x509_crt_get_activation_time (cert);

      printf ("\tCertificate is valid since: %s", ctime (&activation_time));
      printf ("\tCertificate expires: %s", ctime (&expiration_time));

      /* Print the serial number of the certificate.
       */
      size = sizeof (serial);
      gnutls_x509_crt_get_serial (cert, serial, &size);

      printf ("\tCertificate serial number: %s\n", bin2hex (serial, size));

      /* Extract some of the public key algorithm's parameters
       */
      algo = gnutls_x509_crt_get_pk_algorithm (cert, &bits);

      printf ("Certificate public key: %s",
              gnutls_pk_algorithm_get_name (algo));

      /* Print the version of the X.509
       * certificate.
       */
      printf ("\tCertificate version: #%d\n",
              gnutls_x509_crt_get_version (cert));

      size = sizeof (dn);
      gnutls_x509_crt_get_dn (cert, dn, &size);
      printf ("\tDN: %s\n", dn);

      size = sizeof (dn);
      gnutls_x509_crt_get_issuer_dn (cert, dn, &size);
      printf ("\tIssuer's DN: %s\n", dn);

      gnutls_x509_crt_deinit (cert);

    }
}

