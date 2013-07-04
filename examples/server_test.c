#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <zmq.h>
//#include "../src/szmq.c"
//#include "../src/szmq_callback.c"
//#include "../include/szmq.h"
#include <szmq.h>

#define KEYFILE "/home/harsh/ssl_key"
#define CERTFILE "/home/harsh/harsh.crt"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define CRLFILE "crl.pem"

#define MAX_BUF 1024
#define MSG "WORLD\0"


int main (void)
{
  int ret;
  szmq_session s_sess;
  szmq_context s_ctx;
  char buffer[MAX_BUF + 1];
  void  *context_server;
  void *responder;

  /* initialize global SZMQ context and global parameters for GNUTLS */
  szmq_global_init(&s_ctx);
  
  /* Provide trusted CAs file */
  szmq_set_ca_file (&s_ctx, CAFILE, GNUTLS_X509_FMT_PEM);
  
  /* Add the Certificate revocation lists(CRLs) with appropriate flags */
  szmq_set_crl_file (&s_ctx, CRLFILE, GNUTLS_X509_FMT_PEM);
  
  /* Provide key pair for the certificate to be used in GNUTLS communication */
  ret = szmq_set_key_file (&s_ctx, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM);

  /* Create a new ZMQ context */
  context_server = zmq_ctx_new();
  
  /* Create a ZMQ_REP type socket to accept requests and reply to them */
  responder = zmq_socket(context_server, ZMQ_REP);
  
  /* Bind the socket to accept incoming connections at the specified endpoint */
  int rc = zmq_bind (responder, "tcp://*:5555");
  assert (rc == 0);

  /* Initialize a GNUTLS session */
  szmq_session_init (&s_ctx, &s_sess, responder, GNUTLS_SERVER);

  /* Perform the handshake with a timeout of 10000 milliseconds*/
  szmq_handshake (&s_sess, 10000);
  
  /* Keep waiting for requests */
  while(1)
  {
    ret = szmq_recv (&s_sess, buffer, MAX_BUF);
    if(ret <= 0) goto end;
    else printf ("- Received %d bytes: %s\n", ret, buffer);

    szmq_send (&s_sess, MSG, sizeof(MSG));
  }

end:
  /* Destroy the SZMQ session along with the GNUTLS session */
  szmq_bye (&s_sess);
  /* Terminate the connection */
  szmq_session_deinit (&s_sess);
  /* Destroy the SZMQ context and free all GNUTLS globals set in the beginning */
  szmq_global_deinit (&s_ctx);
  
  return 0;

}

