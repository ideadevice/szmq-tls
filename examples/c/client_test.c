#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <zmq.h>
#include "../../src/szmq.c"
#include "../../src/szmq_callback.c"
//#include "../include/szmq.h"
//#include <szmq.h>
#include "session-info.c"

#define KEYFILE "/home/harsh/ssl_key"
#define CERTFILE "/home/harsh/harsh.crt"
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"
#define CRLFILE "crl.pem"

#define MAX_BUF 1024
#define MSG "HELLO\0"


int main (void)
{
  int ret, i;
  szmq_session s_sess;
  szmq_context s_ctx;
  char buffer[MAX_BUF + 1];
  void  *context_client;
  void *requester;

  /* initialize global SZMQ context and global parameters for GNUTLS */
  szmq_global_init(&s_ctx);
  
  /* Provide trusted CAs file */
  szmq_set_ca_file (&s_ctx, CAFILE, GNUTLS_X509_FMT_PEM);
  
  /* Add the Certificate revocation lists(CRLs) with appropriate flags */
  szmq_set_crl_file (&s_ctx, CRLFILE, GNUTLS_X509_FMT_PEM);
  
  /* Provide key pair for the certificate to be used in GNUTLS communication */
  ret = szmq_set_key_file (&s_ctx, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM);

  /* Create a new ZMQ context */
  context_client = zmq_ctx_new();
  
  /* Create a ZMQ_REQ type socket to make requests */
  requester = zmq_socket(context_client, ZMQ_REQ);
  
  /* Connect the socket to create outgoing connections from the specified endpoint */
  int rc = zmq_connect (requester, "tcp://localhost:5555");
  assert (rc == 0);

  /* Initialize a GNUTLS session */
  szmq_session_init (&s_ctx, &s_sess, requester, GNUTLS_CLIENT);
 
  /* To verify if the peer's name matches the one on the provided 
     certificate, set the name of the host you want to connect to.*/
  //gnutls_session_set_ptr(s_sess.gnutls_session, "harsh");
  
  /* Perform the handshake with a timeout of 10000 milliseconds*/
  szmq_handshake (&s_sess, 10000);
  print_info(s_sess.gnutls_session);

  /* Send and receive messages from the server in a loop and print the received message */
  for (i=0;i<2;i++)
  {
    szmq_send (&s_sess, MSG, sizeof(MSG));

    ret = szmq_recv (&s_sess, buffer, MAX_BUF);

    printf ("- Received %d bytes: %s\n", ret, buffer);

  }

  /* Destroy the SZMQ session along with the GNUTLS session */
  szmq_bye (&s_sess);
  /* Terminate the connection */
  szmq_session_deinit (&s_sess);
  /* Destroy the SZMQ context and free all GNUTLS globals set in the beginning */
  szmq_global_deinit (&s_ctx);
  
  return 0;

}

