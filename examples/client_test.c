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
  void  *context_server;
  void *requester;

  szmq_global_init(&s_ctx);
  szmq_set_ca_file (&s_ctx, CAFILE, GNUTLS_X509_FMT_PEM);
  szmq_set_crl_file (&s_ctx, CRLFILE, GNUTLS_X509_FMT_PEM);
  ret = szmq_set_key_file (&s_ctx, CERTFILE, KEYFILE, GNUTLS_X509_FMT_PEM);

  context_server = zmq_ctx_new();
  requester = zmq_socket(context_server, ZMQ_REQ);
  int rc = zmq_connect (requester, "tcp://localhost:5555");
  assert (rc == 0);

  szmq_session_init (&s_ctx, &s_sess, requester, GNUTLS_CLIENT);
  szmq_handshake (&s_sess, 10000);
  print_info(s_sess.gnutls_session);

  for (i=0;i<2;i++)
  {
    szmq_send (&s_sess, MSG, sizeof(MSG));

    ret = szmq_recv (&s_sess, buffer, MAX_BUF);

    printf ("- Received %d bytes: %s\n", ret, buffer);

  }

  szmq_bye (&s_sess);
  szmq_session_deinit (&s_sess);
  szmq_global_deinit (&s_ctx);
  return 0;

}

