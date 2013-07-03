#include <stdio.h>
#include <stdlib.h>
#include <zmq.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include "../include/szmq.h"
#include "szmq_callback.h"


void szmq_global_init (szmq_context *szmq_ctx)
{
  gnutls_global_init ();

//  szmq_ctx = (szmq_context *) malloc ( sizeof ( szmq_context));

  gnutls_certificate_allocate_credentials (&(szmq_ctx->credentials));

  generate_dh_params (&(szmq_ctx->dh_params));

  gnutls_certificate_set_dh_params (szmq_ctx->credentials, szmq_ctx->dh_params);

  /* set gnutls priority priority string 
   call this function from your program to set a different value */
  gnutls_priority_init (&(szmq_ctx->priority), "NORMAL", NULL);

  /* set callback function to verify peer's certificate */
  gnutls_certificate_set_verify_function (szmq_ctx->credentials, _verify_certificate_callback);

}

int szmq_set_ca_file (szmq_context *szmq_ctx, const char *cafile, unsigned int flags)
{
  return gnutls_certificate_set_x509_trust_file (szmq_ctx->credentials, cafile, flags);
}

int szmq_set_key_file (szmq_context *szmq_ctx, const char *certfile,
		      const char *keyfile, unsigned int flags)
{
  return gnutls_certificate_set_x509_key_file (szmq_ctx->credentials,
					    certfile, keyfile,  flags);
}

int szmq_set_crl_file (szmq_context *szmq_ctx, const char *crlfile,unsigned int flags)
{
  return gnutls_certificate_set_x509_crl_file (szmq_ctx->credentials,
					      crlfile, flags);
}

/* Initialize szmq session.
This function initializes the gnutls session, sets up the required callbacks. */
void szmq_session_init (szmq_context *szmq_ctx, szmq_session  *session, void *socket, unsigned int flags)
{
 // session = (szmq_session *) malloc (sizeof(szmq_session));
  session->transport.pos = 0;
  session->transport.size = 0;
  session->transport.sending = 0;
  session->transport.zmq_flags = 0;
  session->transport.socket = socket;	/* zmq socket */
  session->type = flags;
  /* init gnutls session */
  gnutls_init (&(session->gnutls_session), flags);

  gnutls_transport_set_ptr ((session->gnutls_session), &(session->transport));

  gnutls_transport_set_push_function ((session->gnutls_session), z_send);

  gnutls_transport_set_pull_function ((session->gnutls_session), z_recv);

  gnutls_transport_set_pull_timeout_function ((session->gnutls_session), z_timeout);

  /* cipher suite priority for gnutls */
  gnutls_priority_set ((session->gnutls_session), szmq_ctx->priority);

  gnutls_credentials_set ((session->gnutls_session), GNUTLS_CRD_CERTIFICATE, szmq_ctx->credentials);

}

/* set last argument for the next zmq_send or zmq_recv call */
void szmq_set_flag(szmq_session *session, unsigned int flag)
{
  session->transport.zmq_flags = flag;
}

/* perform the TLS handshake */
int szmq_handshake (szmq_session *session, int timeout)
{
  fprintf(stderr, "Initiating handshake\n");
  int ret;
  gnutls_transport_set_push_function ((session->gnutls_session), z_send_handshake);
  gnutls_transport_set_pull_function ((session->gnutls_session), z_recv_handshake);
  gnutls_handshake_set_timeout(session->gnutls_session, timeout);
  zmq_pollitem_t item [] = { {session->transport.socket, 0, ZMQ_POLLIN | ZMQ_POLLOUT, 0} };
  do
  {
    /* In case of a server, poll the socket for incoming or outgoing messages.
      If there are unsent messages in zmq buffer this will continue the handshake without blocking.*/
    if(session->type & GNUTLS_SERVER) {
      if(zmq_poll(item, 1, -1) == 1) ret = gnutls_handshake (session->gnutls_session);
      /* retry without clearing the buffers for E_AGAIN and E_INTERRUPTED */
      if(ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) z_clear_buffer_server(session);
    }
    else {
      ret = gnutls_handshake (session->gnutls_session);
    }
  } while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

  if (ret < 0)
  {
    if(session->type & GNUTLS_SERVER) z_clear_buffer_server(session);
    fprintf (stderr, "*** Handshake has failed (%s)\n\n",
	    gnutls_strerror (ret));
  }
  /* after the handshake is over change to strictly synchronous callbacks */
  gnutls_transport_set_push_function ((session->gnutls_session), z_send);

  gnutls_transport_set_pull_function ((session->gnutls_session), z_recv);
  fprintf(stderr, "handshake done\n");
  return ret;
}

/* Sends the message on the zmq socket after encrypting */
int szmq_send(szmq_session *session,void *buf, size_t len)
{
  int ret;
  ret = gnutls_record_send(session->gnutls_session,(const void *) buf, len);
  session->transport.zmq_flags = 0;
  return ret;
}

/* Receives and decrypts message on the zmq socket */
int szmq_recv(szmq_session *session, void *buf, size_t len)
{
  int ret;
  ret = gnutls_record_recv(session->gnutls_session, buf, len);
  session->transport.zmq_flags = 0;
  return ret;
}

/* free the szmq session including the gnutls session */
void szmq_session_deinit(szmq_session *session)
{
  gnutls_deinit(session->gnutls_session);
//  free(session);
}

/* destroy szmq context and deinitialize gnutls global structs */
void szmq_global_deinit(szmq_context *ctx)
{
  gnutls_certificate_free_credentials(ctx->credentials);
  gnutls_priority_deinit(ctx->priority);
  gnutls_dh_params_deinit(ctx->dh_params);
//  free(ctx);
  gnutls_global_deinit();
}

/* close the szmq session */
int szmq_bye (szmq_session *session)
{
  return gnutls_bye(session->gnutls_session, GNUTLS_SHUT_WR);
}
