#include <stdio.h>
#include <stdlib.h>
#include <zmq.h>
#include <assert.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <szmq_callback.h>


void szmq_global_init (szmq-context *szmq_ctx)
{
  gnutls_global_init ();

  szmq_ctx = (szmq_context *) malloc ( sizeof ( szmq_context));

  gnutls_certificate_allocate_credentials (&(szmq_ctx->credentials));

  generate_dh_params (&(szmq_ctx->dh_params));

  gnutls_certificate_set_dh_params (szmq_ctx->credentials, szmq_ctx->dh_params);

  gnutls_priority_init (&(szmq_ctx->priority), "NORMAL", NULL);

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
					    certile, keyfile,  flags);
}

int szmq_set_crl_file (szmq_context *szmq_ctx, const char *crlfile,unsigned int flags)
{
  return gnutls_certificate_set_x509_crl_file (szmq_ctx->credentials,
					      crlfile, flags);
}

void szmq_session_init (szmq_context *szmq_ctx, szmq_session  *session,			      void *socket, unsigned int flags)
{
  session = (szmq_session *) malloc (sizeof(szmq_session));
  session->flags = flags;
  gnutls_init (&(session->gnutls_session), flags);

  gnutls_transport_set_ptr ((session->gnutls_session), socket);

  gnutls_transport_set_push_function ((session->gnutls_session), z_send);

  gnutls_transport_set_pull_function ((session->gnutls_session), z_recv);

  gnutls_transport_set_pull_timeout_function ((session->gnutls_session), z_timeout);

  gnutls_priority_set ((session->gnutls_session), szmq_ctx->priority);

  gnutls_credentials_set ((session->gnutls_session), GNUTLS_CRD_CERTIFICATE, szmq_ctx->credentials);

}

void szmq_set_flag(void *session, unsigned int flag)
{
  session->zmq_flags = flag;
}

int szmq_handshake (szmq_session *session, int timeout)
{
  int ret;
  void *socket = gnutls_transport_get_ptr(session->gnutls_session);
  gnutls_transport_set_push_function ((session->gnutls_session), z_send_handshake);

  gnutls_transport_set_pull_function ((session->gnutls_session), z_recv_handshake);
  gnutls_handshake_set_timeout(session->gnutls_session, timeout);
  zmq_pollitem_t item [] = { {socket, 0, ZMQ_POLLIN | ZMQ_POLLOUT, 0} };
  do
  {
    if(session->flags & GNUTLS_SERVER) {
      if(zmq_poll(item, 1, -1) == 1) ret = gnutls_handshake (session);
      if(ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) z_clear_buffer_server(socket);
    }
    else {
      ret = gnutls_handshake (session);
    }
  } while (ret < 0 && gnutls_error_is_fatal (ret) == 0);

  if (ret < 0)
  {
    if(session->flags & GNUTLS_SERVER) z_clear_buffer_server(socket);
    fprintf (stderr, "*** Handshake has failed (%s)\n\n",
	    gnutls_strerror (ret));
    sleep(1);
    continue;
  }
  gnutls_transport_set_push_function ((session->gnutls_session), z_send);

  gnutls_transport_set_pull_function ((session->gnutls_session), z_recv);
  return ret;
}


int szmq_send(szmq_session *session,void *buf, size_t len)
{
  int ret;
  ret = gnutls_record_send(session->gnutls_session,(const void *) buf, len, session->zmq_flags);
  session->zmq_flags = 0;
  return ret;
}

int szmq_recv(szmq_session *session, void *buf, size_t len)
{
  int ret;
  ret = gnutls_record_recv(session->gnutls_session, buf, len, session->zmq_flags);
  session->zmq_flags = 0;
  return ret;
}

void szmq_session_deinit(szmq_session *session)
{
  gnutls_deinit(session->gnutls_session);
  free(session);
}

void szmq_global_deinit(szmq_context *ctx)
{
  gnutls_certificate_free_credentials(ctx->credentials);
  gnutls_priority_deinit(ctx->priority);
  gnutls_dh_params_deinit(ctx->dh_params);
  free(ctx);
  gnutls_global_deinit();
}


int szmq_bye (szmq_session *session)
{
  return gnutls_bye(session->gnutls_session, GNUTLS_SHUT_WR);
}
