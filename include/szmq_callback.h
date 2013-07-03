#ifndef __SZMQ_CALLBACK_H_INCLUDED__
#define __SZMQ_CALLBACK_H_INCLUDED__

#include <gnutls/gnutls.h>

static int generate_dh_params (gnutls_dh_params_t *dh_params);

static int _verify_certificate_callback (gnutls_session_t session);

ssize_t z_send_handshake(gnutls_transport_ptr_t socket, const void* buf,size_t len );

ssize_t z_send(gnutls_transport_ptr_t socket, const void* buf,size_t len );

int z_recv_socket(gnutls_transport_ptr_t socket);

ssize_t z_recv_handshake(gnutls_transport_ptr_t socket, void* buf, size_t len);

ssize_t z_recv(gnutls_transport_ptr_t socket, void* buf, size_t len);

void z_clear_buffer_server(szmq_session *session);

int z_timeout(gnutls_transport_ptr_t socket, unsigned int time);

#endif
