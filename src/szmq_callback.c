#include <stdio.h>
#include <stdlib.h>
#include <zmq.h>
#include <assert.h>
#include <errno.h>
#include <gnutls/gnutls.h>

static int
generate_dh_params (gnutls_dh_params_t *dh_params)
{
  unsigned int bits = 
    gnutls_sec_param_to_pk_bits (GNUTLS_PK_DH, GNUTLS_SEC_PARAM_LEGACY);

  /* Generate Diffie-Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters often.
   */
  gnutls_dh_params_init (dh_params);
  gnutls_dh_params_generate2 (*dh_params, bits);

  return 0;
}

static int
_verify_certificate_callback (gnutls_session_t session)
{
  return 0;
  unsigned int status;
  int ret, type;
  const char *hostname;
  gnutls_datum_t out;

  /* read hostname */
  hostname = gnutls_session_get_ptr (session);
  /* This verification function uses the trusted CAs in the credentials
   * structure. So you must have installed one or more CA certificates.
   */
  ret = gnutls_certificate_verify_peers3 (session, hostname, &status);
  if (ret < 0)
    {
      printf ("Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }

  type = gnutls_certificate_type_get (session);

  ret = gnutls_certificate_verification_status_print( status, type, &out, 0);
  if (ret < 0)
    {
      printf ("Error\n");
      return GNUTLS_E_CERTIFICATE_ERROR;
    }
  
  printf ("%s", out.data);
  
  gnutls_free(out.data);

  if (status != 0) /* Certificate is not trusted */
      return GNUTLS_E_CERTIFICATE_ERROR;

  /* notify gnutls to continue handshake normally */
  return 0;
}

// Push function to be used during gnutls handshake
ssize_t z_send_handshake(gnutls_transport_ptr_t socket, const void* buf,size_t len )
{
  char c;
  
  if(SZMQ_DEBUG_FUNCTION_CALLS) fprintf(stderr,"handshake sending...\n");
  sending = 1;

  // During TLS handshake, we may need to send multiple messages before receiving. 
  // Send them as multipart messages to avoid EFSM on req-rep sockets. Send a delimiter frame later before receiving.
  int rc = zmq_send(socket, buf, len, ZMQ_SNDMORE);
  if(rc < 0) perror("send error");
  else if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr,"Message queued %d\n",rc);
  return rc;
}

// Push function to be used after handshake is over.
// Follows request-reply mode strictly.
ssize_t z_send(gnutls_transport_ptr_t socket, const void* buf,size_t len )
{
  if(SZMQ_DEBUG_FUNCTION_CALLS) fprintf(stderr,"sending...\n");
  int rc = zmq_send((void *)socket,buf, len, zmq_flags);
  zmq_flags = 0;
  if(rc < 0) perror("send error");
  else if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr," Send successful %d\n",rc);
  return rc;
}

// Helper function for reading messages from ZMQ socket
int z_recv_socket(gnutls_transport_ptr_t socket)
{
    int size = zmq_recv(socket, recv_buf, RECV_BUFSIZE, zmq_flags);
    zmq_flags = 0;

    if(size < 0) {
      perror("receive error");
      return -1;
    }

    if(size >= RECV_BUFSIZE) {
      fprintf(stderr,"receive buffer overflow\n");
      return -1;
    }

    pos = 0;

    if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr, "Received message %d\n",size);
    return size;
}

// Pull function to be used during gnutls handshake
ssize_t z_recv_handshake(gnutls_transport_ptr_t socket, void* buf, size_t len)
{
  if(SZMQ_DEBUG_FUNCTION_CALLS) fprintf(stderr,"handshake receiving...\n");

  // If buffer is empty, read data from ZMQ socket
  if(size == 0) {
    size = z_recv_socket(socket);
    if(size < 0) return -1;
  }

  // Copy the portion of the received message required by gnutls
  memcpy(buf, (recv_buf+ pos), len);
  if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr, "Read message from buffer %d\n",len);
  pos += len;
  size -= len;

  // If buffer is empty receive the next message part or the delimiter.
  if(size == 0) {
    size = z_recv_socket(socket);
    if(size < 0) return -1;
  }
  return len;
}

// Pull function to be used after handshake is over.
// Follows request-reply mode strictly.
ssize_t z_recv(gnutls_transport_ptr_t socket, void* buf, size_t len)
{
  if(SZMQ_DEBUG_FUNCTION_CALLS) fprintf(stderr,"receiving...\n");

  // If buffer is empty, read data from ZMQ socket
  if(size == 0 ) {
    size = z_recv_socket(socket);
    if(size < 0) return -1;
  }

  // Copy the portion required by gnutls
  memcpy(buf, (recv_buf + pos), len);
  if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr, "Read message from buffer %d\n",len);
  pos += len;
  size -= len;
  return len;
}

// Clear server buffer after handshake
void z_clear_buffer_server(void* socket, int ret)
{
  if(SZMQ_DEBUG_FUNCTION_CALLS) fprintf(stderr,"clearing buffer...\n");
  z_print_state();
  pos = 0;
  size = 0;

  // Discard any unread messages from a failed handshake
  zmq_pollitem_t item [] = { {socket, 0, ZMQ_POLLIN, 0} };
  while(zmq_poll(item, 1, 0) == 1) {
    zmq_recv(socket, recv_buf, RECV_BUFSIZE, 0);
    if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr, "discarded message\n");
  }

  // Send delimiter frame and change the socket state to receive
    zmq_send(socket, "", 0, ZMQ_DONTWAIT);
    sending = 0;
    if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr, "Queued messages sent\n");
}

// Poll function
int z_timeout(gnutls_transport_ptr_t socket, unsigned int time)
{
  if(SZMQ_DEBUG_FUNCTION_CALLS) fprintf(stderr, "timeout function...\n");

  // Do not poll if buffer is not empty 
  if(size != 0 ) return 1;

  // Send queued messages before polling
  if(sending) {
    int a = zmq_send(socket, "", 0, 0);
    if(a>=0 && SZMQ_DEBUG_PUSH_PULL) fprintf(stderr, "Queued messages sent\n");
    sending = 0;
  }

  if(SZMQ_DEBUG_PUSH_PULL) fprintf(stderr,"polling...\n");

  // Poll the socket for incoming messages
  zmq_pollitem_t item;
  item.socket = (void *)socket;
  item.events = ZMQ_POLLIN;
  int rc = zmq_poll(&item, 1, (long) time);
  if(rc<0 ) return -1; 
  if( item.revents & ZMQ_POLLIN ) return 1;
  return 0;
}
