#include <cstdio>
#include <stdarg.h>

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include "../common/openssl_utility.h"
#include "enclave.h"
#include "enclave_t.h"
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

unsigned long inet_addr2(const char *str)
{
  unsigned long lHost = 0;
  char *pLong = (char *)&lHost;
  char *p = (char *)str;
  while (p)
    {
      *pLong++ = atoi(p);
      p = strchr(p, '.');
      if (p)
        ++p;
    }
  return lHost;
}
// This routine conducts a simple HTTP request/response communication with
// server
int communicate_with_server(SSL* ssl)
{
  unsigned char buf[200];
  int ret = 1;
  int error = 0;
  int len = 0;
  int bytes_written = 0;
  int bytes_read = 0;

  // Send a heartbeat when the client starts
  heartbeat_start_trigger();
  SSL_heartbeat(ssl);
  heartbeat_stop_trigger();
  ret = 0;
  return ret;

  // Write an GET request to the server
  //t_print(TLS_CLIENT "-----> Write to server:\n");
  len = snprintf((char*)buf, sizeof(buf) - 1, CLIENT_PAYLOAD);

  while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
      error = SSL_get_error(ssl, bytes_written);
      if (error == SSL_ERROR_WANT_WRITE)
        continue;
      //t_print(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
      if (bytes_written == 0) ret = -1;
      else ret = bytes_written;
      goto done;
    }

  //t_print(TLS_CLIENT "%d bytes written\n", bytes_written);

  // Read the HTTP response from server
  //t_print(TLS_CLIENT "<---- Read from server:\n");
  do
    {
      //t_print(TLS_CLIENT "Attempting read\n");
      len = sizeof(buf) - 1;
      memset(buf, 0, sizeof(buf));
      //t_print(TLS_CLIENT "Just before SSL_read\n");
      bytes_read = SSL_read(ssl, buf, (size_t)len);
      //t_print(TLS_CLIENT "SSL_read called\n");
      if (bytes_read <= 0)
        {
          int error = SSL_get_error(ssl, bytes_read);
          if (error == SSL_ERROR_WANT_READ)
            continue;

          if (error == SSL_ERROR_ZERO_RETURN) {
            ret = bytes_read;
            break;
          }

          t_print(TLS_CLIENT "Failed! SSL_read returned error=%d\n", error);
          if (bytes_read == 0) ret = -1;
          else ret = bytes_read;
          break;
        }

      PRINT("%s", buf);


      //t_print(TLS_CLIENT " %d bytes read\n", bytes_read);
      // check to to see if received payload is expected
      // Note that if you just want to use client here but server from other
      // applications, you need to ignore this check, SERVER_PAYLOAD_SIZE
      // need to be adjusted.
      /*if ((bytes_read != SERVER_PAYLOAD_SIZE) ||
        (memcmp(SERVER_PAYLOAD, buf, bytes_read) != 0))
        {
        t_print(
        TLS_CLIENT "ERROR: expected reading %lu bytes but only "
        "received %d bytes\n",
        SERVER_PAYLOAD_SIZE,
        bytes_read);
        ret = bytes_read;
        break;
        }
        else*/
      //{
      //t_print(TLS_CLIENT " received all the expected data from server\n\n");
      //ret = 0;
      //break;
      //}
    } while (1);
  PRINT("\n");
 done:

  return ret;
}

// create a socket and connect to the server_name:server_port
int create_socket(char* server_name, char* server_port)
{
  int sockfd = -1;
  struct sockaddr_in dest_sock;
  int res = -1;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
    {
      t_print(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
      goto done;
    }

  dest_sock.sin_family = AF_INET;
  dest_sock.sin_port = htons(atoi(server_port));
  dest_sock.sin_addr.s_addr = inet_addr2(server_name);
  bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));

  //t_print(TLS_CLIENT "Values: %hu %d\n", dest_sock.sin_port, dest_sock.sin_addr.s_addr);

  if (connect(
              sockfd, (sockaddr*) &dest_sock,
              sizeof(struct sockaddr)) == -1)
    {
      t_print(
              TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
              server_name,
              server_port,
              errno);
      ocall_close(&res, sockfd);
      if (res != 0)
        t_print(TLS_CLIENT "OCALL: error closing socket\n");
      sockfd = -1;
      goto done;
    }
  //t_print(TLS_CLIENT "connected to %s:%s\n", server_name, server_port);

 done:
  return sockfd;
}

int launch_tls_client(char* server_name, char* server_port, uint64_t* stack_start_ptr, uint64_t* stack_end_ptr, uint64_t* heap_start_ptr, uint64_t* heap_end_ptr)
{
  //t_print(TLS_CLIENT " called launch tls client\n");

  uint8_t *stack_start = (uint8_t*)(*stack_start_ptr);
  uint8_t *stack_end = (uint8_t*)(*stack_end_ptr);
  t_print(TLS_CLIENT "Stack start: %llx\n", stack_start);
  t_print(TLS_CLIENT "Stack end: %llx\n", stack_end);

  uint8_t *heap_start = (uint8_t*)(*heap_start_ptr);
  uint8_t *heap_end = (uint8_t*)(*heap_end_ptr);
  t_print(TLS_CLIENT "Heap start: %llx\n", heap_start);
  t_print(TLS_CLIENT "Heap end: %llx\n", heap_end);


  int ret = 0;

  SSL_CTX* ssl_client_ctx = nullptr;
  SSL* ssl_session = nullptr;
  SSL_SESSION* ssl_session_2 = nullptr;

  X509* cert = nullptr;
  EVP_PKEY* pkey = nullptr;
  SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

  int client_socket = -1;
  int error = 0;

  //t_print("\nStarting" TLS_CLIENT "\n\n\n");

  if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
    {
      t_print(TLS_CLIENT "unable to create a new SSL context\n");
      goto done;
    }

  if (initalize_ssl_context(ssl_confctx, ssl_client_ctx) != SGX_SUCCESS)
    {
      t_print(TLS_CLIENT "unable to create a initialize SSL context\n ");
      goto done;
    }

  // specify the verify_callback for custom verification
  SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, &verify_callback);
  //t_print(TLS_CLIENT "load cert and key\n");
  if (load_tls_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
    {
      //t_print(TLS_CLIENT " unable to load certificate and private key on the client\n");
      //goto done;
    }

  if ((ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
    {
      t_print(TLS_CLIENT
              "Unable to create a new SSL connection state object\n");
      goto done;
    }

  //t_print(TLS_CLIENT "new ssl connection getting created\n");
  client_socket = create_socket(server_name, server_port);
  if (client_socket == -1)
    {
      t_print(
              TLS_CLIENT
              "create a socket and initiate a TCP connect to server: %s:%s "
              "(errno=%d)\n",
              server_name,
              server_port,
              errno);
      goto done;
    }

  // set up ssl socket and initiate TLS connection with TLS server
  SSL_set_fd(ssl_session, client_socket);

  if ((error = SSL_connect(ssl_session)) != 1)
    {
      t_print(
              TLS_CLIENT "Error: Could not establish a TLS session ret2=%d "
              "SSL_get_error()=%d\n",
              error,
              SSL_get_error(ssl_session, error));
      goto done;
    }
  //t_print(TLS_CLIENT "successfully established TLS channel:%s\n", SSL_get_version(ssl_session));

  ssl_session_2 = SSL_get_session(ssl_session);

  SSL_set_stack_start(ssl_session, stack_start);
  SSL_set_stack_end(ssl_session, stack_end);
  SSL_set_heap_start(ssl_session, heap_start);
  SSL_set_heap_end(ssl_session, heap_end);

  // start the client server communication
  if ((error = communicate_with_server(ssl_session)) != 0)
    {
      t_print(TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", error);
      goto done;
    }

  // Free the structures we don't need anymore
  ret = 0;
 done:
  //t_print(TLS_CLIENT "DONE\n");
  if (client_socket != -1)
    {
      ocall_close(&ret, client_socket);
      if (ret != 0)
        t_print(TLS_CLIENT "OCALL: error close socket\n");
    }

  if (ssl_session)
    {
      SSL_shutdown(ssl_session);
      SSL_free(ssl_session);
    }

  //t_print(TLS_CLIENT "Session closed\n");

  if (cert)
    X509_free(cert);

  if (pkey)
    EVP_PKEY_free(pkey);

  if (ssl_client_ctx)
    SSL_CTX_free(ssl_client_ctx);

  if (ssl_confctx)
    SSL_CONF_CTX_free(ssl_confctx);

  //t_print(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
  return (ret);
}
