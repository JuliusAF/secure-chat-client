#include "network.h"
#include "safe_wrappers.h"
#include "database.h"
#include "server_network.h"

/* creates an error packet. That is a packet that is transmitted to make
the client aware of some error. It takes as input the id of the packet
and the error message (null terminated) */
packet_t *gen_s_error_packet(uint16_t id, char *err_msg) {
  unsigned int payload_sz;
  packet_hdr_t *header = NULL;
  unsigned char *payload = NULL;

  if (err_msg == NULL || strlen(err_msg) == 0)
    return NULL;

  payload_sz = strlen(err_msg);
  payload = safe_malloc(sizeof(unsigned char) * payload_sz);
  if (payload == NULL)
    return NULL;

  header = initialize_header(id, payload_sz);
  if (header == NULL) {
    free(payload);
    return NULL;
  }

  memcpy(payload, err_msg, header->pckt_sz);

  return pack_packet(header, payload);
}

/* this function generates a packet with the user info that is sent
to the client on a successful registration or login. It takes an id
as input because the id for a successful login or register is different and
must be specified */
packet_t *gen_s_userinfo_packet(fetched_userinfo_t *f, uint16_t id) {
  unsigned char *payload = NULL, *tmp = NULL;
  packet_hdr_t *header = NULL;

  if (!is_fetched_userinfo_legal(f))
    return NULL;

  const unsigned int payload_sz = IV_SIZE + sizeof(unsigned int) + f->encrypt_sz;
  if (payload_sz > MAX_PAYLOAD_SIZE) {
    fprintf(stderr, "register packet too big: %d\n", payload_sz);
    return NULL;
  }

  payload = safe_malloc(sizeof(unsigned char) * payload_sz);
  header = initialize_header(id, payload_sz);
  if (payload == NULL || header == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  tmp = payload;
  memcpy(tmp, f->iv, IV_SIZE);
  tmp += IV_SIZE;
  memcpy(tmp, &f->encrypt_sz, sizeof(unsigned int));
  tmp +=sizeof(unsigned int);
  memcpy(tmp, f->encrypted_keys, f->encrypt_sz);

  return pack_packet(header, payload);
}

/* This function creates a packet that holds the list of users currently logged in,
delimited with spaces */

packet_t *gen_s_users_packet(char *users) {
  unsigned char *payload = NULL;
  packet_hdr_t *header = NULL;

  if (users == NULL)
    return NULL;

  header = initialize_header(S_MSG_USERS, strlen(users));
  payload = safe_malloc(sizeof(unsigned char) * strlen(users));
  if (payload == NULL || header == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  memcpy(payload, users, strlen(users));

  return pack_packet(header, payload);
}

/* the function serializes a message payload. It gets the components of the message
from a msg_components_t struct and the size of the expected payload from the second
argument unsigned int payload_sz */
unsigned char *serialize_message(msg_components_t *m, unsigned int payload_sz) {
  unsigned char *payload = NULL, *tmp;

  if (m == NULL)
    return NULL;

  payload = safe_malloc(sizeof(unsigned char) * payload_sz);
  if (payload == NULL)
    return NULL;

  tmp = payload;

  memcpy(tmp, &m->siglen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, m->sig, m->siglen);
  tmp += m->siglen;
  memcpy(tmp, &m->publen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, m->pubkey, m->publen);
  tmp += m->publen;
  memcpy(tmp, &m->msglen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, m->message, m->msglen);
  tmp += m->msglen;

  if (m->type == PRIV_MSG_TYPE) {
    /* constant 20 bytes is allocated for recipient name. Size defined in USERNAME_MAX */
    memset(tmp, '\0', USERNAME_MAX);
    memcpy(tmp, m->recipient, m->reclen);
    tmp += USERNAME_MAX;

    memcpy(tmp, m->iv, IV_SIZE);
    tmp += IV_SIZE;
    memcpy(tmp, &m->s_symkeylen, sizeof(unsigned int));
    tmp += sizeof(unsigned int);
    memcpy(tmp, m->s_symkey, m->s_symkeylen);
    tmp += m->s_symkeylen;
    memcpy(tmp, &m->r_symkeylen, sizeof(unsigned int));
    tmp += sizeof(unsigned int);
    memcpy(tmp, m->r_symkey, m->r_symkeylen);
  }

  return payload;
}

/* this function creates a packet for a message packet. There are two types of messages,
public and private. The public message has all the same components as a private message,
but a private message had extra fields. As such their makeups differ */
packet_t *gen_s_msg_packet(msg_components_t *m) {
  unsigned int payload_sz;
  unsigned char *payload = NULL;
  packet_hdr_t *header = NULL;

  if (m == NULL || m->type == 0)
    return NULL;

  payload_sz = sizeof(unsigned int) + m->siglen + sizeof(unsigned int) + m->publen +
               sizeof(unsigned int) + m->msglen;

  if (m->type == PRIV_MSG_TYPE) {
    payload_sz += USERNAME_MAX + IV_SIZE + sizeof(unsigned int) + m->s_symkeylen +
                  sizeof(unsigned int) + m->r_symkeylen;
  }
  payload = serialize_message(m, payload_sz);
  if (m->type == PUB_MSG_TYPE)
    header = initialize_header(S_MSG_PUBMSG, payload_sz);
  else
    header = initialize_header(S_MSG_PRIVMSG, payload_sz);

  if (header == NULL || payload == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  return pack_packet(header, payload);
}

/* serialized the response to a public key request from the client */
unsigned char *serialize_pubkey_request(client_parsed_t *p, char *key, unsigned int len, unsigned int payload_sz) {
  unsigned char *payload, *tmp;

  payload = safe_malloc(sizeof(unsigned char) * payload_sz);
  if (payload == NULL)
    return NULL;

  tmp = payload;

  memcpy(tmp, &len, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, key, len);
  tmp += len;
  memcpy(tmp, &p->pubkey_rqst.siglen, sizeof(unsigned int));
  tmp += sizeof(unsigned int);
  memcpy(tmp, p->pubkey_rqst.sig, p->pubkey_rqst.siglen);
  tmp += p->pubkey_rqst.siglen;
  memcpy(tmp, p->pubkey_rqst.original, p->pubkey_rqst.original_sz);

  return payload;
}

/* creates a packet in response to a public key request */
packet_t *gen_s_pubkey_rqst_packet(client_parsed_t *p, char *key, unsigned int len) {
  unsigned int payloadsz;
  unsigned char *payload = NULL;
  packet_hdr_t *header = NULL;

  payloadsz = p->pubkey_rqst.original_sz + sizeof(unsigned int) + len + p->pubkey_rqst.siglen + sizeof(unsigned int);

  header = initialize_header(S_META_PUBKEY_RESPONSE, payloadsz);
  payload = serialize_pubkey_request(p, key, len, payloadsz);
  if (header == NULL || payload == NULL) {
    free(header);
    free(payload);
    return NULL;
  }

  return pack_packet(header, payload);
}
