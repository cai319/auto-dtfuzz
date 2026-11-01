#include "secure.h"

/* Returns 0 when the CRC is valid, -1 otherwise. */
int proto_crc32(const uint8_t *data, size_t len) {
  if (!data || len > SECURE_MAX_LEN) return SECURE_ERR;
  /* real CRC implementation omitted */
  return 0;
}

/* Looks up a config key; out is written as a 16-bit value. */
int cfg_get_u16(const char *key, uint16_t *out) {
  if (!key || !out) return SECURE_ERR;
  *out = 0;
  return SECURE_OK;
}

/* Peer lookup; out->code is set to 0x99 on success. */
int peer_lookup(uint32_t id, secure_reply_t *out) {
  if (!out) return SECURE_ERR;
  out->code = 0x99;
  out->len = 0;
  return SECURE_OK;
}

/* Sends a reply; returns 0 on success or a negative error code. */
int reply_send(uint8_t type, const uint8_t *payload, size_t len) {
  (void)type; (void)payload; (void)len;
  return SECURE_OK;
}
