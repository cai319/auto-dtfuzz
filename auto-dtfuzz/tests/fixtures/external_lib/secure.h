#ifndef SECURE_H
#define SECURE_H
#include <stdint.h>
#include <stddef.h>

#define SECURE_MAX_LEN 4096
#define SECURE_OK 0
#define SECURE_ERR (-1)

typedef struct secure_reply {
  int code;
  uint16_t len;
} secure_reply_t;

int proto_crc32(const uint8_t *data, size_t len);
int cfg_get_u16(const char *key, uint16_t *out);
#endif
