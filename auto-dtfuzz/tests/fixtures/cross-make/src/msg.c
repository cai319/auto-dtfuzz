#include "msg.h"

#ifndef MSG_PROTO_V2
#error "MSG_PROTO_V2 must come from the project Makefile"
#endif

int msg_dispatch(const uint8_t *buf, size_t len) {
  if (!buf || len == 0) {
    return -1;
  }
  if (len > MSG_MAX_LEN) {
    return -2;
  }
  switch (buf[0]) {
    case 0x10:
      return len >= 2 && buf[1] == 0x20 ? 1 : 2;
    case 0x11:
      return len >= 4 ? 3 : 4;
    case 0x12:
      return len == MSG_MAX_LEN ? 5 : 6;
    default:
      return 0;
  }
}
