#include "secure.h"

static secure_reply_t g_reply;

int use_secure(void) {
  return SECURE_MAX_LEN + g_reply.code;
}
