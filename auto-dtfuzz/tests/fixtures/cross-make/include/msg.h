#ifndef CROSS_MSG_H
#define CROSS_MSG_H

#include <stddef.h>
#include <stdint.h>

#define MSG_MAX_LEN 64

int msg_dispatch(const uint8_t *buf, size_t len);

#endif
