#pragma once

#include "crosscall.h"
#include "message.h"
#include <string.h>
#include <stdint.h>

int DebugLog(const char *message) {
    static uint8_t buffer[65536];

    * (uint32_t *) &buffer[0] = (uint32_t) MSG_DEBUG_PRINT;

    int len = strlen(message);
    if(sizeof(buffer) - 4 < len) len = sizeof(buffer) - 4;

    memcpy(buffer + 4, (const uint8_t *) message, len);
    if(kSendMessage((unsigned long) buffer, len + 4) < 0) return -1;
    return 0;
}