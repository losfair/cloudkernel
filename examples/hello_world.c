#include <ck/polyfill.h>

#include <ck/debug.h>
#include <string.h>

int _start() {
    DebugLog("Hello, world!");
    DebugLog("Hello, world! (2)");

    return 0;
}
