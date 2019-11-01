#include <ck/import.h>
#include <string.h>

int _start() {
    const char *message1 = "Hello, world!";
    kDebugLog((unsigned long) message1, strlen(message1));

    const char *message2 = "Hello, world! (2)";
    kDebugLog((unsigned long) message2, strlen(message2));

    return 0;
}
