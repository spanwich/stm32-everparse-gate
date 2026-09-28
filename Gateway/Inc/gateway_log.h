#ifndef GATEWAY_LOG_H
#define GATEWAY_LOG_H
#include <stddef.h>
void gateway_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
/* Length-delimited, bounded output. Thread context only. */
int gateway_log_write(const char *text, size_t length);
int gateway_log_binary(const void *bytes, size_t length);
#endif
