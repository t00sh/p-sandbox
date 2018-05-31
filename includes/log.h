#ifndef DEF_LOG_H
#define DEF_LOG_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define _LOG(_stream, ...) do {                 \
    fprintf(_stream, __VA_ARGS__);              \
  } while(0)

#define LOG_APPEND(_stream, ...) do {           \
    fprintf(_stream, __VA_ARGS__);              \
  } while(0)

#define LOG(_stream, ...) do {                  \
    fprintf(_stream, "[SANDBOX] ");             \
    fprintf(_stream, __VA_ARGS__);              \
  } while(0)

#define LOGN(_stream, ...) do {                 \
    LOG(_stream, __VA_ARGS__);                  \
    fprintf(_stream, "\n");                     \
  } while(0)

#define LOG_ERRX(_stream, ...) do {             \
    fprintf(_stream, "[SANDBOX] ERROR - ");     \
    _LOG(_stream, __VA_ARGS__);                 \
    fprintf(_stream, "\n");                     \
    exit(EXIT_FAILURE);                         \
  } while(0)

#define LOG_WARNX(_stream, ...) do {            \
    fprintf(_stream, "[SANDBOX] WARNING - ");   \
    _LOG(_stream, __VA_ARGS__);                 \
    fprintf(_stream, "\n");                     \
  } while(0)

#define LOG_ERR(_stream, ...) do {                      \
    fprintf(_stream, "[SANDBOX] ERROR - ");             \
    _LOG(_stream, __VA_ARGS__);                         \
    fprintf(_stream, ": %s\n", strerror(errno));        \
    exit(EXIT_FAILURE);                                 \
  } while(0)

#define LOG_WARN(_stream, ...) do {                     \
    fprintf(_stream, "[SANDBOX] WARNING - ");           \
    _LOG(_stream, __VA_ARGS__);                         \
    fprintf(_stream, ": %s\n", strerror(errno));        \
  } while(0)

#endif /* DEF_LOG_H */
