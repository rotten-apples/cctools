#ifndef STRLCPY_H
#define STRLCPY_H

#include "config.h"

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#endif

