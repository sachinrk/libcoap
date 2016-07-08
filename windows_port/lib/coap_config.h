#ifndef _CONFIG_H_
#define _CONFIG_H_

#define PACKAGE_NAME "libcoap-NT"
#define PACKAGE_VERSION "0"
#define PACKAGE_STRING PACKAGE_NAME PACKAGE_VERSION

/* it's just provided by libc. i hope we don't get too many of those, as
 * actually we'd need autotools again to find out what environment we're
 * building in */
#define HAVE_LIMITS_H
#define HAVE_STRNLEN
//#define NDEBUG
#define HAVE_MALLOC

#define COAP_RESOURCES_NOHASH

#include <time.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <basetsd.h>
#include <string.h>
#include <windows.h>
#include <stdint.h>
#include <mswsock.h>
#include <stdlib.h>
#include <malloc.h>
#include <basetsd.h>
// #include <assert.h>

#define inline __inline
#define ssize_t int
#define assert(x)
#define strcasecmp _stricmp

#define COAP_HDR_SIZE sizeof(coap_hdr_t)

#endif /* _CONFIG_H_ */
