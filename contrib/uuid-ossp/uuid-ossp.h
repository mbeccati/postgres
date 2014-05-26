/*-------------------------------------------------------------------------
 *
 * UUID generation functions using the OSSP, Linux or BSD UUID library
 *
 * Copyright (c) 2007-2014, PostgreSQL Global Development Group
 *
 * Some parts are Copyright (c) 2009 Andrew Gierth
 *
 * contrib/uuid-ossp/uuid-ossp.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/uuid.h"

/*
 * There's some confusion over the location of the uuid.h header file.
 * On Debian, it's installed as ossp/uuid.h, while on Fedora, or if you
 * install ossp-uuid from a tarball, it's installed as uuid.h. Don't know
 * what other systems do.
 */
#ifdef HAVE_OSSP_UUID_H
 #include <ossp/uuid.h>
#else
 #ifdef HAVE_UUID_UUID_H
  #include <uuid/uuid.h>
 #else
  #ifdef HAVE_UUID_H
   #ifdef HAVE_UUID_BSD
    /* OS has a uuid_hash that conflicts with ours; kill it */
    #undef uuid_hash
    #define uuid_hash bsd_uuid_hash
    #include <uuid.h>
    #undef uuid_hash
   #else
    /* This must be the OSSP UUID header */
    #include <uuid.h>
   #endif
  #else
   #error uuid.h not found
  #endif
 #endif
#endif

#ifndef HAVE_UUID_OSSP
/* Some BSD variants offer md5 and sha1 implementations
* but Linux does not, so we use a copy of the ones from
* pgcrypto. They are not needed with OSSP though */
#include "md5.h"
#include "sha1.h"

/* Define some constants to make the code more readable */
#define UUID_MAKE_MC 0
#define UUID_MAKE_V1 1
#define UUID_MAKE_V2 2
#define UUID_MAKE_V3 3
#define UUID_MAKE_V4 4
#define UUID_MAKE_V5 5
#else
/* better both be 16 */
#if (UUID_LEN != UUID_LEN_BIN)
#error UUID length mismatch
#endif
#endif

#ifndef HAVE_UUID_OSSP

#ifdef HAVE_UUID_LINUX
/* A DCE 1.1 compatible source representation of UUIDs, derived from
* the BSD implementation
*/
typedef struct dce_uuid {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq_hi_and_reserved;
	uint8_t clock_seq_low;
	uint8_t node[6];
} dce_uuid_t;
#else
#define dce_uuid_t uuid_t
#endif

#define UUID_TO_NETWORK(uu) \
do \
{ \
	uu.time_low = htonl(uu.time_low); \
	uu.time_mid = htons(uu.time_mid); \
	uu.time_hi_and_version = htons(uu.time_hi_and_version); \
} while (0)

#define UUID_TO_LOCAL(uu) \
do \
{ \
	uu.time_low = ntohl(uu.time_low); \
	uu.time_mid = ntohs(uu.time_mid); \
	uu.time_hi_and_version = ntohs(uu.time_hi_and_version); \
} while (0)

#define UUID_V3_OR_V5(uu, v) \
do \
{ \
	uu.time_hi_and_version &= 0x0FFF; \
	uu.time_hi_and_version |= (v << 12); \
	uu.clock_seq_hi_and_reserved &= 0x3F; \
	uu.clock_seq_hi_and_reserved |= 0x80; \
} while(0)

#endif
