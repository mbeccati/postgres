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

#include "uuid-ossp.h"

PG_MODULE_MAGIC;


PG_FUNCTION_INFO_V1(uuid_nil);
PG_FUNCTION_INFO_V1(uuid_ns_dns);
PG_FUNCTION_INFO_V1(uuid_ns_url);
PG_FUNCTION_INFO_V1(uuid_ns_oid);
PG_FUNCTION_INFO_V1(uuid_ns_x500);

PG_FUNCTION_INFO_V1(uuid_generate_v1);
PG_FUNCTION_INFO_V1(uuid_generate_v1mc);
PG_FUNCTION_INFO_V1(uuid_generate_v3);
PG_FUNCTION_INFO_V1(uuid_generate_v4);
PG_FUNCTION_INFO_V1(uuid_generate_v5);

#ifdef HAVE_UUID_OSSP
static void
pguuid_complain(uuid_rc_t rc)
{
	char	   *err = uuid_error(rc);

	if (err != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("OSSP uuid library failure: %s", err)));
	else
		ereport(ERROR,
				(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
				 errmsg("OSSP uuid library failure: error code %d", rc)));
}

static char *
uuid_to_string(const uuid_t *uuid)
{
	char	   *buf = palloc(UUID_LEN_STR + 1);
	void	   *ptr = buf;
	size_t		len = UUID_LEN_STR + 1;
	uuid_rc_t	rc;

	rc = uuid_export(uuid, UUID_FMT_STR, &ptr, &len);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);

	return buf;
}


static void
string_to_uuid(const char *str, uuid_t *uuid)
{
	uuid_rc_t	rc;

	rc = uuid_import(uuid, UUID_FMT_STR, str, UUID_LEN_STR + 1);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);
}


static Datum
special_uuid_value(const char *name)
{
	uuid_t	   *uuid;
	char	   *str;
	uuid_rc_t	rc;

	rc = uuid_create(&uuid);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);
	rc = uuid_load(uuid, name);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);
	str = uuid_to_string(uuid);
	rc = uuid_destroy(uuid);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);

	return DirectFunctionCall1(uuid_in, CStringGetDatum(str));
}

static Datum
uuid_generate_internal(int mode, const uuid_t *ns, const char *name)
{
	uuid_t	   *uuid;
	char	   *str;
	uuid_rc_t	rc;

	rc = uuid_create(&uuid);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);
	rc = uuid_make(uuid, mode, ns, name);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);
	str = uuid_to_string(uuid);
	rc = uuid_destroy(uuid);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);

	return DirectFunctionCall1(uuid_in, CStringGetDatum(str));
}


static Datum
uuid_generate_v35_internal(int mode, pg_uuid_t *ns, text *name)
{
	uuid_t	   *ns_uuid;
	Datum		result;
	uuid_rc_t	rc;

	rc = uuid_create(&ns_uuid);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);
	string_to_uuid(DatumGetCString(DirectFunctionCall1(uuid_out, UUIDPGetDatum(ns))),
				   ns_uuid);

	result = uuid_generate_internal(mode,
									ns_uuid,
									text_to_cstring(name));

	rc = uuid_destroy(ns_uuid);
	if (rc != UUID_RC_OK)
		pguuid_complain(rc);

	return result;
}


#else

static Datum
uuid_generate_internal(int v, unsigned char *ns, char *ptr, int len)
{
	char strbuf[40];

	switch (v)
	{
		case 0:	 /* constant-value uuids: nil, or namespace uuids */
			strlcpy(strbuf, ptr, 37);
			break;

		case 4: default:   /* random uuid */
		{
#ifdef HAVE_UUID_LINUX
			uuid_t uu;

			uuid_generate_random(uu);
			uuid_unparse(uu, strbuf);
#else
			sprintf(strbuf, "%08lx-%04x-%04x-%04x-%04x%08lx",
					(unsigned long) arc4random(),
					(unsigned) (arc4random() & 0xffff),
					(unsigned) ((arc4random() & 0xfff) | 0x4000),
					(unsigned) ((arc4random() & 0x3fff) | 0x8000),
					(unsigned) (arc4random() & 0xffff),
					(unsigned long) arc4random());
#endif
			break;
		}

		case 1:	 /* time/node-based uuids */
		{
			uuid_t uu;
#ifdef HAVE_UUID_BSD
			uint32_t status = uuid_s_ok;
			char *str = NULL;

			uuid_create(&uu, &status);

			if (status == uuid_s_ok)
			{
				uuid_to_string(&uu, &str, &status);
				if (status == uuid_s_ok)
				{
					strlcpy(strbuf, str, 37);

					/* PTR, if set, replaces the trailing characters of the uuid;
					 * this is to support v1mc, where a random multicast MAC is
					 * used instead of the physical one
					 */

					if (ptr && len <= 36)
						strcpy(strbuf + (36 - len), ptr);
				}
				if (str)
					free(str);
			}

			if (status != uuid_s_ok)
			{
				ereport(ERROR,
						(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
						 errmsg("uuid library failure: %d", (int) status)));
			}
#else

			uuid_generate_time(uu);
			uuid_unparse(uu, strbuf);

			/* PTR, if set, replaces the trailing characters of the uuid;
			 * this is to support v1mc, where a random multicast MAC is
			 * used instead of the physical one
			 */

			if (ptr && len <= 36)
				strcpy(strbuf + (36 - len), ptr);
#endif

			break;
		}

		case 3:	 /* namespace-based MD5 uuids */
		case 5:	 /* namespace-based SHA1 uuids */
		{
			dce_uuid_t uu;
#ifdef HAVE_UUID_BSD
			uint32_t status = uuid_s_ok;
			char *str = NULL;
#endif

			if (v == 3)
			{
				MD5_CTX ctx;

				MD5Init(&ctx);
				MD5Update(&ctx, ns, sizeof(uu));
				MD5Update(&ctx, (unsigned char *)ptr, len);
				MD5Final((unsigned char *)&uu, &ctx);
			}
			else
			{
				SHA1_CTX ctx;

				SHA1Init(&ctx);
				SHA1Update(&ctx, ns, sizeof(uu));
				SHA1Update(&ctx, (unsigned char *)ptr, len);
				SHA1Final((unsigned char *)&uu, &ctx);
			}

			/* the calculated hash is using local order */
			UUID_TO_NETWORK(uu);
			UUID_V3_OR_V5(uu, v);

#ifdef HAVE_UUID_LINUX
			/* uuid_unparse expects local order */
			UUID_TO_LOCAL(uu);
			uuid_unparse((unsigned char *)&uu, strbuf);
#else
			uuid_to_string(&uu, &str, &status);

			if (status == uuid_s_ok)
			{
				strlcpy(strbuf, str, 37);
			}
			if (str)
			{
				free(str);
			}


			if (status != uuid_s_ok)
			{
				ereport(ERROR,
					(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
					errmsg("uuid library failure: %d", (int) status)));
			}

#endif
			break;
		}
	}

	return DirectFunctionCall1(uuid_in, CStringGetDatum(strbuf));
}
#endif


Datum
uuid_nil(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return special_uuid_value("nil");
#else
	return uuid_generate_internal(0, NULL, "00000000-0000-0000-0000-000000000000", 36);
#endif
}


Datum
uuid_ns_dns(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return special_uuid_value("ns:DNS");
#else
	return uuid_generate_internal(0, NULL, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", 36);
#endif
}


Datum
uuid_ns_url(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return special_uuid_value("ns:URL");
#else
	return uuid_generate_internal(0, NULL, "6ba7b811-9dad-11d1-80b4-00c04fd430c8", 36);
#endif
}


Datum
uuid_ns_oid(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return special_uuid_value("ns:OID");
#else
	return uuid_generate_internal(0, NULL, "6ba7b812-9dad-11d1-80b4-00c04fd430c8", 36);
#endif
}


Datum
uuid_ns_x500(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return special_uuid_value("ns:X500");
#else
	return uuid_generate_internal(0, NULL, "6ba7b814-9dad-11d1-80b4-00c04fd430c8", 36);
#endif
}


Datum
uuid_generate_v1(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return uuid_generate_internal(UUID_MAKE_V1, NULL, NULL);
#else
	return uuid_generate_internal(1, NULL, NULL, 0);
#endif
}


Datum
uuid_generate_v1mc(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return uuid_generate_internal(UUID_MAKE_V1 | UUID_MAKE_MC, NULL, NULL);
#else
#ifdef HAVE_UUID_LINUX
	char strbuf[40];
	char *buf;
	uuid_t uu;

	uuid_generate_random(uu);               
	uuid_unparse(uu, strbuf);
	buf = strbuf + 24;
#else
	char buf[16];

	sprintf(buf, "-%04x%08lx",
			/* set IEEE802 multicast and local-admin bits */
			(unsigned)((arc4random() & 0xffff) | 0x0300),
			(unsigned long) arc4random());
#endif
	return uuid_generate_internal(1, NULL, buf, 13);
#endif
}


Datum
uuid_generate_v3(PG_FUNCTION_ARGS)
{
	pg_uuid_t  *ns = PG_GETARG_UUID_P(0);
	text	   *name = PG_GETARG_TEXT_P(1);

#ifdef HAVE_UUID_OSSP
	return uuid_generate_v35_internal(UUID_MAKE_V3, ns, name);
#else
	return uuid_generate_internal(3, (unsigned char *)ns,
					  VARDATA(name), VARSIZE(name) - VARHDRSZ);
#endif
}


Datum
uuid_generate_v4(PG_FUNCTION_ARGS)
{
#ifdef HAVE_UUID_OSSP
	return uuid_generate_internal(UUID_MAKE_V4, NULL, NULL);
#else
	return uuid_generate_internal(4, NULL, NULL, 0);
#endif
}


Datum
uuid_generate_v5(PG_FUNCTION_ARGS)
{
	pg_uuid_t  *ns = PG_GETARG_UUID_P(0);
	text	   *name = PG_GETARG_TEXT_P(1);

#ifdef HAVE_UUID_OSSP
	return uuid_generate_v35_internal(UUID_MAKE_V5, ns, name);
#else
	return uuid_generate_internal(5, (unsigned char *)ns,
					  VARDATA(name), VARSIZE(name) - VARHDRSZ);	
#endif
}
