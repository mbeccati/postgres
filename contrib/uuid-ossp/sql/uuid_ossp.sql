CREATE EXTENSION "uuid-ossp";

SELECT uuid_nil();
SELECT uuid_ns_dns();
SELECT uuid_ns_url();
SELECT uuid_ns_oid();
SELECT uuid_ns_x500();

SELECT uuid_generate_v1() < uuid_generate_v1();
SELECT uuid_generate_v1() < uuid_generate_v1mc();

SELECT substr(uuid_generate_v1()::text, 25) = substr(uuid_generate_v1()::text, 25);
SELECT substr(uuid_generate_v1()::text, 25) <> substr(uuid_generate_v1mc()::text, 25);
SELECT substr(uuid_generate_v1mc()::text, 25) <> substr(uuid_generate_v1mc()::text, 25);

SELECT uuid_generate_v3(uuid_ns_dns(), 'www.widgets.com');
SELECT uuid_generate_v5(uuid_ns_dns(), 'www.widgets.com');

SELECT uuid_generate_v4()::text ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$';

DO $_$
DECLARE
  u text;
  i int;
  c int;
BEGIN
  FOR i in 1..32 LOOP
    u := substr(uuid_generate_v1mc()::text, 25, 2);
    EXECUTE 'SELECT x''' || u || '''::int & 3' INTO c;
    IF c <> 3 THEN
      RAISE WARNING 'v1mc broken';
    END IF;
  END LOOP;
END;
$_$;

