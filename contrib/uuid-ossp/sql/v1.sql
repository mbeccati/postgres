
SELECT uuid_generate_v1() < uuid_generate_v1();
SELECT uuid_generate_v1() < uuid_generate_v1mc();

SELECT substr(uuid_generate_v1()::text, 25) = substr(uuid_generate_v1()::text, 25);
SELECT substr(uuid_generate_v1()::text, 25) <> substr(uuid_generate_v1mc()::text, 25);
SELECT substr(uuid_generate_v1mc()::text, 25) <> substr(uuid_generate_v1mc()::text, 25);
