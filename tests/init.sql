-- What the database needs before Auth runs. It is what supabase/auth's own hack/init_postgres.sql does (MIT), minus the roles of Supabase's platform that Auth does not need:
-- the role Auth connects as, the schema it owns, the right to create in the database, and the search path. The password is given by the test (psql -v authpw=...).
-- Auth's own migration 20240612123726 also grants to the role "postgres": it has to exist before (the official image has it).
CREATE USER supabase_auth_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION PASSWORD :'authpw';
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION supabase_auth_admin;
GRANT CREATE ON DATABASE postgres TO supabase_auth_admin;
ALTER USER supabase_auth_admin SET search_path = 'auth';
