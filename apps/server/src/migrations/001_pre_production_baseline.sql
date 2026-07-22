-- KCML pre-production canonical baseline migration
-- Generated from the verified active schema on 2026-07-22.
-- This baseline intentionally replaces the previous pre-production migration chain.

--
-- PostgreSQL database dump
--


-- Dumped from database version 16.14 (Homebrew)
-- Dumped by pg_dump version 16.14 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- Name: EXTENSION citext; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION citext IS 'data type for case-insensitive character strings';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: integration_token_kind; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.integration_token_kind AS ENUM (
    'SINGLE_COMPONENT',
    'BLUEPRINT_RELEASE'
);


--
-- Name: managed_service_api_state; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.managed_service_api_state AS ENUM (
    'ENABLED',
    'DISABLED'
);


--
-- Name: managed_service_auth_mode; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.managed_service_auth_mode AS ENUM (
    'OAUTH2_CLIENT_CREDENTIALS',
    'STATIC_BEARER',
    'STATIC_API_KEY',
    'MTLS',
    'NONE'
);


--
-- Name: managed_service_kind; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.managed_service_kind AS ENUM (
    'MCP',
    'EXTERNAL_API',
    'COMPONENT'
);


--
-- Name: managed_service_state; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.managed_service_state AS ENUM (
    'DRAFT',
    'REGISTERED_DISABLED',
    'TRIAL',
    'ACTIVE',
    'SUSPENDED',
    'QUARANTINED',
    'RETIRED'
);


--
-- Name: onboarding_job_state; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.onboarding_job_state AS ENUM (
    'CREATED',
    'SOURCE_UPLOADED',
    'PR_CREATED',
    'CI_RUNNING',
    'AWAITING_REVISION',
    'MERGED',
    'ARTIFACT_BUILDING',
    'DEPLOYING',
    'REGISTERED_DISABLED',
    'TRIAL_TESTING',
    'ACTIVE',
    'FAILED',
    'QUARANTINED',
    'CANCELLED'
);


--
-- Name: operational_state; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.operational_state AS ENUM (
    'UNKNOWN',
    'DISABLED',
    'HEALTHY',
    'DEGRADED',
    'UNHEALTHY',
    'QUARANTINED',
    'MAINTENANCE',
    'RETIRED'
);


--
-- Name: registration_state; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.registration_state AS ENUM (
    'DRAFT',
    'DOCUMENTATION_INCOMPLETE',
    'PENDING_TECH_REVIEW',
    'PENDING_SECURITY_REVIEW',
    'PENDING_TEST',
    'TEST_FAILED',
    'APPROVED',
    'REGISTERED_DISABLED',
    'TRIAL',
    'ACTIVE',
    'SUSPENDED',
    'QUARANTINED',
    'REJECTED',
    'RETIRED'
);


--
-- Name: service_pipeline_kind; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.service_pipeline_kind AS ENUM (
    'MCP_ONBOARDING',
    'EXTERNAL_API_REGISTRATION',
    'COMPONENT_ONBOARDING'
);


--
-- Name: append_audit_event(text, text, text, text, text, jsonb, jsonb, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.append_audit_event(p_event_type text, p_actor_type text, p_actor_id text, p_object_type text, p_object_id text, p_before jsonb, p_after jsonb, p_correlation_id uuid) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
declare
  inserted_id bigint;
begin
  insert into public.audit_event(
    event_type, actor_type, actor_id, object_type, object_id,
    before_json, after_json, correlation_id
  ) values (
    p_event_type, p_actor_type, p_actor_id, p_object_type, p_object_id,
    p_before, p_after, p_correlation_id
  ) returning id into inserted_id;
  return inserted_id;
end $$;


--
-- Name: audit_event_hash_before_insert(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.audit_event_hash_before_insert() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
declare
  head audit_head%rowtype;
begin
  select * into head from audit_head where singleton is true for update;
  if not found then
    raise exception 'audit_head_missing';
  end if;
  new.chain_sequence := head.last_sequence + 1;
  new.prev_hash := head.event_hash;
  new.event_hash := compute_audit_event_hash(
    head.event_hash,
    new.event_type,
    new.actor_type,
    new.actor_id,
    new.object_type,
    new.object_id,
    new.before_json,
    new.after_json,
    new.correlation_id
  );
  update audit_head
     set last_sequence=new.chain_sequence,
         event_hash=new.event_hash,
         updated_at=now()
   where singleton is true;
  return new;
end $$;


--
-- Name: audit_event_no_update_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.audit_event_no_update_delete() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
  raise exception 'audit_event is append-only';
end $$;


--
-- Name: component_audit_event_no_update_delete(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.component_audit_event_no_update_delete() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  raise exception 'component_audit_event is append-only';
end $$;


--
-- Name: component_policy_epoch_sync(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.component_policy_epoch_sync() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  if (new.enabled, new.ingress_enabled, new.pulse_enabled, new.egress_enabled, new.activation_state,
      new.operational_state, new.monitoring_state, new.lifecycle_state)
     is distinct from
     (old.enabled, old.ingress_enabled, old.pulse_enabled, old.egress_enabled, old.activation_state,
      old.operational_state, old.monitoring_state, old.lifecycle_state) then
    new.policy_epoch := old.policy_epoch + 1;
  end if;
  new.updated_at := now();
  return new;
end $$;


--
-- Name: compute_audit_event_hash(bytea, text, text, text, text, text, jsonb, jsonb, uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.compute_audit_event_hash(p_prev_hash bytea, p_event_type text, p_actor_type text, p_actor_id text, p_object_type text, p_object_id text, p_before jsonb, p_after jsonb, p_correlation_id uuid) RETURNS bytea
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'public'
    AS $$
  select public.digest(
    pg_catalog.convert_to(
      pg_catalog.jsonb_build_object(
        'prevHash', case when p_prev_hash is null then null else pg_catalog.encode(p_prev_hash, 'hex') end,
        'eventType', p_event_type,
        'actorType', p_actor_type,
        'actorId', p_actor_id,
        'objectType', p_object_type,
        'objectId', p_object_id,
        'before', coalesce(p_before, 'null'::jsonb),
        'after', coalesce(p_after, 'null'::jsonb),
        'correlationId', p_correlation_id::text
      )::text,
      'UTF8'
    ),
    'sha256'
  )
$$;


--
-- Name: enqueue_audit_archive_event(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enqueue_audit_archive_event() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
  insert into public.audit_archive_outbox(event_id,payload)
  values (
    new.id,
    pg_catalog.jsonb_build_object(
      'id',new.id,
      'sequence',new.chain_sequence,
      'eventType',new.event_type,
      'actorType',new.actor_type,
      'actorId',new.actor_id,
      'objectType',new.object_type,
      'objectId',new.object_id,
      'before',new.before_json,
      'after',new.after_json,
      'correlationId',new.correlation_id,
      'createdAt',new.created_at,
      'previousHash',case when new.prev_hash is null then null else pg_catalog.encode(new.prev_hash,'hex') end,
      'eventHash',pg_catalog.encode(new.event_hash,'hex')
    )
  ) on conflict (event_id) do nothing;
  return new;
end $$;


--
-- Name: kcml_factory_reset_truncate(text[]); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.kcml_factory_reset_truncate(table_names text[]) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'public'
    AS $$
declare
  candidate_table_name text;
  qualified_tables text := '';
begin
  if array_length(table_names, 1) is null then
    return;
  end if;

  foreach candidate_table_name in array table_names loop
    if candidate_table_name in ('schema_migration','operational_config_setting','operational_config_applied') then
      raise exception 'factory_reset_table_not_allowed:%', candidate_table_name;
    end if;
    if not exists (
      select 1
        from information_schema.tables
       where table_schema = 'public'
         and table_type = 'BASE TABLE'
         and information_schema.tables.table_name = candidate_table_name
    ) then
      raise exception 'factory_reset_table_not_found:%', candidate_table_name;
    end if;
    qualified_tables := qualified_tables || case when qualified_tables = '' then '' else ', ' end || format('public.%I', candidate_table_name);
  end loop;

  execute 'truncate table ' || qualified_tables || ' restart identity cascade';
end;
$$;


--
-- Name: preserve_last_admin_owner(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.preserve_last_admin_owner() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
begin
  if old.active is true and old.role='OWNER' then
    if tg_op='DELETE' then
      if not exists(select 1 from public.admin_account where id<>old.id and active is true and role='OWNER') then
        raise exception 'last_owner_required';
      end if;
    elsif new.active is not true or new.role<>'OWNER' then
      if not exists(select 1 from public.admin_account where id<>old.id and active is true and role='OWNER') then
        raise exception 'last_owner_required';
      end if;
    end if;
  end if;
  if tg_op='DELETE' then return old; end if;
  return new;
end $$;


--
-- Name: set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
  new.updated_at = now();
  return new;
end $$;


--
-- Name: verify_audit_chain(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.verify_audit_chain() RETURNS TABLE(valid boolean, event_count bigint, latest_event_id bigint, broken_event_id bigint)
    LANGUAGE plpgsql STABLE
    SET search_path TO 'pg_catalog', 'public'
    AS $$
declare
  audit_row record;
  previous_hash bytea := null;
  expected_sequence bigint := 0;
  expected_hash bytea;
begin
  select count(*), max(id) into event_count, latest_event_id from audit_event;
  for audit_row in select * from audit_event order by chain_sequence asc loop
    expected_sequence := expected_sequence + 1;
    expected_hash := compute_audit_event_hash(
      previous_hash,
      audit_row.event_type,
      audit_row.actor_type,
      audit_row.actor_id,
      audit_row.object_type,
      audit_row.object_id,
      audit_row.before_json,
      audit_row.after_json,
      audit_row.correlation_id
    );
    if audit_row.chain_sequence <> expected_sequence
       or audit_row.prev_hash is distinct from previous_hash
       or audit_row.event_hash is distinct from expected_hash then
      valid := false;
      broken_event_id := audit_row.id;
      return next;
      return;
    end if;
    previous_hash := audit_row.event_hash;
  end loop;
  valid := true;
  broken_event_id := null;
  return next;
end $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_token (
    lookup_digest bytea NOT NULL,
    key_id text NOT NULL,
    fingerprint text NOT NULL,
    credential_id uuid NOT NULL,
    server_id uuid NOT NULL,
    audience text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    credential_revocation_epoch uuid NOT NULL,
    server_revocation_epoch uuid NOT NULL,
    component_id uuid
);


--
-- Name: kaja_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kaja_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    public_id public.citext NOT NULL,
    secret_hash text NOT NULL,
    secret_fingerprint text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    revoked_at timestamp with time zone,
    deleted_at timestamp with time zone,
    revocation_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    label text DEFAULT 'Bez označení'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    principal_token_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    CONSTRAINT kaja_credential_public_id_check CHECK ((public_id OPERATOR(public.~*) '^Kaja[0-9]{4,}$'::public.citext))
);


--
-- Name: access_token_credential; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.access_token_credential AS
 SELECT id,
    public_id,
    secret_hash,
    secret_fingerprint,
    active,
    revoked_at,
    deleted_at,
    revocation_epoch,
    created_at,
    label,
    updated_at,
    expires_at,
    principal_token_epoch
   FROM public.kaja_credential;


--
-- Name: kaja_permission; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kaja_permission (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    credential_id uuid NOT NULL,
    server_id uuid NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    access_level text DEFAULT 'EXECUTE'::text NOT NULL,
    CONSTRAINT kaja_permission_access_level_check CHECK ((access_level = 'EXECUTE'::text))
);


--
-- Name: access_token_permission; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.access_token_permission AS
 SELECT id,
    credential_id,
    server_id,
    granted_at,
    revoked_at,
    access_level
   FROM public.kaja_permission;


--
-- Name: admin_account; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_account (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    username public.citext NOT NULL,
    password_hash text,
    password_changed_at timestamp with time zone,
    mfa_enabled boolean DEFAULT false NOT NULL,
    mfa_secret text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    role text DEFAULT 'ADMIN'::text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    activated_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    session_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    CONSTRAINT admin_account_role_check CHECK ((role = ANY (ARRAY['OWNER'::text, 'ADMIN'::text, 'AUDITOR'::text])))
);


--
-- Name: admin_bootstrap_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_bootstrap_state (
    singleton boolean DEFAULT true NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    completed_at timestamp with time zone,
    completed_by uuid,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT admin_bootstrap_state_singleton_check CHECK (singleton)
);


--
-- Name: admin_login_throttle; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_login_throttle (
    attempt_key bytea NOT NULL,
    failure_count integer DEFAULT 0 NOT NULL,
    first_failed_at timestamp with time zone NOT NULL,
    last_failed_at timestamp with time zone NOT NULL,
    locked_until timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT admin_login_throttle_failure_count_check CHECK ((failure_count >= 0))
);


--
-- Name: admin_recovery_code; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_recovery_code (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    code_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    consumed_at timestamp with time zone
);


--
-- Name: admin_session; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_session (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    account_id uuid NOT NULL,
    session_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    lookup_digest bytea,
    reauthenticated_at timestamp with time zone,
    session_epoch uuid NOT NULL
);


--
-- Name: alert_webhook_delivery; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_webhook_delivery (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    alert_id uuid NOT NULL,
    channel text NOT NULL,
    idempotency_key uuid NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    state text DEFAULT 'PENDING'::text NOT NULL,
    last_http_status integer,
    last_error text,
    response_digest text,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT alert_webhook_delivery_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT alert_webhook_delivery_channel_check CHECK ((channel = ANY (ARRAY['PRIMARY'::text, 'BACKUP'::text]))),
    CONSTRAINT alert_webhook_delivery_state_check CHECK ((state = ANY (ARRAY['PENDING'::text, 'DELIVERED'::text, 'RETRY'::text, 'DEAD_LETTER'::text])))
);


--
-- Name: audit_archive_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_archive_outbox (
    event_id bigint NOT NULL,
    payload jsonb NOT NULL,
    state text DEFAULT 'PENDING'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_id uuid,
    lease_expires_at timestamp with time zone,
    last_error text,
    archived_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_archive_outbox_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT audit_archive_outbox_state_check CHECK ((state = ANY (ARRAY['PENDING'::text, 'PROCESSING'::text, 'ARCHIVED'::text])))
);


--
-- Name: audit_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_event (
    id bigint NOT NULL,
    event_type text NOT NULL,
    actor_type text NOT NULL,
    actor_id text,
    object_type text,
    object_id text,
    before_json jsonb,
    after_json jsonb,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    chain_sequence bigint NOT NULL,
    prev_hash bytea,
    event_hash bytea NOT NULL
);


--
-- Name: audit_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_event_id_seq OWNED BY public.audit_event.id;


--
-- Name: audit_head; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_head (
    singleton boolean DEFAULT true NOT NULL,
    last_sequence bigint NOT NULL,
    event_hash bytea,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_head_singleton_check CHECK (singleton)
);


--
-- Name: component; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kcml_number bigint NOT NULL,
    code public.citext NOT NULL,
    hostname public.citext NOT NULL,
    display_name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    category text NOT NULL,
    registration_type text NOT NULL,
    component_role text DEFAULT 'SERVICE'::text NOT NULL,
    owners jsonb DEFAULT '{}'::jsonb NOT NULL,
    contacts jsonb DEFAULT '{}'::jsonb NOT NULL,
    lifecycle_state text DEFAULT 'DRAFT'::text NOT NULL,
    activation_state text DEFAULT 'INACTIVE'::text NOT NULL,
    operational_state text DEFAULT 'UNKNOWN'::text NOT NULL,
    monitoring_state text DEFAULT 'NOT_CONFIGURED'::text NOT NULL,
    recertification_state text DEFAULT 'NOT_DUE'::text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    ingress_enabled boolean DEFAULT false NOT NULL,
    pulse_enabled boolean DEFAULT false NOT NULL,
    egress_enabled boolean DEFAULT false NOT NULL,
    active_revision_id uuid,
    revocation_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_epoch bigint DEFAULT 0 NOT NULL,
    release_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    deregistered_at timestamp with time zone,
    release_wave_key text,
    blueprint_component_id text,
    principal_id uuid NOT NULL,
    kind_metadata text DEFAULT 'generic'::text NOT NULL,
    activated_at timestamp with time zone,
    CONSTRAINT component_activation_state_check CHECK ((activation_state = ANY (ARRAY['INACTIVE'::text, 'READY'::text, 'READY_FOR_ACTIVATION'::text, 'ACTIVE'::text, 'BLOCKED'::text, 'ENABLE_REQUESTED'::text, 'DISABLE_REQUESTED'::text, 'DISABLE_UNCONFIRMED'::text]))),
    CONSTRAINT component_category_check CHECK ((category = ANY (ARRAY['AI_CLIENT'::text, 'AI_AGENT'::text, 'MCP_SERVER'::text, 'MANAGED_RUNTIME'::text, 'EXTERNAL_SERVICE'::text, 'PLATFORM_SERVICE'::text]))),
    CONSTRAINT component_check CHECK ((hostname OPERATOR(public.~*) (('^'::text || lower((code)::text)) || '[.][a-z0-9][a-z0-9.-]*[a-z0-9]$'::text))),
    CONSTRAINT component_check1 CHECK (((enabled IS FALSE) OR (activation_state = 'ACTIVE'::text))),
    CONSTRAINT component_check2 CHECK (((lifecycle_state <> ALL (ARRAY['RETIRED'::text, 'DEREGISTERED'::text])) OR (enabled IS FALSE))),
    CONSTRAINT component_code_check CHECK ((code OPERATOR(public.~*) '^KCML[0-9]{4,}$'::public.citext)),
    CONSTRAINT component_component_role_check CHECK ((component_role = ANY (ARRAY['CLIENT'::text, 'AGENT'::text, 'SERVICE'::text, 'RUNTIME'::text, 'PLATFORM'::text]))),
    CONSTRAINT component_lifecycle_state_check CHECK ((lifecycle_state = ANY (ARRAY['DRAFT'::text, 'REVIEW'::text, 'APPROVED'::text, 'ACTIVE'::text, 'SUSPENDED'::text, 'QUARANTINED'::text, 'RETIRED'::text, 'DEREGISTERED'::text]))),
    CONSTRAINT component_monitoring_state_check CHECK ((monitoring_state = ANY (ARRAY['NOT_CONFIGURED'::text, 'PENDING'::text, 'HEALTHY'::text, 'DEGRADED'::text, 'FAILED'::text]))),
    CONSTRAINT component_operational_state_check CHECK ((operational_state = ANY (ARRAY['UNKNOWN'::text, 'DISABLED'::text, 'HEALTHY'::text, 'DEGRADED'::text, 'UNHEALTHY'::text, 'MAINTENANCE'::text, 'QUARANTINED'::text, 'RETIRED'::text]))),
    CONSTRAINT component_policy_epoch_check CHECK ((policy_epoch >= 0)),
    CONSTRAINT component_recertification_state_check CHECK ((recertification_state = ANY (ARRAY['NOT_DUE'::text, 'DUE'::text, 'OVERDUE'::text, 'IN_REVIEW'::text, 'PASSED'::text, 'FAILED'::text])))
);


--
-- Name: component_access_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_access_token (
    lookup_digest bytea NOT NULL,
    key_id text NOT NULL,
    fingerprint text NOT NULL,
    credential_id uuid NOT NULL,
    source_component_id uuid NOT NULL,
    target_component_id uuid NOT NULL,
    audience text NOT NULL,
    scope_names text[] DEFAULT '{}'::text[] NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    credential_revocation_epoch uuid NOT NULL,
    target_revocation_epoch uuid NOT NULL,
    policy_epoch_at_issue bigint NOT NULL
);


--
-- Name: component_attribute_contract; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_attribute_contract (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    contract_kind text NOT NULL,
    mask_key text NOT NULL,
    attribute_path text NOT NULL,
    required boolean DEFAULT false NOT NULL,
    attribute_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: component_audit_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_audit_event (
    stream_id uuid NOT NULL,
    sequence_number bigint NOT NULL,
    event_type text NOT NULL,
    workflow text,
    workflow_step text,
    initiated_by_type text NOT NULL,
    initiated_by_id text,
    occurred_at timestamp with time zone NOT NULL,
    model_name text,
    tool_name text,
    service_name text,
    input_classification text,
    output_classification text,
    input_summary jsonb,
    output_summary jsonb,
    principal_id text,
    principal_fingerprint text,
    scope_name text,
    route text,
    authorization_decision text,
    authorization_reason text,
    protocol_result text,
    http_status integer,
    retry_count integer DEFAULT 0 NOT NULL,
    idempotency_key text,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    trace_id text,
    span_id text,
    state_change jsonb,
    catalog_version text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_at timestamp with time zone,
    revision_id uuid,
    previous_event_hash text,
    canonical_payload_digest text,
    event_hash text,
    CONSTRAINT component_audit_event_http_status_check CHECK (((http_status IS NULL) OR ((http_status >= 100) AND (http_status <= 599)))),
    CONSTRAINT component_audit_event_retry_count_check CHECK ((retry_count >= 0)),
    CONSTRAINT component_audit_event_sequence_number_check CHECK ((sequence_number > 0))
);


--
-- Name: component_audit_stream; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_audit_stream (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    expected_next_sequence bigint DEFAULT 1 NOT NULL,
    highest_received_sequence bigint DEFAULT 0 NOT NULL,
    highest_acknowledged_sequence bigint DEFAULT 0 NOT NULL,
    gap_state text DEFAULT 'CONTIGUOUS'::text NOT NULL,
    gap_from_sequence bigint,
    gap_to_sequence bigint,
    replay_requested_at timestamp with time zone,
    last_event_at timestamp with time zone,
    last_acknowledged_at timestamp with time zone,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    current_event_hash text,
    integrity_state text DEFAULT 'VALID'::text NOT NULL,
    integrity_reason text,
    broken_at timestamp with time zone,
    CONSTRAINT component_audit_stream_check CHECK (((gap_from_sequence IS NULL) = (gap_to_sequence IS NULL))),
    CONSTRAINT component_audit_stream_check1 CHECK (((gap_from_sequence IS NULL) OR (gap_from_sequence <= gap_to_sequence))),
    CONSTRAINT component_audit_stream_expected_next_sequence_check CHECK ((expected_next_sequence > 0)),
    CONSTRAINT component_audit_stream_gap_state_check CHECK ((gap_state = ANY (ARRAY['CONTIGUOUS'::text, 'GAP_DETECTED'::text, 'REPLAY_REQUESTED'::text, 'REPLAYING'::text, 'UNAVAILABLE'::text]))),
    CONSTRAINT component_audit_stream_highest_acknowledged_sequence_check CHECK ((highest_acknowledged_sequence >= 0)),
    CONSTRAINT component_audit_stream_highest_received_sequence_check CHECK ((highest_received_sequence >= 0)),
    CONSTRAINT component_audit_stream_integrity_state_check CHECK ((integrity_state = ANY (ARRAY['VALID'::text, 'CONFLICT'::text, 'BROKEN'::text])))
);


--
-- Name: component_call_mask; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_call_mask (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    mask_key text NOT NULL,
    direction text NOT NULL,
    route_pattern text NOT NULL,
    scope_name text NOT NULL,
    request_schema jsonb NOT NULL,
    response_schema jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_call_mask_direction_check CHECK ((direction = ANY (ARRAY['INBOUND'::text, 'OUTBOUND'::text, 'CONTROL'::text, 'E2E'::text]))),
    CONSTRAINT component_call_mask_request_schema_check CHECK ((jsonb_typeof(request_schema) = 'object'::text)),
    CONSTRAINT component_call_mask_response_schema_check CHECK ((jsonb_typeof(response_schema) = 'object'::text))
);


--
-- Name: component_control_command; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_control_command (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid,
    command_key text NOT NULL,
    command_type text NOT NULL,
    endpoint_path text NOT NULL,
    request_schema jsonb NOT NULL,
    response_schema jsonb NOT NULL,
    status text DEFAULT 'DECLARED'::text NOT NULL,
    ack_payload jsonb,
    acknowledged_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_control_command_command_type_check CHECK ((command_type = ANY (ARRAY['enable'::text, 'disable'::text, 'state'::text, 'heartbeat'::text]))),
    CONSTRAINT component_control_command_status_check CHECK ((status = ANY (ARRAY['DECLARED'::text, 'SENT'::text, 'ACKED'::text, 'FAILED'::text])))
);


--
-- Name: component_control_dispatch; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_control_dispatch (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    command_contract_id uuid NOT NULL,
    command_type text NOT NULL,
    target_hostname public.citext NOT NULL,
    endpoint_path text NOT NULL,
    request_body jsonb NOT NULL,
    request_digest text NOT NULL,
    requested_policy_epoch bigint NOT NULL,
    expected_state_key text,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    deadline_at timestamp with time zone NOT NULL,
    retry_policy jsonb DEFAULT '{}'::jsonb NOT NULL,
    state text DEFAULT 'PENDING'::text NOT NULL,
    final_result jsonb,
    final_error_code text,
    attempt_count integer DEFAULT 0 NOT NULL,
    last_attempt_at timestamp with time zone,
    ack_digest text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    lease_owner text,
    lease_until timestamp with time zone,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_control_dispatch_attempt_count_check CHECK ((attempt_count >= 0)),
    CONSTRAINT component_control_dispatch_command_type_check CHECK ((command_type = ANY (ARRAY['enable'::text, 'disable'::text, 'state'::text, 'heartbeat'::text]))),
    CONSTRAINT component_control_dispatch_state_check CHECK ((state = ANY (ARRAY['QUEUED'::text, 'CLAIMED'::text, 'SENT'::text, 'ACK_PENDING'::text, 'ACKED'::text, 'STATE_CONFIRMED'::text, 'HEARTBEAT_CONFIRMED'::text, 'SUCCEEDED'::text, 'FAILED'::text, 'EXPIRED'::text, 'PENDING'::text, 'COMPLETED'::text])))
);


--
-- Name: component_control_dispatch_attempt; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_control_dispatch_attempt (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    dispatch_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    status text NOT NULL,
    request_body jsonb NOT NULL,
    response_body jsonb,
    response_digest text,
    error_code text,
    correlation_id uuid NOT NULL,
    attempted_at timestamp with time zone DEFAULT now() NOT NULL,
    transport_status text,
    request_digest text,
    CONSTRAINT component_control_dispatch_attempt_attempt_number_check CHECK ((attempt_number > 0)),
    CONSTRAINT component_control_dispatch_attempt_status_check CHECK ((status = ANY (ARRAY['SENT'::text, 'FAILED'::text, 'ACKED'::text])))
);


--
-- Name: component_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    public_id public.citext NOT NULL,
    key_id text NOT NULL,
    secret_digest bytea NOT NULL,
    secret_fingerprint text NOT NULL,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    rotated_at timestamp with time zone,
    revocation_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT component_credential_check CHECK (((status = 'REVOKED'::text) = (revoked_at IS NOT NULL))),
    CONSTRAINT component_credential_public_id_check CHECK ((public_id OPERATOR(public.~*) '^KCML[0-9]{4,}[-]C[0-9]{2,}$'::public.citext)),
    CONSTRAINT component_credential_status_check CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'ROTATING'::text, 'REVOKED'::text, 'EXPIRED'::text])))
);


--
-- Name: component_readiness_gate_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_readiness_gate_evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    gate_key text NOT NULL,
    evaluator_version text NOT NULL,
    status text NOT NULL,
    reason_code text NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    evidence_digest text NOT NULL,
    correlation_id uuid NOT NULL,
    executed_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    runtime_digest text,
    revision_digest text,
    artifact_digest text,
    request_digest text,
    response_digest text,
    variant text,
    CONSTRAINT component_readiness_gate_evidence_status_check CHECK ((status = ANY (ARRAY['PASS'::text, 'FAIL'::text])))
);


--
-- Name: component_current_readiness; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.component_current_readiness AS
 SELECT c.id AS component_id,
    c.active_revision_id,
    COALESCE(bool_and(((g.status = 'PASS'::text) AND ((g.expires_at IS NULL) OR (g.expires_at > now())))), false) AS ready
   FROM (public.component c
     LEFT JOIN LATERAL ( SELECT DISTINCT ON (component_readiness_gate_evidence.gate_key) component_readiness_gate_evidence.gate_key,
            component_readiness_gate_evidence.status,
            component_readiness_gate_evidence.expires_at
           FROM public.component_readiness_gate_evidence
          WHERE ((component_readiness_gate_evidence.component_id = c.id) AND (component_readiness_gate_evidence.revision_id = c.active_revision_id))
          ORDER BY component_readiness_gate_evidence.gate_key, component_readiness_gate_evidence.executed_at DESC) g ON (true))
  GROUP BY c.id, c.active_revision_id;


--
-- Name: component_document_blob; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_document_blob (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    evidence_key text NOT NULL,
    media_type text NOT NULL,
    content bytea NOT NULL,
    digest text NOT NULL,
    size_bytes integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_document_blob_check CHECK ((digest = ('sha256:'::text || encode(sha256(content), 'hex'::text)))),
    CONSTRAINT component_document_blob_check1 CHECK ((size_bytes = octet_length(content))),
    CONSTRAINT component_document_blob_size_bytes_check CHECK ((size_bytes >= 0))
);


--
-- Name: component_documentation_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_documentation_evidence (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    evidence_key text NOT NULL,
    evidence_ref text NOT NULL,
    evidence_digest text,
    media_type text,
    required boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    content bytea,
    content_verified_at timestamp with time zone
);


--
-- Name: component_e2e_execution_run; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_e2e_execution_run (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    scenario_id uuid NOT NULL,
    onboarding_job_id uuid,
    executor_kind text DEFAULT 'component.report'::text NOT NULL,
    caller_generated_output_digest text,
    computed_output_digest text NOT NULL,
    expected_output_digest text NOT NULL,
    canonical_output_match boolean NOT NULL,
    digest_match boolean NOT NULL,
    generated_output jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    stdout_text text,
    stderr_text text,
    exit_code integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_e2e_execution_run_executor_kind_check CHECK ((executor_kind = ANY (ARRAY['component.report'::text, 'kcml.executor'::text])))
);


--
-- Name: component_e2e_fixture; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_e2e_fixture (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    revision_id uuid NOT NULL,
    scenario_key text NOT NULL,
    variant_key text NOT NULL,
    input_content bytea NOT NULL,
    input_media_type text NOT NULL,
    input_digest text NOT NULL,
    expected_content bytea NOT NULL,
    expected_media_type text NOT NULL,
    expected_digest text NOT NULL,
    invocation_kind text,
    invocation_name text,
    timeout_ms integer DEFAULT 30000 NOT NULL,
    cleanup_contract jsonb DEFAULT '{"required": false}'::jsonb NOT NULL,
    CONSTRAINT component_e2e_fixture_check CHECK ((input_digest = ('sha256:'::text || encode(sha256(input_content), 'hex'::text)))),
    CONSTRAINT component_e2e_fixture_check1 CHECK ((expected_digest = ('sha256:'::text || encode(sha256(expected_content), 'hex'::text))))
);


--
-- Name: component_e2e_result; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_e2e_result (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    scenario_id uuid NOT NULL,
    status text NOT NULL,
    generated_output_digest text NOT NULL,
    generated_output jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_e2e_result_status_check CHECK ((status = ANY (ARRAY['PASS'::text, 'FAIL'::text])))
);


--
-- Name: component_e2e_run; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_e2e_run (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    runtime_digest text NOT NULL,
    requested_by_principal_id uuid,
    status text DEFAULT 'QUEUED'::text NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    correlation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    lease_owner text,
    lease_until timestamp with time zone,
    deadline_at timestamp with time zone DEFAULT (now() + '00:15:00'::interval) NOT NULL,
    cancellation_requested_at timestamp with time zone,
    worker_heartbeat_at timestamp with time zone,
    attempt_count integer DEFAULT 0 NOT NULL,
    final_error_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_e2e_run_status_check CHECK ((status = ANY (ARRAY['QUEUED'::text, 'RUNNING'::text, 'PASS'::text, 'FAIL'::text, 'CANCELLED'::text])))
);


--
-- Name: component_e2e_run_result; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_e2e_run_result (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    run_id uuid NOT NULL,
    fixture_id uuid NOT NULL,
    response_content bytea,
    response_digest text,
    exact_match boolean DEFAULT false NOT NULL,
    status text NOT NULL,
    error_code text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT component_e2e_run_result_status_check CHECK ((status = ANY (ARRAY['PASS'::text, 'FAIL'::text, 'ERROR'::text])))
);


--
-- Name: component_e2e_scenario; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_e2e_scenario (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    scenario_key text NOT NULL,
    variant text NOT NULL,
    input_ref text NOT NULL,
    input_digest text NOT NULL,
    expected_output_ref text NOT NULL,
    expected_output_digest text NOT NULL,
    expected_output jsonb NOT NULL,
    test_commands text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_e2e_scenario_expected_output_check CHECK ((jsonb_typeof(expected_output) = ANY (ARRAY['object'::text, 'array'::text])))
);


--
-- Name: component_endpoint_contract; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_endpoint_contract (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    endpoint_id text NOT NULL,
    public_hostname public.citext NOT NULL,
    path text NOT NULL,
    methods text[] NOT NULL,
    auth_mode text NOT NULL,
    request_schema jsonb NOT NULL,
    response_schema jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_endpoint_contract_public_hostname_check CHECK ((public_hostname OPERATOR(public.~*) '^kcml[0-9]{4,}[.]kajovocml[.]hcasc[.]cz$'::public.citext))
);


--
-- Name: component_external_access_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_external_access_token (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    lookup_digest bytea NOT NULL,
    key_id text NOT NULL,
    fingerprint text NOT NULL,
    credential_id uuid,
    external_principal_id uuid,
    external_target_id uuid NOT NULL,
    audience text NOT NULL,
    scope_names text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    source_component_id uuid,
    CONSTRAINT component_external_access_token_subject_check CHECK ((((external_principal_id IS NOT NULL) AND (source_component_id IS NULL)) OR ((external_principal_id IS NULL) AND (source_component_id IS NOT NULL))))
);


--
-- Name: component_external_gateway_call; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_external_gateway_call (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_component_id uuid NOT NULL,
    external_target_id uuid NOT NULL,
    external_permission_id uuid NOT NULL,
    route_path text NOT NULL,
    scope_name text NOT NULL,
    correlation_id uuid NOT NULL,
    request_digest text NOT NULL,
    response_digest text,
    request_payload jsonb NOT NULL,
    response_payload jsonb,
    status text NOT NULL,
    http_status integer,
    error_code text,
    attempt_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT component_external_gateway_call_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'SUCCEEDED'::text, 'FAILED'::text, 'BLOCKED'::text])))
);


--
-- Name: component_external_permission; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_external_permission (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid,
    external_principal_id uuid,
    external_target_id uuid NOT NULL,
    route_pattern text NOT NULL,
    scope_name text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT component_external_permission_check CHECK (((component_id IS NOT NULL) OR (external_principal_id IS NOT NULL)))
);


--
-- Name: component_external_principal; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_external_principal (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    public_id public.citext NOT NULL,
    display_name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    token_fingerprint text,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    principal_id uuid NOT NULL,
    CONSTRAINT component_external_principal_status_check CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'DISABLED'::text, 'REVOKED'::text])))
);


--
-- Name: component_external_principal_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_external_principal_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    external_principal_id uuid NOT NULL,
    public_id public.citext NOT NULL,
    key_id text NOT NULL,
    secret_digest bytea NOT NULL,
    secret_fingerprint text NOT NULL,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    revocation_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT component_external_principal_credential_status_check CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'REVOKED'::text])))
);


--
-- Name: component_external_target; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_external_target (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    target_key text NOT NULL,
    display_name text NOT NULL,
    base_url text NOT NULL,
    audit_required boolean DEFAULT true NOT NULL,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    allowed_path_prefixes text[] DEFAULT '{/}'::text[] NOT NULL,
    connect_timeout_ms integer DEFAULT 5000 NOT NULL,
    request_timeout_ms integer DEFAULT 15000 NOT NULL,
    max_retries integer DEFAULT 1 NOT NULL,
    tls_required boolean DEFAULT true NOT NULL,
    circuit_state text DEFAULT 'CLOSED'::text NOT NULL,
    circuit_failure_count integer DEFAULT 0 NOT NULL,
    circuit_failure_threshold integer DEFAULT 5 NOT NULL,
    circuit_open_seconds integer DEFAULT 60 NOT NULL,
    circuit_opened_at timestamp with time zone,
    circuit_probe_in_flight boolean DEFAULT false NOT NULL,
    CONSTRAINT component_external_target_circuit_failure_count_check CHECK ((circuit_failure_count >= 0)),
    CONSTRAINT component_external_target_circuit_failure_threshold_check CHECK (((circuit_failure_threshold >= 1) AND (circuit_failure_threshold <= 100))),
    CONSTRAINT component_external_target_circuit_open_seconds_check CHECK (((circuit_open_seconds >= 1) AND (circuit_open_seconds <= 3600))),
    CONSTRAINT component_external_target_circuit_state_check CHECK ((circuit_state = ANY (ARRAY['CLOSED'::text, 'OPEN'::text, 'HALF_OPEN'::text]))),
    CONSTRAINT component_external_target_connect_timeout_ms_check CHECK (((connect_timeout_ms >= 100) AND (connect_timeout_ms <= 30000))),
    CONSTRAINT component_external_target_max_retries_check CHECK (((max_retries >= 0) AND (max_retries <= 3))),
    CONSTRAINT component_external_target_request_timeout_ms_check CHECK (((request_timeout_ms >= 100) AND (request_timeout_ms <= 60000))),
    CONSTRAINT component_external_target_status_check CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'DISABLED'::text, 'REVOKED'::text])))
);


--
-- Name: component_heartbeat; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_heartbeat (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    heartbeat_at timestamp with time zone NOT NULL,
    policy_epoch bigint NOT NULL,
    operational_state text NOT NULL,
    state_digest text,
    correlation_id uuid NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    challenge_id uuid,
    challenge_nonce text,
    declared_client_id text,
    declared_component_code text,
    validation_state text DEFAULT 'ACCEPTED'::text NOT NULL,
    rejection_reason text,
    CONSTRAINT component_heartbeat_validation_state_check CHECK ((validation_state = ANY (ARRAY['ACCEPTED'::text, 'REJECTED'::text])))
);


--
-- Name: component_heartbeat_challenge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_heartbeat_challenge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    dispatch_id uuid,
    challenge_nonce text NOT NULL,
    requested_policy_epoch bigint NOT NULL,
    correlation_id uuid NOT NULL,
    status text DEFAULT 'PENDING'::text NOT NULL,
    response_digest text,
    responded_at timestamp with time zone,
    response_payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_heartbeat_challenge_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'RESPONDED'::text, 'FAILED'::text])))
);


--
-- Name: component_onboarding_job; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_onboarding_job (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_token_id uuid NOT NULL,
    component_id uuid,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    category text NOT NULL,
    registration_type text NOT NULL,
    state text DEFAULT 'SUBMITTED'::text NOT NULL,
    manifest jsonb NOT NULL,
    manifest_digest text NOT NULL,
    gate_results jsonb DEFAULT '[]'::jsonb NOT NULL,
    credential_id uuid,
    credential_claim_digest bytea,
    credential_claim_expires_at timestamp with time zone,
    credential_claimed_at timestamp with time zone,
    failure_code text,
    release_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    cancelled_at timestamp with time zone,
    release_wave_key text,
    blueprint_component_id text,
    authorization_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    principal_access_token_digest bytea,
    principal_access_token_fingerprint text,
    principal_access_token_handed_off_at timestamp with time zone,
    principal_access_token_ciphertext text,
    principal_access_token_key_id text,
    CONSTRAINT component_onboarding_access_token_handoff_check CHECK (((principal_access_token_handed_off_at IS NULL) OR (principal_access_token_ciphertext IS NULL))),
    CONSTRAINT component_onboarding_job_state_check CHECK ((state = ANY (ARRAY['SUBMITTED'::text, 'IN_REVIEW'::text, 'GATES_PENDING'::text, 'READY'::text, 'READY_FOR_ACTIVATION'::text, 'BLOCKED'::text, 'ACTIVE'::text, 'CANCELLED'::text, 'FAILED'::text])))
);


--
-- Name: component_onboarding_revision_request; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_onboarding_revision_request (
    job_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: component_operation_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_operation_event (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    pulse_type text,
    direction text,
    operation_key text NOT NULL,
    input_digest text NOT NULL,
    input_payload jsonb NOT NULL,
    process_trace jsonb NOT NULL,
    output_digest text NOT NULL,
    output_payload jsonb NOT NULL,
    success boolean NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    trace_id text,
    access_token_fingerprint text,
    occurred_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: component_operation_lease; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_operation_lease (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_principal_id uuid NOT NULL,
    target_component_id uuid NOT NULL,
    operation_kind text NOT NULL,
    operation_name text NOT NULL,
    input_payload jsonb NOT NULL,
    input_digest text NOT NULL,
    output_payload jsonb,
    output_digest text,
    process_trace jsonb,
    success boolean,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    correlation_id uuid NOT NULL,
    causation_id uuid,
    trace_id text,
    token_fingerprint text NOT NULL,
    permission_epoch bigint NOT NULL,
    CONSTRAINT component_operation_lease_check CHECK ((input_digest = ('sha256:'::text || encode(sha256(convert_to((input_payload)::text, 'utf8'::name)), 'hex'::text)))),
    CONSTRAINT component_operation_lease_operation_kind_check CHECK ((operation_kind = ANY (ARRAY['TOOL'::text, 'PULSE'::text, 'ENDPOINT'::text, 'CONTROL'::text, 'E2E'::text])))
);


--
-- Name: component_permission; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_permission (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_component_id uuid NOT NULL,
    target_component_id uuid NOT NULL,
    route_pattern text NOT NULL,
    scope_name text NOT NULL,
    access_level text DEFAULT 'INVOKE'::text NOT NULL,
    constraints_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_by_type text DEFAULT 'system'::text NOT NULL,
    granted_by_id text,
    revoked_at timestamp with time zone,
    CONSTRAINT component_permission_access_level_check CHECK ((access_level = ANY (ARRAY['DISCOVER'::text, 'MONITOR'::text, 'INVOKE'::text, 'READ'::text, 'WRITE'::text, 'ADMIN'::text])))
);


--
-- Name: component_pulse_mask; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_pulse_mask (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    pulse_type text NOT NULL,
    direction text NOT NULL,
    route_acl text[] DEFAULT '{}'::text[] NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    envelope_schema jsonb NOT NULL,
    execution_mode text NOT NULL,
    idempotency text NOT NULL,
    token_required boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_pulse_mask_direction_check CHECK ((direction = ANY (ARRAY['INCOMING'::text, 'OUTGOING'::text]))),
    CONSTRAINT component_pulse_mask_envelope_schema_check CHECK ((jsonb_typeof(envelope_schema) = 'object'::text))
);


--
-- Name: component_revision; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_revision (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision text NOT NULL,
    schema_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    catalog_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    validation_state text DEFAULT 'PENDING'::text NOT NULL,
    manifest jsonb NOT NULL,
    manifest_digest text NOT NULL,
    artifact_digest text,
    capabilities text[] DEFAULT '{}'::text[] NOT NULL,
    protocols text[] DEFAULT '{}'::text[] NOT NULL,
    transports text[] DEFAULT '{}'::text[] NOT NULL,
    derived_gates jsonb DEFAULT '[]'::jsonb NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    approved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_revision_validation_state_check CHECK ((validation_state = ANY (ARRAY['PENDING'::text, 'APPROVED'::text, 'REJECTED'::text, 'SUPERSEDED'::text])))
);


--
-- Name: component_runtime_target; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_runtime_target (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    transport text NOT NULL,
    upstream text NOT NULL,
    expected_tls_identity text,
    socket_path text,
    status text DEFAULT 'PENDING'::text NOT NULL,
    last_probe_at timestamp with time zone,
    runtime_digest text NOT NULL,
    circuit_failure_count integer DEFAULT 0 NOT NULL,
    circuit_open_until timestamp with time zone,
    last_dispatch_error text,
    runtime_resources jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT component_runtime_target_check CHECK ((((transport = 'UDS'::text) AND (socket_path IS NOT NULL) AND (expected_tls_identity IS NULL)) OR ((transport = 'HTTPS'::text) AND (expected_tls_identity IS NOT NULL) AND (socket_path IS NULL)))),
    CONSTRAINT component_runtime_target_circuit_failure_count_check CHECK ((circuit_failure_count >= 0)),
    CONSTRAINT component_runtime_target_resources_object_check CHECK ((jsonb_typeof(runtime_resources) = 'object'::text)),
    CONSTRAINT component_runtime_target_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'HEALTHY'::text, 'UNHEALTHY'::text, 'DISABLED'::text]))),
    CONSTRAINT component_runtime_target_transport_check CHECK ((transport = ANY (ARRAY['UDS'::text, 'HTTPS'::text])))
);


--
-- Name: component_secret_policy; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_secret_policy (
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    policy_mode text NOT NULL,
    all_secrets_requires_grant boolean DEFAULT true NOT NULL,
    audit_level text DEFAULT 'FULL'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_secret_policy_policy_mode_check CHECK ((policy_mode = ANY (ARRAY['GRANTED_SECRETS'::text, 'ALL_SECRETS'::text])))
);


--
-- Name: component_state_contract; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_state_contract (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    state_key text NOT NULL,
    category text DEFAULT 'OPERATIONAL'::text NOT NULL,
    state_schema jsonb NOT NULL,
    terminal boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_state_contract_state_key_check CHECK ((state_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{1,159}$'::text)),
    CONSTRAINT component_state_contract_state_schema_check CHECK ((jsonb_typeof(state_schema) = 'object'::text))
);


--
-- Name: component_state_observation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_state_observation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    state_key text NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    correlation_id uuid NOT NULL,
    state_payload jsonb NOT NULL,
    validation_state text NOT NULL,
    rejection_reason text,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    query_run_id uuid,
    declared_client_id text,
    declared_component_code text,
    policy_epoch bigint,
    CONSTRAINT component_state_observation_validation_state_check CHECK ((validation_state = ANY (ARRAY['ACCEPTED'::text, 'REJECTED'::text])))
);


--
-- Name: component_state_query_run; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_state_query_run (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    dispatch_id uuid,
    requested_state_keys text[] DEFAULT '{}'::text[] NOT NULL,
    challenge_nonce text NOT NULL,
    requested_policy_epoch bigint NOT NULL,
    correlation_id uuid NOT NULL,
    status text DEFAULT 'PENDING'::text NOT NULL,
    response_state_key text,
    response_digest text,
    response_payload jsonb,
    observed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_state_query_run_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'RESPONDED'::text, 'FAILED'::text])))
);


--
-- Name: component_state_snapshot; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_state_snapshot (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    query_run_id uuid,
    observed_at timestamp with time zone NOT NULL,
    states jsonb NOT NULL,
    state_digest text NOT NULL,
    validation_state text NOT NULL,
    rejection_reason text,
    correlation_id uuid NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT component_state_snapshot_states_check CHECK ((jsonb_typeof(states) = 'object'::text)),
    CONSTRAINT component_state_snapshot_validation_state_check CHECK ((validation_state = ANY (ARRAY['ACCEPTED'::text, 'REJECTED'::text])))
);


--
-- Name: component_state_transition; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_state_transition (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    from_state_key text NOT NULL,
    to_state_key text NOT NULL,
    trigger_mask text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: component_tool_contract; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.component_tool_contract (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    component_id uuid NOT NULL,
    revision_id uuid NOT NULL,
    name text NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    input_schema jsonb NOT NULL,
    output_schema jsonb NOT NULL,
    annotations jsonb DEFAULT '{}'::jsonb NOT NULL,
    scope_name text NOT NULL,
    timeout_ms integer NOT NULL,
    limits jsonb DEFAULT '{}'::jsonb NOT NULL,
    idempotency jsonb DEFAULT '{}'::jsonb NOT NULL,
    variants jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT component_tool_contract_check CHECK (((jsonb_typeof(input_schema) = 'object'::text) AND (jsonb_typeof(output_schema) = 'object'::text))),
    CONSTRAINT component_tool_contract_timeout_ms_check CHECK (((timeout_ms >= 1) AND (timeout_ms <= 60000)))
);


--
-- Name: egress_capability; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.egress_capability (
    lookup_digest bytea NOT NULL,
    fingerprint text NOT NULL,
    job_id uuid NOT NULL,
    server_id uuid,
    allowlist jsonb NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone
);


--
-- Name: external_api_service_profile; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.external_api_service_profile (
    managed_service_id uuid NOT NULL,
    base_url text NOT NULL,
    healthcheck_url text,
    readiness_url text,
    token_endpoint_url text,
    jwks_url text,
    auth_metadata_url text,
    api_style text DEFAULT 'REST'::text NOT NULL,
    auth_header_name text DEFAULT 'Authorization'::text NOT NULL,
    auth_header_scheme text,
    token_forwarding_mode text DEFAULT 'BEARER'::text NOT NULL,
    rate_window_seconds integer,
    rate_max_requests integer,
    timeout_ms integer,
    upstream_contract jsonb DEFAULT '{}'::jsonb NOT NULL,
    monitoring_contract jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT external_api_service_profile_api_style_check CHECK ((api_style = ANY (ARRAY['REST'::text, 'GRAPHQL'::text, 'CUSTOM_HTTP'::text]))),
    CONSTRAINT external_api_service_profile_auth_metadata_url_check CHECK (((auth_metadata_url IS NULL) OR (auth_metadata_url ~* '^https://'::text))),
    CONSTRAINT external_api_service_profile_base_url_check CHECK ((base_url ~* '^https://'::text)),
    CONSTRAINT external_api_service_profile_healthcheck_url_check CHECK (((healthcheck_url IS NULL) OR (healthcheck_url ~* '^https://'::text))),
    CONSTRAINT external_api_service_profile_jwks_url_check CHECK (((jwks_url IS NULL) OR (jwks_url ~* '^https://'::text))),
    CONSTRAINT external_api_service_profile_rate_max_requests_check CHECK (((rate_max_requests IS NULL) OR ((rate_max_requests >= 1) AND (rate_max_requests <= 100000)))),
    CONSTRAINT external_api_service_profile_rate_window_seconds_check CHECK (((rate_window_seconds IS NULL) OR ((rate_window_seconds >= 1) AND (rate_window_seconds <= 86400)))),
    CONSTRAINT external_api_service_profile_readiness_url_check CHECK (((readiness_url IS NULL) OR (readiness_url ~* '^https://'::text))),
    CONSTRAINT external_api_service_profile_timeout_ms_check CHECK (((timeout_ms IS NULL) OR ((timeout_ms >= 100) AND (timeout_ms <= 60000)))),
    CONSTRAINT external_api_service_profile_token_endpoint_url_check CHECK (((token_endpoint_url IS NULL) OR (token_endpoint_url ~* '^https://'::text))),
    CONSTRAINT external_api_service_profile_token_forwarding_mode_check CHECK ((token_forwarding_mode = ANY (ARRAY['BEARER'::text, 'HEADER_VALUE'::text, 'QUERY_FORBIDDEN'::text])))
);


--
-- Name: function_concurrency_lease; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.function_concurrency_lease (
    lease_id uuid DEFAULT gen_random_uuid() NOT NULL,
    server_id uuid NOT NULL,
    acquired_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: function_rate_bucket; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.function_rate_bucket (
    server_id uuid NOT NULL,
    window_started_at timestamp with time zone NOT NULL,
    request_count integer NOT NULL,
    credential_id uuid NOT NULL,
    CONSTRAINT function_rate_bucket_request_count_check CHECK ((request_count >= 0))
);


--
-- Name: function_statistics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.function_statistics (
    server_id uuid NOT NULL,
    success_count bigint DEFAULT 0 NOT NULL,
    unauthorized_count bigint DEFAULT 0 NOT NULL,
    failure_count bigint DEFAULT 0 NOT NULL,
    last_success_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    last_unauthorized_at timestamp with time zone,
    CONSTRAINT function_statistics_failure_count_check CHECK ((failure_count >= 0)),
    CONSTRAINT function_statistics_success_count_check CHECK ((success_count >= 0)),
    CONSTRAINT function_statistics_unauthorized_count_check CHECK ((unauthorized_count >= 0))
);


--
-- Name: http_rate_bucket; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.http_rate_bucket (
    bucket_key bytea NOT NULL,
    window_started_at timestamp with time zone NOT NULL,
    request_count integer NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT http_rate_bucket_bucket_key_check CHECK ((octet_length(bucket_key) = 32)),
    CONSTRAINT http_rate_bucket_request_count_check CHECK ((request_count > 0))
);


--
-- Name: integration_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_token (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    label text NOT NULL,
    lookup_digest bytea NOT NULL,
    key_id text NOT NULL,
    fingerprint text NOT NULL,
    created_by uuid NOT NULL,
    onboarding_job_id uuid,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    initial_expires_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    max_expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    deleted_at timestamp with time zone,
    last_used_at timestamp with time zone,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    descriptor jsonb NOT NULL,
    legacy_backfill boolean DEFAULT false NOT NULL,
    service_kind public.managed_service_kind DEFAULT 'COMPONENT'::public.managed_service_kind NOT NULL,
    allowed_pipeline public.service_pipeline_kind DEFAULT 'COMPONENT_ONBOARDING'::public.service_pipeline_kind NOT NULL,
    usage_count integer DEFAULT 0 NOT NULL,
    token_kind public.integration_token_kind DEFAULT 'SINGLE_COMPONENT'::public.integration_token_kind NOT NULL,
    release_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    max_child_jobs integer DEFAULT 1 NOT NULL,
    auto_activate_after_pass boolean DEFAULT false NOT NULL,
    manual_approval_required_after_issuance boolean DEFAULT true NOT NULL,
    release_wave_key text,
    blueprint_release_version text,
    CONSTRAINT integration_token_descriptor_check CHECK (((jsonb_typeof(descriptor) = 'object'::text) AND (descriptor ?& ARRAY['summary'::text, 'businessPurpose'::text, 'serviceOwner'::text, 'technicalOwner'::text, 'criticality'::text]) AND ((descriptor - ARRAY['summary'::text, 'businessPurpose'::text, 'serviceOwner'::text, 'technicalOwner'::text, 'criticality'::text]) = '{}'::jsonb) AND (jsonb_typeof((descriptor -> 'summary'::text)) = 'string'::text) AND (jsonb_typeof((descriptor -> 'businessPurpose'::text)) = 'string'::text) AND (jsonb_typeof((descriptor -> 'serviceOwner'::text)) = 'string'::text) AND (jsonb_typeof((descriptor -> 'technicalOwner'::text)) = 'string'::text) AND ((descriptor ->> 'criticality'::text) = ANY (ARRAY['LOW'::text, 'MEDIUM'::text, 'HIGH'::text, 'CRITICAL'::text])))),
    CONSTRAINT integration_token_label_check CHECK (((char_length(label) >= 1) AND (char_length(label) <= 120))),
    CONSTRAINT integration_token_max_child_jobs_check CHECK ((((max_child_jobs >= 1) AND (max_child_jobs <= 200)) AND ((token_kind <> 'BLUEPRINT_RELEASE'::public.integration_token_kind) OR ((max_child_jobs >= 1) AND (max_child_jobs <= 20))))),
    CONSTRAINT integration_token_single_use_24h_check CHECK (((initial_expires_at = (issued_at + '24:00:00'::interval)) AND (expires_at = (issued_at + '24:00:00'::interval)) AND (max_expires_at = (issued_at + '24:00:00'::interval)) AND (max_child_jobs = 1)))
);


--
-- Name: integration_token_allowed_component; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_token_allowed_component (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_id uuid NOT NULL,
    blueprint_component_id text NOT NULL,
    registration_type text NOT NULL,
    release_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    release_wave_key text,
    CONSTRAINT integration_token_allowed_component_registration_type_check CHECK ((registration_type = ANY (ARRAY['KCML_ACCESS_CLIENT'::text, 'KAJA_CLIENT'::text, 'MCP_SERVER'::text, 'MANAGED_PLATFORM_SERVICE'::text])))
);


--
-- Name: integration_token_child_job; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_token_child_job (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_id uuid NOT NULL,
    onboarding_job_id uuid,
    blueprint_component_id text NOT NULL,
    registration_type text NOT NULL,
    release_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    authorization_snapshot jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    release_wave_key text,
    component_onboarding_job_id uuid,
    CONSTRAINT integration_token_child_job_registration_type_check CHECK ((registration_type = ANY (ARRAY['KCML_ACCESS_CLIENT'::text, 'KAJA_CLIENT'::text, 'MCP_SERVER'::text, 'MANAGED_PLATFORM_SERVICE'::text])))
);


--
-- Name: kaja_number_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.kaja_number_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: kcml_number_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.kcml_number_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: kcml_number_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.kcml_number_seq OWNED BY public.component.kcml_number;


--
-- Name: principal; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principal (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    public_id public.citext NOT NULL,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    policy_epoch bigint DEFAULT 1 NOT NULL,
    revocation_epoch bigint DEFAULT 1 NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT principal_kind_check CHECK ((kind = ANY (ARRAY['COMPONENT'::text, 'EXTERNAL'::text, 'PLATFORM'::text, 'ADMIN_AUTOMATION'::text]))),
    CONSTRAINT principal_policy_epoch_check CHECK ((policy_epoch > 0)),
    CONSTRAINT principal_revocation_epoch_check CHECK ((revocation_epoch > 0)),
    CONSTRAINT principal_status_check CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'SUSPENDED'::text, 'QUARANTINED'::text, 'REVOKED'::text])))
);


--
-- Name: legacy_component_runtime_adapter; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.legacy_component_runtime_adapter AS
 SELECT c.id AS component_id,
    c.code,
    c.hostname,
    c.active_revision_id,
    c.enabled,
    p.status AS principal_status
   FROM (public.component c
     JOIN public.principal p ON ((p.id = c.principal_id)));


--
-- Name: managed_service; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    legacy_mcp_server_id uuid,
    code public.citext NOT NULL,
    slug public.citext NOT NULL,
    display_name text NOT NULL,
    description text NOT NULL,
    service_kind public.managed_service_kind NOT NULL,
    lifecycle_state public.managed_service_state DEFAULT 'DRAFT'::public.managed_service_state NOT NULL,
    operational_state public.operational_state DEFAULT 'UNKNOWN'::public.operational_state NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    public_hostname public.citext,
    base_url text,
    resource_uri text,
    auth_mode public.managed_service_auth_mode DEFAULT 'OAUTH2_CLIENT_CREDENTIALS'::public.managed_service_auth_mode NOT NULL,
    api_state public.managed_service_api_state DEFAULT 'DISABLED'::public.managed_service_api_state NOT NULL,
    api_disabled_reason text,
    criticality text DEFAULT 'MEDIUM'::text NOT NULL,
    owners jsonb DEFAULT '{}'::jsonb NOT NULL,
    contacts jsonb DEFAULT '{}'::jsonb NOT NULL,
    governance jsonb DEFAULT '{}'::jsonb NOT NULL,
    active_revision_id uuid,
    monitoring_enabled boolean DEFAULT false NOT NULL,
    monitoring_profile_digest text,
    review_approved_at timestamp with time zone,
    review_due_at timestamp with time zone,
    review_interval_days integer,
    revocation_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    environment text DEFAULT 'production'::text NOT NULL,
    service_token_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    permission_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    active_revision_epoch bigint DEFAULT 0 NOT NULL,
    last_policy_invalidation_at timestamp with time zone,
    component_id uuid NOT NULL,
    CONSTRAINT managed_service_base_url_check CHECK (((base_url IS NULL) OR (base_url ~* '^https://'::text))),
    CONSTRAINT managed_service_check CHECK ((((lifecycle_state = ANY (ARRAY['ACTIVE'::public.managed_service_state, 'TRIAL'::public.managed_service_state])) AND (enabled IS TRUE)) OR (lifecycle_state <> ALL (ARRAY['ACTIVE'::public.managed_service_state, 'TRIAL'::public.managed_service_state])) OR (enabled IS FALSE))),
    CONSTRAINT managed_service_criticality_check CHECK ((criticality = ANY (ARRAY['LOW'::text, 'MEDIUM'::text, 'HIGH'::text, 'CRITICAL'::text]))),
    CONSTRAINT managed_service_public_hostname_check CHECK (((public_hostname IS NULL) OR (public_hostname OPERATOR(public.~*) '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'::public.citext))),
    CONSTRAINT managed_service_resource_uri_check CHECK (((resource_uri IS NULL) OR (resource_uri ~* '^https://'::text))),
    CONSTRAINT managed_service_review_interval_days_check CHECK (((review_interval_days IS NULL) OR ((review_interval_days >= 1) AND (review_interval_days <= 365))))
);


--
-- Name: managed_service_access_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_access_token (
    lookup_digest bytea NOT NULL,
    key_id text NOT NULL,
    fingerprint text NOT NULL,
    credential_id uuid NOT NULL,
    managed_service_id uuid NOT NULL,
    audience text NOT NULL,
    scope_names text[] DEFAULT '{}'::text[] NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    credential_revocation_epoch uuid NOT NULL,
    service_revocation_epoch uuid NOT NULL,
    environment text DEFAULT 'production'::text NOT NULL,
    principal_token_epoch uuid NOT NULL,
    service_token_epoch uuid NOT NULL,
    permission_epoch_snapshot uuid NOT NULL,
    active_revision_epoch_snapshot bigint DEFAULT 0 NOT NULL,
    legacy_access_token_digest bytea,
    component_id uuid
);


--
-- Name: managed_service_api_status; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_api_status (
    managed_service_id uuid NOT NULL,
    api_state public.managed_service_api_state NOT NULL,
    disabled_reason text,
    changed_by_type text NOT NULL,
    changed_by_id text,
    correlation_id uuid,
    changed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: managed_service_api_status_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_api_status_history (
    id bigint NOT NULL,
    managed_service_id uuid NOT NULL,
    previous_state public.managed_service_api_state,
    current_state public.managed_service_api_state NOT NULL,
    reason text,
    actor_type text NOT NULL,
    actor_id text,
    lock_version bigint NOT NULL,
    correlation_id uuid,
    decision_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: managed_service_api_status_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.managed_service_api_status_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: managed_service_api_status_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.managed_service_api_status_history_id_seq OWNED BY public.managed_service_api_status_history.id;


--
-- Name: managed_service_permission; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_permission (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    credential_id uuid NOT NULL,
    managed_service_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    state text DEFAULT 'GRANTED'::text NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_to timestamp with time zone,
    permission_version bigint DEFAULT 0 NOT NULL,
    audit_metadata jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: managed_service_policy_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_policy_event (
    id bigint NOT NULL,
    managed_service_id uuid NOT NULL,
    event_type text NOT NULL,
    correlation_id uuid NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: managed_service_policy_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.managed_service_policy_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: managed_service_policy_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.managed_service_policy_event_id_seq OWNED BY public.managed_service_policy_event.id;


--
-- Name: managed_service_probe_result; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_probe_result (
    id bigint NOT NULL,
    managed_service_id uuid NOT NULL,
    probe_type text NOT NULL,
    status text NOT NULL,
    latency_ms integer,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    checked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT managed_service_probe_result_status_check CHECK ((status = ANY (ARRAY['PASS'::text, 'FAIL'::text, 'STALE'::text])))
);


--
-- Name: managed_service_probe_result_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.managed_service_probe_result_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: managed_service_probe_result_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.managed_service_probe_result_id_seq OWNED BY public.managed_service_probe_result.id;


--
-- Name: managed_service_revision; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_revision (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    managed_service_id uuid NOT NULL,
    revision text NOT NULL,
    schema_version text NOT NULL,
    service_kind public.managed_service_kind NOT NULL,
    validation_state text DEFAULT 'APPROVED'::text NOT NULL,
    manifest jsonb NOT NULL,
    manifest_digest text NOT NULL,
    artifact_digest text,
    contract_digest text,
    sbom_digest text,
    provenance_digest text,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    approved_at timestamp with time zone,
    review_due_at timestamp with time zone,
    review_interval_days integer,
    active boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT managed_service_revision_review_interval_days_check CHECK (((review_interval_days IS NULL) OR ((review_interval_days >= 1) AND (review_interval_days <= 365))))
);


--
-- Name: managed_service_runtime_log_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_runtime_log_event (
    id bigint NOT NULL,
    managed_service_id uuid NOT NULL,
    level text NOT NULL,
    event_name text NOT NULL,
    fields jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT managed_service_runtime_log_event_level_check CHECK ((level = ANY (ARRAY['info'::text, 'warn'::text, 'error'::text])))
);


--
-- Name: managed_service_runtime_log_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.managed_service_runtime_log_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: managed_service_runtime_log_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.managed_service_runtime_log_event_id_seq OWNED BY public.managed_service_runtime_log_event.id;


--
-- Name: managed_service_scope; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_scope (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    managed_service_id uuid NOT NULL,
    scope_name text NOT NULL,
    level text NOT NULL,
    description text NOT NULL,
    constraints_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT managed_service_scope_level_check CHECK ((level = ANY (ARRAY['DISCOVER'::text, 'MONITOR'::text, 'INVOKE'::text, 'READ'::text, 'WRITE'::text, 'ADMIN'::text])))
);


--
-- Name: managed_service_usage_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_service_usage_event (
    id bigint NOT NULL,
    managed_service_id uuid NOT NULL,
    credential_id uuid,
    scope_name text,
    request_digest text,
    response_digest text,
    outcome text NOT NULL,
    latency_ms integer,
    classification text,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT managed_service_usage_event_latency_ms_check CHECK (((latency_ms IS NULL) OR (latency_ms >= 0))),
    CONSTRAINT managed_service_usage_event_outcome_check CHECK ((outcome = ANY (ARRAY['ACCEPTED'::text, 'SUCCEEDED'::text, 'FAILED'::text, 'UNAUTHORIZED'::text, 'RATE_LIMITED'::text])))
);


--
-- Name: managed_service_usage_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.managed_service_usage_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: managed_service_usage_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.managed_service_usage_event_id_seq OWNED BY public.managed_service_usage_event.id;


--
-- Name: mcp_invocation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_invocation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    server_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    request_digest text NOT NULL,
    idempotency_key text,
    status text NOT NULL,
    latency_ms integer,
    error_class text,
    response_digest text,
    accepted_at timestamp with time zone DEFAULT now() NOT NULL,
    finalized_at timestamp with time zone,
    CONSTRAINT mcp_invocation_latency_ms_check CHECK (((latency_ms IS NULL) OR (latency_ms >= 0))),
    CONSTRAINT mcp_invocation_status_check CHECK ((status = ANY (ARRAY['ACCEPTED'::text, 'SUCCEEDED'::text, 'FAILED'::text, 'FINALIZATION_FAILED'::text])))
);


--
-- Name: mcp_invocation_idempotency; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_invocation_idempotency (
    server_id uuid NOT NULL,
    credential_id uuid NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    status text NOT NULL,
    response_json jsonb,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    pending_expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mcp_invocation_idempotency_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'COMPLETED'::text])))
);


--
-- Name: mcp_invocation_metric; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_invocation_metric (
    id bigint NOT NULL,
    server_id uuid NOT NULL,
    success boolean NOT NULL,
    latency_ms integer NOT NULL,
    classification text,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mcp_invocation_metric_latency_ms_check CHECK ((latency_ms >= 0))
);


--
-- Name: mcp_invocation_metric_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mcp_invocation_metric_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mcp_invocation_metric_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mcp_invocation_metric_id_seq OWNED BY public.mcp_invocation_metric.id;


--
-- Name: mcp_rate_bucket; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_rate_bucket (
    scope_type text NOT NULL,
    scope_key bytea NOT NULL,
    server_id uuid,
    credential_id uuid,
    window_started_at timestamp with time zone NOT NULL,
    request_count integer NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mcp_rate_bucket_request_count_check CHECK ((request_count >= 0)),
    CONSTRAINT mcp_rate_bucket_scope_shape_check CHECK ((((scope_type = 'SERVER'::text) AND (server_id IS NOT NULL) AND (credential_id IS NULL)) OR ((scope_type = 'CREDENTIAL'::text) AND (server_id IS NULL) AND (credential_id IS NOT NULL)) OR ((scope_type = 'SERVER_CREDENTIAL'::text) AND (server_id IS NOT NULL) AND (credential_id IS NOT NULL)))),
    CONSTRAINT mcp_rate_bucket_scope_type_check CHECK ((scope_type = ANY (ARRAY['SERVER'::text, 'CREDENTIAL'::text, 'SERVER_CREDENTIAL'::text])))
);


--
-- Name: mcp_server; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_server (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kcml_number bigint NOT NULL,
    code public.citext NOT NULL,
    hostname public.citext NOT NULL,
    tool_name public.citext NOT NULL,
    display_name text NOT NULL,
    description text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    registration_state public.registration_state DEFAULT 'DRAFT'::public.registration_state NOT NULL,
    operational_state public.operational_state DEFAULT 'UNKNOWN'::public.operational_state NOT NULL,
    input_schema jsonb NOT NULL,
    output_schema jsonb NOT NULL,
    handler_key text NOT NULL,
    handler_version text NOT NULL,
    contract_version text NOT NULL,
    artifact_digest text NOT NULL,
    manifest_digest text NOT NULL,
    revocation_epoch uuid DEFAULT gen_random_uuid() NOT NULL,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    retired_at timestamp with time zone,
    image_reference text,
    image_digest text,
    sbom_digest text,
    provenance_digest text,
    runtime_socket text,
    timeout_ms integer DEFAULT 30000 NOT NULL,
    max_concurrency integer DEFAULT 1 NOT NULL,
    request_max_bytes integer DEFAULT 1048576 NOT NULL,
    response_max_bytes integer DEFAULT 5242880 NOT NULL,
    rate_window_seconds integer DEFAULT 60 NOT NULL,
    rate_max_requests integer DEFAULT 60 NOT NULL,
    read_only_hint boolean,
    destructive_hint boolean,
    idempotent_hint boolean,
    open_world_hint boolean,
    effect_class text,
    shutdown_policy text,
    idempotency_policy text,
    active_revision_id uuid,
    release_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    blueprint_component_id text,
    archived_at timestamp with time zone,
    archive_reason text,
    component_id uuid NOT NULL,
    release_wave_key text,
    CONSTRAINT mcp_server_check CHECK ((((registration_state = ANY (ARRAY['ACTIVE'::public.registration_state, 'TRIAL'::public.registration_state])) AND (enabled IS TRUE)) OR (registration_state <> ALL (ARRAY['ACTIVE'::public.registration_state, 'TRIAL'::public.registration_state])) OR (enabled IS FALSE))),
    CONSTRAINT mcp_server_code_check CHECK ((code OPERATOR(public.~*) '^KCML[0-9]{4,}$'::public.citext)),
    CONSTRAINT mcp_server_effect_class_check CHECK (((effect_class IS NULL) OR (effect_class = ANY (ARRAY['READ_ONLY'::text, 'IDEMPOTENT_WRITE'::text, 'NON_IDEMPOTENT_WRITE'::text])))),
    CONSTRAINT mcp_server_hostname_check CHECK (((split_part(lower((hostname)::text), '.'::text, 1) = lower((code)::text)) AND (hostname OPERATOR(public.~*) '^kcml[0-9]{4,}[.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'::public.citext))),
    CONSTRAINT mcp_server_max_concurrency_check CHECK (((max_concurrency >= 1) AND (max_concurrency <= 32))),
    CONSTRAINT mcp_server_rate_max_requests_check CHECK (((rate_max_requests >= 1) AND (rate_max_requests <= 100000))),
    CONSTRAINT mcp_server_rate_window_seconds_check CHECK (((rate_window_seconds >= 1) AND (rate_window_seconds <= 86400))),
    CONSTRAINT mcp_server_request_max_bytes_check CHECK (((request_max_bytes >= 1) AND (request_max_bytes <= 1048576))),
    CONSTRAINT mcp_server_response_max_bytes_check CHECK (((response_max_bytes >= 1) AND (response_max_bytes <= 5242880))),
    CONSTRAINT mcp_server_shutdown_policy_check CHECK (((shutdown_policy IS NULL) OR (shutdown_policy = ANY (ARRAY['COMPLETE_IN_FLIGHT'::text, 'CANCEL_SAFE'::text, 'COMPENSATE'::text])))),
    CONSTRAINT mcp_server_timeout_ms_check CHECK (((timeout_ms >= 100) AND (timeout_ms <= 60000)))
);


--
-- Name: monitoring_probe_result; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.monitoring_probe_result (
    id bigint NOT NULL,
    server_id uuid NOT NULL,
    probe_type text NOT NULL,
    status text NOT NULL,
    latency_ms integer,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    checked_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT monitoring_probe_result_status_check CHECK ((status = ANY (ARRAY['PASS'::text, 'FAIL'::text, 'STALE'::text])))
);


--
-- Name: monitoring_probe_result_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.monitoring_probe_result_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: monitoring_probe_result_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.monitoring_probe_result_id_seq OWNED BY public.monitoring_probe_result.id;


--
-- Name: monitoring_profile; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.monitoring_profile (
    server_id uuid NOT NULL,
    profile jsonb NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    registration_revision_id uuid,
    profile_digest text,
    next_probe_at timestamp with time zone DEFAULT now() NOT NULL,
    last_probe_at timestamp with time zone,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    version bigint DEFAULT 0 NOT NULL,
    CONSTRAINT monitoring_profile_consecutive_failures_check CHECK ((consecutive_failures >= 0)),
    CONSTRAINT monitoring_profile_version_check CHECK ((version >= 0))
);


--
-- Name: monitoring_scheduler_heartbeat; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.monitoring_scheduler_heartbeat (
    singleton boolean DEFAULT true NOT NULL,
    worker_id text NOT NULL,
    last_started_at timestamp with time zone NOT NULL,
    last_completed_at timestamp with time zone,
    last_error text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT monitoring_scheduler_heartbeat_singleton_check CHECK (singleton)
);


--
-- Name: onboarding_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.onboarding_event (
    id bigint NOT NULL,
    job_id uuid NOT NULL,
    from_state public.onboarding_job_state,
    to_state public.onboarding_job_state NOT NULL,
    event_type text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: onboarding_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.onboarding_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: onboarding_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.onboarding_event_id_seq OWNED BY public.onboarding_event.id;


--
-- Name: onboarding_gate; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.onboarding_gate (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    job_id uuid NOT NULL,
    gate_name text NOT NULL,
    stage text NOT NULL,
    status text NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT onboarding_gate_status_check CHECK ((status = ANY (ARRAY['PENDING'::text, 'RUNNING'::text, 'PASS'::text, 'FAIL'::text, 'QUARANTINED'::text, 'SKIPPED'::text])))
);


--
-- Name: onboarding_job; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.onboarding_job (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_id uuid NOT NULL,
    server_id uuid,
    kcml_number bigint,
    code public.citext,
    hostname public.citext,
    tool_name public.citext,
    state public.onboarding_job_state DEFAULT 'CREATED'::public.onboarding_job_state NOT NULL,
    correlation_id uuid NOT NULL,
    manifest jsonb,
    manifest_digest text,
    source_digest text,
    source_archive_path text,
    source_revision integer DEFAULT 0 NOT NULL,
    github_branch text,
    github_pr_number bigint,
    github_pr_url text,
    source_commit text,
    build_id text,
    image_reference text,
    image_digest text,
    sbom_digest text,
    provenance_digest text,
    blocking_error_code text,
    blocking_error_detail text,
    lease_owner text,
    lease_expires_at timestamp with time zone,
    heartbeat_at timestamp with time zone,
    token_extended_at timestamp with time zone,
    next_run_at timestamp with time zone DEFAULT now() NOT NULL,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    runtime_stopped_at timestamp with time zone,
    service_kind public.managed_service_kind DEFAULT 'MCP'::public.managed_service_kind NOT NULL,
    release_version text DEFAULT '2026.07.22-compliance.1'::text NOT NULL,
    blueprint_component_id text,
    registration_type text,
    archived_at timestamp with time zone,
    archive_reason text,
    component_id uuid,
    release_wave_key text,
    authorization_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT onboarding_job_code_check CHECK (((code IS NULL) OR (code OPERATOR(public.~*) '^KCML[0-9]{4,}$'::public.citext))),
    CONSTRAINT onboarding_job_hostname_check CHECK (((hostname IS NULL) OR ((code IS NOT NULL) AND (split_part(lower((hostname)::text), '.'::text, 1) = lower((code)::text)) AND (hostname OPERATOR(public.~*) '^kcml[0-9]{4,}[.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'::public.citext)))),
    CONSTRAINT onboarding_job_registration_type_check CHECK (((registration_type IS NULL) OR (registration_type = ANY (ARRAY['KCML_ACCESS_CLIENT'::text, 'KAJA_CLIENT'::text, 'MCP_SERVER'::text, 'MANAGED_PLATFORM_SERVICE'::text])))),
    CONSTRAINT onboarding_job_source_revision_check CHECK ((source_revision >= 0))
);


--
-- Name: onboarding_source_revision; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.onboarding_source_revision (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    job_id uuid NOT NULL,
    revision integer NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    source_digest text NOT NULL,
    archive_path text NOT NULL,
    manifest jsonb NOT NULL,
    manifest_digest text NOT NULL,
    validation_evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT onboarding_source_revision_revision_check CHECK ((revision > 0))
);


--
-- Name: operational_alert; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.operational_alert (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    server_id uuid,
    severity text NOT NULL,
    alert_type text NOT NULL,
    status text DEFAULT 'OPEN'::text NOT NULL,
    title text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_by uuid,
    acknowledged_at timestamp with time zone,
    suppression_reason text,
    suppression_owner uuid,
    suppressed_until timestamp with time zone,
    closed_at timestamp with time zone,
    managed_service_id uuid,
    CONSTRAINT operational_alert_severity_check CHECK ((severity = ANY (ARRAY['WARNING'::text, 'HIGH'::text, 'CRITICAL'::text]))),
    CONSTRAINT operational_alert_status_check CHECK ((status = ANY (ARRAY['OPEN'::text, 'ACKNOWLEDGED'::text, 'SUPPRESSED'::text, 'CLOSED'::text])))
);


--
-- Name: operational_config_applied; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.operational_config_applied (
    key text NOT NULL,
    process_role text NOT NULL,
    version integer NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT operational_config_applied_process_role_check CHECK ((process_role = ANY (ARRAY['web'::text, 'worker'::text, 'monitor'::text, 'egress'::text]))),
    CONSTRAINT operational_config_applied_version_check CHECK ((version >= 0))
);


--
-- Name: operational_config_setting; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.operational_config_setting (
    key text NOT NULL,
    value_json jsonb,
    updated_by uuid,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    version integer DEFAULT 0 NOT NULL,
    secret_ciphertext text,
    is_secret boolean DEFAULT false NOT NULL,
    CONSTRAINT operational_config_value_shape_check CHECK (((is_secret AND (value_json IS NULL) AND (secret_ciphertext IS NOT NULL) AND (secret_ciphertext ~~ 'vault:v1:%'::text)) OR ((NOT is_secret) AND (value_json IS NOT NULL) AND (secret_ciphertext IS NULL))))
);


--
-- Name: platform_worker_access_identity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_worker_access_identity (
    singleton boolean DEFAULT true NOT NULL,
    principal_id uuid NOT NULL,
    access_token_id uuid,
    token_ciphertext text,
    key_id text,
    fingerprint text,
    rotated_by uuid,
    rotated_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_worker_access_identity_check CHECK ((((access_token_id IS NULL) AND (token_ciphertext IS NULL) AND (key_id IS NULL) AND (fingerprint IS NULL)) OR ((access_token_id IS NOT NULL) AND (token_ciphertext IS NOT NULL) AND (key_id IS NOT NULL) AND (fingerprint IS NOT NULL)))),
    CONSTRAINT platform_worker_access_identity_singleton_check CHECK (singleton)
);


--
-- Name: platform_worker_heartbeat; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_worker_heartbeat (
    worker_kind text NOT NULL,
    worker_id text NOT NULL,
    build_id text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    last_heartbeat_at timestamp with time zone NOT NULL,
    last_completed_at timestamp with time zone,
    last_error text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT platform_worker_heartbeat_worker_kind_check CHECK ((worker_kind = ANY (ARRAY['COMPONENT_CONTROL'::text, 'COMPONENT_E2E'::text])))
);


--
-- Name: principal_access_token; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principal_access_token (
    lookup_digest bytea NOT NULL,
    fingerprint text NOT NULL,
    source_principal_id uuid NOT NULL,
    target_component_id uuid,
    audience text NOT NULL,
    scope_names text[] DEFAULT '{}'::text[] NOT NULL,
    issued_policy_epoch bigint NOT NULL,
    issued_revocation_epoch bigint NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    handed_off_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at timestamp with time zone,
    rotation_reason text,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_id text DEFAULT 'v1'::text NOT NULL,
    CONSTRAINT principal_access_token_long_lived_check CHECK ((expires_at = 'infinity'::timestamp with time zone))
);


--
-- Name: principal_component_permission; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principal_component_permission (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_principal_id uuid NOT NULL,
    target_component_id uuid NOT NULL,
    route_pattern text NOT NULL,
    scope_name text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone
);


--
-- Name: principal_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principal_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    principal_id uuid NOT NULL,
    public_id public.citext NOT NULL,
    secret_digest bytea NOT NULL,
    fingerprint text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revocation_epoch bigint DEFAULT 1 NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT principal_credential_revocation_epoch_check CHECK ((revocation_epoch > 0))
);


--
-- Name: registration_revision; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.registration_revision (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    server_id uuid,
    revision text NOT NULL,
    state public.registration_state NOT NULL,
    manifest jsonb NOT NULL,
    manifest_digest text NOT NULL,
    artifact_digest text NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    schema_version text,
    approved_at timestamp with time zone,
    review_due_at timestamp with time zone,
    review_interval_days integer,
    certification_digest text,
    validation_state text,
    active boolean DEFAULT false NOT NULL,
    superseded_at timestamp with time zone,
    warning_emitted_at timestamp with time zone,
    CONSTRAINT registration_revision_review_interval_check CHECK (((review_interval_days >= 1) AND (review_interval_days <= 365))),
    CONSTRAINT registration_revision_validation_state_check CHECK ((validation_state = ANY (ARRAY['VALID'::text, 'INVALID'::text])))
);


--
-- Name: release_epoch; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.release_epoch (
    release_version text NOT NULL,
    blueprint_version text NOT NULL,
    catalog_version text NOT NULL,
    manifest_schema_version text NOT NULL,
    pulse_envelope_version text NOT NULL,
    policy_baseline date NOT NULL,
    mcp_protocol_version text NOT NULL,
    sealed_previous_epoch_hash text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT release_epoch_release_version_check CHECK ((release_version ~ '^[0-9]{4}[.][0-9]{2}[.][0-9]{2}(-[a-z0-9]+([.][a-z0-9]+)*)?$'::text))
);


--
-- Name: release_wave; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.release_wave (
    release_version text NOT NULL,
    wave_key text NOT NULL,
    display_name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    baseline boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: release_wave_component; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.release_wave_component (
    release_version text NOT NULL,
    wave_key text NOT NULL,
    blueprint_component_id text NOT NULL,
    category text NOT NULL,
    registration_type text NOT NULL,
    component_role text NOT NULL,
    required_in_baseline boolean DEFAULT true NOT NULL,
    display_order integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT release_wave_component_category_check CHECK ((category = ANY (ARRAY['AI_AGENT'::text, 'MCP_SERVER'::text, 'PLATFORM_SERVICE'::text]))),
    CONSTRAINT release_wave_component_component_role_check CHECK ((component_role = ANY (ARRAY['AGENT'::text, 'SERVICE'::text, 'PLATFORM'::text]))),
    CONSTRAINT release_wave_component_registration_type_check CHECK ((registration_type = ANY (ARRAY['KCML_ACCESS_CLIENT'::text, 'KAJA_CLIENT'::text, 'MCP_SERVER'::text, 'MANAGED_PLATFORM_SERVICE'::text])))
);


--
-- Name: runtime_log_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runtime_log_event (
    id bigint NOT NULL,
    server_id uuid NOT NULL,
    level text NOT NULL,
    event_name text NOT NULL,
    fields jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    image_digest text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT runtime_log_event_level_check CHECK ((level = ANY (ARRAY['info'::text, 'warn'::text, 'error'::text])))
);


--
-- Name: runtime_log_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.runtime_log_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: runtime_log_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.runtime_log_event_id_seq OWNED BY public.runtime_log_event.id;


--
-- Name: secret_admin_reveal_grant; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_admin_reveal_grant (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    secret_version_id uuid NOT NULL,
    admin_account_id uuid NOT NULL,
    correlation_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    admin_session_id uuid,
    purpose text DEFAULT 'admin reveal'::text NOT NULL,
    ui_event_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT secret_admin_reveal_grant_check CHECK ((expires_at > created_at)),
    CONSTRAINT secret_admin_reveal_grant_ui_event_count_check CHECK ((ui_event_count >= 0))
);


--
-- Name: secret_api_rate_limit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_api_rate_limit (
    bucket_key bytea NOT NULL,
    window_started_at timestamp with time zone NOT NULL,
    request_count integer NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT secret_api_rate_limit_request_count_check CHECK ((request_count >= 0))
);


--
-- Name: secret_grant; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_grant (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    secret_id uuid NOT NULL,
    principal_kind text NOT NULL,
    principal_id uuid,
    principal_public_id public.citext,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_by uuid,
    revoked_at timestamp with time zone,
    revoked_by uuid,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    all_secrets boolean DEFAULT false NOT NULL,
    CONSTRAINT secret_grant_check CHECK (((principal_id IS NOT NULL) OR (principal_public_id IS NOT NULL))),
    CONSTRAINT secret_grant_principal_kind_check CHECK ((principal_kind = ANY (ARRAY['KAJA'::text, 'COMPONENT'::text])))
);


--
-- Name: secret_record; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_record (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    stable_name public.citext NOT NULL,
    display_name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    owner_kind text DEFAULT 'PLATFORM'::text NOT NULL,
    owner_id uuid,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    active_version_id uuid,
    lock_version bigint DEFAULT 0 NOT NULL,
    created_by uuid,
    updated_by uuid,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT secret_record_check CHECK (((status = 'DELETED'::text) = (deleted_at IS NOT NULL))),
    CONSTRAINT secret_record_lock_version_check CHECK ((lock_version >= 0)),
    CONSTRAINT secret_record_owner_kind_check CHECK ((owner_kind = ANY (ARRAY['PLATFORM'::text, 'COMPONENT'::text, 'MANAGED_SERVICE'::text, 'KAJA'::text]))),
    CONSTRAINT secret_record_stable_name_check CHECK ((stable_name OPERATOR(public.~) '^[A-Z][A-Z0-9_]{2,127}$'::public.citext)),
    CONSTRAINT secret_record_status_check CHECK ((status = ANY (ARRAY['ACTIVE'::text, 'DISABLED'::text, 'DELETED'::text])))
);


--
-- Name: secret_resolve_idempotency; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_resolve_idempotency (
    principal_kind text NOT NULL,
    principal_identity text NOT NULL,
    idempotency_key text NOT NULL,
    request_digest text NOT NULL,
    response_digest text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: secret_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_version (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    secret_id uuid NOT NULL,
    version_number integer NOT NULL,
    ciphertext text NOT NULL,
    key_id text NOT NULL,
    algorithm text DEFAULT 'AES-256-GCM'::text NOT NULL,
    fingerprint text NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    retired_at timestamp with time zone,
    CONSTRAINT secret_version_version_number_check CHECK ((version_number > 0))
);


--
-- Name: server_state_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.server_state_history (
    id bigint NOT NULL,
    server_id uuid NOT NULL,
    registration_state public.registration_state NOT NULL,
    operational_state public.operational_state NOT NULL,
    recertification_phase text NOT NULL,
    reason text NOT NULL,
    correlation_id uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: server_state_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.server_state_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: server_state_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.server_state_history_id_seq OWNED BY public.server_state_history.id;


--
-- Name: service_pipeline_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_pipeline_event (
    id bigint NOT NULL,
    pipeline_run_id uuid NOT NULL,
    from_state text,
    to_state text NOT NULL,
    event_type text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: service_pipeline_event_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.service_pipeline_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: service_pipeline_event_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.service_pipeline_event_id_seq OWNED BY public.service_pipeline_event.id;


--
-- Name: service_pipeline_run; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_pipeline_run (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    managed_service_id uuid,
    integration_token_id uuid,
    pipeline_kind public.service_pipeline_kind NOT NULL,
    state text NOT NULL,
    source_revision integer DEFAULT 0 NOT NULL,
    lock_version bigint DEFAULT 0 NOT NULL,
    request_digest text,
    blocking_error_code text,
    blocking_error_detail text,
    correlation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
);


--
-- Name: audit_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_event ALTER COLUMN id SET DEFAULT nextval('public.audit_event_id_seq'::regclass);


--
-- Name: component kcml_number; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component ALTER COLUMN kcml_number SET DEFAULT nextval('public.kcml_number_seq'::regclass);


--
-- Name: managed_service_api_status_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_api_status_history ALTER COLUMN id SET DEFAULT nextval('public.managed_service_api_status_history_id_seq'::regclass);


--
-- Name: managed_service_policy_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_policy_event ALTER COLUMN id SET DEFAULT nextval('public.managed_service_policy_event_id_seq'::regclass);


--
-- Name: managed_service_probe_result id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_probe_result ALTER COLUMN id SET DEFAULT nextval('public.managed_service_probe_result_id_seq'::regclass);


--
-- Name: managed_service_runtime_log_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_runtime_log_event ALTER COLUMN id SET DEFAULT nextval('public.managed_service_runtime_log_event_id_seq'::regclass);


--
-- Name: managed_service_usage_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_usage_event ALTER COLUMN id SET DEFAULT nextval('public.managed_service_usage_event_id_seq'::regclass);


--
-- Name: mcp_invocation_metric id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation_metric ALTER COLUMN id SET DEFAULT nextval('public.mcp_invocation_metric_id_seq'::regclass);


--
-- Name: monitoring_probe_result id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_probe_result ALTER COLUMN id SET DEFAULT nextval('public.monitoring_probe_result_id_seq'::regclass);


--
-- Name: onboarding_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_event ALTER COLUMN id SET DEFAULT nextval('public.onboarding_event_id_seq'::regclass);


--
-- Name: runtime_log_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_log_event ALTER COLUMN id SET DEFAULT nextval('public.runtime_log_event_id_seq'::regclass);


--
-- Name: server_state_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_state_history ALTER COLUMN id SET DEFAULT nextval('public.server_state_history_id_seq'::regclass);


--
-- Name: service_pipeline_event id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_pipeline_event ALTER COLUMN id SET DEFAULT nextval('public.service_pipeline_event_id_seq'::regclass);


--
-- Name: access_token access_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_token
    ADD CONSTRAINT access_token_pkey PRIMARY KEY (lookup_digest);


--
-- Name: admin_account admin_account_mfa_secret_ciphertext_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.admin_account
    ADD CONSTRAINT admin_account_mfa_secret_ciphertext_check CHECK (((mfa_secret IS NULL) OR (mfa_secret ~~ 'enc:v2:%'::text))) NOT VALID;


--
-- Name: admin_account admin_account_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_account
    ADD CONSTRAINT admin_account_pkey PRIMARY KEY (id);


--
-- Name: admin_account admin_account_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_account
    ADD CONSTRAINT admin_account_username_key UNIQUE (username);


--
-- Name: admin_bootstrap_state admin_bootstrap_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_bootstrap_state
    ADD CONSTRAINT admin_bootstrap_state_pkey PRIMARY KEY (singleton);


--
-- Name: admin_login_throttle admin_login_throttle_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_login_throttle
    ADD CONSTRAINT admin_login_throttle_pkey PRIMARY KEY (attempt_key);


--
-- Name: admin_recovery_code admin_recovery_code_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_recovery_code
    ADD CONSTRAINT admin_recovery_code_pkey PRIMARY KEY (id);


--
-- Name: admin_session admin_session_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_session
    ADD CONSTRAINT admin_session_pkey PRIMARY KEY (id);


--
-- Name: alert_webhook_delivery alert_webhook_delivery_alert_id_channel_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_webhook_delivery
    ADD CONSTRAINT alert_webhook_delivery_alert_id_channel_key UNIQUE (alert_id, channel);


--
-- Name: alert_webhook_delivery alert_webhook_delivery_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_webhook_delivery
    ADD CONSTRAINT alert_webhook_delivery_idempotency_key_key UNIQUE (idempotency_key);


--
-- Name: alert_webhook_delivery alert_webhook_delivery_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_webhook_delivery
    ADD CONSTRAINT alert_webhook_delivery_pkey PRIMARY KEY (id);


--
-- Name: audit_archive_outbox audit_archive_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_archive_outbox
    ADD CONSTRAINT audit_archive_outbox_pkey PRIMARY KEY (event_id);


--
-- Name: audit_event audit_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_event
    ADD CONSTRAINT audit_event_pkey PRIMARY KEY (id);


--
-- Name: audit_head audit_head_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_head
    ADD CONSTRAINT audit_head_pkey PRIMARY KEY (singleton);


--
-- Name: component_access_token component_access_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_access_token
    ADD CONSTRAINT component_access_token_pkey PRIMARY KEY (lookup_digest);


--
-- Name: component_attribute_contract component_attribute_contract_component_id_revision_id_contr_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_attribute_contract
    ADD CONSTRAINT component_attribute_contract_component_id_revision_id_contr_key UNIQUE (component_id, revision_id, contract_kind, mask_key, attribute_path);


--
-- Name: component_attribute_contract component_attribute_contract_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_attribute_contract
    ADD CONSTRAINT component_attribute_contract_pkey PRIMARY KEY (id);


--
-- Name: component_audit_event component_audit_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_audit_event
    ADD CONSTRAINT component_audit_event_pkey PRIMARY KEY (stream_id, sequence_number);


--
-- Name: component_audit_stream component_audit_stream_component_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_audit_stream
    ADD CONSTRAINT component_audit_stream_component_id_key UNIQUE (component_id);


--
-- Name: component_audit_stream component_audit_stream_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_audit_stream
    ADD CONSTRAINT component_audit_stream_pkey PRIMARY KEY (id);


--
-- Name: component_call_mask component_call_mask_component_id_revision_id_mask_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_call_mask
    ADD CONSTRAINT component_call_mask_component_id_revision_id_mask_key_key UNIQUE (component_id, revision_id, mask_key);


--
-- Name: component_call_mask component_call_mask_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_call_mask
    ADD CONSTRAINT component_call_mask_pkey PRIMARY KEY (id);


--
-- Name: component component_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT component_code_key UNIQUE (code);


--
-- Name: component_control_command component_control_command_component_id_revision_id_command__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_command
    ADD CONSTRAINT component_control_command_component_id_revision_id_command__key UNIQUE (component_id, revision_id, command_type);


--
-- Name: component_control_command component_control_command_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_command
    ADD CONSTRAINT component_control_command_pkey PRIMARY KEY (id);


--
-- Name: component_control_dispatch_attempt component_control_dispatch_attem_dispatch_id_attempt_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_dispatch_attempt
    ADD CONSTRAINT component_control_dispatch_attem_dispatch_id_attempt_number_key UNIQUE (dispatch_id, attempt_number);


--
-- Name: component_control_dispatch_attempt component_control_dispatch_attempt_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_dispatch_attempt
    ADD CONSTRAINT component_control_dispatch_attempt_pkey PRIMARY KEY (id);


--
-- Name: component_control_dispatch component_control_dispatch_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_dispatch
    ADD CONSTRAINT component_control_dispatch_pkey PRIMARY KEY (id);


--
-- Name: component_credential component_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_credential
    ADD CONSTRAINT component_credential_pkey PRIMARY KEY (id);


--
-- Name: component_credential component_credential_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_credential
    ADD CONSTRAINT component_credential_public_id_key UNIQUE (public_id);


--
-- Name: component_credential component_credential_secret_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_credential
    ADD CONSTRAINT component_credential_secret_digest_key UNIQUE (secret_digest);


--
-- Name: component_document_blob component_document_blob_component_id_revision_id_evidence_k_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_document_blob
    ADD CONSTRAINT component_document_blob_component_id_revision_id_evidence_k_key UNIQUE (component_id, revision_id, evidence_key);


--
-- Name: component_document_blob component_document_blob_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_document_blob
    ADD CONSTRAINT component_document_blob_pkey PRIMARY KEY (id);


--
-- Name: component_document_blob component_document_blob_revision_id_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_document_blob
    ADD CONSTRAINT component_document_blob_revision_id_digest_key UNIQUE (revision_id, digest);


--
-- Name: component_documentation_evidence component_documentation_evide_component_id_revision_id_evid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_documentation_evidence
    ADD CONSTRAINT component_documentation_evide_component_id_revision_id_evid_key UNIQUE (component_id, revision_id, evidence_key);


--
-- Name: component_documentation_evidence component_documentation_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_documentation_evidence
    ADD CONSTRAINT component_documentation_evidence_pkey PRIMARY KEY (id);


--
-- Name: component_e2e_execution_run component_e2e_execution_run_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_execution_run
    ADD CONSTRAINT component_e2e_execution_run_pkey PRIMARY KEY (id);


--
-- Name: component_e2e_fixture component_e2e_fixture_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_fixture
    ADD CONSTRAINT component_e2e_fixture_pkey PRIMARY KEY (id);


--
-- Name: component_e2e_fixture component_e2e_fixture_revision_id_scenario_key_variant_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_fixture
    ADD CONSTRAINT component_e2e_fixture_revision_id_scenario_key_variant_key_key UNIQUE (revision_id, scenario_key, variant_key);


--
-- Name: component_e2e_result component_e2e_result_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_result
    ADD CONSTRAINT component_e2e_result_pkey PRIMARY KEY (id);


--
-- Name: component_e2e_run component_e2e_run_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run
    ADD CONSTRAINT component_e2e_run_pkey PRIMARY KEY (id);


--
-- Name: component_e2e_run_result component_e2e_run_result_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run_result
    ADD CONSTRAINT component_e2e_run_result_pkey PRIMARY KEY (id);


--
-- Name: component_e2e_run_result component_e2e_run_result_run_id_fixture_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run_result
    ADD CONSTRAINT component_e2e_run_result_run_id_fixture_id_key UNIQUE (run_id, fixture_id);


--
-- Name: component_e2e_scenario component_e2e_scenario_component_id_revision_id_scenario_ke_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_scenario
    ADD CONSTRAINT component_e2e_scenario_component_id_revision_id_scenario_ke_key UNIQUE (component_id, revision_id, scenario_key);


--
-- Name: component_e2e_scenario component_e2e_scenario_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_scenario
    ADD CONSTRAINT component_e2e_scenario_pkey PRIMARY KEY (id);


--
-- Name: component_endpoint_contract component_endpoint_contract_component_id_revision_id_endpoi_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_endpoint_contract
    ADD CONSTRAINT component_endpoint_contract_component_id_revision_id_endpoi_key UNIQUE (component_id, revision_id, endpoint_id);


--
-- Name: component_endpoint_contract component_endpoint_contract_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_endpoint_contract
    ADD CONSTRAINT component_endpoint_contract_pkey PRIMARY KEY (id);


--
-- Name: component_external_access_token component_external_access_token_lookup_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_access_token
    ADD CONSTRAINT component_external_access_token_lookup_digest_key UNIQUE (lookup_digest);


--
-- Name: component_external_access_token component_external_access_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_access_token
    ADD CONSTRAINT component_external_access_token_pkey PRIMARY KEY (id);


--
-- Name: component_external_gateway_call component_external_gateway_call_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_gateway_call
    ADD CONSTRAINT component_external_gateway_call_pkey PRIMARY KEY (id);


--
-- Name: component_external_permission component_external_permission_component_id_external_princip_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_permission
    ADD CONSTRAINT component_external_permission_component_id_external_princip_key UNIQUE (component_id, external_principal_id, external_target_id, route_pattern, scope_name);


--
-- Name: component_external_permission component_external_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_permission
    ADD CONSTRAINT component_external_permission_pkey PRIMARY KEY (id);


--
-- Name: component_external_principal_credential component_external_principal_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_principal_credential
    ADD CONSTRAINT component_external_principal_credential_pkey PRIMARY KEY (id);


--
-- Name: component_external_principal_credential component_external_principal_credential_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_principal_credential
    ADD CONSTRAINT component_external_principal_credential_public_id_key UNIQUE (public_id);


--
-- Name: component_external_principal component_external_principal_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_principal
    ADD CONSTRAINT component_external_principal_pkey PRIMARY KEY (id);


--
-- Name: component_external_principal component_external_principal_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_principal
    ADD CONSTRAINT component_external_principal_public_id_key UNIQUE (public_id);


--
-- Name: component_external_target component_external_target_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_target
    ADD CONSTRAINT component_external_target_pkey PRIMARY KEY (id);


--
-- Name: component_external_target component_external_target_target_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_target
    ADD CONSTRAINT component_external_target_target_key_key UNIQUE (target_key);


--
-- Name: component_heartbeat_challenge component_heartbeat_challenge_component_id_challenge_nonce_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat_challenge
    ADD CONSTRAINT component_heartbeat_challenge_component_id_challenge_nonce_key UNIQUE (component_id, challenge_nonce);


--
-- Name: component_heartbeat_challenge component_heartbeat_challenge_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat_challenge
    ADD CONSTRAINT component_heartbeat_challenge_pkey PRIMARY KEY (id);


--
-- Name: component_heartbeat component_heartbeat_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat
    ADD CONSTRAINT component_heartbeat_pkey PRIMARY KEY (id);


--
-- Name: component component_hostname_kajovocml_suffix_check; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.component
    ADD CONSTRAINT component_hostname_kajovocml_suffix_check CHECK ((hostname OPERATOR(public.~*) (('^'::text || lower((code)::text)) || '[.]kajovocml[.]hcasc[.]cz$'::text))) NOT VALID;


--
-- Name: component component_hostname_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT component_hostname_key UNIQUE (hostname);


--
-- Name: component component_kcml_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT component_kcml_number_key UNIQUE (kcml_number);


--
-- Name: component_onboarding_job component_onboarding_job_credential_claim_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_job
    ADD CONSTRAINT component_onboarding_job_credential_claim_digest_key UNIQUE (credential_claim_digest);


--
-- Name: component_onboarding_job component_onboarding_job_integration_token_id_idempotency_k_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_job
    ADD CONSTRAINT component_onboarding_job_integration_token_id_idempotency_k_key UNIQUE (integration_token_id, idempotency_key);


--
-- Name: component_onboarding_job component_onboarding_job_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_job
    ADD CONSTRAINT component_onboarding_job_pkey PRIMARY KEY (id);


--
-- Name: component_onboarding_revision_request component_onboarding_revision_request_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_revision_request
    ADD CONSTRAINT component_onboarding_revision_request_pkey PRIMARY KEY (job_id, idempotency_key);


--
-- Name: component_operation_event component_operation_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_operation_event
    ADD CONSTRAINT component_operation_event_pkey PRIMARY KEY (id);


--
-- Name: component_operation_lease component_operation_lease_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_operation_lease
    ADD CONSTRAINT component_operation_lease_pkey PRIMARY KEY (id);


--
-- Name: component_permission component_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_permission
    ADD CONSTRAINT component_permission_pkey PRIMARY KEY (id);


--
-- Name: component_permission component_permission_source_component_id_target_component_i_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_permission
    ADD CONSTRAINT component_permission_source_component_id_target_component_i_key UNIQUE (source_component_id, target_component_id, route_pattern, scope_name);


--
-- Name: component component_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT component_pkey PRIMARY KEY (id);


--
-- Name: component_pulse_mask component_pulse_mask_component_id_revision_id_pulse_type_di_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_pulse_mask
    ADD CONSTRAINT component_pulse_mask_component_id_revision_id_pulse_type_di_key UNIQUE (component_id, revision_id, pulse_type, direction);


--
-- Name: component_pulse_mask component_pulse_mask_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_pulse_mask
    ADD CONSTRAINT component_pulse_mask_pkey PRIMARY KEY (id);


--
-- Name: component_readiness_gate_evidence component_readiness_gate_evid_component_id_revision_id_gate_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_readiness_gate_evidence
    ADD CONSTRAINT component_readiness_gate_evid_component_id_revision_id_gate_key UNIQUE (component_id, revision_id, gate_key, correlation_id);


--
-- Name: component_readiness_gate_evidence component_readiness_gate_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_readiness_gate_evidence
    ADD CONSTRAINT component_readiness_gate_evidence_pkey PRIMARY KEY (id);


--
-- Name: component_revision component_revision_component_id_revision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_revision
    ADD CONSTRAINT component_revision_component_id_revision_key UNIQUE (component_id, revision);


--
-- Name: component_revision component_revision_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_revision
    ADD CONSTRAINT component_revision_pkey PRIMARY KEY (id);


--
-- Name: component_runtime_target component_runtime_target_component_id_revision_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_runtime_target
    ADD CONSTRAINT component_runtime_target_component_id_revision_id_key UNIQUE (component_id, revision_id);


--
-- Name: component_runtime_target component_runtime_target_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_runtime_target
    ADD CONSTRAINT component_runtime_target_pkey PRIMARY KEY (id);


--
-- Name: component_secret_policy component_secret_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_secret_policy
    ADD CONSTRAINT component_secret_policy_pkey PRIMARY KEY (component_id, revision_id);


--
-- Name: component_state_contract component_state_contract_component_id_revision_id_state_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_contract
    ADD CONSTRAINT component_state_contract_component_id_revision_id_state_key_key UNIQUE (component_id, revision_id, state_key);


--
-- Name: component_state_contract component_state_contract_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_contract
    ADD CONSTRAINT component_state_contract_pkey PRIMARY KEY (id);


--
-- Name: component_state_observation component_state_observation_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_observation
    ADD CONSTRAINT component_state_observation_pkey PRIMARY KEY (id);


--
-- Name: component_state_query_run component_state_query_run_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_query_run
    ADD CONSTRAINT component_state_query_run_pkey PRIMARY KEY (id);


--
-- Name: component_state_snapshot component_state_snapshot_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_snapshot
    ADD CONSTRAINT component_state_snapshot_pkey PRIMARY KEY (id);


--
-- Name: component_state_transition component_state_transition_component_id_revision_id_from_st_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_transition
    ADD CONSTRAINT component_state_transition_component_id_revision_id_from_st_key UNIQUE (component_id, revision_id, from_state_key, to_state_key, trigger_mask);


--
-- Name: component_state_transition component_state_transition_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_transition
    ADD CONSTRAINT component_state_transition_pkey PRIMARY KEY (id);


--
-- Name: component_tool_contract component_tool_contract_component_id_revision_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_tool_contract
    ADD CONSTRAINT component_tool_contract_component_id_revision_id_name_key UNIQUE (component_id, revision_id, name);


--
-- Name: component_tool_contract component_tool_contract_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_tool_contract
    ADD CONSTRAINT component_tool_contract_pkey PRIMARY KEY (id);


--
-- Name: egress_capability egress_capability_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.egress_capability
    ADD CONSTRAINT egress_capability_pkey PRIMARY KEY (lookup_digest);


--
-- Name: external_api_service_profile external_api_service_profile_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_api_service_profile
    ADD CONSTRAINT external_api_service_profile_pkey PRIMARY KEY (managed_service_id);


--
-- Name: function_concurrency_lease function_concurrency_lease_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.function_concurrency_lease
    ADD CONSTRAINT function_concurrency_lease_pkey PRIMARY KEY (lease_id);


--
-- Name: function_rate_bucket function_rate_bucket_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.function_rate_bucket
    ADD CONSTRAINT function_rate_bucket_pkey PRIMARY KEY (server_id, credential_id);


--
-- Name: function_statistics function_statistics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.function_statistics
    ADD CONSTRAINT function_statistics_pkey PRIMARY KEY (server_id);


--
-- Name: http_rate_bucket http_rate_bucket_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.http_rate_bucket
    ADD CONSTRAINT http_rate_bucket_pkey PRIMARY KEY (bucket_key);


--
-- Name: integration_token_allowed_component integration_token_allowed_com_token_id_blueprint_component__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_allowed_component
    ADD CONSTRAINT integration_token_allowed_com_token_id_blueprint_component__key UNIQUE (token_id, blueprint_component_id);


--
-- Name: integration_token_allowed_component integration_token_allowed_component_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_allowed_component
    ADD CONSTRAINT integration_token_allowed_component_pkey PRIMARY KEY (id);


--
-- Name: integration_token_child_job integration_token_child_job_onboarding_job_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_child_job
    ADD CONSTRAINT integration_token_child_job_onboarding_job_id_key UNIQUE (onboarding_job_id);


--
-- Name: integration_token_child_job integration_token_child_job_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_child_job
    ADD CONSTRAINT integration_token_child_job_pkey PRIMARY KEY (id);


--
-- Name: integration_token_child_job integration_token_child_job_token_id_blueprint_component_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_child_job
    ADD CONSTRAINT integration_token_child_job_token_id_blueprint_component_id_key UNIQUE (token_id, blueprint_component_id);


--
-- Name: integration_token integration_token_lookup_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_lookup_digest_key UNIQUE (lookup_digest);


--
-- Name: integration_token integration_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_pkey PRIMARY KEY (id);


--
-- Name: kaja_credential kaja_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kaja_credential
    ADD CONSTRAINT kaja_credential_pkey PRIMARY KEY (id);


--
-- Name: kaja_credential kaja_credential_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kaja_credential
    ADD CONSTRAINT kaja_credential_public_id_key UNIQUE (public_id);


--
-- Name: kaja_permission kaja_permission_credential_id_server_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kaja_permission
    ADD CONSTRAINT kaja_permission_credential_id_server_id_key UNIQUE (credential_id, server_id);


--
-- Name: kaja_permission kaja_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kaja_permission
    ADD CONSTRAINT kaja_permission_pkey PRIMARY KEY (id);


--
-- Name: managed_service_access_token managed_service_access_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_access_token
    ADD CONSTRAINT managed_service_access_token_pkey PRIMARY KEY (lookup_digest);


--
-- Name: managed_service_api_status_history managed_service_api_status_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_api_status_history
    ADD CONSTRAINT managed_service_api_status_history_pkey PRIMARY KEY (id);


--
-- Name: managed_service_api_status managed_service_api_status_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_api_status
    ADD CONSTRAINT managed_service_api_status_pkey PRIMARY KEY (managed_service_id);


--
-- Name: managed_service managed_service_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service
    ADD CONSTRAINT managed_service_code_key UNIQUE (code);


--
-- Name: managed_service managed_service_legacy_mcp_server_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service
    ADD CONSTRAINT managed_service_legacy_mcp_server_id_key UNIQUE (legacy_mcp_server_id);


--
-- Name: managed_service_permission managed_service_permission_credential_id_managed_service_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_permission
    ADD CONSTRAINT managed_service_permission_credential_id_managed_service_id_key UNIQUE (credential_id, managed_service_id, scope_id);


--
-- Name: managed_service_permission managed_service_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_permission
    ADD CONSTRAINT managed_service_permission_pkey PRIMARY KEY (id);


--
-- Name: managed_service managed_service_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service
    ADD CONSTRAINT managed_service_pkey PRIMARY KEY (id);


--
-- Name: managed_service_policy_event managed_service_policy_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_policy_event
    ADD CONSTRAINT managed_service_policy_event_pkey PRIMARY KEY (id);


--
-- Name: managed_service_probe_result managed_service_probe_result_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_probe_result
    ADD CONSTRAINT managed_service_probe_result_pkey PRIMARY KEY (id);


--
-- Name: managed_service_revision managed_service_revision_managed_service_id_revision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_revision
    ADD CONSTRAINT managed_service_revision_managed_service_id_revision_key UNIQUE (managed_service_id, revision);


--
-- Name: managed_service_revision managed_service_revision_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_revision
    ADD CONSTRAINT managed_service_revision_pkey PRIMARY KEY (id);


--
-- Name: managed_service_runtime_log_event managed_service_runtime_log_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_runtime_log_event
    ADD CONSTRAINT managed_service_runtime_log_event_pkey PRIMARY KEY (id);


--
-- Name: managed_service_scope managed_service_scope_managed_service_id_scope_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_scope
    ADD CONSTRAINT managed_service_scope_managed_service_id_scope_name_key UNIQUE (managed_service_id, scope_name);


--
-- Name: managed_service_scope managed_service_scope_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_scope
    ADD CONSTRAINT managed_service_scope_pkey PRIMARY KEY (id);


--
-- Name: managed_service managed_service_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service
    ADD CONSTRAINT managed_service_slug_key UNIQUE (slug);


--
-- Name: managed_service_usage_event managed_service_usage_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_usage_event
    ADD CONSTRAINT managed_service_usage_event_pkey PRIMARY KEY (id);


--
-- Name: mcp_invocation mcp_invocation_correlation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation
    ADD CONSTRAINT mcp_invocation_correlation_id_key UNIQUE (correlation_id);


--
-- Name: mcp_invocation_idempotency mcp_invocation_idempotency_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation_idempotency
    ADD CONSTRAINT mcp_invocation_idempotency_pkey PRIMARY KEY (server_id, credential_id, idempotency_key);


--
-- Name: mcp_invocation_metric mcp_invocation_metric_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation_metric
    ADD CONSTRAINT mcp_invocation_metric_pkey PRIMARY KEY (id);


--
-- Name: mcp_invocation mcp_invocation_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation
    ADD CONSTRAINT mcp_invocation_pkey PRIMARY KEY (id);


--
-- Name: mcp_rate_bucket mcp_rate_bucket_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_rate_bucket
    ADD CONSTRAINT mcp_rate_bucket_pkey PRIMARY KEY (scope_type, scope_key);


--
-- Name: mcp_server mcp_server_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_server
    ADD CONSTRAINT mcp_server_code_key UNIQUE (code);


--
-- Name: mcp_server mcp_server_hostname_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_server
    ADD CONSTRAINT mcp_server_hostname_key UNIQUE (hostname);


--
-- Name: mcp_server mcp_server_kcml_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_server
    ADD CONSTRAINT mcp_server_kcml_number_key UNIQUE (kcml_number);


--
-- Name: mcp_server mcp_server_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_server
    ADD CONSTRAINT mcp_server_pkey PRIMARY KEY (id);


--
-- Name: monitoring_probe_result monitoring_probe_result_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_probe_result
    ADD CONSTRAINT monitoring_probe_result_pkey PRIMARY KEY (id);


--
-- Name: monitoring_profile monitoring_profile_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_profile
    ADD CONSTRAINT monitoring_profile_pkey PRIMARY KEY (server_id);


--
-- Name: monitoring_scheduler_heartbeat monitoring_scheduler_heartbeat_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_scheduler_heartbeat
    ADD CONSTRAINT monitoring_scheduler_heartbeat_pkey PRIMARY KEY (singleton);


--
-- Name: onboarding_event onboarding_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_event
    ADD CONSTRAINT onboarding_event_pkey PRIMARY KEY (id);


--
-- Name: onboarding_gate onboarding_gate_job_id_gate_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_gate
    ADD CONSTRAINT onboarding_gate_job_id_gate_name_key UNIQUE (job_id, gate_name);


--
-- Name: onboarding_gate onboarding_gate_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_gate
    ADD CONSTRAINT onboarding_gate_pkey PRIMARY KEY (id);


--
-- Name: onboarding_job onboarding_job_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_code_key UNIQUE (code);


--
-- Name: onboarding_job onboarding_job_hostname_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_hostname_key UNIQUE (hostname);


--
-- Name: onboarding_job onboarding_job_kcml_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_kcml_number_key UNIQUE (kcml_number);


--
-- Name: onboarding_job onboarding_job_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_pkey PRIMARY KEY (id);


--
-- Name: onboarding_job onboarding_job_server_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_server_id_key UNIQUE (server_id);


--
-- Name: onboarding_job onboarding_job_token_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_token_id_key UNIQUE (token_id);


--
-- Name: onboarding_source_revision onboarding_source_revision_job_id_idempotency_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_source_revision
    ADD CONSTRAINT onboarding_source_revision_job_id_idempotency_key_key UNIQUE (job_id, idempotency_key);


--
-- Name: onboarding_source_revision onboarding_source_revision_job_id_revision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_source_revision
    ADD CONSTRAINT onboarding_source_revision_job_id_revision_key UNIQUE (job_id, revision);


--
-- Name: onboarding_source_revision onboarding_source_revision_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_source_revision
    ADD CONSTRAINT onboarding_source_revision_pkey PRIMARY KEY (id);


--
-- Name: operational_alert operational_alert_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_alert
    ADD CONSTRAINT operational_alert_pkey PRIMARY KEY (id);


--
-- Name: operational_config_applied operational_config_applied_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_config_applied
    ADD CONSTRAINT operational_config_applied_pkey PRIMARY KEY (key, process_role);


--
-- Name: operational_config_setting operational_config_setting_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_config_setting
    ADD CONSTRAINT operational_config_setting_pkey PRIMARY KEY (key);


--
-- Name: platform_worker_access_identity platform_worker_access_identity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_worker_access_identity
    ADD CONSTRAINT platform_worker_access_identity_pkey PRIMARY KEY (singleton);


--
-- Name: platform_worker_access_identity platform_worker_access_identity_principal_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_worker_access_identity
    ADD CONSTRAINT platform_worker_access_identity_principal_id_key UNIQUE (principal_id);


--
-- Name: platform_worker_heartbeat platform_worker_heartbeat_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_worker_heartbeat
    ADD CONSTRAINT platform_worker_heartbeat_pkey PRIMARY KEY (worker_kind);


--
-- Name: principal_access_token principal_access_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_access_token
    ADD CONSTRAINT principal_access_token_pkey PRIMARY KEY (lookup_digest);


--
-- Name: principal_component_permission principal_component_permissio_source_principal_id_target_co_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_component_permission
    ADD CONSTRAINT principal_component_permissio_source_principal_id_target_co_key UNIQUE (source_principal_id, target_component_id, route_pattern, scope_name);


--
-- Name: principal_component_permission principal_component_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_component_permission
    ADD CONSTRAINT principal_component_permission_pkey PRIMARY KEY (id);


--
-- Name: principal_credential principal_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_credential
    ADD CONSTRAINT principal_credential_pkey PRIMARY KEY (id);


--
-- Name: principal_credential principal_credential_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_credential
    ADD CONSTRAINT principal_credential_public_id_key UNIQUE (public_id);


--
-- Name: principal_credential principal_credential_secret_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_credential
    ADD CONSTRAINT principal_credential_secret_digest_key UNIQUE (secret_digest);


--
-- Name: principal principal_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal
    ADD CONSTRAINT principal_pkey PRIMARY KEY (id);


--
-- Name: principal principal_public_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal
    ADD CONSTRAINT principal_public_id_key UNIQUE (public_id);


--
-- Name: registration_revision registration_revision_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_revision
    ADD CONSTRAINT registration_revision_pkey PRIMARY KEY (id);


--
-- Name: registration_revision registration_revision_server_id_revision_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_revision
    ADD CONSTRAINT registration_revision_server_id_revision_key UNIQUE (server_id, revision);


--
-- Name: release_epoch release_epoch_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_epoch
    ADD CONSTRAINT release_epoch_pkey PRIMARY KEY (release_version);


--
-- Name: release_wave_component release_wave_component_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_wave_component
    ADD CONSTRAINT release_wave_component_pkey PRIMARY KEY (release_version, wave_key, blueprint_component_id);


--
-- Name: release_wave release_wave_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_wave
    ADD CONSTRAINT release_wave_pkey PRIMARY KEY (release_version, wave_key);


--
-- Name: runtime_log_event runtime_log_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_log_event
    ADD CONSTRAINT runtime_log_event_pkey PRIMARY KEY (id);


--
-- Name: secret_admin_reveal_grant secret_admin_reveal_grant_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_admin_reveal_grant
    ADD CONSTRAINT secret_admin_reveal_grant_pkey PRIMARY KEY (id);


--
-- Name: secret_api_rate_limit secret_api_rate_limit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_api_rate_limit
    ADD CONSTRAINT secret_api_rate_limit_pkey PRIMARY KEY (bucket_key);


--
-- Name: secret_grant secret_grant_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_grant
    ADD CONSTRAINT secret_grant_pkey PRIMARY KEY (id);


--
-- Name: secret_record secret_record_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_record
    ADD CONSTRAINT secret_record_pkey PRIMARY KEY (id);


--
-- Name: secret_record secret_record_stable_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_record
    ADD CONSTRAINT secret_record_stable_name_key UNIQUE (stable_name);


--
-- Name: secret_resolve_idempotency secret_resolve_idempotency_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_resolve_idempotency
    ADD CONSTRAINT secret_resolve_idempotency_pkey PRIMARY KEY (principal_kind, principal_identity, idempotency_key);


--
-- Name: secret_version secret_version_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_version
    ADD CONSTRAINT secret_version_pkey PRIMARY KEY (id);


--
-- Name: secret_version secret_version_secret_id_version_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_version
    ADD CONSTRAINT secret_version_secret_id_version_number_key UNIQUE (secret_id, version_number);


--
-- Name: server_state_history server_state_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_state_history
    ADD CONSTRAINT server_state_history_pkey PRIMARY KEY (id);


--
-- Name: service_pipeline_event service_pipeline_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_pipeline_event
    ADD CONSTRAINT service_pipeline_event_pkey PRIMARY KEY (id);


--
-- Name: service_pipeline_run service_pipeline_run_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_pipeline_run
    ADD CONSTRAINT service_pipeline_run_pkey PRIMARY KEY (id);


--
-- Name: admin_account_active_role_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_account_active_role_idx ON public.admin_account USING btree (active, role);


--
-- Name: admin_login_throttle_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_login_throttle_expiry_idx ON public.admin_login_throttle USING btree (updated_at);


--
-- Name: admin_recovery_code_account_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_recovery_code_account_idx ON public.admin_recovery_code USING btree (account_id, created_at DESC);


--
-- Name: admin_session_account_epoch_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX admin_session_account_epoch_idx ON public.admin_session USING btree (account_id, session_epoch) WHERE (revoked_at IS NULL);


--
-- Name: admin_session_lookup_digest_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX admin_session_lookup_digest_idx ON public.admin_session USING btree (lookup_digest) WHERE (lookup_digest IS NOT NULL);


--
-- Name: alert_webhook_delivery_runnable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX alert_webhook_delivery_runnable_idx ON public.alert_webhook_delivery USING btree (next_attempt_at, created_at) WHERE (state = ANY (ARRAY['PENDING'::text, 'RETRY'::text]));


--
-- Name: audit_archive_outbox_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_archive_outbox_pending_idx ON public.audit_archive_outbox USING btree (next_attempt_at, event_id) WHERE (state <> 'ARCHIVED'::text);


--
-- Name: audit_event_chain_sequence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX audit_event_chain_sequence_idx ON public.audit_event USING btree (chain_sequence);


--
-- Name: audit_event_event_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX audit_event_event_hash_idx ON public.audit_event USING btree (event_hash);


--
-- Name: component_access_token_target_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_access_token_target_expires_idx ON public.component_access_token USING btree (target_component_id, expires_at DESC) WHERE (revoked_at IS NULL);


--
-- Name: component_audit_event_correlation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_audit_event_correlation_idx ON public.component_audit_event USING btree (correlation_id);


--
-- Name: component_audit_event_hash_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX component_audit_event_hash_unique_idx ON public.component_audit_event USING btree (stream_id, event_hash) WHERE (event_hash IS NOT NULL);


--
-- Name: component_audit_event_trace_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_audit_event_trace_idx ON public.component_audit_event USING btree (trace_id) WHERE (trace_id IS NOT NULL);


--
-- Name: component_control_dispatch_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_control_dispatch_component_idx ON public.component_control_dispatch USING btree (component_id, created_at DESC);


--
-- Name: component_control_dispatch_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_control_dispatch_pending_idx ON public.component_control_dispatch USING btree (state, deadline_at) WHERE (state = ANY (ARRAY['PENDING'::text, 'SENT'::text, 'ACK_PENDING'::text, 'ACKED'::text, 'STATE_CONFIRMED'::text]));


--
-- Name: component_e2e_execution_run_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_e2e_execution_run_component_idx ON public.component_e2e_execution_run USING btree (component_id, created_at DESC);


--
-- Name: component_e2e_result_latest_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_e2e_result_latest_idx ON public.component_e2e_result USING btree (scenario_id, received_at DESC);


--
-- Name: component_e2e_run_result_run_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_e2e_run_result_run_idx ON public.component_e2e_run_result USING btree (run_id, started_at);


--
-- Name: component_e2e_run_worker_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_e2e_run_worker_idx ON public.component_e2e_run USING btree (status, deadline_at, created_at) WHERE (status = ANY (ARRAY['QUEUED'::text, 'RUNNING'::text]));


--
-- Name: component_external_access_token_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_external_access_token_component_idx ON public.component_external_access_token USING btree (source_component_id, external_target_id, expires_at DESC) WHERE (source_component_id IS NOT NULL);


--
-- Name: component_external_gateway_call_target_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_external_gateway_call_target_idx ON public.component_external_gateway_call USING btree (external_target_id, created_at DESC);


--
-- Name: component_external_principal_canonical_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX component_external_principal_canonical_uidx ON public.component_external_principal USING btree (principal_id);


--
-- Name: component_external_principal_credential_principal_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_external_principal_credential_principal_idx ON public.component_external_principal_credential USING btree (external_principal_id, issued_at DESC);


--
-- Name: component_heartbeat_challenge_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_heartbeat_challenge_component_idx ON public.component_heartbeat_challenge USING btree (component_id, created_at DESC);


--
-- Name: component_heartbeat_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_heartbeat_component_idx ON public.component_heartbeat USING btree (component_id, heartbeat_at DESC);


--
-- Name: component_onboarding_job_state_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_onboarding_job_state_idx ON public.component_onboarding_job USING btree (state, created_at);


--
-- Name: component_onboarding_principal_access_token_digest_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX component_onboarding_principal_access_token_digest_uidx ON public.component_onboarding_job USING btree (principal_access_token_digest) WHERE (principal_access_token_digest IS NOT NULL);


--
-- Name: component_onboarding_token_blueprint_live_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX component_onboarding_token_blueprint_live_uidx ON public.component_onboarding_job USING btree (integration_token_id, blueprint_component_id) WHERE ((blueprint_component_id IS NOT NULL) AND (state <> ALL (ARRAY['CANCELLED'::text, 'FAILED'::text])));


--
-- Name: component_operation_event_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_operation_event_component_idx ON public.component_operation_event USING btree (component_id, occurred_at DESC);


--
-- Name: component_operation_lease_target_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_operation_lease_target_idx ON public.component_operation_lease USING btree (target_component_id, started_at DESC);


--
-- Name: component_permission_current_route_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_permission_current_route_idx ON public.component_permission USING btree (source_component_id, target_component_id, scope_name, route_pattern) WHERE (revoked_at IS NULL);


--
-- Name: component_principal_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX component_principal_unique_idx ON public.component USING btree (principal_id);


--
-- Name: component_pulse_mask_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_pulse_mask_lookup_idx ON public.component_pulse_mask USING btree (component_id, pulse_type, direction);


--
-- Name: component_readiness_active_evidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_readiness_active_evidence_idx ON public.component_readiness_gate_evidence USING btree (component_id, revision_id, gate_key, revision_digest, runtime_digest, executed_at DESC);


--
-- Name: component_readiness_current_evidence_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_readiness_current_evidence_idx ON public.component_readiness_gate_evidence USING btree (component_id, revision_id, gate_key, executed_at DESC);


--
-- Name: component_readiness_gate_evidence_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_readiness_gate_evidence_component_idx ON public.component_readiness_gate_evidence USING btree (component_id, executed_at DESC);


--
-- Name: component_release_wave_blueprint_live_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX component_release_wave_blueprint_live_uidx ON public.component USING btree (release_version, release_wave_key, blueprint_component_id) WHERE ((blueprint_component_id IS NOT NULL) AND (lifecycle_state <> 'DEREGISTERED'::text));


--
-- Name: component_state_observation_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_state_observation_component_idx ON public.component_state_observation USING btree (component_id, observed_at DESC);


--
-- Name: component_state_query_run_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_state_query_run_component_idx ON public.component_state_query_run USING btree (component_id, created_at DESC);


--
-- Name: component_state_snapshot_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX component_state_snapshot_component_idx ON public.component_state_snapshot USING btree (component_id, observed_at DESC);


--
-- Name: egress_capability_job_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX egress_capability_job_idx ON public.egress_capability USING btree (job_id, expires_at) WHERE (revoked_at IS NULL);


--
-- Name: egress_capability_server_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX egress_capability_server_idx ON public.egress_capability USING btree (server_id) WHERE ((server_id IS NOT NULL) AND (revoked_at IS NULL));


--
-- Name: function_concurrency_lease_server_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX function_concurrency_lease_server_idx ON public.function_concurrency_lease USING btree (server_id, expires_at);


--
-- Name: function_rate_bucket_window_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX function_rate_bucket_window_idx ON public.function_rate_bucket USING btree (window_started_at);


--
-- Name: http_rate_bucket_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX http_rate_bucket_updated_idx ON public.http_rate_bucket USING btree (updated_at);


--
-- Name: integration_token_active_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_token_active_lookup_idx ON public.integration_token USING btree (lookup_digest, expires_at) WHERE ((revoked_at IS NULL) AND (deleted_at IS NULL));


--
-- Name: integration_token_child_component_onboarding_job_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX integration_token_child_component_onboarding_job_uidx ON public.integration_token_child_job USING btree (component_onboarding_job_id) WHERE (component_onboarding_job_id IS NOT NULL);


--
-- Name: integration_token_created_by_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_token_created_by_idx ON public.integration_token USING btree (created_by, issued_at DESC);


--
-- Name: integration_token_job_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_token_job_idx ON public.integration_token USING btree (onboarding_job_id, issued_at DESC) WHERE (onboarding_job_id IS NOT NULL);


--
-- Name: integration_token_release_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_token_release_active_idx ON public.integration_token USING btree (release_version, token_kind, issued_at DESC) WHERE ((revoked_at IS NULL) AND (deleted_at IS NULL));


--
-- Name: managed_service_access_token_legacy_access_token_digest_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX managed_service_access_token_legacy_access_token_digest_idx ON public.managed_service_access_token USING btree (legacy_access_token_digest) WHERE (legacy_access_token_digest IS NOT NULL);


--
-- Name: managed_service_access_token_service_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_service_access_token_service_expires_idx ON public.managed_service_access_token USING btree (managed_service_id, expires_at DESC) WHERE (revoked_at IS NULL);


--
-- Name: managed_service_active_revision_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX managed_service_active_revision_unique_idx ON public.managed_service_revision USING btree (managed_service_id) WHERE (active IS TRUE);


--
-- Name: managed_service_api_status_history_service_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_service_api_status_history_service_created_idx ON public.managed_service_api_status_history USING btree (managed_service_id, created_at DESC);


--
-- Name: managed_service_component_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX managed_service_component_unique_idx ON public.managed_service USING btree (component_id);


--
-- Name: managed_service_permission_lookup_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_service_permission_lookup_idx ON public.managed_service_permission USING btree (credential_id, managed_service_id) WHERE (revoked_at IS NULL);


--
-- Name: managed_service_policy_event_service_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_service_policy_event_service_created_idx ON public.managed_service_policy_event USING btree (managed_service_id, created_at DESC);


--
-- Name: managed_service_probe_service_checked_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_service_probe_service_checked_idx ON public.managed_service_probe_result USING btree (managed_service_id, probe_type, checked_at DESC);


--
-- Name: managed_service_runtime_log_correlation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_service_runtime_log_correlation_idx ON public.managed_service_runtime_log_event USING btree (correlation_id);


--
-- Name: managed_service_usage_event_service_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_service_usage_event_service_created_idx ON public.managed_service_usage_event USING btree (managed_service_id, created_at DESC);


--
-- Name: mcp_invocation_idempotency_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_invocation_idempotency_created_idx ON public.mcp_invocation_idempotency USING btree (created_at);


--
-- Name: mcp_invocation_idempotency_pending_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_invocation_idempotency_pending_expiry_idx ON public.mcp_invocation_idempotency USING btree (pending_expires_at) WHERE (status = 'PENDING'::text);


--
-- Name: mcp_invocation_metric_server_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_invocation_metric_server_created_idx ON public.mcp_invocation_metric USING btree (server_id, created_at DESC);


--
-- Name: mcp_invocation_server_accepted_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_invocation_server_accepted_idx ON public.mcp_invocation USING btree (server_id, accepted_at DESC);


--
-- Name: mcp_rate_bucket_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_rate_bucket_updated_idx ON public.mcp_rate_bucket USING btree (updated_at);


--
-- Name: mcp_server_component_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX mcp_server_component_unique_idx ON public.mcp_server USING btree (component_id);


--
-- Name: mcp_server_release_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX mcp_server_release_active_idx ON public.mcp_server USING btree (release_version, blueprint_component_id, registration_state) WHERE (archived_at IS NULL);


--
-- Name: monitoring_probe_server_checked_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX monitoring_probe_server_checked_idx ON public.monitoring_probe_result USING btree (server_id, probe_type, checked_at DESC);


--
-- Name: monitoring_profile_revision_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX monitoring_profile_revision_idx ON public.monitoring_profile USING btree (registration_revision_id, version);


--
-- Name: onboarding_event_job_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX onboarding_event_job_created_idx ON public.onboarding_event USING btree (job_id, created_at, id);


--
-- Name: onboarding_gate_job_stage_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX onboarding_gate_job_stage_idx ON public.onboarding_gate USING btree (job_id, stage, gate_name);


--
-- Name: onboarding_job_component_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX onboarding_job_component_idx ON public.onboarding_job USING btree (component_id, state) WHERE (archived_at IS NULL);


--
-- Name: onboarding_job_release_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX onboarding_job_release_active_idx ON public.onboarding_job USING btree (release_version, blueprint_component_id, state) WHERE (archived_at IS NULL);


--
-- Name: onboarding_job_runnable_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX onboarding_job_runnable_idx ON public.onboarding_job USING btree (next_run_at, created_at) WHERE (state <> ALL (ARRAY['ACTIVE'::public.onboarding_job_state, 'FAILED'::public.onboarding_job_state, 'QUARANTINED'::public.onboarding_job_state, 'CANCELLED'::public.onboarding_job_state]));


--
-- Name: onboarding_job_server_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX onboarding_job_server_idx ON public.onboarding_job USING btree (server_id);


--
-- Name: operational_alert_active_unique_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX operational_alert_active_unique_idx ON public.operational_alert USING btree (COALESCE(server_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(managed_service_id, '00000000-0000-0000-0000-000000000000'::uuid), alert_type) WHERE (status = ANY (ARRAY['OPEN'::text, 'ACKNOWLEDGED'::text, 'SUPPRESSED'::text]));


--
-- Name: operational_alert_managed_service_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX operational_alert_managed_service_status_idx ON public.operational_alert USING btree (managed_service_id, status, severity, last_seen_at DESC) WHERE (managed_service_id IS NOT NULL);


--
-- Name: operational_alert_status_severity_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX operational_alert_status_severity_idx ON public.operational_alert USING btree (status, severity, last_seen_at DESC);


--
-- Name: operational_config_applied_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX operational_config_applied_pending_idx ON public.operational_config_applied USING btree (process_role, key, version);


--
-- Name: platform_worker_access_token_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX platform_worker_access_token_idx ON public.platform_worker_access_identity USING btree (access_token_id) WHERE (access_token_id IS NOT NULL);


--
-- Name: principal_access_token_id_uidx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX principal_access_token_id_uidx ON public.principal_access_token USING btree (id);


--
-- Name: principal_access_token_target_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX principal_access_token_target_active_idx ON public.principal_access_token USING btree (target_component_id, expires_at DESC) WHERE (revoked_at IS NULL);


--
-- Name: registration_revision_one_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX registration_revision_one_active_idx ON public.registration_revision USING btree (server_id) WHERE ((active IS TRUE) AND (server_id IS NOT NULL));


--
-- Name: runtime_log_correlation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX runtime_log_correlation_idx ON public.runtime_log_event USING btree (correlation_id);


--
-- Name: runtime_log_server_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX runtime_log_server_created_idx ON public.runtime_log_event USING btree (server_id, created_at DESC);


--
-- Name: secret_admin_reveal_grant_live_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX secret_admin_reveal_grant_live_idx ON public.secret_admin_reveal_grant USING btree (admin_account_id, secret_version_id, expires_at) WHERE (consumed_at IS NULL);


--
-- Name: secret_admin_reveal_grant_session_live_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX secret_admin_reveal_grant_session_live_idx ON public.secret_admin_reveal_grant USING btree (admin_account_id, admin_session_id, secret_version_id, expires_at) WHERE (consumed_at IS NULL);


--
-- Name: secret_grant_current_all_secrets_identity_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX secret_grant_current_all_secrets_identity_idx ON public.secret_grant USING btree (principal_kind, COALESCE((principal_id)::text, ''::text), COALESCE((principal_public_id)::text, ''::text)) WHERE ((revoked_at IS NULL) AND (all_secrets IS TRUE));


--
-- Name: secret_grant_current_identity_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX secret_grant_current_identity_idx ON public.secret_grant USING btree (secret_id, principal_kind, COALESCE((principal_id)::text, ''::text), COALESCE((principal_public_id)::text, ''::text), all_secrets) WHERE (revoked_at IS NULL);


--
-- Name: secret_grant_principal_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX secret_grant_principal_idx ON public.secret_grant USING btree (principal_kind, principal_id, principal_public_id) WHERE (revoked_at IS NULL);


--
-- Name: secret_record_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX secret_record_status_idx ON public.secret_record USING btree (status, updated_at DESC);


--
-- Name: secret_version_secret_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX secret_version_secret_created_idx ON public.secret_version USING btree (secret_id, created_at DESC);


--
-- Name: server_state_history_server_recorded_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX server_state_history_server_recorded_idx ON public.server_state_history USING btree (server_id, recorded_at DESC);


--
-- Name: service_pipeline_event_run_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX service_pipeline_event_run_created_idx ON public.service_pipeline_event USING btree (pipeline_run_id, created_at DESC);


--
-- Name: service_pipeline_run_service_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX service_pipeline_run_service_created_idx ON public.service_pipeline_run USING btree (managed_service_id, created_at DESC);


--
-- Name: admin_account admin_account_preserve_last_owner; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER admin_account_preserve_last_owner BEFORE DELETE OR UPDATE ON public.admin_account FOR EACH ROW EXECUTE FUNCTION public.preserve_last_admin_owner();


--
-- Name: audit_event audit_event_append_only_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_event_append_only_update BEFORE DELETE OR UPDATE ON public.audit_event FOR EACH ROW EXECUTE FUNCTION public.audit_event_no_update_delete();


--
-- Name: audit_event audit_event_archive_enqueue; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_event_archive_enqueue AFTER INSERT ON public.audit_event FOR EACH ROW EXECUTE FUNCTION public.enqueue_audit_archive_event();


--
-- Name: audit_event audit_event_hash_insert; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER audit_event_hash_insert BEFORE INSERT ON public.audit_event FOR EACH ROW EXECUTE FUNCTION public.audit_event_hash_before_insert();


--
-- Name: component_audit_event component_audit_event_append_only; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER component_audit_event_append_only BEFORE DELETE OR UPDATE ON public.component_audit_event FOR EACH ROW EXECUTE FUNCTION public.component_audit_event_no_update_delete();


--
-- Name: component component_policy_epoch_sync_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER component_policy_epoch_sync_trigger BEFORE UPDATE ON public.component FOR EACH ROW EXECUTE FUNCTION public.component_policy_epoch_sync();


--
-- Name: integration_token integration_token_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER integration_token_updated_at BEFORE UPDATE ON public.integration_token FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: kaja_credential kaja_credential_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER kaja_credential_updated_at BEFORE UPDATE ON public.kaja_credential FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: monitoring_profile monitoring_profile_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER monitoring_profile_updated_at BEFORE UPDATE ON public.monitoring_profile FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: onboarding_job onboarding_job_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER onboarding_job_updated_at BEFORE UPDATE ON public.onboarding_job FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();


--
-- Name: access_token access_token_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_token
    ADD CONSTRAINT access_token_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: access_token access_token_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_token
    ADD CONSTRAINT access_token_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id);


--
-- Name: access_token access_token_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_token
    ADD CONSTRAINT access_token_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: admin_bootstrap_state admin_bootstrap_state_completed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_bootstrap_state
    ADD CONSTRAINT admin_bootstrap_state_completed_by_fkey FOREIGN KEY (completed_by) REFERENCES public.admin_account(id);


--
-- Name: admin_recovery_code admin_recovery_code_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_recovery_code
    ADD CONSTRAINT admin_recovery_code_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.admin_account(id) ON DELETE CASCADE;


--
-- Name: admin_session admin_session_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_session
    ADD CONSTRAINT admin_session_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.admin_account(id);


--
-- Name: alert_webhook_delivery alert_webhook_delivery_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_webhook_delivery
    ADD CONSTRAINT alert_webhook_delivery_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.operational_alert(id) ON DELETE CASCADE;


--
-- Name: audit_archive_outbox audit_archive_outbox_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_archive_outbox
    ADD CONSTRAINT audit_archive_outbox_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.audit_event(id);


--
-- Name: component_access_token component_access_token_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_access_token
    ADD CONSTRAINT component_access_token_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.component_credential(id) ON DELETE CASCADE;


--
-- Name: component_access_token component_access_token_source_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_access_token
    ADD CONSTRAINT component_access_token_source_component_id_fkey FOREIGN KEY (source_component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_access_token component_access_token_target_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_access_token
    ADD CONSTRAINT component_access_token_target_component_id_fkey FOREIGN KEY (target_component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component component_active_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT component_active_revision_id_fkey FOREIGN KEY (active_revision_id) REFERENCES public.component_revision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: component_attribute_contract component_attribute_contract_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_attribute_contract
    ADD CONSTRAINT component_attribute_contract_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_attribute_contract component_attribute_contract_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_attribute_contract
    ADD CONSTRAINT component_attribute_contract_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_audit_event component_audit_event_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_audit_event
    ADD CONSTRAINT component_audit_event_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE SET NULL;


--
-- Name: component_audit_event component_audit_event_stream_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_audit_event
    ADD CONSTRAINT component_audit_event_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES public.component_audit_stream(id) ON DELETE CASCADE;


--
-- Name: component_audit_stream component_audit_stream_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_audit_stream
    ADD CONSTRAINT component_audit_stream_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_call_mask component_call_mask_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_call_mask
    ADD CONSTRAINT component_call_mask_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_call_mask component_call_mask_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_call_mask
    ADD CONSTRAINT component_call_mask_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_control_command component_control_command_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_command
    ADD CONSTRAINT component_control_command_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_control_command component_control_command_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_command
    ADD CONSTRAINT component_control_command_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_control_dispatch_attempt component_control_dispatch_attempt_dispatch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_dispatch_attempt
    ADD CONSTRAINT component_control_dispatch_attempt_dispatch_id_fkey FOREIGN KEY (dispatch_id) REFERENCES public.component_control_dispatch(id) ON DELETE CASCADE;


--
-- Name: component_control_dispatch component_control_dispatch_command_contract_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_dispatch
    ADD CONSTRAINT component_control_dispatch_command_contract_id_fkey FOREIGN KEY (command_contract_id) REFERENCES public.component_control_command(id) ON DELETE CASCADE;


--
-- Name: component_control_dispatch component_control_dispatch_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_dispatch
    ADD CONSTRAINT component_control_dispatch_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_control_dispatch component_control_dispatch_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_control_dispatch
    ADD CONSTRAINT component_control_dispatch_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_credential component_credential_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_credential
    ADD CONSTRAINT component_credential_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_document_blob component_document_blob_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_document_blob
    ADD CONSTRAINT component_document_blob_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_document_blob component_document_blob_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_document_blob
    ADD CONSTRAINT component_document_blob_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_documentation_evidence component_documentation_evidence_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_documentation_evidence
    ADD CONSTRAINT component_documentation_evidence_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_documentation_evidence component_documentation_evidence_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_documentation_evidence
    ADD CONSTRAINT component_documentation_evidence_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_e2e_execution_run component_e2e_execution_run_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_execution_run
    ADD CONSTRAINT component_e2e_execution_run_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_e2e_execution_run component_e2e_execution_run_onboarding_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_execution_run
    ADD CONSTRAINT component_e2e_execution_run_onboarding_job_id_fkey FOREIGN KEY (onboarding_job_id) REFERENCES public.component_onboarding_job(id) ON DELETE SET NULL;


--
-- Name: component_e2e_execution_run component_e2e_execution_run_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_execution_run
    ADD CONSTRAINT component_e2e_execution_run_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_e2e_execution_run component_e2e_execution_run_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_execution_run
    ADD CONSTRAINT component_e2e_execution_run_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.component_e2e_scenario(id) ON DELETE CASCADE;


--
-- Name: component_e2e_fixture component_e2e_fixture_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_fixture
    ADD CONSTRAINT component_e2e_fixture_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_e2e_result component_e2e_result_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_result
    ADD CONSTRAINT component_e2e_result_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_e2e_result component_e2e_result_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_result
    ADD CONSTRAINT component_e2e_result_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_e2e_result component_e2e_result_scenario_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_result
    ADD CONSTRAINT component_e2e_result_scenario_id_fkey FOREIGN KEY (scenario_id) REFERENCES public.component_e2e_scenario(id) ON DELETE CASCADE;


--
-- Name: component_e2e_run component_e2e_run_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run
    ADD CONSTRAINT component_e2e_run_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component_e2e_run component_e2e_run_requested_by_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run
    ADD CONSTRAINT component_e2e_run_requested_by_principal_id_fkey FOREIGN KEY (requested_by_principal_id) REFERENCES public.principal(id);


--
-- Name: component_e2e_run_result component_e2e_run_result_fixture_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run_result
    ADD CONSTRAINT component_e2e_run_result_fixture_id_fkey FOREIGN KEY (fixture_id) REFERENCES public.component_e2e_fixture(id);


--
-- Name: component_e2e_run_result component_e2e_run_result_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run_result
    ADD CONSTRAINT component_e2e_run_result_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.component_e2e_run(id) ON DELETE CASCADE;


--
-- Name: component_e2e_run component_e2e_run_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_run
    ADD CONSTRAINT component_e2e_run_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id);


--
-- Name: component_e2e_scenario component_e2e_scenario_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_scenario
    ADD CONSTRAINT component_e2e_scenario_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_e2e_scenario component_e2e_scenario_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_e2e_scenario
    ADD CONSTRAINT component_e2e_scenario_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_endpoint_contract component_endpoint_contract_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_endpoint_contract
    ADD CONSTRAINT component_endpoint_contract_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_endpoint_contract component_endpoint_contract_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_endpoint_contract
    ADD CONSTRAINT component_endpoint_contract_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_external_access_token component_external_access_token_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_access_token
    ADD CONSTRAINT component_external_access_token_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.component_external_principal_credential(id) ON DELETE CASCADE;


--
-- Name: component_external_access_token component_external_access_token_external_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_access_token
    ADD CONSTRAINT component_external_access_token_external_principal_id_fkey FOREIGN KEY (external_principal_id) REFERENCES public.component_external_principal(id) ON DELETE CASCADE;


--
-- Name: component_external_access_token component_external_access_token_external_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_access_token
    ADD CONSTRAINT component_external_access_token_external_target_id_fkey FOREIGN KEY (external_target_id) REFERENCES public.component_external_target(id) ON DELETE CASCADE;


--
-- Name: component_external_access_token component_external_access_token_source_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_access_token
    ADD CONSTRAINT component_external_access_token_source_component_id_fkey FOREIGN KEY (source_component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_external_gateway_call component_external_gateway_call_external_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_gateway_call
    ADD CONSTRAINT component_external_gateway_call_external_permission_id_fkey FOREIGN KEY (external_permission_id) REFERENCES public.component_external_permission(id) ON DELETE RESTRICT;


--
-- Name: component_external_gateway_call component_external_gateway_call_external_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_gateway_call
    ADD CONSTRAINT component_external_gateway_call_external_target_id_fkey FOREIGN KEY (external_target_id) REFERENCES public.component_external_target(id) ON DELETE RESTRICT;


--
-- Name: component_external_gateway_call component_external_gateway_call_source_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_gateway_call
    ADD CONSTRAINT component_external_gateway_call_source_component_id_fkey FOREIGN KEY (source_component_id) REFERENCES public.component(id) ON DELETE RESTRICT;


--
-- Name: component_external_permission component_external_permission_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_permission
    ADD CONSTRAINT component_external_permission_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_external_permission component_external_permission_external_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_permission
    ADD CONSTRAINT component_external_permission_external_principal_id_fkey FOREIGN KEY (external_principal_id) REFERENCES public.component_external_principal(id) ON DELETE CASCADE;


--
-- Name: component_external_permission component_external_permission_external_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_permission
    ADD CONSTRAINT component_external_permission_external_target_id_fkey FOREIGN KEY (external_target_id) REFERENCES public.component_external_target(id) ON DELETE CASCADE;


--
-- Name: component_external_principal_credential component_external_principal_credent_external_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_principal_credential
    ADD CONSTRAINT component_external_principal_credent_external_principal_id_fkey FOREIGN KEY (external_principal_id) REFERENCES public.component_external_principal(id) ON DELETE CASCADE;


--
-- Name: component_external_principal component_external_principal_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_external_principal
    ADD CONSTRAINT component_external_principal_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.principal(id);


--
-- Name: component_heartbeat_challenge component_heartbeat_challenge_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat_challenge
    ADD CONSTRAINT component_heartbeat_challenge_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_heartbeat_challenge component_heartbeat_challenge_dispatch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat_challenge
    ADD CONSTRAINT component_heartbeat_challenge_dispatch_id_fkey FOREIGN KEY (dispatch_id) REFERENCES public.component_control_dispatch(id) ON DELETE CASCADE;


--
-- Name: component_heartbeat component_heartbeat_challenge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat
    ADD CONSTRAINT component_heartbeat_challenge_id_fkey FOREIGN KEY (challenge_id) REFERENCES public.component_heartbeat_challenge(id) ON DELETE SET NULL;


--
-- Name: component_heartbeat_challenge component_heartbeat_challenge_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat_challenge
    ADD CONSTRAINT component_heartbeat_challenge_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_heartbeat component_heartbeat_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_heartbeat
    ADD CONSTRAINT component_heartbeat_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_onboarding_job component_onboarding_job_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_job
    ADD CONSTRAINT component_onboarding_job_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component_onboarding_job component_onboarding_job_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_job
    ADD CONSTRAINT component_onboarding_job_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.component_credential(id);


--
-- Name: component_onboarding_job component_onboarding_job_integration_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_job
    ADD CONSTRAINT component_onboarding_job_integration_token_id_fkey FOREIGN KEY (integration_token_id) REFERENCES public.integration_token(id);


--
-- Name: component_onboarding_job component_onboarding_job_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_job
    ADD CONSTRAINT component_onboarding_job_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: component_onboarding_revision_request component_onboarding_revision_request_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_onboarding_revision_request
    ADD CONSTRAINT component_onboarding_revision_request_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.component_onboarding_job(id) ON DELETE CASCADE;


--
-- Name: component_operation_event component_operation_event_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_operation_event
    ADD CONSTRAINT component_operation_event_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_operation_lease component_operation_lease_source_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_operation_lease
    ADD CONSTRAINT component_operation_lease_source_principal_id_fkey FOREIGN KEY (source_principal_id) REFERENCES public.principal(id);


--
-- Name: component_operation_lease component_operation_lease_target_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_operation_lease
    ADD CONSTRAINT component_operation_lease_target_component_id_fkey FOREIGN KEY (target_component_id) REFERENCES public.component(id);


--
-- Name: component_permission component_permission_source_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_permission
    ADD CONSTRAINT component_permission_source_component_id_fkey FOREIGN KEY (source_component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_permission component_permission_target_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_permission
    ADD CONSTRAINT component_permission_target_component_id_fkey FOREIGN KEY (target_component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component component_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT component_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.principal(id);


--
-- Name: component_pulse_mask component_pulse_mask_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_pulse_mask
    ADD CONSTRAINT component_pulse_mask_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_pulse_mask component_pulse_mask_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_pulse_mask
    ADD CONSTRAINT component_pulse_mask_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_readiness_gate_evidence component_readiness_gate_evidence_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_readiness_gate_evidence
    ADD CONSTRAINT component_readiness_gate_evidence_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_readiness_gate_evidence component_readiness_gate_evidence_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_readiness_gate_evidence
    ADD CONSTRAINT component_readiness_gate_evidence_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component component_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT component_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: component_revision component_revision_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_revision
    ADD CONSTRAINT component_revision_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_runtime_target component_runtime_target_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_runtime_target
    ADD CONSTRAINT component_runtime_target_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_runtime_target component_runtime_target_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_runtime_target
    ADD CONSTRAINT component_runtime_target_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_secret_policy component_secret_policy_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_secret_policy
    ADD CONSTRAINT component_secret_policy_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_secret_policy component_secret_policy_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_secret_policy
    ADD CONSTRAINT component_secret_policy_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_state_contract component_state_contract_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_contract
    ADD CONSTRAINT component_state_contract_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_state_contract component_state_contract_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_contract
    ADD CONSTRAINT component_state_contract_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_state_observation component_state_observation_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_observation
    ADD CONSTRAINT component_state_observation_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_state_observation component_state_observation_query_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_observation
    ADD CONSTRAINT component_state_observation_query_run_id_fkey FOREIGN KEY (query_run_id) REFERENCES public.component_state_query_run(id) ON DELETE SET NULL;


--
-- Name: component_state_query_run component_state_query_run_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_query_run
    ADD CONSTRAINT component_state_query_run_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_state_query_run component_state_query_run_dispatch_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_query_run
    ADD CONSTRAINT component_state_query_run_dispatch_id_fkey FOREIGN KEY (dispatch_id) REFERENCES public.component_control_dispatch(id) ON DELETE CASCADE;


--
-- Name: component_state_query_run component_state_query_run_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_query_run
    ADD CONSTRAINT component_state_query_run_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_state_snapshot component_state_snapshot_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_snapshot
    ADD CONSTRAINT component_state_snapshot_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_state_snapshot component_state_snapshot_query_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_snapshot
    ADD CONSTRAINT component_state_snapshot_query_run_id_fkey FOREIGN KEY (query_run_id) REFERENCES public.component_state_query_run(id) ON DELETE SET NULL;


--
-- Name: component_state_snapshot component_state_snapshot_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_snapshot
    ADD CONSTRAINT component_state_snapshot_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_state_transition component_state_transition_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_transition
    ADD CONSTRAINT component_state_transition_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_state_transition component_state_transition_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_state_transition
    ADD CONSTRAINT component_state_transition_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: component_tool_contract component_tool_contract_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_tool_contract
    ADD CONSTRAINT component_tool_contract_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: component_tool_contract component_tool_contract_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.component_tool_contract
    ADD CONSTRAINT component_tool_contract_revision_id_fkey FOREIGN KEY (revision_id) REFERENCES public.component_revision(id) ON DELETE CASCADE;


--
-- Name: egress_capability egress_capability_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.egress_capability
    ADD CONSTRAINT egress_capability_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.onboarding_job(id) ON DELETE CASCADE;


--
-- Name: egress_capability egress_capability_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.egress_capability
    ADD CONSTRAINT egress_capability_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: external_api_service_profile external_api_service_profile_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.external_api_service_profile
    ADD CONSTRAINT external_api_service_profile_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: function_concurrency_lease function_concurrency_lease_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.function_concurrency_lease
    ADD CONSTRAINT function_concurrency_lease_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: function_rate_bucket function_rate_bucket_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.function_rate_bucket
    ADD CONSTRAINT function_rate_bucket_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id) ON DELETE CASCADE;


--
-- Name: function_rate_bucket function_rate_bucket_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.function_rate_bucket
    ADD CONSTRAINT function_rate_bucket_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: function_statistics function_statistics_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.function_statistics
    ADD CONSTRAINT function_statistics_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: integration_token_allowed_component integration_token_allowed_component_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_allowed_component
    ADD CONSTRAINT integration_token_allowed_component_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: integration_token_allowed_component integration_token_allowed_component_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_allowed_component
    ADD CONSTRAINT integration_token_allowed_component_token_id_fkey FOREIGN KEY (token_id) REFERENCES public.integration_token(id) ON DELETE CASCADE;


--
-- Name: integration_token_child_job integration_token_child_job_component_onboarding_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_child_job
    ADD CONSTRAINT integration_token_child_job_component_onboarding_job_id_fkey FOREIGN KEY (component_onboarding_job_id) REFERENCES public.component_onboarding_job(id) ON DELETE CASCADE;


--
-- Name: integration_token_child_job integration_token_child_job_onboarding_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_child_job
    ADD CONSTRAINT integration_token_child_job_onboarding_job_id_fkey FOREIGN KEY (onboarding_job_id) REFERENCES public.onboarding_job(id) ON DELETE CASCADE;


--
-- Name: integration_token_child_job integration_token_child_job_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_child_job
    ADD CONSTRAINT integration_token_child_job_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: integration_token_child_job integration_token_child_job_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token_child_job
    ADD CONSTRAINT integration_token_child_job_token_id_fkey FOREIGN KEY (token_id) REFERENCES public.integration_token(id) ON DELETE CASCADE;


--
-- Name: integration_token integration_token_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.admin_account(id);


--
-- Name: integration_token integration_token_onboarding_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_onboarding_job_id_fkey FOREIGN KEY (onboarding_job_id) REFERENCES public.onboarding_job(id);


--
-- Name: integration_token integration_token_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_token
    ADD CONSTRAINT integration_token_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: kaja_permission kaja_permission_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kaja_permission
    ADD CONSTRAINT kaja_permission_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id);


--
-- Name: kaja_permission kaja_permission_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kaja_permission
    ADD CONSTRAINT kaja_permission_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: managed_service_access_token managed_service_access_token_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_access_token
    ADD CONSTRAINT managed_service_access_token_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: managed_service_access_token managed_service_access_token_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_access_token
    ADD CONSTRAINT managed_service_access_token_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id);


--
-- Name: managed_service_access_token managed_service_access_token_legacy_access_token_digest_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_access_token
    ADD CONSTRAINT managed_service_access_token_legacy_access_token_digest_fkey FOREIGN KEY (legacy_access_token_digest) REFERENCES public.access_token(lookup_digest) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: managed_service_access_token managed_service_access_token_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_access_token
    ADD CONSTRAINT managed_service_access_token_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service managed_service_active_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service
    ADD CONSTRAINT managed_service_active_revision_id_fkey FOREIGN KEY (active_revision_id) REFERENCES public.managed_service_revision(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: managed_service_api_status_history managed_service_api_status_history_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_api_status_history
    ADD CONSTRAINT managed_service_api_status_history_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service_api_status managed_service_api_status_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_api_status
    ADD CONSTRAINT managed_service_api_status_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service managed_service_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service
    ADD CONSTRAINT managed_service_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: managed_service managed_service_legacy_mcp_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service
    ADD CONSTRAINT managed_service_legacy_mcp_server_id_fkey FOREIGN KEY (legacy_mcp_server_id) REFERENCES public.mcp_server(id) ON DELETE SET NULL;


--
-- Name: managed_service_permission managed_service_permission_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_permission
    ADD CONSTRAINT managed_service_permission_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id);


--
-- Name: managed_service_permission managed_service_permission_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_permission
    ADD CONSTRAINT managed_service_permission_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service_permission managed_service_permission_scope_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_permission
    ADD CONSTRAINT managed_service_permission_scope_id_fkey FOREIGN KEY (scope_id) REFERENCES public.managed_service_scope(id) ON DELETE CASCADE;


--
-- Name: managed_service_policy_event managed_service_policy_event_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_policy_event
    ADD CONSTRAINT managed_service_policy_event_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service_probe_result managed_service_probe_result_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_probe_result
    ADD CONSTRAINT managed_service_probe_result_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service_revision managed_service_revision_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_revision
    ADD CONSTRAINT managed_service_revision_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service_runtime_log_event managed_service_runtime_log_event_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_runtime_log_event
    ADD CONSTRAINT managed_service_runtime_log_event_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service_scope managed_service_scope_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_scope
    ADD CONSTRAINT managed_service_scope_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: managed_service_usage_event managed_service_usage_event_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_usage_event
    ADD CONSTRAINT managed_service_usage_event_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id);


--
-- Name: managed_service_usage_event managed_service_usage_event_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_service_usage_event
    ADD CONSTRAINT managed_service_usage_event_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: mcp_invocation mcp_invocation_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation
    ADD CONSTRAINT mcp_invocation_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id);


--
-- Name: mcp_invocation_idempotency mcp_invocation_idempotency_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation_idempotency
    ADD CONSTRAINT mcp_invocation_idempotency_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id) ON DELETE CASCADE;


--
-- Name: mcp_invocation_idempotency mcp_invocation_idempotency_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation_idempotency
    ADD CONSTRAINT mcp_invocation_idempotency_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: mcp_invocation_metric mcp_invocation_metric_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation_metric
    ADD CONSTRAINT mcp_invocation_metric_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: mcp_invocation mcp_invocation_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_invocation
    ADD CONSTRAINT mcp_invocation_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: mcp_rate_bucket mcp_rate_bucket_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_rate_bucket
    ADD CONSTRAINT mcp_rate_bucket_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.kaja_credential(id) ON DELETE CASCADE;


--
-- Name: mcp_rate_bucket mcp_rate_bucket_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_rate_bucket
    ADD CONSTRAINT mcp_rate_bucket_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: mcp_server mcp_server_active_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_server
    ADD CONSTRAINT mcp_server_active_revision_id_fkey FOREIGN KEY (active_revision_id) REFERENCES public.registration_revision(id);


--
-- Name: mcp_server mcp_server_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_server
    ADD CONSTRAINT mcp_server_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: mcp_server mcp_server_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_server
    ADD CONSTRAINT mcp_server_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: monitoring_probe_result monitoring_probe_result_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_probe_result
    ADD CONSTRAINT monitoring_probe_result_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: monitoring_profile monitoring_profile_registration_revision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_profile
    ADD CONSTRAINT monitoring_profile_registration_revision_id_fkey FOREIGN KEY (registration_revision_id) REFERENCES public.registration_revision(id);


--
-- Name: monitoring_profile monitoring_profile_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.monitoring_profile
    ADD CONSTRAINT monitoring_profile_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: onboarding_event onboarding_event_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_event
    ADD CONSTRAINT onboarding_event_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.onboarding_job(id) ON DELETE CASCADE;


--
-- Name: onboarding_gate onboarding_gate_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_gate
    ADD CONSTRAINT onboarding_gate_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.onboarding_job(id) ON DELETE CASCADE;


--
-- Name: onboarding_job onboarding_job_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_component_id_fkey FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: onboarding_job onboarding_job_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: onboarding_job onboarding_job_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: onboarding_job onboarding_job_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_job
    ADD CONSTRAINT onboarding_job_token_id_fkey FOREIGN KEY (token_id) REFERENCES public.integration_token(id);


--
-- Name: onboarding_source_revision onboarding_source_revision_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.onboarding_source_revision
    ADD CONSTRAINT onboarding_source_revision_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.onboarding_job(id) ON DELETE CASCADE;


--
-- Name: operational_alert operational_alert_acknowledged_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_alert
    ADD CONSTRAINT operational_alert_acknowledged_by_fkey FOREIGN KEY (acknowledged_by) REFERENCES public.admin_account(id);


--
-- Name: operational_alert operational_alert_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_alert
    ADD CONSTRAINT operational_alert_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- Name: operational_alert operational_alert_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_alert
    ADD CONSTRAINT operational_alert_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: operational_alert operational_alert_suppression_owner_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_alert
    ADD CONSTRAINT operational_alert_suppression_owner_fkey FOREIGN KEY (suppression_owner) REFERENCES public.admin_account(id);


--
-- Name: operational_config_applied operational_config_applied_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_config_applied
    ADD CONSTRAINT operational_config_applied_key_fkey FOREIGN KEY (key) REFERENCES public.operational_config_setting(key) ON DELETE CASCADE;


--
-- Name: operational_config_setting operational_config_setting_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.operational_config_setting
    ADD CONSTRAINT operational_config_setting_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.admin_account(id) ON DELETE SET NULL;


--
-- Name: platform_worker_access_identity platform_worker_access_identity_access_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_worker_access_identity
    ADD CONSTRAINT platform_worker_access_identity_access_token_id_fkey FOREIGN KEY (access_token_id) REFERENCES public.principal_access_token(id);


--
-- Name: platform_worker_access_identity platform_worker_access_identity_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_worker_access_identity
    ADD CONSTRAINT platform_worker_access_identity_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.principal(id);


--
-- Name: platform_worker_access_identity platform_worker_access_identity_rotated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_worker_access_identity
    ADD CONSTRAINT platform_worker_access_identity_rotated_by_fkey FOREIGN KEY (rotated_by) REFERENCES public.admin_account(id);


--
-- Name: principal_access_token principal_access_token_source_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_access_token
    ADD CONSTRAINT principal_access_token_source_principal_id_fkey FOREIGN KEY (source_principal_id) REFERENCES public.principal(id) ON DELETE CASCADE;


--
-- Name: principal_access_token principal_access_token_target_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_access_token
    ADD CONSTRAINT principal_access_token_target_component_id_fkey FOREIGN KEY (target_component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: principal_component_permission principal_component_permission_source_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_component_permission
    ADD CONSTRAINT principal_component_permission_source_principal_id_fkey FOREIGN KEY (source_principal_id) REFERENCES public.principal(id) ON DELETE CASCADE;


--
-- Name: principal_component_permission principal_component_permission_target_component_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_component_permission
    ADD CONSTRAINT principal_component_permission_target_component_id_fkey FOREIGN KEY (target_component_id) REFERENCES public.component(id) ON DELETE CASCADE;


--
-- Name: principal_credential principal_credential_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principal_credential
    ADD CONSTRAINT principal_credential_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.principal(id) ON DELETE CASCADE;


--
-- Name: registration_revision registration_revision_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_revision
    ADD CONSTRAINT registration_revision_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: release_wave_component release_wave_component_release_version_wave_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_wave_component
    ADD CONSTRAINT release_wave_component_release_version_wave_key_fkey FOREIGN KEY (release_version, wave_key) REFERENCES public.release_wave(release_version, wave_key) ON DELETE CASCADE;


--
-- Name: release_wave release_wave_release_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.release_wave
    ADD CONSTRAINT release_wave_release_version_fkey FOREIGN KEY (release_version) REFERENCES public.release_epoch(release_version);


--
-- Name: runtime_log_event runtime_log_event_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runtime_log_event
    ADD CONSTRAINT runtime_log_event_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id) ON DELETE CASCADE;


--
-- Name: secret_admin_reveal_grant secret_admin_reveal_grant_admin_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_admin_reveal_grant
    ADD CONSTRAINT secret_admin_reveal_grant_admin_account_id_fkey FOREIGN KEY (admin_account_id) REFERENCES public.admin_account(id) ON DELETE CASCADE;


--
-- Name: secret_admin_reveal_grant secret_admin_reveal_grant_admin_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_admin_reveal_grant
    ADD CONSTRAINT secret_admin_reveal_grant_admin_session_id_fkey FOREIGN KEY (admin_session_id) REFERENCES public.admin_session(id) ON DELETE CASCADE;


--
-- Name: secret_admin_reveal_grant secret_admin_reveal_grant_secret_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_admin_reveal_grant
    ADD CONSTRAINT secret_admin_reveal_grant_secret_version_id_fkey FOREIGN KEY (secret_version_id) REFERENCES public.secret_version(id) ON DELETE CASCADE;


--
-- Name: secret_grant secret_grant_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_grant
    ADD CONSTRAINT secret_grant_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.admin_account(id) ON DELETE SET NULL;


--
-- Name: secret_grant secret_grant_revoked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_grant
    ADD CONSTRAINT secret_grant_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES public.admin_account(id) ON DELETE SET NULL;


--
-- Name: secret_grant secret_grant_secret_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_grant
    ADD CONSTRAINT secret_grant_secret_id_fkey FOREIGN KEY (secret_id) REFERENCES public.secret_record(id) ON DELETE CASCADE;


--
-- Name: secret_record secret_record_active_version_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_record
    ADD CONSTRAINT secret_record_active_version_fkey FOREIGN KEY (active_version_id) REFERENCES public.secret_version(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: secret_record secret_record_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_record
    ADD CONSTRAINT secret_record_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.admin_account(id) ON DELETE SET NULL;


--
-- Name: secret_record secret_record_updated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_record
    ADD CONSTRAINT secret_record_updated_by_fkey FOREIGN KEY (updated_by) REFERENCES public.admin_account(id) ON DELETE SET NULL;


--
-- Name: secret_version secret_version_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_version
    ADD CONSTRAINT secret_version_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.admin_account(id) ON DELETE SET NULL;


--
-- Name: secret_version secret_version_secret_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_version
    ADD CONSTRAINT secret_version_secret_id_fkey FOREIGN KEY (secret_id) REFERENCES public.secret_record(id) ON DELETE CASCADE;


--
-- Name: server_state_history server_state_history_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.server_state_history
    ADD CONSTRAINT server_state_history_server_id_fkey FOREIGN KEY (server_id) REFERENCES public.mcp_server(id);


--
-- Name: service_pipeline_event service_pipeline_event_pipeline_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_pipeline_event
    ADD CONSTRAINT service_pipeline_event_pipeline_run_id_fkey FOREIGN KEY (pipeline_run_id) REFERENCES public.service_pipeline_run(id) ON DELETE CASCADE;


--
-- Name: service_pipeline_run service_pipeline_run_integration_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_pipeline_run
    ADD CONSTRAINT service_pipeline_run_integration_token_id_fkey FOREIGN KEY (integration_token_id) REFERENCES public.integration_token(id) ON DELETE SET NULL;


--
-- Name: service_pipeline_run service_pipeline_run_managed_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_pipeline_run
    ADD CONSTRAINT service_pipeline_run_managed_service_id_fkey FOREIGN KEY (managed_service_id) REFERENCES public.managed_service(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--



--
-- PostgreSQL database dump
--


-- Dumped from database version 16.14 (Homebrew)
-- Dumped by pg_dump version 16.14 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: admin_account; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.admin_account (id, username, password_hash, password_changed_at, mfa_enabled, mfa_secret, created_at, role, active, activated_at, updated_at, session_epoch) VALUES ('d52da24a-4dd2-493f-800e-f2ba0b4fc3a5', 'karmar78', NULL, NULL, false, NULL, '2026-07-22 22:42:24.194864+02', 'ADMIN', false, NULL, '2026-07-22 22:42:24.432156+02', '7605f0fc-cca7-49a2-a761-2b27a99ca237');


--
-- Data for Name: admin_bootstrap_state; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.admin_bootstrap_state (singleton, completed, completed_at, completed_by, updated_at) VALUES (true, false, NULL, NULL, '2026-07-22 22:42:24.432156+02');


--
-- Data for Name: audit_head; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.audit_head (singleton, last_sequence, event_hash, updated_at) VALUES (true, 0, NULL, '2026-07-22 22:42:24.348557+02');


--
-- Data for Name: principal; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.principal (id, kind, public_id, status, policy_epoch, revocation_epoch, metadata, created_at, updated_at) VALUES ('8cfcfbbe-8180-404b-a95d-0d8529938f29', 'PLATFORM', 'KCML-PLATFORM-WORKER', 'ACTIVE', 1, 1, '{"purpose": "control-and-e2e-workers", "managedBy": "KCML"}', '2026-07-22 22:42:24.766077+02', '2026-07-22 22:42:24.766077+02');


--
-- Data for Name: platform_worker_access_identity; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.platform_worker_access_identity (singleton, principal_id, access_token_id, token_ciphertext, key_id, fingerprint, rotated_by, rotated_at, updated_at) VALUES (true, '8cfcfbbe-8180-404b-a95d-0d8529938f29', NULL, NULL, NULL, NULL, NULL, NULL, '2026-07-22 22:42:24.766077+02');


--
-- Data for Name: release_epoch; Type: TABLE DATA; Schema: public; Owner: -
--

INSERT INTO public.release_epoch (release_version, blueprint_version, catalog_version, manifest_schema_version, pulse_envelope_version, policy_baseline, mcp_protocol_version, sealed_previous_epoch_hash, created_at) VALUES ('2026.07.22-compliance.1', '2026.07.22-compliance.1', '2026.07.22-compliance.1', '2026.07.22-compliance.1', '2026.07.22-compliance.1', '2026-07-22', '2025-11-25', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '2026-07-22 22:42:24.730209+02');


--
-- Data for Name: release_wave; Type: TABLE DATA; Schema: public; Owner: -
--

--
-- PostgreSQL database dump complete
--




--
-- Canonical pre-production baseline seeds
--

INSERT INTO public.release_epoch (
  release_version,
  blueprint_version,
  catalog_version,
  manifest_schema_version,
  pulse_envelope_version,
  policy_baseline,
  mcp_protocol_version,
  sealed_previous_epoch_hash
) VALUES (
  '2026.07.22-compliance.1',
  '2026.07.22-compliance.1',
  '2026.07.22-compliance.1',
  '2026.07.22-compliance.1',
  '2026.07.22-compliance.1',
  DATE '2026-07-22',
  '2025-11-25',
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
)
ON CONFLICT (release_version) DO NOTHING;
