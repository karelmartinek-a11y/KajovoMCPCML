create table if not exists http_rate_bucket (
  bucket_key bytea primary key check (octet_length(bucket_key)=32),
  window_started_at timestamptz not null,
  request_count integer not null check (request_count > 0),
  updated_at timestamptz not null
);

create index if not exists http_rate_bucket_updated_idx
  on http_rate_bucket(updated_at);
