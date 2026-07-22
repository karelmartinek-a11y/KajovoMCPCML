alter table component_runtime_target
  add column if not exists runtime_resources jsonb not null default '{}'::jsonb;

update component_runtime_target target
   set runtime_resources=coalesce(revision.manifest->'runtime'->'resources','{}'::jsonb)
  from component_revision revision
 where revision.id=target.revision_id
   and target.runtime_resources='{}'::jsonb;

alter table component_runtime_target
  drop constraint if exists component_runtime_target_resources_object_check;
alter table component_runtime_target
  add constraint component_runtime_target_resources_object_check check (jsonb_typeof(runtime_resources)='object');
