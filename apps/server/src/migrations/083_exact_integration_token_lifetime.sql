update integration_token
   set revoked_at=case when revoked_at is null and (
         initial_expires_at<>issued_at+interval '24 hours'
         or expires_at<>issued_at+interval '24 hours'
         or max_expires_at<>issued_at+interval '24 hours'
       ) then now() else revoked_at end,
       initial_expires_at=issued_at+interval '24 hours',
       expires_at=issued_at+interval '24 hours',
       max_expires_at=issued_at+interval '24 hours',
       lock_version=lock_version+1
 where initial_expires_at<>issued_at+interval '24 hours'
    or expires_at<>issued_at+interval '24 hours'
    or max_expires_at<>issued_at+interval '24 hours';

alter table integration_token drop constraint if exists integration_token_single_use_24h_check;
alter table integration_token add constraint integration_token_single_use_24h_check check (
  initial_expires_at=issued_at+interval '24 hours'
  and expires_at=issued_at+interval '24 hours'
  and max_expires_at=issued_at+interval '24 hours'
  and max_child_jobs=1
);
