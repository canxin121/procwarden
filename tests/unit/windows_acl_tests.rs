use std::path::PathBuf;

use super::AclRollback;

#[test]
fn rollback_tracks_paths_for_future_revoke() {
    let mut rollback = AclRollback::new(std::ptr::null_mut());
    rollback.track(PathBuf::from(r"C:\temp\one"));
    rollback.track(PathBuf::from(r"C:\temp\two"));
    assert_eq!(rollback.tracked_len(), 2);
}
