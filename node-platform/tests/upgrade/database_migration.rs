#[test]
fn database_migration() {
    crate::support::upgrade("upgrade/database_migration");
}
