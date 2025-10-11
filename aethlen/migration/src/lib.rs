use sea_orm_migration::prelude::*;

// declare your migration modules here
mod m2025_10_08_create_docs_chunks;
mod m2025_10_10_000001_create_refresh_tokens; // ← ensure this line exists

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            // keep correct order (older first, and ensure `users` migration (if you have one)
            // appears BEFORE refresh_tokens). Example:
            // Box::new(m2025_09_01_000000_create_users::Migration),

            Box::new(m2025_10_08_create_docs_chunks::Migration),
            Box::new(m2025_10_10_000001_create_refresh_tokens::Migration),
        ]
    }
}
