use sea_orm_migration::prelude::*;

mod m2025_10_08_create_docs_chunks;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m2025_10_08_create_docs_chunks::Migration)]
    }
}
