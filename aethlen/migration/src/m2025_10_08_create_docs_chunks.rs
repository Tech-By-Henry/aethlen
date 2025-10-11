use sea_orm_migration::prelude::*;

/// Table: documents
#[derive(DeriveIden)]
enum Documents {
    Table,
    Id,
    Title,
    Source,
    CreatedAt,
}

/// Table: chunks (FK -> documents, includes pgvector column)
#[derive(DeriveIden)]
enum Chunks {
    Table,
    Id,
    DocumentId,
    Page,
    StartChar,
    EndChar,
    Text,
    Embedding,
    CreatedAt,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // documents
        manager
            .create_table(
                Table::create()
                    .table(Documents::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Documents::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Documents::Title).string().not_null())
                    .col(ColumnDef::new(Documents::Source).string().not_null())
                    .col(
                        ColumnDef::new(Documents::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        // chunks (with pgvector)
        manager
            .create_table(
                Table::create()
                    .table(Chunks::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Chunks::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Chunks::DocumentId).big_integer().not_null())
                    .col(ColumnDef::new(Chunks::Page).integer().not_null())
                    .col(ColumnDef::new(Chunks::StartChar).integer().not_null())
                    .col(ColumnDef::new(Chunks::EndChar).integer().not_null())
                    .col(ColumnDef::new(Chunks::Text).text().not_null())
                    // pgvector column (dim = 768)
                    .col(ColumnDef::new(Chunks::Embedding).custom(Alias::new("vector(768)")))
                    .col(
                        ColumnDef::new(Chunks::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_chunks_document")
                            .from(Chunks::Table, Chunks::DocumentId)
                            .to(Documents::Table, Documents::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Chunks::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Documents::Table).to_owned())
            .await
    }
}
