use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // assumes a `users` table with `id BIGINT` already exists
        manager
            .create_table(
                Table::create()
                    .table(RefreshToken::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RefreshToken::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RefreshToken::UserId).big_integer().not_null())
                    .col(ColumnDef::new(RefreshToken::Jti).uuid().not_null().unique_key())
                    .col(ColumnDef::new(RefreshToken::SessionId).uuid().not_null())
                    .col(ColumnDef::new(RefreshToken::IssuedAt).timestamp_with_time_zone().not_null())
                    .col(ColumnDef::new(RefreshToken::ExpiresAt).timestamp_with_time_zone().not_null())
                    .col(ColumnDef::new(RefreshToken::RevokedAt).timestamp_with_time_zone().null())
                    .col(ColumnDef::new(RefreshToken::ReplacedBy).uuid().null())
                    .col(
                        ColumnDef::new(RefreshToken::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_refresh_user")
                            .from(RefreshToken::Table, RefreshToken::UserId)
                            .to(Alias::new("users"), Alias::new("id"))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_user")
                    .table(RefreshToken::Table)
                    .col(RefreshToken::UserId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_refresh_expires")
                    .table(RefreshToken::Table)
                    .col(RefreshToken::ExpiresAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RefreshToken::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum RefreshToken {
    Table,
    Id,
    UserId,
    Jti,
    SessionId,
    IssuedAt,
    ExpiresAt,
    RevokedAt,
    ReplacedBy,
    CreatedAt,
}
