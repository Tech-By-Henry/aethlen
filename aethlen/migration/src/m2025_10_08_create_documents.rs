use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
enum Documents {
    Table,
    Id,
    Title,
    Content,
    Embedding,
    CreatedAt,
}

pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Documents::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Documents::Id).big_integer().not_null().auto_increment().primary_key())
                    .col(ColumnDef::new(Documents::Title).string().not_null())
                    .col(ColumnDef::new(Documents::Content).text().not_null())
                    .col(ColumnDef::new(Documents::Embedding).custom("vector(768)"))
                    .col(ColumnDef::new(Documents::CreatedAt).timestamp_with_time_zone().not_null().default(Expr::current_timestamp()))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.drop_table(Table::drop().table(Documents::Table).to_owned()).await
    }
}
