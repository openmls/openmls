use std::time::{Duration, Instant};

use futures_core::future::BoxFuture;
use sqlx::{
    Connection, Executor, SqliteConnection,
    migrate::{AppliedMigration, Migrate, MigrateError, Migration},
    query, query_as,
};

pub(super) struct MigratorWrapper<'a>(pub(super) &'a mut SqliteConnection);

// The following migration is copied exactly from the `sqlx::migrate::Migrate`
// implementation for `SqliteConnection` in sqlx 8.6. The only adaptation is the
// name of the migration table which is `_openmls_sqlx_migrations` instead of
// `_sqlx_migrations`.
impl<'a> Migrate for MigratorWrapper<'a> {
    fn ensure_migrations_table(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move {
            // language=SQLite
            self.0
                .execute(
                    r#"
CREATE TABLE IF NOT EXISTS _openmls_sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);
                "#,
                )
                .await?;

            Ok(())
        })
    }

    fn dirty_version(&mut self) -> BoxFuture<'_, Result<Option<i64>, MigrateError>> {
        Box::pin(async move {
            // language=SQLite
            let row: Option<(i64,)> = query_as(
                "SELECT version FROM _openmls_sqlx_migrations WHERE success = false ORDER BY version LIMIT 1",
            )
            .fetch_optional(&mut *self.0)
            .await?;

            Ok(row.map(|r| r.0))
        })
    }

    fn list_applied_migrations(
        &mut self,
    ) -> BoxFuture<'_, Result<Vec<AppliedMigration>, MigrateError>> {
        Box::pin(async move {
            // language=SQLite
            let rows: Vec<(i64, Vec<u8>)> =
                query_as("SELECT version, checksum FROM _openmls_sqlx_migrations ORDER BY version")
                    .fetch_all(&mut *self.0)
                    .await?;

            let migrations = rows
                .into_iter()
                .map(|(version, checksum)| AppliedMigration {
                    version,
                    checksum: checksum.into(),
                })
                .collect();

            Ok(migrations)
        })
    }

    fn lock(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move { Ok(()) })
    }

    fn unlock(&mut self) -> BoxFuture<'_, Result<(), MigrateError>> {
        Box::pin(async move { Ok(()) })
    }

    fn apply<'e: 'm, 'm>(
        &'e mut self,
        migration: &'m Migration,
    ) -> BoxFuture<'m, Result<Duration, MigrateError>> {
        Box::pin(async move {
            let mut tx = self.0.begin().await?;
            let start = Instant::now();

            // Use a single transaction for the actual migration script and the essential bookeeping so we never
            // execute migrations twice. See https://github.com/launchbadge/sqlx/issues/1966.
            // The `execution_time` however can only be measured for the whole transaction. This value _only_ exists for
            // data lineage and debugging reasons, so it is not super important if it is lost. So we initialize it to -1
            // and update it once the actual transaction completed.
            let _ = tx
                .execute(&*migration.sql)
                .await
                .map_err(|e| MigrateError::ExecuteMigration(e, migration.version))?;

            // language=SQL
            let _ = query(
                r#"
    INSERT INTO _openmls_sqlx_migrations ( version, description, success, checksum, execution_time )
    VALUES ( ?1, ?2, TRUE, ?3, -1 )
                "#,
            )
            .bind(migration.version)
            .bind(&*migration.description)
            .bind(&*migration.checksum)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;

            // Update `elapsed_time`.
            // NOTE: The process may disconnect/die at this point, so the elapsed time value might be lost. We accept
            //       this small risk since this value is not super important.

            let elapsed = start.elapsed();

            // language=SQL
            #[allow(clippy::cast_possible_truncation)]
            let _ = query(
                r#"
    UPDATE _openmls_sqlx_migrations
    SET execution_time = ?1
    WHERE version = ?2
                "#,
            )
            .bind(elapsed.as_nanos() as i64)
            .bind(migration.version)
            .execute(&mut *self.0)
            .await?;

            Ok(elapsed)
        })
    }

    fn revert<'e: 'm, 'm>(
        &'e mut self,
        migration: &'m Migration,
    ) -> BoxFuture<'m, Result<Duration, MigrateError>> {
        Box::pin(async move {
            // Use a single transaction for the actual migration script and the essential bookkeeping so we never
            // execute migrations twice. See https://github.com/launchbadge/sqlx/issues/1966.
            let mut tx = self.0.begin().await?;
            let start = Instant::now();

            let _ = tx.execute(&*migration.sql).await?;

            // language=SQL
            let _ = query(r#"DELETE FROM _openmls_sqlx_migrations WHERE version = ?1"#)
                .bind(migration.version)
                .execute(&mut *tx)
                .await?;

            tx.commit().await?;

            let elapsed = start.elapsed();

            Ok(elapsed)
        })
    }
}
