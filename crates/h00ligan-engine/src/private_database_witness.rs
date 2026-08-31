//! Process-local authority carried from a private database writer to its
//! publication owner.
//!
//! Durable content proofs remain serializable data. This witness is different:
//! it is a one-use capability bound to the exact live `redb::Database` handle
//! that produced a proof. It lets the owning publication lifecycle carry
//! already-established authority without rereading the same private payload,
//! while reopened or substituted databases receive no authority and must take
//! their ordinary full-validation path.

use std::{
    fmt,
    sync::{Arc, Weak},
};

use redb::Database;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivateDatabaseWitnessError {
    #[error("the private database that produced this witness is no longer live")]
    ProducerClosed,
    #[error("the witness belongs to a different private database")]
    DatabaseMismatch,
}

/// A non-cloneable, one-use value bound to one exact live database handle.
pub struct PrivateDatabaseWitness<T> {
    database: Weak<Database>,
    value: T,
}

impl<T: fmt::Debug> fmt::Debug for PrivateDatabaseWitness<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateDatabaseWitness")
            .field("producer_live", &self.database.strong_count().gt(&0))
            .field("value", &self.value)
            .finish()
    }
}

impl<T> PrivateDatabaseWitness<T> {
    pub fn bind(database: &Arc<Database>, value: T) -> Self {
        Self {
            database: Arc::downgrade(database),
            value,
        }
    }

    pub fn authorize(self, database: &Arc<Database>) -> Result<T, PrivateDatabaseWitnessError> {
        let producer = self
            .database
            .upgrade()
            .ok_or(PrivateDatabaseWitnessError::ProducerClosed)?;
        if !Arc::ptr_eq(&producer, database) {
            return Err(PrivateDatabaseWitnessError::DatabaseMismatch);
        }
        Ok(self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_authorizes_only_its_exact_live_database() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let producer = Arc::new(
            Database::create(temporary.path().join("producer.redb")).expect("producer database"),
        );
        let substituted = Arc::new(
            Database::create(temporary.path().join("substituted.redb"))
                .expect("substituted database"),
        );

        let exact = PrivateDatabaseWitness::bind(&producer, "exact proof");
        assert_eq!(
            exact.authorize(&producer),
            Ok("exact proof"),
            "positive control: the producing live handle must receive its value"
        );

        let foreign = PrivateDatabaseWitness::bind(&producer, "foreign proof");
        assert_eq!(
            foreign.authorize(&substituted),
            Err(PrivateDatabaseWitnessError::DatabaseMismatch),
            "a substituted database must receive no authority"
        );

        let expired = PrivateDatabaseWitness::bind(&producer, "expired proof");
        drop(producer);
        assert_eq!(
            expired.authorize(&substituted),
            Err(PrivateDatabaseWitnessError::ProducerClosed),
            "a witness cannot resurrect authority after its producer closes"
        );
    }
}
