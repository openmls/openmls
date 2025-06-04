use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::*;

pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    MemberExists,
    MissingMember,
}

impl Default for Db {
    fn default() -> Self {
        Self::new("./group.db")
    }
}

impl Db {
    pub fn new(path: &str) -> Self {
        let conn = Connection::open(path).unwrap();

        // If the schema changes, the db must be deleted manually.
        let sql =
        "CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, cwk BLOB NOT NULL, signer BLOB NOT NULL, group_id BLOB NOT NULL, storage BLOB NOT NULL)";
        conn.execute(sql, ()).unwrap();

        Self {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    pub fn reset(&self) {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM groups", ())
            .unwrap();
    }

    pub fn write(&self, member: &Member) -> Result<(), Error> {
        let cwk = bitcode::serialize(&member.credential_with_key).unwrap();
        let signer = bitcode::serialize(&member.signer).unwrap();
        let group_id = bitcode::serialize(&member.group_id).unwrap();

        let mut group = vec![];
        member
            .provider
            .storage()
            .save_to_writer(&mut group)
            .unwrap();

        let sql = "REPLACE INTO groups (id, cwk, signer, group_id, storage) VALUES (?, ?, ?, ?, ?)";
        if self
            .conn
            .lock()
            .unwrap()
            .execute(sql, (member.id, &cwk, &signer, &group_id, &group))
            .is_err()
        {
            return Err(Error::MemberExists);
        }

        Ok(())
    }

    pub fn read(&self, id: u64) -> Result<Member, Error> {
        let sql = "SELECT cwk, signer, group_id, storage FROM groups WHERE id = ?";
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(sql).unwrap();

        let result = stmt.query_map([id], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            let credential_with_key: CredentialWithKey = bitcode::deserialize(&bytes).unwrap();

            let bytes: Vec<u8> = row.get(1)?;
            let signer: SignatureKeyPair = bitcode::deserialize(&bytes).unwrap();

            let bytes: Vec<u8> = row.get(2)?;
            let group_id: Option<GroupId> = bitcode::deserialize(&bytes).unwrap();

            let bytes: Vec<u8> = row.get(3)?;
            let mut provider = Provider::default();
            provider
                .storage_mut()
                .load_from_reader(&mut bytes.as_slice())
                .unwrap();

            Ok(Member {
                id,
                provider,
                credential_with_key,
                signer,
                group_id,
            })
        });

        let result = result
            .unwrap()
            .next() // Take the first entry
            .unwrap()
            .map_err(|_| Error::MissingMember);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_test() {
        let db = Db::default();
        db.reset(); // reset to ensure that nothing is in the database.

        let (member, _) = Member::new(1);
        db.write(&member).unwrap();
        let (member5, _) = Member::new(5);
        db.write(&member5).unwrap();

        let result_member = db.read(1).unwrap();
        assert_eq!(result_member.id, 1);
        assert_eq!(
            result_member.credential_with_key.credential,
            member.credential_with_key.credential
        );

        let result_member = db.read(5).unwrap();
        assert_eq!(result_member.id, 5);
        assert_eq!(
            result_member.credential_with_key.credential,
            member5.credential_with_key.credential
        );
    }
}
