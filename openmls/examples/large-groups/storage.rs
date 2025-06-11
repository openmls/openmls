use std::{
    io::{Read, Write},
    os::unix::fs::FileExt,
    path::Path,
    sync::{Arc, Mutex},
};

use rusqlite::Connection;

use crate::*;

pub struct Db {
    // conn: Arc<Mutex<Connection>>,
}

const FOLDER: &str = "benches/members";

#[derive(Debug, Clone, Copy)]
pub enum Error {
    MemberExists,
    MissingMember,
}

impl Default for Db {
    fn default() -> Self {
        // Self::new("./group.db")
        Self {}
    }
}

impl Db {
    // pub fn new(path: &str) -> Self {
    //     let conn = Connection::open(path).unwrap();

    //     // If the schema changes, the db must be deleted manually.
    //     let sql =
    //     "CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, cwk BLOB NOT NULL, signer BLOB NOT NULL, group_id BLOB NOT NULL, storage BLOB NOT NULL)";
    //     conn.execute(sql, ()).unwrap();

    //     Self {
    //         conn: Arc::new(Mutex::new(conn)),
    //     }
    // }

    pub fn reset(&self) {
        // self.conn
        //     .lock()
        //     .unwrap()
        //     .execute("DELETE FROM groups", ())
        //     .unwrap();
    }

    pub fn write(&self, member: &Member) -> Result<(), Error> {
        let cwk = bitcode::serialize(&member.credential_with_key).unwrap();
        let signer = bitcode::serialize(&member.signer).unwrap();
        let group_id = bitcode::serialize(&member.group_id).unwrap();

        let mut group = vec![];
        member
            .provider
            .storage()
            .save_to_binary_writer(&mut group)
            .unwrap();
        let group = bitcode::serialize(&group).unwrap();

        // Always override existing file.
        let mut file = File::create(file_name(member.id)).unwrap();
        file.write_all(&(cwk.len() as u64).to_be_bytes()).unwrap();
        file.write_all(&cwk).unwrap();
        file.write_all(&(signer.len() as u64).to_be_bytes())
            .unwrap();
        file.write_all(&signer).unwrap();
        file.write_all(&(group_id.len() as u64).to_be_bytes())
            .unwrap();
        file.write_all(&group_id).unwrap();
        file.write_all(&(group.len() as u64).to_be_bytes()).unwrap();
        file.write_all(&group).unwrap();

        // let sql = "REPLACE INTO groups (id, cwk, signer, group_id, storage) VALUES (?, ?, ?, ?, ?)";
        // if self
        //     .conn
        //     .lock()
        //     .unwrap()
        //     .execute(sql, (member.id, &cwk, &signer, &group_id, &group))
        //     .is_err()
        // {
        //     return Err(Error::MemberExists);
        // }

        Ok(())
    }

    pub fn read(&self, id: u64) -> Result<Member, Error> {
        let file = File::open(file_name(id)).unwrap();

        let mut offset = 0;

        let credential_with_key: CredentialWithKey = read_value(&file, &mut offset);
        let signer: SignatureKeyPair = read_value(&file, &mut offset);
        let group_id: Option<GroupId> = read_value(&file, &mut offset);

        let mut provider = Provider::default();
        let group_bytes: Vec<u8> = read_value(&file, &mut offset);
        provider
            .storage_mut()
            .load_from_reader(&mut group_bytes.as_slice())
            .unwrap();

        Ok(Member {
            id,
            provider,
            credential_with_key,
            signer,
            group_id,
        })

        // let sql = "SELECT cwk, signer, group_id, storage FROM groups WHERE id = ?";
        // let conn = self.conn.lock().unwrap();
        // let mut stmt = conn.prepare(sql).unwrap();

        // let result = stmt.query_map([id], |row| {
        //     let bytes: Vec<u8> = row.get(0)?;
        //     let credential_with_key: CredentialWithKey = bitcode::deserialize(&bytes).unwrap();

        //     let bytes: Vec<u8> = row.get(1)?;
        //     let signer: SignatureKeyPair = bitcode::deserialize(&bytes).unwrap();

        //     let bytes: Vec<u8> = row.get(2)?;
        //     let group_id: Option<GroupId> = bitcode::deserialize(&bytes).unwrap();

        //     let bytes: Vec<u8> = row.get(3)?;
        //     let bytes: Vec<u8> = bitcode::deserialize(&bytes).unwrap();
        //     let mut provider = Provider::default();
        // provider
        //     .storage_mut()
        //     .load_from_reader(&mut bytes.as_slice())
        //     .unwrap();

        //     Ok(Member {
        //         id,
        //         provider,
        //         credential_with_key,
        //         signer,
        //         group_id,
        //     })
        // });

        // let result = result
        //     .unwrap()
        //     .next() // Take the first entry
        //     .unwrap()
        //     .map_err(|_| Error::MissingMember);

        // result
    }
}

fn read_value<T>(file: &File, offset: &mut u64) -> T
where
    T: for<'a> Deserialize<'a> + Clone,
{
    // Read length
    let mut bytes = vec![0u8; 8];
    file.read_exact_at(&mut bytes, *offset).unwrap();
    let len = u64::from_be_bytes(bytes.try_into().unwrap());
    *offset += 8;

    // Read value
    let mut bytes = vec![0u8; len as usize];
    file.read_exact_at(&mut bytes, *offset).unwrap();
    *offset += len;

    bitcode::deserialize::<T>(&bytes).unwrap()
}

fn file_name(id: u64) -> std::path::PathBuf {
    Path::new(FOLDER).join(format!("member{}", id))
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
