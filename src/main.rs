use std::collections::HashMap;

use crate::ape::structs::{DenieablePerms, PermissionLevel, TokenPermissions, UserAttributes};

pub mod ape;

fn main() {
    let data = UserAttributes {
        global_admin: false,
        service_account: false,
        projects: HashMap::from([
            (diesel_ulid::DieselUlid::generate(), PermissionLevel::READ),
            (diesel_ulid::DieselUlid::generate(), PermissionLevel::WRITE),
        ]),
        collections: DenieablePerms {
            allow: HashMap::from([
                (diesel_ulid::DieselUlid::generate(), PermissionLevel::READ),
                (diesel_ulid::DieselUlid::generate(), PermissionLevel::WRITE),
            ]),
            deny: vec![diesel_ulid::DieselUlid::generate()],
        },
        objects: DenieablePerms {
            allow: HashMap::from([
                (diesel_ulid::DieselUlid::generate(), PermissionLevel::READ),
                (diesel_ulid::DieselUlid::generate(), PermissionLevel::WRITE),
            ]),
            deny: vec![diesel_ulid::DieselUlid::generate()],
        },
        tokens: HashMap::from([(
            diesel_ulid::DieselUlid::generate(),
            TokenPermissions::Personal,
        )]),
    };

    // Serialize it to a JSON string.
    let j = serde_json::to_string(&data).unwrap();

    // Print, write to a file, or send to an HTTP server.
    println!("{}", j);
}
