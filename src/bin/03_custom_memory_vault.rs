use jwtvault::prelude::*;
use std::collections::HashMap;
use rand::Rng;
use rand;
use std::ops::{Deref, DerefMut};
use jwtvault::plugins::hashers::default::MemoryHasher;

fn main() {
    let mut users = HashMap::new();

    // User: John Doe
    let user_john = "John Doe";
    let password_for_john = "john";

    // User: Jane Doe
    let user_jane = "Jane Doe";
    let password_for_jane = "jane";

    // load users and their password from database/somewhere
    users.insert(user_john.to_string(), password_for_john.to_string());
    users.insert(user_jane.to_string(), password_for_jane.to_string());

    // Initialized the vault
    let mut vault = MyVault(MemoryVault::new(users, MemoryHasher::default()));

    // John needs to login now
    let token = vault.login(
        user_john,
        password_for_john,
        None,
        None,
    ).ok().unwrap().unwrap();

    // When John presents authentication token it can be used to restore session info
    let server_refresh_token = vault.resolve_server_token_from_client_authentication_token(user_john.as_bytes(), token.authentication_token()).ok().unwrap();

    // private_info_about_john (variable) contains John's private session information
    // which never leaves the server
    let private_info_about_john = server_refresh_token.server().unwrap();


    // server_refresh_token (variable) contains client which captures client data
    let data_from_server_side = server_refresh_token.client().unwrap();

    println!(" [Public] John Info: {}", String::from_utf8_lossy(data_from_server_side.as_slice()).to_string());
    println!("[Private] John Info: {}", String::from_utf8_lossy(private_info_about_john.as_slice()).to_string());

    // client_authentication_token (variable) contains buffer which captures client data
    let client_authentication_token = decode_client_token(vault.key_pairs().public_authentication_certificate(), token.authentication_token()).ok().unwrap();
    let data_from_client_side = client_authentication_token.buffer().unwrap();

    // Validate data on server is same a data on client
    assert_eq!(data_from_server_side, data_from_client_side);

    // lets renew authentication token
    let new_token = vault.renew(
        user_john.as_bytes(),
        token.refresh_token(),
        None,
    ).ok().unwrap();

    // When John presents new authentication token it can be used to restore session info
    let new_server_refresh_token = vault.resolve_server_token_from_client_authentication_token(
        user_john.as_bytes(), new_token.as_str(),
    ).ok().unwrap();

    // Validate data for the client did not change post refresh
    assert_eq!(new_server_refresh_token.client().unwrap(), server_refresh_token.client().unwrap());
}


// Define a new type
// https://doc.rust-lang.org/1.0.0/style/features/types/newtype.html

struct MyVault(MemoryVault<MemoryHasher>);

/// Implementation
impl UserAuthentication for MyVault {
    /// Return normally if login succeeds else return an Error
    fn check_user_valid<T: AsRef<[u8]>>(&mut self, user: T, pass: T) -> Result<Option<Session>, Error> {
        let user = String::from_utf8(user.as_ref().to_vec())?;
        // load password from in memory or some remote location/database
        let password = self.user_passwords().get(&user);
        if password.is_none() {
            return Err(MissingPassword(user, "No password".to_string()).into());
        };
        let password = password.unwrap().as_bytes();
        if password != pass.as_ref() {
            return Err(InvalidPassword(user, "Password does not match".to_string()).into());
        };

        let mut rng = rand::thread_rng();

        // Generate some session information

        // value of 'client' variable will stored on client JWT and send back to client
        let client = Some(format!("ClientSide Public Info: {}", rng.gen_range(1, 1000)).into_bytes());
        // value of 'server' variable will stored on server JWT and will be retained on server
        let server = Some(format!("ServerSide Private Info: {}", rng.gen_range(1000, 100000)).into_bytes());

        let session = Session::new(client, server);

        Ok(Some(session))
    }
}

// Boilerplate code
impl Deref for MyVault {
    type Target = MemoryVault<MemoryHasher>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Boilerplate code
impl DerefMut for MyVault {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
