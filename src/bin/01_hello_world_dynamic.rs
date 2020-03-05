use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;

use jwtvault::prelude::*;

fn main() {
    let hasher = ArgonPasswordHasher::default();
    // User: John Doe
    let user_john = "john_doe";
    let password_for_john = "john";
    // Save value 'hashed_password_for_john' to persistent storage
    // This is more relevant during user signup/password reset
    let hashed_password_for_john = hasher.hash_user_password(user_john, password_for_john).unwrap();

    // User: Jane Doe
    let user_jane = "jane_doe";
    let password_for_jane = "jane";
    // Save 'hashed_password_for_jane' to persistent storage
    // This is more relevant during user signup/password reset
    let hashed_password_for_jane = hasher.hash_user_password(user_jane, password_for_jane).unwrap();

    let mut users = HashMap::new();

    // load users and their password from database/somewhere
    users.insert(user_john.to_string(), hashed_password_for_john.to_string());
    users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

    // Setup app users
    let login = LoginInfo::new(users);

     // Initialize vault
    let mut vault = DynamicVault::default(Box::new(login));

    // John needs to login now
    let token = block_on(vault.login(
        user_john,
        password_for_john,
        None,
        None,
    ));
    let token = token.ok().unwrap();
    // When John presents authentication token, it can be used to restore John's session info
    let server_refresh_token = block_on(resolve_session_from_client_authentication_token(
        &mut vault,
        user_john,
        token.authentication(),
    ));
    let server_refresh_token = server_refresh_token.ok().unwrap();

    // server_refresh_token (variable) contains server method which captures client private info
    // which never leaves the server
    let private_info_about_john = server_refresh_token.server().unwrap();
    let key = digest::<_, DefaultHasher>(user_john);
    let data_on_server_side = private_info_about_john.get(&key).unwrap();

    // server_refresh_token (variable) contains client method which captures client public info
    // which is also send back to client
    assert!(server_refresh_token.client().is_none());

    // Check out the data on client and server which are public and private respectively
    println!("[Private] John Info: {}",
             String::from_utf8_lossy(data_on_server_side.as_slice()).to_string());

    // lets renew authentication token
    let new_token = block_on(vault.renew(
        user_john,
        token.refresh(),
        None,
    ));
    let new_token = new_token.ok().unwrap();

    // When John presents new authentication token it can be used to restore session info
    let result = block_on(resolve_session_from_client_authentication_token(
        &mut vault,
        user_john,
        new_token.as_str(),
    ));
    let _ = result.ok().unwrap();
}