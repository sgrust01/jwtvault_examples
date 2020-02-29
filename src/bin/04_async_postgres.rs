use failure::Error;
use jwtvault::prelude::*;
use jwtvault_examples::database::setup::signup_user;

fn signup_app_users() {

    let loader = CertificateManger::default();
    let private_key = loader.password_hashing_secret();
    let secret_key = private_key.as_str();

    // User: John Doe
    let user_john = "john_doe";
    let password_for_john = "john";

    let hashed_password_for_john = hash_password_with_argon(
        password_for_john,
        secret_key,
    ).unwrap();
    let result = signup_user::<&str>(&user_john, &hashed_password_for_john);
    if let Err(e) = result {
        let reason = e.to_string();
        eprintln!("Signup failed for user: {} Reason: {}", user_john, reason);
    };

    // User: Jane Doe
    let user_jane = "jane_doe";
    let password_for_jane = "jane";

    let hashed_password_for_jane = hash_password_with_argon(
        password_for_jane,
        loader.password_hashing_secret().as_str(),
    ).unwrap();
    let result = signup_user::<&str>(&user_jane, &hashed_password_for_jane);
    if let Err(e) = result {
        let reason = e.to_string();
        eprintln!("Signup failed for user: {} Reason: {}", user_jane, reason);
    };
}



fn main() {
    dotenv::dotenv().ok();
    signup_app_users()
}