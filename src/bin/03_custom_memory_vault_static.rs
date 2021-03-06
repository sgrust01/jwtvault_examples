use jwtvault::prelude::*;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use jwtvault::errors::LoginFailed::PasswordHashingFailed;


fn main() {
    let mut users = HashMap::new();

    let loader = CertificateManger::default();

    // User: John Doe
    let user_john = "john_doe";
    let password_for_john = "john";

    // This should ideally be pre-computed during user sign-up/password reset/change password
    let hashed_password_for_john = hash_password_with_argon(
        password_for_john,
        loader.password_hashing_secret().as_str(),
    ).unwrap();

    // User: Jane Doe
    let user_jane = "jane_doe";
    let password_for_jane = "jane";

    // This should ideally be pre-computed during user sign-up/password reset/change password
    let hashed_password_for_jane = hash_password_with_argon(
        password_for_jane,
        loader.password_hashing_secret().as_str(),
    ).unwrap();

    // load users and their (argon hashed) password from database/somewhere
    users.insert(user_john.to_string(), hashed_password_for_john.to_string());
    users.insert(user_jane.to_string(), hashed_password_for_jane.to_string());

    // Initialize vault
    let mut vault = MyVault::new(loader, users);

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


#[derive(Debug, Clone, PartialEq)]
pub struct MyVault {
    public_authentication_certificate: PublicKey,
    private_authentication_certificate: PrivateKey,
    public_refresh_certificate: PublicKey,
    private_refresh_certificate: PrivateKey,
    password_hashing_secret: PrivateKey,
    store: HashMap<u64, String>,
    users: HashMap<String, String>,

}

impl PersistenceHasher<DefaultHasher> for MyVault {}

impl TrustToken for MyVault {
    fn trust_token_bearer(&self) -> bool {
        false
    }
}

impl PasswordHasher<ArgonHasher<'static>> for MyVault {
    fn hash_user_password<T: AsRef<str>>(&self, user: T, password: T) -> Result<String, Error> {
        let secret_key = self.password_hashing_secret.as_str();
        hash_password_with_argon::<&str>(password.as_ref(), secret_key).map_err(|e| {
            PasswordHashingFailed(user.as_ref().to_string(), e.to_string()).into()
        })
    }

    fn verify_user_password<T: AsRef<str>>(&self, user: T, password: T, hash: T) -> Result<bool, Error> {
        let secret_key = self.password_hashing_secret.as_str();
        verify_user_password_with_argon::<&str>(password.as_ref(), secret_key, hash.as_ref()).map_err(|e| {
            PasswordHashingFailed(user.as_ref().to_string(), e.to_string()).into()
        })
    }
}


impl Store for MyVault {
    fn public_authentication_certificate(&self) -> &PublicKey {
        &self.public_authentication_certificate
    }

    fn private_authentication_certificate(&self) -> &PrivateKey {
        &self.private_authentication_certificate
    }

    fn public_refresh_certificate(&self) -> &PublicKey {
        &self.public_refresh_certificate
    }

    fn private_refresh_certificate(&self) -> &PrivateKey {
        &self.private_refresh_certificate
    }

}

impl MyVault {
    pub fn new<T: Keys>(loader: T, users: HashMap<String, String>) -> Self {
        let public_authentication_certificate = loader.public_authentication_certificate().clone();
        let private_authentication_certificate = loader.private_authentication_certificate().clone();
        let public_refresh_certificate = loader.public_refresh_certificate().clone();
        let private_refresh_certificate = loader.private_refresh_certificate().clone();
        let password_hashing_secret = loader.password_hashing_secret();
        let store = HashMap::new();

        Self {
            public_authentication_certificate,
            private_authentication_certificate,
            public_refresh_certificate,
            private_refresh_certificate,
            password_hashing_secret,
            store,
            users,
        }
    }
}


#[async_trait]
impl Persistence for MyVault {
    async fn store(&mut self, key: u64, value: String) {
        self.store.insert(key, value);
    }

    async fn load(&self, key: u64) -> Option<&String> {
        self.store.get(&key)
    }

    async fn remove(&mut self, key: u64) -> Option<String> {
        self.store.remove(&key)
    }
}

#[async_trait]
impl UserIdentity for MyVault {
    async fn check_same_user(&self, user: &str, user_from_token: &str) -> Result<(), Error> {
        if user != user_from_token {
            let msg = "Login Failed".to_string();
            let reason = "Invalid token".to_string();
            return Err(LoginFailed::InvalidTokenOwner(msg, reason).into());
        }
        Ok(())
    }
}

#[async_trait]
impl UserAuthentication for MyVault {
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error> {
        let password_from_disk = self.users.get(&user.to_string());
        if password_from_disk.is_none() {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };

        let password_from_disk = password_from_disk.unwrap();
        let result = verify_user_password_with_argon(password, self.password_hashing_secret.as_str(), password_from_disk)?;
        if ! result {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };
        let reference = digest::<_, DefaultHasher>(user.as_bytes());
        let mut server = HashMap::new();
        server.insert(reference, user.clone().as_bytes().to_vec());
        let session = Session::new(None, Some(server));
        Ok(Some(session))
    }
}


#[async_trait]
impl Workflow<DefaultHasher, ArgonHasher<'static>> for MyVault {
    async fn login(&mut self, user: &str, pass: &str, authentication_token_expiry_in_seconds: Option<i64>, refresh_token_expiry_in_seconds: Option<i64>) -> Result<Token, Error> {
        continue_login(self, user, pass, authentication_token_expiry_in_seconds, refresh_token_expiry_in_seconds).await
    }

    async fn renew(&mut self, user: &str, client_refresh_token: &String, authentication_token_expiry_in_seconds: Option<i64>) -> Result<String, Error> {
        continue_renew(self, user, client_refresh_token, authentication_token_expiry_in_seconds).await
    }

    async fn logout(&mut self, user: &str, client_authentication_token: &String) -> Result<(), Error> {
        continue_logout(self, user, client_authentication_token).await
    }

    async fn revoke(&mut self, client_refresh_token: &String) -> Result<(), Error> {
        continue_revoke(self, client_refresh_token).await
    }
}
