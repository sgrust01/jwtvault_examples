use std::sync::Mutex;
use std::ops::DerefMut;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;

use actix_web::{get, App, web, HttpServer, Responder};
use actix_http::{Response, body::Body, error::ErrorBadRequest};

use postgres::NoTls;
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;

use jwtvault::prelude::*;
use jwtvault_examples::database::setup::connection;
use jwtvault::errors::LoginFailed::PasswordHashingFailed;


#[derive(Debug, Clone)]
pub struct WebVault {
    public_authentication_certificate: PublicKey,
    private_authentication_certificate: PrivateKey,
    public_refresh_certificate: PublicKey,
    private_refresh_certificate: PrivateKey,
    password_hashing_secret: PrivateKey,
    store: HashMap<u64, String>,
    pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl PersistenceHasher<DefaultHasher> for WebVault {}

impl TrustToken for WebVault {
    fn trust_token_bearer(&self) -> bool {
        false
    }
}

impl PasswordHasher<ArgonHasher<'static>> for WebVault {
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


impl Store for WebVault {
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

    fn password_hashing_secret(&self) -> &PrivateKey {
        &self.password_hashing_secret
    }
}

impl WebVault {
    pub fn new<T: Keys>(loader: T, pool: Pool<PostgresConnectionManager<NoTls>>) -> Self {
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
            pool,
        }
    }
    async fn signup_app_user(&self, user: &str, password: &str) -> Result<String, Error> {
        let user_id = format!("{}", digest::<_, DefaultHasher>(user));
        let secret_key = self.password_hashing_secret.as_str();
        let password = hash_password_with_argon(
            password,
            secret_key,
        )?;
        let _ = signup_user::<&str>(self.pool.clone(), &user_id, &password).await?;
        Ok(user_id)
    }
}


#[async_trait]
impl Persistence for WebVault {
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
impl UserIdentity for WebVault {
    async fn check_same_user(&self, _: &str, _: &str) -> Result<(), Error> {
        // If the user was encrypted then it can be decrypted and compared
        Ok(())
    }
}

#[async_trait]
impl UserAuthentication for WebVault {
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error> {
        // lookup database instead of im-memory
        let password_from_disk = resolve_password_for_user::<&str>(self.pool.clone(), user).await?;
        // let password_from_disk = self.users.get(&user.to_string());
        if password_from_disk.is_none() {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };

        let password_from_disk = password_from_disk.unwrap();
        let result = verify_user_password_with_argon(password, self.password_hashing_secret.as_str(), password_from_disk.as_str())?;
        if !result {
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
impl Workflow<DefaultHasher, ArgonHasher<'static>> for WebVault {
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


impl Default for WebVault {
    fn default() -> Self {
        let pool = connection();
        if let Err(e) = pool {
            eprintln!("DB Connection failed Reason: {}", e.to_string());
        };
        let pool = connection().ok().unwrap();
        Self::new(CertificateManger::default(), pool)
    }
}

async fn signup_user<T: AsRef<str>>(pool: Pool<PostgresConnectionManager<NoTls>>, user: T, password: T) -> Result<(), Error> {
    let mut conn = pool.get()?;
    let user = user.as_ref();
    let password = password.as_ref();
    // Watch out for SQL Injection
    let query = format!("INSERT INTO tbl_users VALUES ('{}', '{}')", user, password);
    let _ = conn.execute(query.as_str(), &[])?;
    Ok(())
}

async fn resolve_password_for_user<T: AsRef<str>>(pool: Pool<PostgresConnectionManager<NoTls>>, user: T) -> Result<Option<String>, Error> {
    let mut conn = pool.get()?;
    let query = format!("SELECT user_password FROM tbl_users WHERE user_id = '{}' ", user.as_ref());
    let rs = conn.query(query.as_str(), &[])?;
    for row in rs {
        let rs: Option<String> = row.get(0);
        return Ok(rs);
    }
    return Ok(None);
}


struct ServerVault {
    vault: Mutex<WebVault>
}

#[get("/")]
async fn index() -> impl Responder {
    format!("WebServer for hosting JWTVault!!!")
}


#[get("/signup/{user}/{password}")]
async fn signup(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    println!("=== Signup ===");
    let user = &info.0;
    let password = &info.1;
    println!("user = {} password = {}", user, password);
    let manager = vault.vault.lock().unwrap();
    let result = manager.signup_app_user(user, password).await;
    if result.is_err() {
        return Response::from_error(ErrorBadRequest(result.err().unwrap()));
    };
    let result = result.ok().unwrap();

    let body = Body::from(
        result
    );

    let response = Response::Ok()
        .header("Content-Type", "application/json")
        .finish();

    response.set_body(body)
}

#[get("/login/{user}/{password}")]
async fn login(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    println!("=== Login ===");

    let mut manager = vault.vault.lock().unwrap();

    let user = &info.0;
    let password = &info.1;
    println!("user = {} password = {}", user, password);

    let token = manager.login(
        user.as_str(),
        password.as_str(),
        None,
        None,
    ).await;
    if token.is_err() {
        return Response::from_error(ErrorBadRequest(token.err().unwrap()));
    };
    let token = token.ok().unwrap();
    let token = serde_json::to_string(&token).unwrap();

    let body = Body::from(
        token
    );

    let response = Response::Ok()
        .header("Content-Type", "application/json")
        .finish();

    response.set_body(body)
}

#[get("/execute/{user}/{token}")]
async fn execute(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    println!("=== Execute ===");
    let mut engine = vault.vault.lock().unwrap();
    let vault = engine.deref_mut();

    let user = &info.0;
    let token = &info.1;

    let result = resolve_session_from_client_authentication_token(
        vault,
        user.as_str(), token.as_str(),
    ).await;

    if result.is_err() {
        let response = Response::Unauthorized()
            .header("content-type", "text/plain")
            .finish();
        return response;
    };
    let result = result.ok();

    if result.is_none() {
        let response = Response::NotAcceptable()
            .header("content-type", "text/plain")
            .finish();
        return response;
    };
    let session = result.unwrap();

    let client = session.client();
    let server = session.server();

    println!("Session for User: {} - Client: {:#?} Server: {:#?}", user, client, server.unwrap());

    // Prepare json for dispatch
    let body = Body::from(
        format!("{}", "Executed")
    );

    let response = Response::Ok()
        .header("Content-Type", "text/plain")
        .finish();
    response.set_body(body)
}

#[get("/renew/{user}/{token}")]
async fn renew(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    println!("=== Renew ===");
    let mut engine = vault.vault.lock().unwrap();
    let user = &info.0;
    let client_refresh_token = &info.1;

    let result = engine.renew(user.as_str(), &client_refresh_token, None).await;
    if result.is_err() {
        let response = Response::Unauthorized()
            .header("content-type", "text/plain")
            .finish();
        return response;
    };
    let client_authentication_token = result.ok().unwrap();

    println!("Renewed: {}", user);

    // Prepare json for dispatch
    let token = Token::new(client_authentication_token.clone(), client_refresh_token.clone());
    let token = serde_json::to_string(&token).unwrap();
    let body = Body::from(
        token
    );


    let response = Response::Ok()
        .header("Content-Type", "application/json")
        .finish();

    response.set_body(body)
}

#[get("/logout/{user}/{token}")]
async fn logout(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    println!("=== Logout ===");
    let mut engine = vault.vault.lock().unwrap();
    let user = &info.0;
    let client_authentication_token = &info.1;
    let result = engine.logout(user.as_str(), client_authentication_token).await;
    if result.is_err() {
        let response = Response::Unauthorized()
            .header("content-type", "text/plain")
            .finish();
        return response;
    };
    println!("Logout: {}", user);

    // Prepare json for dispatch
    let body = Body::from(
        format!("Logged out")
    );

    let response = Response::Ok()
        .header("Content-Type", "text/plain")
        .finish();

    response.set_body(body)
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let uri = "127.0.0.1:8080";

    let vault = Mutex::new(WebVault::default());
    let vault = ServerVault { vault };
    let vault = web::Data::new(vault);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(vault.clone())
            .service(index)
            .service(signup)
            .service(login)
            .service(execute)
            .service(renew)
            .service(logout)
    });

    println!("Running Server: {}", uri);

    println!("00 - Homepage: http://{}/", uri);
    println!("01 - Signup: http://{}/signup/<userid>/<password>", uri);
    println!("02 - Login: http://{}/login/<userid>/<password>", uri);
    println!("03 - Execute: http://{}/execute/<userid>/<authentication_token>", uri);
    println!("04 - Renew: http://{}/renew/<userid>/<refresh_token>", uri);
    println!("05 - Logout: http://{}/logout/<userid>/<authentication_token>", uri);

    server.bind(uri)?.workers(1).run().await
}

