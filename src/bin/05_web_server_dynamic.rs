use std::ops::DerefMut;

use postgres::NoTls;
use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;

use actix_web::{get, App, web, HttpServer, Responder};
use actix_http::{Response, body::Body, error::ErrorBadRequest};

use jwtvault::prelude::*;

use jwtvault_examples::database::setup::connection;
use jwtvault_examples::database::users_setup::{resolve_password_for_user, signup_user};
use std::sync::Mutex;
use std::collections::hash_map::DefaultHasher;

struct WebDynamicVault {
    pool: Pool<PostgresConnectionManager<NoTls>>,
    hasher: ArgonPasswordHasher,
}


impl Default for WebDynamicVault {
    fn default() -> Self {
        let pool = connection().ok().unwrap();
        let hasher = ArgonPasswordHasher::default();
        WebDynamicVault { pool, hasher }
    }
}

#[async_trait]
impl UserAuthentication for WebDynamicVault {
    async fn check_user_valid(&mut self, user: &str, password: &str) -> Result<Option<Session>, Error> {
        let password_from_disk = resolve_password_for_user(self.pool.clone(), user).await?;

        if password_from_disk.is_none() {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };
        let password_from_disk = password_from_disk.unwrap();
        let hash = password_from_disk.as_str();
        let result = self.hasher.verify_user_password(user, password, hash)?;
        if !result {
            let msg = "Login Failed".to_string();
            let reason = "Invalid userid/password".to_string();
            return Err(LoginFailed::InvalidPassword(msg, reason).into());
        };
        let session: Option<Session> = None;
        Ok(session)
    }
}

struct ServerVault {
    vault: Mutex<DynamicVault>,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    hasher: ArgonPasswordHasher,
}

impl Default for ServerVault {
    fn default() -> Self {
        let vault = Mutex::new(
            DynamicVault::default(Box::new(WebDynamicVault::default()))
        );
        let pool = connection().ok().unwrap();
        let hasher = ArgonPasswordHasher::default();
        Self {
            vault,
            pool,
            hasher,

        }
    }
}


impl ServerVault {
    async fn signup_app_user(&self, user: &str, password: &str) -> Result<String, Error> {
        let user_id = format!("{}", digest::<_, DefaultHasher>(user));
        let password = self.hasher.hash_user_password(
            user,
            password,
        )?;
        let _ = signup_user::<&str>(self.pool.clone(), &user_id, &password).await?;
        Ok(user_id)
    }
}

#[get("/")]
async fn index() -> impl Responder {
    format!("WebServer (dynamic) for hosting JWTVault!!!")
}

#[get("/signup/{user}/{password}")]
async fn signup(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    println!("=== Signup ===");
    let user = &info.0;
    let password = &info.1;
    println!("user = {} password = {}", user, password);

    let result = vault.signup_app_user(user, password).await;
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
    let vault = manager.deref_mut();

    let user = &info.0;
    let password = &info.1;
    println!("user = {} password = {}", user, password);

    let token = vault.login(
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

    println!("Session for User: {} - Client: {:#?} Server: {:#?}", user, client, server);

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
    let vault = ServerVault::default();
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

    println!("[Web server - Dynamic] Running Server: {}", uri);

    println!("00 - Homepage: http://{}/", uri);
    println!("01 - Signup: http://{}/signup/<userid>/<password>", uri);
    println!("02 - Login: http://{}/login/<userid>/<password>", uri);
    println!("03 - Execute: http://{}/execute/<userid>/<authentication_token>", uri);
    println!("04 - Renew: http://{}/renew/<userid>/<refresh_token>", uri);
    println!("05 - Logout: http://{}/logout/<userid>/<authentication_token>", uri);

    server.bind(uri)?.workers(1).run().await
}