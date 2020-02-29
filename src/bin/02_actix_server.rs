use std::sync::Mutex;
use actix_web::{get, App, web, HttpServer, Responder};
use actix_http::{Response, body::Body, error::ErrorBadRequest};
use std::ops::DerefMut;

use jwtvault::prelude::*;

use std::collections::HashMap;


#[get("/")]
async fn index() -> impl Responder {
    format!("Hello JWT!!!")
}


struct ServerVault {
    vault: Mutex<DefaultVault>
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
    let uri = "127.0.0.1:8080";

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
    users.insert(user_john.to_string(), hashed_password_for_john);
    users.insert(user_jane.to_string(), hashed_password_for_jane);


    // Initialize vault
    let vault = DefaultVault::new(loader, users, false);
    let vault = ServerVault { vault: Mutex::new(vault) };
    let vault = web::Data::new(vault);


    let server = HttpServer::new(move || {
        App::new()
            .app_data(vault.clone())
            .service(index)
            .service(login)
            .service(execute)
            .service(renew)
            .service(logout)
    });

    println!("Running Server: {}", uri);

    println!("01 - Login: http://{}/login/<userid>/<password>", uri);
    println!("02 - Execute: http://{}/execute/<userid>/<authentication_token>", uri);
    println!("03 - Renew: http://{}/renew/<userid>/<refresh_token>", uri);
    println!("04 - Logout: http://{}/logout/<userid>/<authentication_token>", uri);

    server.bind(uri)?.workers(1).run().await
}

