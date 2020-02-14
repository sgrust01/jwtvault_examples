use std::ops::Deref;
use std::sync::Mutex;
use std::collections::HashMap;

use actix_web::{get, App, web, HttpServer, Responder};
use actix_http::{Response, body::Body};

use jwtvault::prelude::*;

#[get("/")]
async fn index() -> impl Responder {
    format!("Hello World!!!")
}


struct ServerVault {
    vault: Mutex<DefaultVault>
}

#[get("/login/{user}/{password}")]
async fn login(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    let mut engine = vault.vault.lock().unwrap();

    let user = &info.0;
    let password = &info.1;

    // Try login to the app
    let token = engine.login(
        user.as_bytes(),
        password.as_bytes(),
        None,
        None);

    // Check if a token has been generated
    if let Err(_) = token {
        let response = Response::Unauthorized()
            .header("content-type", "text/plain")
            .finish();
        return response;
    }
    let token = token.ok().unwrap();
    if token.is_none() {
        let response = Response::Forbidden()
            .header("content-type", "text/plain")
            .finish();
        return response;
    };

    let token = token.unwrap();

    println!("Login User: {}", user);

    // Prepare json for dispatch
    let body = Body::from(
        format!("{{ \"auth\": \"{}\", \"ref\": \"{}\" }}", token.authentication_token().deref(), token.refresh_token().deref())
    );

    let response = Response::Ok()
        .header("Content-Type", "application/json")
        .finish();


    response.set_body(body)
}


#[get("/execute/{user}/{token}")]
async fn execute(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    let engine = vault.vault.lock().unwrap();

    let user = &info.0;
    let token = &info.1;

    let result = engine.resolve_server_token_from_client_authentication_token(user.as_bytes(), token.as_str());

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

    let client = String::from_utf8_lossy(session.client().unwrap().as_slice()).to_string();
    let server = String::from_utf8_lossy(session.server().unwrap().as_slice()).to_string();

    println!("Execution by User: {} - {} {}", user, client, server);

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
    let mut engine = vault.vault.lock().unwrap();
    let user = &info.0;
    let client_refresh_token = &info.1;

    let result = engine.renew(user.as_bytes(), &client_refresh_token, None);
    if result.is_err() {
        let response = Response::Unauthorized()
            .header("content-type", "text/plain")
            .finish();
        return response;
    };
    let client_authentication_token = result.ok().unwrap();

    println!("Renewed: {}", user);

    // Prepare json for dispatch
    let body = Body::from(
        format!("{{ \"auth\": \"{}\", \"ref\": \"{}\" }}", client_authentication_token, client_refresh_token)
    );

    let response = Response::Ok()
        .header("Content-Type", "application/json")
        .finish();

    response.set_body(body)
}

#[get("/logout/{user}/{token}")]
async fn logout(info: web::Path<(String, String)>, vault: web::Data<ServerVault>) -> Response {
    let mut engine = vault.vault.lock().unwrap();
    let user = &info.0;
    let client_authentication_token = &info.1;
    let result = engine.logout(user.as_bytes(), client_authentication_token);
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

    // User: John Doe
    let user_john = "john_doe";
    let password_for_john = "john";

    // User: Jane Doe
    let user_jane = "jane_doe";
    let password_for_jane = "jane";

    // load users and their password from database/somewhere
    users.insert(user_john.to_string(), password_for_john.to_string());
    users.insert(user_jane.to_string(), password_for_jane.to_string());

    // Initialize vault
    let vault = DefaultVault::new(users);
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

