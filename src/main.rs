use actix_web::{web, App, HttpServer, HttpResponse, Responder};
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::sync::Mutex;
use serde_json::Value;

struct AppState {
    received_data: Mutex<Vec<String>>,
}

async fn receive_data(data: web::Json<Value>, state: web::Data<AppState>) -> impl Responder {
    let mut received_data = state.received_data.lock().unwrap();
    received_data.push(data.to_string());
    println!("Received data: {}", data);
    HttpResponse::Ok().body("Data received")
}

async fn view_data(state: web::Data<AppState>) -> impl Responder {
    let received_data = state.received_data.lock().unwrap();
    let data = received_data.join("\n");
    HttpResponse::Ok().body(data)
}

fn load_ssl_config() -> ServerConfig {
    // Load SSL certificate
    let cert_file = &mut BufReader::new(File::open("/etc/filebeat/certs/wazuh-server.pem").unwrap());
    let key_file = &mut BufReader::new(File::open("/etc/filebeat/certs/wazuh-server-key.pem").unwrap());
    
    let cert_chain = certs(cert_file)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .unwrap()
        .into_iter()
        .map(PrivateKey)
        .collect();

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_state = web::Data::new(AppState {
        received_data: Mutex::new(Vec::new()),
    });

    let ssl_config = load_ssl_config();

    println!("Starting secure server at https://0.0.0.0:9200");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .route("/", web::post().to(receive_data))
            .route("/view", web::get().to(view_data))
    })
    .bind_rustls("0.0.0.0:9200", ssl_config)?
    .run()
    .await
}


