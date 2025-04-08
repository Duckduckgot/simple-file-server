use actix_multipart::Multipart;
use std::ops::Deref;
use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::Mutex;
use std::io::SeekFrom;
use tokio::io::{AsyncSeekExt, AsyncReadExt, AsyncWriteExt};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use hex;
use lazy_static::lazy_static;
use actix_web::{delete, get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder, http::header};
use futures::{StreamExt, TryStreamExt};
use sanitize_filename::sanitize;
use tokio::{fs::{File, OpenOptions}};
use std::fs;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{engine::general_purpose, Engine as _};
use tokio_util::io::ReaderStream;
use clap::{Command, arg};
use rustls::{ServerConfig, Certificate};
use rustls_pemfile::{certs, rsa_private_keys, pkcs8_private_keys, ec_private_keys};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use mime_guess::from_path;

const SECRET_KEY: &[u8] = b"kali_berd_kepsee_2025";
const FILE_DIR: &str = "/files";

lazy_static! {
    static ref SHORTLINKS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

fn sanitize_filename(input: String) -> String {
    input.replace("../", "").replace("/", "")
}

fn generate_token(filename: &str, expires: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(SECRET_KEY).unwrap();
    mac.update(filename.as_bytes());
    mac.update(expires.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn is_token_valid(req: &HttpRequest, filename: &str) -> bool {
    let query = req.uri().query().unwrap_or("");
    let params: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();

    let token = match params.get("token") {
        Some(t) => t,
        None => return false,
    };

    let expires = match params.get("expires") {
        Some(e) => match e.parse::<u64>() {
            Ok(val) => val,
            Err(_) => return false,
        },
        None => return false,
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if now > expires {
        return false;
    }

    let expected = generate_token(filename, expires);
    &expected == token
}

fn parse_range_header(header_value: &str, file_size: u64) -> Option<(u64, u64)> {
    if header_value.starts_with("bytes=") {
        let range = header_value.trim_start_matches("bytes=");
        if let Some((start, end)) = range.split_once('-') {
            let start: u64 = start.parse().ok()?;
            let end: u64 = end.parse().ok().unwrap_or(file_size - 1);
            if start <= end && end < file_size {
                return Some((start, end));
            }
        }
    }
    None
}

#[get("/download-range/{filename:.*}")]
async fn download_range(path: web::Path<String>, req: HttpRequest) -> impl Responder {
    let filename = sanitize_filename(path.into_inner());

    if !is_token_valid(&req, &filename) {
        return HttpResponse::Unauthorized().body("Invalid or expired token");
    }

    let file_path = PathBuf::from(FILE_DIR).join(&filename);

    if !file_path.exists() {
        return HttpResponse::NotFound().body("File not found");
    }

    let mut file = match File::open(&file_path).await {
        Ok(f) => f,
        Err(_) => return HttpResponse::InternalServerError().body("Could not read file"),
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => return HttpResponse::InternalServerError().body("Could not read metadata"),
    };

    let file_size = metadata.len();
    let content_type = from_path(&file_path).first_or_octet_stream();
    let range_header = req.headers().get("Range");

    if let Some(range_header) = range_header {
        if let Ok(range_str) = range_header.to_str() {
            if let Some((start, end)) = parse_range_header(range_str, file_size) {
                if file.seek(SeekFrom::Start(start)).await.is_err() {
                    return HttpResponse::InternalServerError().body("Seek failed");
                }

                let chunk_size = end - start + 1;
                let stream = ReaderStream::new(file.take(chunk_size));

                return HttpResponse::PartialContent()
                    .append_header(("Content-Type", content_type.to_string()))
                    .append_header(("Content-Range", format!("bytes {}-{}/{}", start, end, file_size)))
                    .append_header(("Accept-Ranges", "bytes"))
                    .streaming(stream);
            }
        }
    }

    let stream = ReaderStream::new(file);
    HttpResponse::Ok()
        .append_header(("Content-Type", content_type.to_string()))
        .append_header(("Accept-Ranges", "bytes"))
        .streaming(stream)
}

#[get("/generate-download-url/{filename:.*}")]
async fn generate_download_url(path: web::Path<String>, req: HttpRequest) -> impl Responder {
    let filename = sanitize_filename(path.into_inner());
    let default_ttl = 300;
    let max_ttl = 3600;

    let ttl = req.uri().query()
        .and_then(|q| {
            q.split('&')
                .find_map(|p| {
                    let (k, v) = p.split_once('=')?;
                    if k == "ttl" {
                        v.parse::<u64>().ok()
                    } else {
                        None
                    }
                })
        })
        .unwrap_or(default_ttl)
        .min(max_ttl);

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expires = now + ttl;
    let token = generate_token(&filename, expires);

    let short_id: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    let full_url = format!("/download-range/{}?token={}&expires={}", filename, token, expires);
    SHORTLINKS.lock().unwrap().insert(short_id.clone(), full_url);

    let conn_info = req.connection_info();
    let scheme = conn_info.scheme();
    let host = conn_info.host();
    let short_url = format!("{}://{}/dl/{}", scheme, host, short_id);

    HttpResponse::Ok()
        .append_header(("Content-Type", "application/json"))
        .body(format!(r#"{{"url":"{}"}}"#, short_url))
}

#[get("/dl/{short_id}")]
async fn redirect_short_link(short_id: web::Path<String>, req: HttpRequest) -> impl Responder {
    let id = short_id.into_inner();

    if let Some(full_url) = SHORTLINKS.lock().unwrap().get(&id) {
        let conn_info = req.connection_info();
        let scheme = conn_info.scheme();
        let host = conn_info.host();
        let redirect_url = format!("{}://{}{}", scheme, host, full_url);

        return HttpResponse::Found()
            .append_header(("Location", redirect_url))
            .finish();
    }

    HttpResponse::NotFound().body("Ссылка не найдена или устарела")
}

/// Handles file uploads to the server.
///
/// This function uses the `Multipart` request payload to process the uploaded file. It goes through each part
/// of the payload until there are no more parts left.
///
/// If a part is a file (determined by the presence of a filename in the part's content-disposition),
/// the function sanitizes the filename to prevent directory traversal attacks and other security issues.
/// It then checks if a file with the same name already exists on the server.
///
/// If the file does not exist, the function creates a new file and writes the uploaded data to it.
/// If the file does exist, the function returns a `Conflict` response and does not overwrite the existing file.
///
/// # Arguments
///
/// * `payload` - A mutable reference to a `Multipart` payload, which represents the uploaded file data.
///
/// # Returns
///
/// An `HttpResponse` which can be:
/// * `Ok` with a success message as the body if the file was successfully uploaded.
/// * `BadRequest` if the filename is invalid or empty.
/// * `Conflict` if a file with the same name already exists on the server.
#[post("/upload")]
async fn upload(mut payload: Multipart) -> impl Responder {
    let upload_dir = PathBuf::from(FILE_DIR);

    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_disposition = field.content_disposition();
        let filename = sanitize(content_disposition.get_filename().unwrap_or_default());

        if filename.is_empty() {
            return HttpResponse::BadRequest().body("Invalid filename");
        }

        let filepath = upload_dir.join(&filename);

        // Попытка создать файл только если он ещё не существует (без гонки)
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filepath)
            .await
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return HttpResponse::Conflict().body("File already exists");
            }
            Err(e) => {
                eprintln!("Failed to create file {}: {}", filepath.display(), e);
                return HttpResponse::InternalServerError().body("Could not create file");
            }
        };

        // Запись чанков
        while let Some(chunk) = field.next().await {
            match chunk {
                Ok(data) => {
                    if let Err(e) = file.write_all(&data).await {
                        eprintln!("Write error for file {}: {}", filepath.display(), e);
                        return HttpResponse::InternalServerError().body("Could not write to file");
                    }
                }
                Err(e) => {
                    eprintln!("Error reading multipart chunk: {}", e);
                    return HttpResponse::InternalServerError().body("Error reading upload data");
                }
            }
        }
    }

    HttpResponse::Ok().body("File uploaded successfully")
}

/// Handles download requests for files on the server by checking if the 
/// requested file exists, and if it does, returns the file's content in its entirety.
/// This may not be efficient for large files as it reads the entire file into memory.
///
/// # Arguments
///
/// * `filename` - A `web::Path<String>` representing the filename to download.
///
/// # Returns
///
/// An `HttpResponse` which can be `Ok` with the file's content as the body 
/// or `NotFound` if the file doesn't exist.
#[get("/download/{filename}")]
async fn download(filename: web::Path<String>) -> impl Responder {
    let filename = sanitize(filename.into_inner());
    let filepath = PathBuf::from(FILE_DIR).join(&filename);

    if filepath.exists() {
        let data = fs::read(filepath).unwrap();
        HttpResponse::Ok().body(data)
    } else {
        HttpResponse::NotFound().body("File not found")
    }
}

/// Handles download requests for files on the server by checking if the 
/// requested file exists, and if it does, returns the file's content in chunks.
/// This is efficient for large files as it streams the file in chunks rather than reading the 
/// entire file into memory.
///
/// # Arguments
///
/// * `path` - A `web::Path<String>` representing the path to the file to download.
///
/// # Returns
///
/// An `HttpResponse` which can be `Ok` with a `Stream` of the file's content as the body,
/// `InternalServerError` if there was a problem reading the file,
/// or `NotFound` if the file doesn't exist.
#[get("/download-chunked/{filename:.*}")]
async fn chunked_download(path: web::Path<String>) -> impl Responder {
    let filename = sanitize(path.into_inner());
    let file_path = PathBuf::from(FILE_DIR).join(filename);

    if file_path.exists() {
        match File::open(&file_path).await {
            Ok(file) => HttpResponse::Ok().streaming(ReaderStream::new(file)),
            Err(_) => HttpResponse::InternalServerError().body("Could not read file"),
        }
    } else {
        HttpResponse::NotFound().body("File not found")
    }
}

// #[get("/download-range/{filename:.*}")]
// async fn download_range(
//     path: web::Path<String>,
//     req: HttpRequest,
// ) -> impl Responder {
//     // ✅ Авторизация через токен
//     if !is_token_valid(&req) {
//         return HttpResponse::Unauthorized().body("Unauthorized");
//     }

//     let filename = sanitize(path.into_inner());
//     let file_path = PathBuf::from("/files").join(&filename);

//     if !file_path.exists() {
//         return HttpResponse::NotFound().body("Файл не найден");
//     }

//     let mut file = match File::open(&file_path).await {
//         Ok(f) => f,
//         Err(_) => return HttpResponse::InternalServerError().body("Ошибка открытия файла"),
//     };

//     let metadata = match file.metadata().await {
//         Ok(m) => m,
//         Err(_) => return HttpResponse::InternalServerError().body("Ошибка метаданных"),
//     };

//     let file_size = metadata.len();
//     let content_type = from_path(&file_path).first_or_octet_stream();
//     let disposition = format!("attachment; filename=\"{}\"", filename);

//     if let Some(range_header) = req.headers().get(header::RANGE) {
//         if let Some((start, end)) = parse_range_header(range_header.to_str().unwrap_or(""), file_size) {
//             let chunk_size = end - start + 1;
//             if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
//                 return HttpResponse::InternalServerError().body("Ошибка seek");
//             }

//             let stream = ReaderStream::new(file.take(chunk_size));

//             return HttpResponse::PartialContent()
//                 .append_header((header::CONTENT_TYPE, content_type.as_ref()))
//                 .append_header((header::CONTENT_LENGTH, chunk_size.to_string()))
//                 .append_header((header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, end, file_size)))
//                 .append_header((header::ACCEPT_RANGES, "bytes"))
//                 .append_header((header::CONTENT_DISPOSITION, disposition))
//                 .streaming(stream);
//         }
//     }

//     let stream = ReaderStream::new(file);
//     HttpResponse::Ok()
//         .append_header((header::CONTENT_TYPE, content_type.as_ref()))
//         .append_header((header::CONTENT_LENGTH, file_size.to_string()))
//         .append_header((header::ACCEPT_RANGES, "bytes"))
//         .append_header((header::CONTENT_DISPOSITION, disposition))
//         .streaming(stream)
// }

/// Handles delete requests for files on the server.
///
/// This function sanitizes the provided filename and checks if the file exists on the server.
/// If the file exists, it is deleted from the server. If the file does not exist, a response
/// indicating the file was not found is returned.
///
/// # Arguments
///
/// * `filename` - A `web::Path<String>` representing the filename to delete.
///
/// # Returns
///
/// An `HttpResponse` which can be:
/// * `Ok` with a success message as the body if the file was successfully deleted.
/// * `NotFound` if the file does not exist on the server.
#[delete("/{filename}")]
async fn delete(filename: web::Path<String>) -> impl Responder {
    let filename = sanitize(filename.into_inner());
    let filepath = PathBuf::from(FILE_DIR).join(&filename);

    if filepath.exists() {
        fs::remove_file(filepath).unwrap();
        HttpResponse::Ok().body("File deleted successfully")
    } else {
        HttpResponse::NotFound().body("File not found")
    }
}

/// Entry point for the File Server application.
///
/// This function sets up the command line arguments, reads the arguments provided by the user,
/// sets up the HTTP server, and runs the server until it is shut down.
///
/// Command line arguments:
/// * `--port [PORT]`: The port to listen on. Defaults to 3000.
/// * `--tls-cert [CERT]`: The path to the TLS certificate file. Optional.
/// * `--tls-key [KEY]`: The path to the TLS key file. Optional.
///
/// If both `--tls-cert` and `--tls-key` are provided, the server will use HTTPS. Otherwise, it will use HTTP.
///
/// The server provides the following services:
/// * `upload`: Upload a file to the server.
/// * `download`: Download a file from the server.
/// * `chunked_download`: Download a file from the server in chunks.
/// * `delete`: Delete a file from the server.
///
/// The server can be shut down by pressing ENTER.
///
/// # Errors
///
/// Returns an `std::io::Error` if an error occurs while setting up the server or running the server.
/// This includes errors like failing to bind to the specified port, failing to read the TLS certificate or key,
/// or failing to set up the server configuration.
///
/// # Examples
///
/// Run the server on port 3000 without TLS:
///
/// ```
/// cargo run -- --port 3000
/// ```
///
/// Run the server on port 3000 with TLS:
///
/// ```
/// cargo run -- --port 3000 --tls-cert cert.pem --tls-key key.pem
/// ```
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Define command line arguments
    let matches = Command::new("File Server")
    .version("1.0")
    .author("DuckGo")
    .about("Serves files over HTTP/HTTPS")
    .arg(arg!(--port [PORT] "Port to listen on").default_value("3000"))
    .arg(arg!(--"tls-cert" [CERT] "Path to the TLS certificate file"))
    .arg(arg!(--"tls-key" [KEY] "Path to the TLS key file"))
    .get_matches();

    // Get the port from the command line arguments
    let port = matches.get_one::<String>("port").unwrap().as_str();
    let bind_address = format!("0.0.0.0:{}", port);

    // Create a one-shot channel for shutting down the server
    // let (tx, _) = tokio::sync::oneshot::channel();

    // Spawn a new task that waits for a line from stdin and then sends a signal to the channel
    // tokio::spawn(async move {
    //     let mut reader = BufReader::new(io::stdin());
    //     let mut buffer = String::new();
    //     reader.read_line(&mut buffer).await.expect("Failed to read line from stdin");
        
    //     // Send a shutdown signal if channel is open
    //     if tx.send(()).is_err() {
    //         eprintln!("Failed to send shutdown signal, the receiver might have dropped.");
    //     }
    // });

    // Create a new HTTP server
    let server = HttpServer::new(|| {
        App::new()
            .service(upload)
            .service(download)
            .service(chunked_download)
            .service(download_range)
            .service(generate_download_url)
            .service(redirect_short_link)
            .service(delete)
    });

    // If the TLS certificate and key are provided, configure the server to use HTTPS
    let server = if let (Some(cert_path), Some(key_path)) = (matches.get_one::<String>("tls-cert"), matches.get_one::<String>("tls-key")) {
        // Read the certificate chain from the certificate file
        let cert_file = std::fs::File::open(cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let cert_chain = certs(&mut cert_reader)
            .filter_map(Result::ok)
            .map(|der| Certificate(der.deref().to_vec())) // Convert &[u8] to Vec<u8>
            .collect::<Vec<Certificate>>();

        // Read the private keys from the key file
        let key_file = std::fs::File::open(key_path)?;
        let mut key_reader = std::io::BufReader::new(key_file);
        
        // Try to read the private keys in RSA format
        let mut keys: Vec<_> = rsa_private_keys(&mut key_reader)
            .filter_map(Result::ok)
            .map(|key| rustls::PrivateKey(key.secret_pkcs1_der().to_vec())) // Convert &[u8] to Vec<u8>
            .collect();

        // If no RSA keys were found, try to read the private keys in PKCS8 format
        if keys.is_empty() {
            let mut key_reader = std::io::BufReader::new(std::fs::File::open(key_path)?);
            keys = pkcs8_private_keys(&mut key_reader)
                .filter_map(Result::ok)
                .map(|key| rustls::PrivateKey(key.secret_pkcs8_der().to_vec())) // Convert &[u8] to Vec<u8>
                .collect();
        }

        // If no PKCS8 keys were found, try to read the private keys in EC format
        if keys.is_empty() {
            let mut key_reader = std::io::BufReader::new(std::fs::File::open(key_path)?);
            keys = ec_private_keys(&mut key_reader)
                .filter_map(Result::ok)
                .map(|key| rustls::PrivateKey(key.secret_sec1_der().to_vec())) // Convert &[u8] to Vec<u8>
                .collect();
        }
    
        // If no certificate or key was found, return an error
        if cert_chain.is_empty() || keys.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid certificate or key"));
        }
    
        // Create a new server configuration with the certificate and key
        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, keys.remove(0))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid certificate or key"))?;
    
        // Bind the server to the address with the configuration
        println!("Listening on https://{}", bind_address);
        server.bind_rustls(bind_address, config)?
    } else {
        // If no certificate or key was provided, bind the server to the address without TLS
        println!("Listening on http://{}", bind_address);
        server.bind(bind_address)?
    };

    // Run the server
    let server = server.run();

    // Wait for either the server to finish or a signal from the channel
    tokio::select! {
        _ = server => {}
    }

    Ok(())
}
