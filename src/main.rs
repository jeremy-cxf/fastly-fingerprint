use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};

// #[derive(serde::Serialize)]
// struct ClientHello {
//     cipher_suites: Vec<u16>,
// }

#[derive(serde::Serialize)]
struct Client {
    client: MSSResp
}

#[derive(serde::Serialize)]
struct TLSInfo {
    protocol: String,
    neg_cipher: String,
    ja3: String,
    ja4: Option<String>,
    // client_hello: String,
}

#[derive(serde::Serialize)]
struct Headers {
    oh_count: String,
    oh_fp: Option<String>,
    oh_order: Vec<String>,
}

#[derive(serde::Serialize)]
struct MSSResp {
    ip: String,
    tls: TLSInfo,
    user_agent: String,
    scheme: String,
    h2fp: Option<String>,
    header_info: Headers,
}


#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    println!(
        "MSS_SERVICE: {}",
        std::env::var("MSS_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );

    // check if we're local
    let local = std::env::var("FASTLY_HOSTNAME").unwrap() == "localhost";

    // Init empty var
    let (ja3_md5, ja4_hash);

    // If we're on a local machine then TLS isn't available.
    // It will panic at runtime using HTTP.
    if local {
        println!("Testing locally");
        ja3_md5 = None;
        ja4_hash = None;
    } else {
        ja3_md5  = req.get_tls_ja3_md5().map(|hash| hex::encode(hash));
        ja4_hash = req.get_tls_ja4()
    }

    // Original Header Fingerprints, Counts etc
    let oh_count = req.get_original_header_count();
    let oh_fp = req.get_client_oh_fingerprint();
    let oh_order = req.get_original_header_names()
        .map(|iter| iter.collect())
        .unwrap_or_else(Vec::new);

    // HTTP2 related variables.
    let h2fp = req.get_client_h2_fingerprint();

    // Extract User-Agent header and convert to String.
    let ua = req.get_header("user-agent")
        .and_then(|header_value| header_value.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    // Filter request methods.
    match req.get_method() {
        // Block requests with unexpected methods
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD, PURGE")
                .with_body_text_plain("This method is not allowed\n"))
        }
        // Let any other requests through
        _ => (),
    };

    // Pattern match on the path...
    match req.get_path() {
        // If request is to the `/` path construct a JSON response.
        "/info" => {

            let tls_info = TLSInfo {
                protocol: req.get_tls_protocol().unwrap().to_string(),
                neg_cipher: req.get_tls_cipher_openssl_name().unwrap().to_string(),
                ja3: ja3_md5.unwrap().to_string(),
                ja4: Option::from(ja4_hash.unwrap().to_string()),
                // client_hello: req.get_tls_client_hello().unwrap().to_string()
            };

            // Populate header info.
            let headers = Headers {
                oh_count: oh_count.unwrap().to_string(),
                oh_fp: Some(oh_fp.unwrap().to_string()),
                oh_order: oh_order,
            };

            let new_json = MSSResp {
                ip: req.get_client_ip_addr().unwrap().to_string(),
                tls: tls_info,
                user_agent: ua,
                scheme: "https".to_string(),
                h2fp: Some(h2fp.unwrap().to_string()),
                header_info: headers,
            };

            let client_json = Client {
                client: new_json,
            };

            return Ok(Response::from_status(StatusCode::OK)
                .with_body_json(&client_json)?)
        }

        // Catch all other requests and return a 403.
        _ => Ok(Response::from_status(StatusCode::FORBIDDEN)
            .with_body_text_plain("Forbidden\n")),
    }
}