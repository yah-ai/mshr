//! Non-Apple backend: the pure-Rust `mdns-sd` responder. Speaks the same
//! DNS-SD wire as mDNSResponder, so it and the [`super::dnssd`] backend
//! find each other. Also compiled on Apple under `cfg(test)` so the
//! cross-backend interop tests run on the dev Mac.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tracing::{debug, warn};

use super::{decode_txt, parse_instance, Advert, Book, SERVICE_TYPE};

fn ty_domain() -> String {
    format!("{SERVICE_TYPE}.local.")
}

fn io_err(e: mdns_sd::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Owns the `mdns-sd` daemon; dropping it shuts the daemon down, which
/// sends goodbyes for our registration and ends the browse thread.
pub(crate) struct Backend {
    daemon: ServiceDaemon,
    /// Currently registered `(fullname, advert)`.
    current: Mutex<Option<(String, Advert)>>,
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("mdns::Backend")
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

impl Backend {
    pub(crate) fn spawn(book: Arc<Book>) -> std::io::Result<Self> {
        let daemon = ServiceDaemon::new().map_err(io_err)?;
        let events = daemon.browse(&ty_domain()).map_err(io_err)?;
        thread::Builder::new()
            .name("mshr-lan-mdns".into())
            .spawn(move || {
                // Ends when the daemon shuts down and drops the sender.
                while let Ok(event) = events.recv() {
                    match event {
                        ServiceEvent::ServiceResolved(svc) => {
                            let Some(id) = parse_instance(&svc.fullname) else { continue };
                            let pairs = svc
                                .txt_properties
                                .iter()
                                .map(|p| (p.key(), p.val_str()));
                            if let Some(record) = decode_txt(pairs) {
                                book.found(id, record);
                            }
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            if let Some(id) = parse_instance(&fullname) {
                                book.lost(id);
                            }
                        }
                        _ => {}
                    }
                }
            })?;
        Ok(Self {
            daemon,
            current: Mutex::new(None),
        })
    }

    /// Replace what we advertise; `None` withdraws it.
    pub(crate) fn advertise(&self, advert: Option<Advert>) {
        let mut current = self.current.lock().expect("mdns current poisoned");
        if current.as_ref().map(|(_, a)| a) == advert.as_ref() {
            return;
        }
        if let Some((fullname, _)) = current.take() {
            if let Err(e) = self.daemon.unregister(&fullname) {
                warn!(%e, "lan: mdns-sd unregister failed");
            }
        }
        let Some(advert) = advert else { return };
        // A host name of our own: the machine's real one belongs to the
        // system responder (avahi / mDNSResponder), and ours must not
        // collide with it.
        let host = format!("mshr-{}.local.", &advert.instance[..16]);
        let ips: Vec<IpAddr> = advert.ips.clone();
        let info = match ServiceInfo::new(
            &ty_domain(),
            &advert.instance,
            &host,
            &ips[..],
            advert.port,
            &advert.txt[..],
        ) {
            Ok(info) => info,
            Err(e) => {
                warn!(%e, "lan: invalid mdns-sd service info");
                return;
            }
        };
        let fullname = info.get_fullname().to_string();
        match self.daemon.register(info) {
            Ok(()) => {
                debug!(%fullname, port = advert.port, "lan: registered");
                *current = Some((fullname, advert));
            }
            Err(e) => warn!(%e, "lan: mdns-sd register failed"),
        }
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}
