//! The relays' TLS trust, as the released helper builds it.
//!
//! `Network::production()` verifies relay certificates with
//! `CaTlsConfig::embedded()`: Mozilla's roots from `webpki-roots`, checked by
//! `rustls-webpki`. In October 2026 eight eMudhra intermediates turned out to
//! have private keys anyone can recover from their certificates
//! (RUSTSEC-2026-0381, RUSTSEC-2026-0382), and none is revoked in a way the
//! helper checks. `data/emudhra/` is a chain through one of them, as eMudhra's
//! incident test host `dv-g3b-noct-emudhra.we-have-a-problem.com` served it on
//! 2026-10-25: the leaf, `EM DV TLS CA - G3B`, and `emSign Root TLS CA - G3`
//! cross-signed by `emSign ECC Root CA - G3`, which `webpki-roots` 1.0.9 still
//! trusted. A lockfile that accepts it lets anyone on the path to a relay
//! impersonate it.

use std::sync::Arc;
use std::time::Duration;

use fermix_iroh::endpoint::Network;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error};

const HOST: &str = "dv-g3b-noct-emudhra.we-have-a-problem.com";

/// 2026-10-24T00:00:00Z, inside the leaf's validity (2026-10-22 to 2027-05-05),
/// so only trust can refuse the chain.
const CHECKED_AT_SECS: u64 = 1_792_800_000;

#[test]
fn the_production_verifier_refuses_a_chain_through_a_compromised_emudhra_intermediate() {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Network::production()
        .ca_tls
        .server_cert_verifier(provider)
        .expect("the embedded verifier builds");
    let leaf = CertificateDer::from(&include_bytes!("data/emudhra/leaf.der")[..]);
    let intermediates = [
        CertificateDer::from(&include_bytes!("data/emudhra/em-dv-tls-ca-g3b.der")[..]),
        CertificateDer::from(&include_bytes!("data/emudhra/emsign-root-tls-ca-g3.der")[..]),
    ];
    let name = ServerName::try_from(HOST).expect("a DNS name");
    let now = UnixTime::since_unix_epoch(Duration::from_secs(CHECKED_AT_SECS));

    let refused = verifier
        .verify_server_cert(&leaf, &intermediates, &name, &[], now)
        .expect_err("a chain through a compromised eMudhra intermediate is refused");
    // rustls-webpki >= 0.103.16 distrusts the intermediates, an `Other` error
    // rustls 0.23 has no variant for. Anything else means the chain no longer
    // reaches that check (an unknown issuer, say, once webpki-roots drops the
    // emSign root), so this test would no longer show the distrust holds.
    let distrusted = matches!(
        &refused,
        Error::InvalidCertificate(CertificateError::Other(other))
            if format!("{other:?}").contains("CertDistrusted")
    );
    assert!(distrusted, "refused for another reason: {refused:?}");
}
