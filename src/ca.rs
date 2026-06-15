pub struct MitmCa {
    ca_key: rcgen::KeyPair,
    ca_cert: rcgen::Certificate,
}

impl MitmCa {
    pub fn load_or_generate() -> Self {
        let cp = std::env::current_dir().unwrap_or_default().join("ca.pem");
        let kp = std::env::current_dir()
            .unwrap_or_default()
            .join("ca-key.pem");
        if cp.exists() && kp.exists() {
            println!("[CA] Loaded from {}", cp.display());
            let key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(&kp).unwrap()).unwrap();
            let mut params =
                rcgen::CertificateParams::new(vec!["bangumi-proxy CA".into()]).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            return Self {
                ca_cert: params.self_signed(&key).unwrap(),
                ca_key: key,
            };
        }

        println!("[CA] Generating...");
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["bangumi-proxy CA".into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(&cp, cert.pem()).unwrap();
        std::fs::write(&kp, key.serialize_pem()).unwrap();
        println!("[CA] Saved to {}", cp.display());

        Self {
            ca_cert: cert,
            ca_key: key,
        }
    }

    pub fn server_config(&self, host: &str) -> rustls::ServerConfig {
        let host_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let host_cert = params
            .signed_by(&host_key, &self.ca_cert, &self.ca_key)
            .unwrap();
        let certs = vec![rustls::pki_types::CertificateDer::from(
            host_cert.der().to_vec(),
        )];
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(host_key.serialize_der());

        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, rustls::pki_types::PrivateKeyDer::from(key))
            .unwrap()
    }
}
