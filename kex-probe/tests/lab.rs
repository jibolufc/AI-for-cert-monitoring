use std::thread;

use kex_probe::{probe, serve, Group, LabServer, ProbeError, ProbeRequest};
use serde_json::Value;

fn lab(groups: Vec<Group>, tls12_only: bool) -> (u16, thread::JoinHandle<()>) {
    let server = LabServer {
        groups,
        tls12_only,
        dns_name: "localhost".into(),
    };
    let (listener, config) = server.bind(0).expect("bind lab server");
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || serve(&listener, config, 1));
    (port, handle)
}

fn run(
    server_groups: Vec<Group>,
    client_groups: Vec<Group>,
    tls12_only: bool,
) -> Result<Value, ProbeError> {
    let (port, handle) = lab(server_groups, tls12_only);
    let mut request = ProbeRequest::new("127.0.0.1", port);
    request.groups = client_groups;
    let result = probe(&request);
    handle.join().unwrap();
    result
}

#[test]
fn hybrid_ml_kem_group_is_observed() {
    let out = run(
        vec![Group::X25519Mlkem768, Group::X25519],
        vec![Group::X25519Mlkem768, Group::X25519],
        false,
    )
    .unwrap();
    assert_eq!(
        out["transport"]["negotiated_key_establishment"],
        "X25519MLKEM768"
    );
    assert_eq!(out["key_establishment"]["family"], "hybrid");
    assert_eq!(out["key_establishment"]["group_id"], 0x11ec);
    assert_eq!(out["transport"]["tls_version"], "TLSv1.3");
}

#[test]
fn classical_server_yields_x25519_even_when_client_offers_ml_kem() {
    let out = run(
        vec![Group::X25519],
        vec![Group::X25519Mlkem768, Group::X25519],
        false,
    )
    .unwrap();
    assert_eq!(out["transport"]["negotiated_key_establishment"], "x25519");
    assert_eq!(out["key_establishment"]["family"], "elliptic-curve");
}

#[test]
fn tls12_records_ecdhe_group() {
    let out = run(vec![Group::Secp256r1], vec![Group::Secp256r1], true).unwrap();
    assert_eq!(out["transport"]["tls_version"], "TLSv1.2");
    assert_eq!(
        out["transport"]["negotiated_key_establishment"],
        "secp256r1"
    );
    assert!(out["transport"]["cipher_suite"]
        .as_str()
        .unwrap()
        .starts_with("TLS_ECDHE_"));
}

#[test]
fn no_common_group_fails_without_inventing_a_value() {
    let err = run(vec![Group::X25519], vec![Group::X25519Mlkem768], false).unwrap_err();
    assert!(matches!(err, ProbeError::Failed(_)), "{err}");
}

#[test]
fn transport_object_has_exactly_the_schema_fields() {
    let out = run(
        vec![Group::X25519Mlkem768],
        vec![Group::X25519Mlkem768],
        false,
    )
    .unwrap();
    let mut keys: Vec<_> = out["transport"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "cipher_suite",
            "negotiated_key_establishment",
            "peer_host",
            "peer_port",
            "peer_verification",
            "protocol",
            "tls_version"
        ]
    );
    assert_eq!(out["transport"]["peer_verification"], "unverified");
    assert!(!out["peer_certificate_der_base64"]
        .as_str()
        .unwrap()
        .is_empty());
}

#[test]
fn non_loopback_and_hostname_targets_are_rejected_before_connecting() {
    for host in [
        "192.0.2.10",
        "10.0.0.1",
        "::ffff:8.8.8.8",
        "localhost",
        "example.com",
    ] {
        let err = probe(&ProbeRequest::new(host, 443)).unwrap_err();
        assert!(matches!(err, ProbeError::Rejected(_)), "{host}: {err}");
    }
    assert!(matches!(
        probe(&ProbeRequest::new("::1", 0)),
        Err(ProbeError::Rejected(_))
    ));
}

#[test]
fn unsupported_group_name_is_rejected() {
    assert!(matches!(
        Group::parse_list("x25519,mlkem512"),
        Err(ProbeError::Rejected(_))
    ));
    assert!(matches!(
        Group::parse_list(""),
        Err(ProbeError::Rejected(_))
    ));
}
