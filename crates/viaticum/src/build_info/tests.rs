use super::*;

#[test]
fn build_id_is_cargo_version_plus_build_suffix() {
    let id = build_id();
    let prefix = concat!(env!("CARGO_PKG_VERSION"), "+");
    assert!(id.starts_with(prefix), "{id} must start with {prefix}");
    assert!(id.len() > prefix.len(), "{id}: empty build suffix");
    match option_env!("VIATICUM_BUILD_ID") {
        Some(env_id) => assert_eq!(id, env_id, "release build: the id is the variable"),
        None => assert!(
            id.ends_with(DEV_SUFFIX),
            "{id}: dev build ends with {DEV_SUFFIX}"
        ),
    }
}

#[test]
fn build_info_reports_embedded_index_hash() {
    // The binary embeds web-ui/dist (rust-embed); build-info names its index.html.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web-ui/dist/index.html");
    let on_disk = std::fs::read(path).expect("web-ui/dist/index.html (the build embeds it)");
    let info = build_info();
    assert_eq!(info.build_id, build_id());
    assert_eq!(
        info.web_ui_index_blake3.as_deref(),
        Some(blake3::hash(&on_disk).to_hex().as_str()),
        "build-info must hash the embedded index.html"
    );
}

#[test]
fn build_info_json_has_build_id_and_index_hash_only() {
    let v = serde_json::to_value(build_info()).expect("serialize");
    let obj = v.as_object().expect("a JSON object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["build_id", "web_ui_index_blake3"]);
    assert_eq!(obj["build_id"], build_id());
    let hash = obj["web_ui_index_blake3"]
        .as_str()
        .expect("hash is a string");
    assert_eq!(hash.len(), 64, "hex blake3");
}

#[test]
fn is_build_id_of_accepts_release_and_dev_ids() {
    assert!(is_build_id_of("0.1.0-alpha.1+abc1234", "0.1.0-alpha.1"));
    assert!(is_build_id_of("0.1.0-alpha.1+dev", "0.1.0-alpha.1"));
    assert!(is_build_id_of(build_id(), env!("CARGO_PKG_VERSION")));
}

#[test]
fn is_build_id_of_rejects_empty_foreign_version_and_bare_version() {
    let v = "0.1.0-alpha.1";
    for bad in [
        "",
        "+abc1234",
        "0.1.0-alpha.1",
        "0.1.0-alpha.1+",
        "0.1.0+abc1234",
        "0.1.0-alpha.2+abc1234",
        "0.1.0-alpha.1-abc1234",
        "0.1.0-alpha.1+abc 1234",
        "0.1.0-alpha.1+abc/1234",
    ] {
        assert!(!is_build_id_of(bad, v), "{bad:?} must be refused");
    }
}
