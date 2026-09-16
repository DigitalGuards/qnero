//! Deterministic raw RPC proof for the real browser worker smoke check.
//! cargo run -p qnero-state-proof --features fixtures --example browser_fixture

fn hex(bytes: &[u8]) -> String {
    let mut out = String::from("0x");
    for byte in bytes {
        use std::fmt::Write;
        write!(out, "{byte:02x}").unwrap();
    }
    out
}

fn array(items: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", items.into_iter().collect::<Vec<_>>().join(","))
}

fn quoted(bytes: &[u8]) -> String {
    format!("\"{}\"", hex(bytes))
}

fn main() {
    let entries = vec![
        (b"map/a".to_vec(), vec![7; 80]),
        (b"map/z".to_vec(), vec![9; 80]),
        (b"other".to_vec(), vec![4; 80]),
    ];
    let keys = vec![
        b"map/a".to_vec(),
        b"map/z".to_vec(),
        b"missing".to_vec(),
        b"map/".to_vec(),
        b"empty/".to_vec(),
    ];
    let (root, nodes) = qnero_state_proof::fixtures::proof(&entries, &keys);
    let values = qnero_state_proof::read_values(root, nodes.clone(), &keys).unwrap();
    let prefix = qnero_state_proof::read_prefix(root, nodes.clone(), b"map/").unwrap();
    println!(
        "{{\"root\":{},\"nodes\":{},\"keys\":{},\"values\":{},\"prefix\":{},\"entries\":{},\"emptyPrefix\":{}}}",
        quoted(&root),
        array(nodes.iter().map(|node| quoted(node))),
        array(keys.iter().map(|key| quoted(key))),
        array(values.iter().map(|value| value.as_deref().map(quoted).unwrap_or("null".into()))),
        quoted(b"map/"),
        array(prefix.iter().map(|(key, value)| array([quoted(key), quoted(value)]))),
        quoted(b"empty/"),
    );
}
