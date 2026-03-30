use std::path::PathBuf;

fn main() {
    // CARGO_MANIFEST_DIR is src/libkrun-cdylib; workspace root is ../../
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
    let schema_path = workspace_root.join("target/ffier-krun.json");

    let json = std::fs::read_to_string(&schema_path).unwrap_or_else(|e| {
        panic!(
            "failed to read {}: {e}\nBuild the cdylib first.",
            schema_path.display()
        )
    });
    let lib: ffier_schema::Library = serde_json::from_str(&json)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", schema_path.display()));

    println!("// Auto-generated. Regenerate with:");
    println!("//   cargo run -p libkrun-cdylib --bin gen-libkrun-rust-client > src/libkrun-via-cdylib/src/generated.rs");
    println!();
    print!("{}", ffier_gen_rust_client::generate(&lib));
}
