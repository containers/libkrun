use std::path::PathBuf;

fn main() {
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

    print!("{}", ffier_gen_c_header::generate(&lib, "LIBKRUN_H"));
}
