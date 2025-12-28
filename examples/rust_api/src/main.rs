fn main() {
    let mut builder = krun::Builder::new();

    builder.set_root(&std::env::args().nth(1).expect("missing NEWROOT argument"));

    let ctx = builder.build();

    ctx.start_enter().unwrap()
}
