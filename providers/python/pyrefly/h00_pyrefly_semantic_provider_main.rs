fn main() {
    if let Err(error) = h00_pyrefly_semantic_provider::run_stdio() {
        eprintln!("h00ligan Pyrefly semantic provider failed: {error:#}");
        std::process::exit(1);
    }
}
