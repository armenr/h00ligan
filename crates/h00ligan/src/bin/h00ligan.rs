//! h00ligan executable entrypoint.

fn main() {
    h00ligan::product::run(h00ligan::product::Product::system_toolchains());
}
