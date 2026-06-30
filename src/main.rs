#[tokio::main]
async fn main() {
    if let Err(err) = bw_touchid_broker::cli::run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
