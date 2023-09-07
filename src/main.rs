use clap::Parser;

use skanner::{Args, run};

#[tokio::main]
async fn main() {
  let args = Args::parse();
  run(args).await;
}
