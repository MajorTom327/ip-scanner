use clap::Parser;

pub mod scanner;

use scanner::{Scanner, Report};

/// Args for the program
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub ip: String,

    #[arg(short, long)]
    pub ports: Option<Vec<u16>>,

    #[arg(short, long)]
    pub output: Option<String>,
}

pub async fn run(args: Args) {
  let mut scanner = Scanner::new(args.ip, args.ports);
  scanner.scan().await;

  let report = scanner.report();

  println!("\n\n{}", report);
}
