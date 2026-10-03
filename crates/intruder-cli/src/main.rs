use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "intruder",
    version,
    about = "GyLiber controlled adversarial assurance"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the global kill-switch state. Execution remains fail-closed until configured.
    KillSwitchStatus,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::KillSwitchStatus => {
            println!("global kill switch: SAFE_DEFAULT_STOP");
        }
    }
}
