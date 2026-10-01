use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "Authenticate Qnero release artifacts with ML-DSA-87")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show the public key fingerprint for independent trust checks.
    Fingerprint {
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Generate a separate offline release key. Output files must be new.
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Export a new public file from an existing private release key.
    PublicKey {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Sign a manifest for files or complete directory trees under --root.
    Sign {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Verify with a separately trusted key and expected source revision.
    Verify {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(long)]
        revision: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        signature: PathBuf,
        /// Require every file in this relative path or tree to be covered.
        #[arg(long)]
        require_path: Vec<String>,
        /// Publish verified bytes in a new directory, after all checks pass.
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Fingerprint { public_key } => {
            println!("{}", qnero_release::fingerprint(&public_key)?);
        }
        Command::Keygen {
            private_key,
            public_key,
        } => {
            let fingerprint = qnero_release::keygen(&private_key, &public_key)?;
            println!("generated release key; public SHA-512 fingerprint: {fingerprint}");
        }
        Command::PublicKey {
            private_key,
            public_key,
        } => {
            qnero_release::export_public(&private_key, &public_key)?;
            println!("exported public release key");
        }
        Command::Sign {
            root,
            private_key,
            revision,
            manifest,
            signature,
            paths,
        } => {
            let manifest = qnero_release::sign(
                &root,
                &private_key,
                &revision,
                &paths,
                &manifest,
                &signature,
            )?;
            println!(
                "signed {} artifacts for {}",
                manifest.files.len(),
                manifest.revision
            );
        }
        Command::Verify {
            root,
            public_key,
            revision,
            manifest,
            signature,
            require_path,
            output_dir,
        } => {
            let manifest = qnero_release::verify(
                &root,
                &public_key,
                &revision,
                &manifest,
                &signature,
                &require_path,
                output_dir.as_deref(),
            )?;
            println!(
                "verified {} artifacts for {} with the trusted release key",
                manifest.files.len(),
                manifest.revision
            );
        }
    }
    Ok(())
}
