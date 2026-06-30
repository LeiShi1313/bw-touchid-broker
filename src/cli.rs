use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::ffi::OsString;
use std::path::PathBuf;

use crate::bw::{BitwardenCli, LoginOptions};
use crate::catalog::{build_catalog, empty_catalog, save_catalog};
use crate::certs::ensure_self_signed_cert;
use crate::config::{
    catalog_path, config_path, default_config, default_home, expand_path, generate_client_secret,
    load_config, save_config, set_client_approval, ClientApprovalMode, ClientConfig,
};
use crate::keychain::{
    build_helper, delete_master_password, has_master_password, read_master_password, self_test,
    store_master_password,
};
use crate::server::serve;
use crate::signing::signed_headers_json;

#[derive(Debug, Parser)]
#[command(
    name = "bw-broker",
    about = "Touch ID-gated local broker for scoped bw CLI secrets."
)]
pub struct Args {
    #[arg(
        long,
        global = true,
        help = "Broker home directory. Defaults to BW_BROKER_HOME or ~/.bw-broker."
    )]
    home: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Create config, TLS cert, client secret, and Keychain helper.")]
    Init {
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long, default_value = "remote-agent")]
        client_id: String,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 27443)]
        port: u16,
        #[arg(long)]
        public_url: Option<String>,
        #[arg(long)]
        force: bool,
    },
    #[command(about = "Rebuild Keychain helper and ensure TLS certificate exists.")]
    Bootstrap,
    #[command(about = "Store the agent account master password behind Touch ID/user presence.")]
    StoreMasterPassword,
    #[command(about = "Check whether the broker has a stored master password.")]
    HasMasterPassword,
    #[command(about = "Delete the stored master password.")]
    DeleteMasterPassword,
    #[command(about = "Store, Touch ID-read, and delete a throwaway Keychain secret.")]
    SelfTestKeychain,
    #[command(
        about = "Log the isolated bw CLI profile in, optionally passing a two-step login code."
    )]
    Login {
        #[arg(
            long,
            help = "Prompt in terminal instead of using Touch ID Keychain retrieval."
        )]
        ask_master_password: bool,
        #[arg(long, help = "Two-step login method passed to bw login --method.")]
        method: Option<String>,
        #[arg(long, help = "Two-step login code passed to bw login --code.")]
        code: Option<String>,
    },
    #[command(
        about = "Unlock bw and build the local agent-visible catalog from accessible vault items."
    )]
    BuildCatalog {
        #[arg(
            long,
            help = "Prompt in terminal instead of using Touch ID Keychain retrieval."
        )]
        ask_master_password: bool,
        #[arg(
            long,
            help = "Client id allowed by generated catalog entries. Repeatable. Defaults to all clients."
        )]
        allowed_client: Vec<String>,
        #[arg(
            long,
            help = "Do not expose Bitwarden item names in catalog descriptions."
        )]
        redact_names: bool,
        #[arg(long, help = "Run bw sync before listing items.")]
        sync: bool,
        #[arg(
            long,
            help = "Two-step login method for first login, passed to bw login --method."
        )]
        login_method: Option<String>,
        #[arg(
            long,
            help = "Two-step login code for first login, passed to bw login --code."
        )]
        login_code: Option<String>,
        #[arg(long, default_value_t = 60)]
        ttl_seconds: u64,
        #[arg(
            long,
            help = "Only list items from one Vaultwarden/Bitwarden collection."
        )]
        collection_id: Option<String>,
        #[arg(
            long,
            help = "Only list items from one Vaultwarden/Bitwarden organization."
        )]
        organization_id: Option<String>,
    },
    #[command(about = "Run the HTTPS broker.")]
    Serve,
    #[command(about = "Print remote client broker URL/id/secret.")]
    ShowClient {
        #[arg(long, default_value = "remote-agent")]
        client_id: String,
    },
    #[command(about = "List configured broker clients without printing client secrets.")]
    ListClients,
    #[command(about = "Add a signed-request client and print its generated secret once.")]
    AddClient {
        #[arg(long)]
        client_id: String,
        #[arg(
            long,
            help = "Allowed secret id. Repeatable. Defaults to all catalog secrets."
        )]
        allowed_secret: Vec<String>,
        #[arg(long, help = "Skip per-request approval prompts for this client.")]
        trusted: bool,
    },
    #[command(about = "Skip per-request approval prompts for an existing client.")]
    TrustClient {
        #[arg(long)]
        client_id: String,
    },
    #[command(about = "Require per-request approval prompts for an existing client.")]
    UntrustClient {
        #[arg(long)]
        client_id: String,
    },
    #[command(about = "Generate signed request headers for testing or agent integration.")]
    SignRequest {
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        method: String,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = "")]
        body: String,
        #[arg(long)]
        nonce: Option<String>,
    },
}

pub async fn run() -> Result<()> {
    let args = Args::parse();
    run_with_args(args).await
}

pub async fn run_from<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_with_args(Args::parse_from(args)).await
}

pub async fn run_with_args(args: Args) -> Result<()> {
    let home = args.home.unwrap_or_else(default_home);
    match args.command {
        Command::Init {
            email,
            server_url,
            client_id,
            host,
            port,
            public_url,
            force,
        } => init(
            &home,
            InitOptions {
                email,
                server_url,
                client_id,
                host,
                port,
                public_url,
                force,
            },
        ),
        Command::Bootstrap => bootstrap(&home),
        Command::StoreMasterPassword => store_master(&home),
        Command::HasMasterPassword => {
            let config = load_config(&home)?;
            println!(
                "{}",
                if has_master_password(&config, &home) {
                    "yes"
                } else {
                    "no"
                }
            );
            Ok(())
        }
        Command::DeleteMasterPassword => {
            let config = load_config(&home)?;
            delete_master_password(&config, &home)?;
            println!("Deleted stored master password if it existed.");
            Ok(())
        }
        Command::SelfTestKeychain => {
            let config = load_config(&home)?;
            self_test(&config, &home)?;
            println!("Keychain self-test passed.");
            Ok(())
        }
        Command::Login {
            ask_master_password,
            method,
            code,
        } => login_command(
            &home,
            LoginCommandOptions {
                ask_master_password,
                method,
                code,
            },
        ),
        Command::BuildCatalog {
            ask_master_password,
            allowed_client,
            redact_names,
            sync,
            login_method,
            login_code,
            ttl_seconds,
            collection_id,
            organization_id,
        } => build_catalog_command(
            &home,
            BuildCatalogOptions {
                ask_master_password,
                allowed_client,
                redact_names,
                sync,
                login_method,
                login_code,
                ttl_seconds,
                collection_id,
                organization_id,
            },
        ),
        Command::Serve => serve(&home).await,
        Command::ShowClient { client_id } => show_client(&home, &client_id),
        Command::ListClients => list_clients(&home),
        Command::AddClient {
            client_id,
            allowed_secret,
            trusted,
        } => add_client(&home, &client_id, allowed_secret, trusted),
        Command::TrustClient { client_id } => {
            set_client_approval_command(&home, &client_id, ClientApprovalMode::Trusted)
        }
        Command::UntrustClient { client_id } => {
            set_client_approval_command(&home, &client_id, ClientApprovalMode::Prompt)
        }
        Command::SignRequest {
            client_id,
            client_secret,
            method,
            path,
            body,
            nonce,
        } => sign_request(
            &client_id,
            &client_secret,
            &method,
            &path,
            body.as_bytes(),
            nonce,
        ),
    }
}

struct InitOptions {
    email: Option<String>,
    server_url: Option<String>,
    client_id: String,
    host: String,
    port: u16,
    public_url: Option<String>,
    force: bool,
}

fn init(home: &std::path::Path, options: InitOptions) -> Result<()> {
    let path = config_path(home);
    if path.exists() && !options.force {
        return Err(anyhow!(
            "config already exists: {}; use --force to replace it",
            path.display()
        ));
    }
    let email = match options.email {
        Some(email) => email,
        None => prompt_line("Vaultwarden agent account email: ")?,
    };
    let server_url = match options.server_url {
        Some(server_url) => server_url,
        None => prompt_line("Vaultwarden server URL, empty for current bw default: ")?,
    };
    let config = default_config(
        home,
        email,
        server_url,
        options.client_id,
        options.host,
        options.port,
        options.public_url,
    );
    save_config(home, &config)?;
    save_catalog(home, &empty_catalog())?;
    let helper = build_helper(&config, home)?;
    let cert = expand_path(&config.server.tls_cert, home);
    let key = expand_path(&config.server.tls_key, home);
    ensure_self_signed_cert(&cert, &key)?;
    let client = config
        .signing
        .clients
        .first()
        .context("missing default client")?;
    println!("Created config: {}", config_path(home).display());
    println!("Created empty catalog: {}", catalog_path(home).display());
    println!("Built keychain helper: {}", helper.display());
    println!("Created TLS cert: {}", cert.display());
    println!();
    println!("Remote agent client config:");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "broker_url": config.server.public_url,
            "client_id": client.id,
            "client_secret": client.secret,
        }))?
    );
    Ok(())
}

fn bootstrap(home: &std::path::Path) -> Result<()> {
    let config = load_config(home)?;
    let helper = build_helper(&config, home)?;
    let cert = expand_path(&config.server.tls_cert, home);
    let key = expand_path(&config.server.tls_key, home);
    ensure_self_signed_cert(&cert, &key)?;
    println!("Built keychain helper: {}", helper.display());
    println!("TLS cert ready: {}", cert.display());
    Ok(())
}

fn store_master(home: &std::path::Path) -> Result<()> {
    let config = load_config(home)?;
    let password = rpassword::prompt_password("Vaultwarden agent master password: ")?;
    let confirm = rpassword::prompt_password("Repeat master password: ")?;
    if password != confirm {
        return Err(anyhow!("passwords did not match"));
    }
    store_master_password(&config, home, &password)?;
    println!("Stored master password in macOS Keychain with user-presence access control.");
    Ok(())
}

struct BuildCatalogOptions {
    ask_master_password: bool,
    allowed_client: Vec<String>,
    redact_names: bool,
    sync: bool,
    login_method: Option<String>,
    login_code: Option<String>,
    ttl_seconds: u64,
    collection_id: Option<String>,
    organization_id: Option<String>,
}

struct LoginCommandOptions {
    ask_master_password: bool,
    method: Option<String>,
    code: Option<String>,
}

fn login_command(home: &std::path::Path, options: LoginCommandOptions) -> Result<()> {
    let config = load_config(home)?;
    let login_options = LoginOptions {
        two_factor_method: options.method,
        two_factor_code: options.code,
    };
    login_options.validate_with_names("--method", "--code")?;
    let master_password = read_or_prompt_master_password(
        &config,
        home,
        options.ask_master_password,
        "Unlock Vaultwarden agent account for first bw broker login",
    )?;
    let bw = BitwardenCli::new(&config, home)?;
    let mut session = None;
    let result = (|| -> Result<()> {
        let session_key = bw.unlock_or_login_with_options(&master_password, &login_options)?;
        session = Some(session_key);
        Ok(())
    })();
    bw.lock(session.as_deref());
    result?;
    println!("Broker bw profile login/unlock succeeded.");
    Ok(())
}

fn build_catalog_command(home: &std::path::Path, options: BuildCatalogOptions) -> Result<()> {
    let config = load_config(home)?;
    let login_options = LoginOptions {
        two_factor_method: options.login_method,
        two_factor_code: options.login_code,
    };
    login_options.validate_with_names("--login-method", "--login-code")?;
    let master_password = read_or_prompt_master_password(
        &config,
        home,
        options.ask_master_password,
        "Unlock Vaultwarden agent account to build bw broker catalog",
    )?;
    let bw = BitwardenCli::new(&config, home)?;
    let mut session = None;
    let result = (|| -> Result<_> {
        let session_key = bw.unlock_or_login_with_options(&master_password, &login_options)?;
        session = Some(session_key.clone());
        if options.sync {
            bw.sync(&session_key)?;
        }
        bw.list_items(
            &session_key,
            options.collection_id.as_deref(),
            options.organization_id.as_deref(),
        )
    })();
    bw.lock(session.as_deref());
    let items = result?;
    let clients = if options.allowed_client.is_empty() {
        vec!["*".to_string()]
    } else {
        options.allowed_client
    };
    let catalog = build_catalog(&items, clients, options.redact_names, options.ttl_seconds);
    save_catalog(home, &catalog)?;
    println!(
        "Wrote {} catalog entries to {}",
        catalog.secrets.len(),
        catalog_path(home).display()
    );
    Ok(())
}

fn read_or_prompt_master_password(
    config: &crate::config::Config,
    home: &std::path::Path,
    ask_master_password: bool,
    reason: &str,
) -> Result<String> {
    if !ask_master_password && has_master_password(config, home) {
        read_master_password(config, home, reason)
    } else {
        rpassword::prompt_password("Vaultwarden agent master password: ")
            .context("failed to read master password")
    }
}

fn show_client(home: &std::path::Path, client_id: &str) -> Result<()> {
    let config = load_config(home)?;
    let client = config
        .signing
        .clients
        .iter()
        .find(|client| client.id == client_id)
        .ok_or_else(|| anyhow!("unknown client id: {client_id}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "broker_url": config.server.public_url,
            "client_id": client.id,
            "client_secret": client.secret,
            "approval": &client.approval,
            "allowed_secrets": client.allowed_secrets,
        }))?
    );
    Ok(())
}

fn list_clients(home: &std::path::Path) -> Result<()> {
    let config = load_config(home)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "broker_url": config.server.public_url,
            "clients": config.signing.clients.iter().map(|client| {
                serde_json::json!({
                    "id": client.id,
                    "secret": "<redacted>",
                    "approval": &client.approval,
                    "allowed_secrets": client.allowed_secrets,
                })
            }).collect::<Vec<_>>()
        }))?
    );
    Ok(())
}

fn add_client(
    home: &std::path::Path,
    client_id: &str,
    allowed_secret: Vec<String>,
    trusted: bool,
) -> Result<()> {
    let mut config = load_config(home)?;
    if config
        .signing
        .clients
        .iter()
        .any(|client| client.id == client_id)
    {
        return Err(anyhow!("client already exists: {client_id}"));
    }
    let secret = generate_client_secret();
    let approval = if trusted {
        ClientApprovalMode::Trusted
    } else {
        ClientApprovalMode::Prompt
    };
    let allowed_secrets = if allowed_secret.is_empty() {
        vec!["*".to_string()]
    } else {
        allowed_secret
    };
    config.signing.clients.push(ClientConfig {
        id: client_id.to_string(),
        secret: secret.clone(),
        approval,
        allowed_secrets: allowed_secrets.clone(),
    });
    save_config(home, &config)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "broker_url": config.server.public_url,
            "client_id": client_id,
            "client_secret": secret,
            "approval": &config.signing.clients.last().expect("client was just added").approval,
            "allowed_secrets": allowed_secrets,
        }))?
    );
    Ok(())
}

fn set_client_approval_command(
    home: &std::path::Path,
    client_id: &str,
    approval: ClientApprovalMode,
) -> Result<()> {
    set_client_approval(home, client_id, approval)?;
    println!("Updated client approval mode: {client_id}");
    Ok(())
}

fn sign_request(
    client_id: &str,
    client_secret: &str,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: Option<String>,
) -> Result<()> {
    let nonce = nonce.unwrap_or_else(|| {
        let mut raw = [0_u8; 18];
        rand::thread_rng().fill_bytes(&mut raw);
        URL_SAFE_NO_PAD.encode(raw)
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&signed_headers_json(
            client_id,
            client_secret,
            method,
            path,
            body,
            &nonce
        )?)?
    );
    Ok(())
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
