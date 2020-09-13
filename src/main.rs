#![deny(warnings)]

use dialoguer::{theme::ColorfulTheme, PasswordInput};
use security_framework::{
    item::{ItemClass, ItemSearchOptions},
    os::macos::keychain::{CreateOptions, KeychainSettings, SecKeychain},
};
use serde::Serialize;
use std::error::Error;
use structopt::StructOpt;

const DEFAULT_CHAIN: &str = "aws-credlock";

/// Credentials Process representation of AWS credentials
/// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Credentials {
    version: u8,
    access_key_id: String,
    secret_access_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<String>,
}

#[derive(StructOpt)]
enum Opts {
    /// Initialize key store
    Init,
    /// Gets a set of credentials
    Get(Get),
    /// Add a set of credentials to the key store
    AddCredentials(AddCredentials),
    /// Remove a set of credentials from the key store
    RemoveCredentials(RemoveCredentials),
    /// List credential profile stored on the key store
    List,
}

#[derive(StructOpt)]
struct Get {
    /// Profile name to fetch credentials for
    profile: String,
}

#[derive(StructOpt)]
struct AddCredentials {
    /// Profile name to store credentials for
    profile: String,
}

#[derive(StructOpt)]
struct RemoveCredentials {
    /// Profile name to remove credentials for
    profile: String,
}

fn init() -> Result<(), Box<dyn Error>> {
    let mut chain = CreateOptions::new()
        .prompt_user(true)
        .create(DEFAULT_CHAIN)?;
    let mut settings = KeychainSettings::new();
    settings.set_lock_on_sleep(true);
    settings.set_lock_interval(Some(300));
    chain.set_settings(&settings)?;
    Ok(())
}

fn list() -> Result<(), Box<dyn Error>> {
    for item in ItemSearchOptions::new()
        .keychains(&[SecKeychain::open(DEFAULT_CHAIN)?])
        .class(ItemClass::generic_password())
        .limit(100)
        .load_data(true)
        .load_attributes(true)
        .search()?
        .into_iter()
        .filter_map(|result| {
            result
                .simplify_dict()
                .unwrap_or_default()
                .get("labl")
                .cloned()
        })
    {
        println!("{}", item);
    }
    Ok(())
}

fn get(args: Get) -> Result<(), Box<dyn Error>> {
    let Get { profile } = args;
    let chain = SecKeychain::open(DEFAULT_CHAIN)?;
    for item in ItemSearchOptions::new()
        .keychains(&[chain])
        .class(ItemClass::generic_password())
        .label(&profile)
        .load_data(true)
        .load_attributes(true)
        .search()?
    {
        let attributes = item.simplify_dict().unwrap_or_default();
        println!(
            "{}",
            serde_json::to_string_pretty(&Credentials {
                version: 1,
                access_key_id: attributes.get("acct").cloned().unwrap_or_default(),
                secret_access_key: attributes.get("v_Data").cloned().unwrap_or_default(),
                session_token: None,
                expiration: None
            })?
        );
    }
    Ok(())
}

fn add_credentials(args: AddCredentials) -> Result<(), Box<dyn Error>> {
    let AddCredentials { profile } = args;
    let access_key_id = PasswordInput::with_theme(&ColorfulTheme::default())
        .with_prompt("🔑 Enter your access_key_id")
        .allow_empty_password(false)
        .interact()?;
    let secret_access_key = PasswordInput::with_theme(&ColorfulTheme::default())
        .with_prompt("🔑 Enter your secret_access_key")
        .allow_empty_password(false)
        .interact()?;
    SecKeychain::open(DEFAULT_CHAIN)?.add_generic_password(
        profile.as_str(),
        access_key_id.as_str(),
        secret_access_key.as_bytes(),
    )?;
    Ok(())
}

fn remove_credentials(args: RemoveCredentials) -> Result<(), Box<dyn Error>> {
    let RemoveCredentials { profile } = args;
    let chain = SecKeychain::open(DEFAULT_CHAIN)?;
    for item in ItemSearchOptions::new()
        .keychains(&[chain])
        .class(ItemClass::generic_password())
        .label(&profile)
        .load_attributes(true)
        .search()?
    {
        let attributes = item.simplify_dict().unwrap_or_default();
        let access_key_id = attributes.get("acct").cloned().unwrap_or_default();
        let (_, item) =
            SecKeychain::open(DEFAULT_CHAIN)?.find_generic_password(&profile, &access_key_id)?;
        item.delete();
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    match Opts::from_args() {
        Opts::Init => init()?,
        Opts::List => list()?,
        Opts::Get(args) => get(args)?,
        Opts::AddCredentials(args) => add_credentials(args)?,
        Opts::RemoveCredentials(args) => remove_credentials(args)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_serialize_as_expected() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            serde_json::to_string(&Credentials {
                version: 1,
                access_key_id: "key".into(),
                secret_access_key: "secret".into(),
                session_token: None,
                expiration: None,
            })?,
            r#"{"Version":1,"AccessKeyId":"key","SecretAccessKey":"secret"}"#
        );
        Ok(())
    }
}
