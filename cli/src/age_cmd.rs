use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use age::secrecy::SecretString as AgeSecretString;
use age::{Decryptor, Encryptor, Identity, Recipient};
use clap::Subcommand;

use crate::confirm::confirm;
use crate::error::CliError;

#[derive(Subcommand, Debug)]
pub enum AgeCmd {
    /// Encrypt a file or stdin to recipients, or with a passphrase
    Encrypt {
        /// Recipient public key (age1…); may be repeated
        #[arg(short = 'r', long = "recipient", value_name = "AGE1...")]
        recipients: Vec<String>,
        /// File with one recipient per line
        #[arg(short = 'R', long = "recipients-file", value_name = "PATH")]
        recipients_file: Option<PathBuf>,
        /// Encrypt with an interactively prompted passphrase instead of recipients
        #[arg(
            short = 'p',
            long = "passphrase",
            conflicts_with_all = ["recipients", "recipients_file"]
        )]
        passphrase: bool,
        /// Output path (default: stdout)
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Input file (default: stdin)
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        input: Option<PathBuf>,
    },
    /// Decrypt age ciphertext or passphrase-protected input
    Decrypt {
        /// Identity file (AGE-SECRET-KEY-1…); may be repeated
        #[arg(short = 'i', long = "identity", value_name = "PATH")]
        identities: Vec<PathBuf>,
        /// Output path (default: stdout)
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Input file (default: stdin)
        #[arg(short = 'f', long = "file", value_name = "PATH")]
        input: Option<PathBuf>,
    },
    /// Generate a new identity, or print the public key(s) of an identity file
    Identity {
        /// Existing identity file (default: generate a new identity)
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Write the key pair to <PATH> (private) and <PATH>.pub (public)
        #[arg(short = 'o', long = "output", value_name = "PATH")]
        output: Option<PathBuf>,
    },
}

pub fn run_age(cmd: AgeCmd) -> Result<(), CliError> {
    match cmd {
        AgeCmd::Encrypt {
            recipients,
            recipients_file,
            passphrase,
            output,
            input,
        } => age_encrypt(
            &recipients,
            recipients_file.as_deref(),
            passphrase,
            output.as_deref(),
            input.as_deref(),
        ),
        AgeCmd::Decrypt {
            identities,
            output,
            input,
        } => age_decrypt(&identities, output.as_deref(), input.as_deref()),
        AgeCmd::Identity { file, output } => age_identity(file.as_deref(), output.as_deref()),
    }
}

fn read_input(input: Option<&std::path::Path>) -> Result<Vec<u8>, CliError> {
    match input {
        Some(path) if path.as_os_str() != "-" => Ok(fs::read(path)?),
        _ => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_output(output: Option<&std::path::Path>, bytes: &[u8]) -> Result<(), CliError> {
    match output {
        Some(path) if path.as_os_str() != "-" => {
            fs::write(path, bytes)?;
            Ok(())
        }
        _ => {
            std::io::stdout().write_all(bytes)?;
            Ok(())
        }
    }
}

fn collect_recipients(
    inline: &[String],
    file: Option<&std::path::Path>,
) -> Result<Vec<age::x25519::Recipient>, CliError> {
    let mut specs: Vec<String> = inline.to_vec();
    if let Some(path) = file {
        let text = fs::read_to_string(path)?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            specs.push(line.to_string());
        }
    }
    if specs.is_empty() {
        return Err(CliError::Config(
            "at least one recipient is required (--recipient or --recipients-file)".into(),
        ));
    }
    specs
        .iter()
        .map(|s| {
            s.parse::<age::x25519::Recipient>()
                .map_err(|_| CliError::Config(format!("invalid recipient public key: {s}")))
        })
        .collect()
}

fn prompt_passphrase_confirmed() -> Result<String, CliError> {
    let passphrase = rpassword::prompt_password("Passphrase: ").map_err(CliError::Io)?;
    if passphrase.is_empty() {
        return Err(CliError::Config("passphrase cannot be empty".into()));
    }
    let confirm = rpassword::prompt_password("Confirm passphrase: ").map_err(CliError::Io)?;
    if passphrase != confirm {
        return Err(CliError::Config("passphrases do not match".into()));
    }
    Ok(passphrase)
}

fn encrypt_with_passphrase(
    passphrase: &str,
    output: Option<&std::path::Path>,
    input: Option<&std::path::Path>,
) -> Result<(), CliError> {
    let plaintext = read_input(input)?;
    let encryptor = Encryptor::with_user_passphrase(AgeSecretString::from(passphrase.to_string()));
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CliError::Config(e.to_string()))?;
    writer.write_all(&plaintext)?;
    writer
        .finish()
        .map_err(|e| CliError::Config(e.to_string()))?;

    write_output(output, &encrypted)
}

fn age_encrypt(
    recipients: &[String],
    recipients_file: Option<&std::path::Path>,
    passphrase: bool,
    output: Option<&std::path::Path>,
    input: Option<&std::path::Path>,
) -> Result<(), CliError> {
    if passphrase {
        let passphrase = prompt_passphrase_confirmed()?;
        return encrypt_with_passphrase(&passphrase, output, input);
    }

    let recipients = collect_recipients(recipients, recipients_file)?;
    let plaintext = read_input(input)?;

    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn Recipient))
        .map_err(|e| CliError::Config(e.to_string()))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| CliError::Config(e.to_string()))?;
    writer.write_all(&plaintext)?;
    writer
        .finish()
        .map_err(|e| CliError::Config(e.to_string()))?;

    write_output(output, &encrypted)
}

fn collect_identities(paths: &[PathBuf]) -> Result<Vec<age::x25519::Identity>, CliError> {
    let mut identities = Vec::new();
    for path in paths {
        let text = fs::read_to_string(path)?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let identity = line
                .parse::<age::x25519::Identity>()
                .map_err(|_| CliError::Config(format!("invalid identity in {}", path.display())))?;
            identities.push(identity);
        }
    }
    Ok(identities)
}

fn decrypt_with(ciphertext: &[u8], identities: &[&dyn Identity]) -> Result<Vec<u8>, CliError> {
    let decryptor =
        Decryptor::new_buffered(ciphertext).map_err(|e| CliError::Config(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(identities.iter().copied())
        .map_err(|e| CliError::Config(e.to_string()))?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out)?;
    Ok(out)
}

fn is_scrypt_ciphertext(ciphertext: &[u8]) -> Result<bool, CliError> {
    let decryptor =
        Decryptor::new_buffered(ciphertext).map_err(|e| CliError::Config(e.to_string()))?;
    Ok(decryptor.is_scrypt())
}

fn age_decrypt(
    identities: &[PathBuf],
    output: Option<&std::path::Path>,
    input: Option<&std::path::Path>,
) -> Result<(), CliError> {
    let ciphertext = read_input(input)?;

    if is_scrypt_ciphertext(&ciphertext)? {
        let passphrase = rpassword::prompt_password("Passphrase: ").map_err(CliError::Io)?;
        let scrypt_identity = age::scrypt::Identity::new(AgeSecretString::from(passphrase));
        let refs: Vec<&dyn Identity> = vec![&scrypt_identity as &dyn Identity];
        let plaintext = decrypt_with(&ciphertext, &refs)
            .map_err(|_| CliError::Config("decryption failed: wrong passphrase".into()))?;
        return write_output(output, &plaintext);
    }

    let key_identities = collect_identities(identities)?;
    if key_identities.is_empty() {
        return Err(CliError::Config(
            "ciphertext is encrypted to recipients; provide an identity with -i".into(),
        ));
    }
    let refs: Vec<&dyn Identity> = key_identities.iter().map(|i| i as &dyn Identity).collect();
    let plaintext = decrypt_with(&ciphertext, &refs)
        .map_err(|_| CliError::Config("decryption failed: wrong identity".into()))?;
    write_output(output, &plaintext)
}

fn age_identity(
    file: Option<&std::path::Path>,
    output: Option<&std::path::Path>,
) -> Result<(), CliError> {
    match (file, output) {
        (None, Some(base)) => generate_to_files(base),
        (Some(_), Some(_)) => Err(CliError::Config(
            "--output is only valid when generating a new identity".into(),
        )),
        (None, None) => {
            let (secret, public) = vault_core::generate_identity()?;
            use secrecy::ExposeSecret;
            println!("# public key: {public}");
            println!("{}", secret.expose_secret());
            Ok(())
        }
        (Some(path), None) => print_public_key(path),
    }
}

fn generate_to_files(base: &std::path::Path) -> Result<(), CliError> {
    let public_path = crate::keys::public_path(base);
    for path in [base, public_path.as_path()] {
        if path.exists()
            && !confirm(&format!(
                "{} already exists. Overwrite? [y/N]: ",
                path.display()
            ))?
        {
            return Err(CliError::Cancelled);
        }
    }
    let (secret, public) = vault_core::generate_identity()?;
    crate::keys::write_keypair(base, &secret, &public)?;
    eprintln!(
        "Wrote {} (private) and {} (public)",
        base.display(),
        public_path.display()
    );
    Ok(())
}

fn print_public_key(path: &std::path::Path) -> Result<(), CliError> {
    let text = fs::read_to_string(path)?;
    let mut found = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let identity = line
            .parse::<age::x25519::Identity>()
            .map_err(|_| CliError::Config(format!("invalid identity in {}", path.display())))?;
        println!("{}", identity.to_public());
        found = true;
    }
    if !found {
        return Err(CliError::Config(format!(
            "no identity found in {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip_with_identity() {
        let dir = std::env::temp_dir().join(format!("nvlt-age-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = vault_core::generate_identity().unwrap();
        let id_path = dir.join("id.txt");
        write_secret(&id_path, &secret);
        let plain_path = dir.join("plain.txt");
        let ct_path = dir.join("ct.age");
        let out_path = dir.join("out.txt");
        fs::write(&plain_path, b"age payload").unwrap();

        age_encrypt(&[public], None, false, Some(&ct_path), Some(&plain_path)).unwrap();
        age_decrypt(&[id_path], Some(&out_path), Some(&ct_path)).unwrap();
        assert_eq!(fs::read(&out_path).unwrap(), b"age payload");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_generate_writes_keypair() {
        let dir = std::env::temp_dir().join(format!("nvlt-age-kp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let base = dir.join("key.txt");
        age_identity(None, Some(&base)).unwrap();

        assert!(base.is_file());
        let public_path = crate::keys::public_path(&base);
        assert!(public_path.is_file());

        let secret = vault_core::load_identity(&base, None).unwrap();
        let derived = vault_core::public_key(&secret).unwrap();
        let printed = fs::read_to_string(&public_path).unwrap();
        assert_eq!(printed.trim(), derived);
        assert!(fs::read_to_string(&base)
            .unwrap()
            .starts_with(&format!("# public key: {derived}")));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&base).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ciphertext_mode_is_detected() {
        let dir = std::env::temp_dir().join(format!("nvlt-age-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let (secret, public) = vault_core::generate_identity().unwrap();
        let plain_path = dir.join("plain.txt");
        let rec_path = dir.join("rec.age");
        let pass_path = dir.join("pass.age");
        fs::write(&plain_path, b"payload").unwrap();

        age_encrypt(&[public], None, false, Some(&rec_path), Some(&plain_path)).unwrap();
        encrypt_with_passphrase("correct horse", Some(&pass_path), Some(&plain_path)).unwrap();

        assert!(!is_scrypt_ciphertext(&fs::read(&rec_path).unwrap()).unwrap());
        assert!(is_scrypt_ciphertext(&fs::read(&pass_path).unwrap()).unwrap());

        drop(secret);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypt_with_passphrase_round_trip() {
        let dir = std::env::temp_dir().join(format!("nvlt-age-pass-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let plain_path = dir.join("plain.txt");
        let ct_path = dir.join("ct.age");
        fs::write(&plain_path, b"secret payload").unwrap();

        encrypt_with_passphrase("correct horse", Some(&ct_path), Some(&plain_path)).unwrap();
        let ciphertext = fs::read(&ct_path).unwrap();

        let identity =
            age::scrypt::Identity::new(AgeSecretString::from("correct horse".to_string()));
        let refs: Vec<&dyn Identity> = vec![&identity as &dyn Identity];
        assert_eq!(decrypt_with(&ciphertext, &refs).unwrap(), b"secret payload");

        let wrong = age::scrypt::Identity::new(AgeSecretString::from("wrong".to_string()));
        let refs: Vec<&dyn Identity> = vec![&wrong as &dyn Identity];
        assert!(decrypt_with(&ciphertext, &refs).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn decrypt_scrypt_passphrase() {
        let dir = std::env::temp_dir().join(format!("nvlt-scrypt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let encryptor =
            Encryptor::with_user_passphrase(AgeSecretString::from("correct horse".to_string()));
        let mut ct = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ct).unwrap();
        writer.write_all(b"hidden").unwrap();
        writer.finish().unwrap();

        let identity =
            age::scrypt::Identity::new(AgeSecretString::from("correct horse".to_string()));
        let refs: Vec<&dyn Identity> = vec![&identity as &dyn Identity];
        assert_eq!(decrypt_with(&ct, &refs).unwrap(), b"hidden");

        let wrong = age::scrypt::Identity::new(AgeSecretString::from("wrong".to_string()));
        let refs: Vec<&dyn Identity> = vec![&wrong as &dyn Identity];
        assert!(decrypt_with(&ct, &refs).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    use secrecy::ExposeSecret;
    fn write_secret(path: &std::path::Path, secret: &secrecy::SecretString) {
        fs::write(path, secret.expose_secret().as_bytes()).unwrap();
    }
}
