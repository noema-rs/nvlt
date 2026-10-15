## Purpose

Exposes age encryption, decryption, and identity handling as a thin command passthrough over the age library already used by nvlt, with no dependency on the vault lock or KDF.

## Requirements

### Requirement: Age encrypt command
The CLI SHALL provide `nvlt age encrypt` that encrypts a file or stdin either to one or more recipients, accepting recipient public keys (`age1…`) and/or a recipients file, or with an interactively prompted passphrase, and writes standard age ciphertext to stdout or a specified output path. The output SHALL be readable by the upstream `age` CLI.

#### Scenario: Encrypt to a recipient
- **WHEN** the user runs `nvlt age encrypt` with a valid recipient public key and input
- **THEN** standard age ciphertext is produced that the `age` CLI can decrypt with the matching identity

#### Scenario: Encrypt with passphrase
- **WHEN** the user runs `nvlt age encrypt` in passphrase mode and enters a passphrase (prompted with confirmation)
- **THEN** standard scrypt-encrypted age ciphertext is produced that decrypts with the same passphrase

#### Scenario: Passphrase confirmation mismatch
- **WHEN** the passphrase entered at confirmation does not match the first entry
- **THEN** the command fails with a clear error and produces no output

#### Scenario: Missing recipient
- **WHEN** neither a recipient nor passphrase mode is supplied
- **THEN** the command fails with a clear error and produces no output

### Requirement: Age decrypt command
The CLI SHALL provide `nvlt age decrypt` that decrypts age ciphertext, writing plaintext to stdout or a specified output path. It SHALL detect the encryption mode from the file header: for recipient-encrypted input it uses one or more identity files (`AGE-SECRET-KEY-1…`), and for passphrase-encrypted (scrypt) input it prompts for the passphrase.

#### Scenario: Decrypt with identity
- **WHEN** ciphertext produced by the `age` CLI is decrypted with the matching identity file
- **THEN** the recovered bytes equal the original plaintext

#### Scenario: Decrypt passphrase-encrypted input
- **WHEN** passphrase-encrypted ciphertext is decrypted
- **THEN** the CLI prompts for the passphrase and, on success, writes the plaintext

#### Scenario: Recipient ciphertext without identity
- **WHEN** recipient-encrypted ciphertext is decrypted without any identity file
- **THEN** the command fails with a clear error and does not prompt for a passphrase

#### Scenario: Wrong identity
- **WHEN** the identity file does not match the ciphertext recipient
- **THEN** decryption fails and no plaintext is written

### Requirement: Age identity command
The CLI SHALL provide `nvlt age identity` that generates a new age X25519 identity and prints it, or, when given an existing identity file, prints the corresponding public key(s). When an output path is supplied while generating, it SHALL write the private identity to that path with private file permissions and the public key to a sibling path suffixed `.pub`, prompting before overwriting any existing file.

#### Scenario: Generate identity
- **WHEN** the user runs `nvlt age identity` with no existing identity file
- **THEN** a new `AGE-SECRET-KEY-1…` identity and its `age1…` public key are printed

#### Scenario: Write identity to files
- **WHEN** the user runs `nvlt age identity` with an output path and no existing identity file
- **THEN** the private identity is written to that path with private file permissions and the public key is written to `<path>.pub`

#### Scenario: Existing output file
- **WHEN** the output path or its `.pub` sibling already exists and the user does not confirm overwrite
- **THEN** no files are written

#### Scenario: Public key from identity file
- **WHEN** the user runs `nvlt age identity` with an identity file
- **THEN** the corresponding `age1…` public key(s) are printed without revealing the secret

### Requirement: No reimplementation and no vault dependency
The age commands SHALL delegate to the age library for all cryptographic operations and SHALL NOT implement age framing or cryptography independently. They SHALL NOT require the vault lock, master password, or unlock key.

#### Scenario: Works without a vault
- **WHEN** the user runs any `nvlt age` subcommand outside an initialized vault
- **THEN** the command operates normally without prompting for vault credentials
