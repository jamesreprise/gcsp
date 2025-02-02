# Google CSEK S3 Proxy for FoundationDB Backups
## Scope
This proxy intercepts requests made by FoundationDB, rewrites them with the appropriate headers for performing
[CSEK](https://cloud.google.com/docs/security/encryption/customer-supplied-encryption-keys) encryption and
forwards the requests on to Google Cloud Storage, returning the responses to FoundationDB.

## Installation
Choose one of the following.
* Download the releases from the GitHub releases page.
* Pull and compile from source with `cargo build --release --locked`

## Usage
Create a 'config.toml' using 'config_example.toml' as a template, then place it adjacent to the binary when run.

Alternatively, you can use `--config-file` to specify the location of the config file.
