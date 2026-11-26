//! `logstash-keystore` commands.
//!
//! 9.5.2 stores secrets in a PKCS12 file (`JavaKeyStore` uses type `pkcs12`),
//! and appends an obfuscated password when `LOGSTASH_KEYSTORE_PASS` is unset.
//! This binary does not read or write that file.

pub(crate) fn execute(args: &[String]) -> Result<String, String> {
    let mut command = None;
    let mut help = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--path.settings" => {
                index += 1;
                if args.get(index).is_none() {
                    return Err(
                        "'--path.settings' found, but it is empty. Please remove '--path.settings' from arguments or provide a value"
                            .to_string(),
                    );
                }
            }
            "--help" | "-h" => help = true,
            "create" | "list" | "add" | "remove" => command = Some(args[index].as_str()),
            other => {
                return Err(format!(
                    "ERROR: keystore command {other} is not implemented"
                ));
            }
        }
        index += 1;
    }
    if help || command.is_none() {
        return Ok(match command {
            Some("create") => "Creates a new keystore. For example: 'rstash keystore create'\n",
            Some("list") => "List all secret identifiers from the keystore. For example: `rstash keystore list`. Note - only the identifiers will be listed, not the secrets.\n",
            Some("add") => "Add secrets to the keystore. For example: `rstash keystore add my-secret`, at the prompt enter your secret. You will use the identifier ${my-secret} in your Logstash configuration.\n",
            Some("remove") => "Remove secrets from the keystore. For example: `rstash keystore remove my-secret`\n",
            _ => USAGE,
        }
        .to_string());
    }
    Err(
        "Logstash keystore files are PKCS12. Reading and writing them is not implemented."
            .to_string(),
    )
}

const USAGE: &str = "\
Usage:
--------
rstash keystore [option] command [argument]

Commands:
--------
create - Creates a new Logstash keystore  (e.g. rstash keystore create)
list   - List entries in the keystore  (e.g. rstash keystore list)
add    - Add values to the keystore (e.g. rstash keystore add secret-one secret-two)
remove - Remove values from the keystore  (e.g. rstash keystore remove secret-one secret-two)

Argument:
--------
--help - Display command specific help  (e.g. rstash keystore add --help)

Options:
--------
--path.settings - Set the directory for the keystore. This is should be the same directory as the logstash.yml settings file. The default is the config directory under Logstash home. (e.g. rstash keystore --path.settings /tmp/foo create)
";
