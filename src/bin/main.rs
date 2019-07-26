extern crate clap;
extern crate pswrd;
extern crate rpassword;

use std::io::{Error, ErrorKind};

use clap::{App, Arg};
use pswrd::pswrd;
use rpassword::prompt_password_stderr;

fn main() -> Result<(), Error> {
    let args = App::new("pswrd")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vitaly Domnikov <oss@vitaly.codes>")
        .about("Stateless password vault.")
        .after_help(
            "EXAMPLES:
    
    Basic usage:
        pswrd foo@bar.tld
    
    Copy generated password to clipboard:
        pswrd foo@bar.tld | xclip
        pswrd foo@bar.tld | pbcopy
    
    Advanced usage:
        pswrd -u foo bar.tld
        pswrd -u foo -s bar.tld
        pswrd -u=foo -s=bar.tld -i=3
        pswrd --user foo --scope bar.tld",
        )
        .arg(
            Arg::with_name("scope")
                .short("s")
                .long("scope")
                .help("Sets the password scope (domain, application name, etc.)")
                .takes_value(true)
                .required(true)
                .display_order(0)
                .index(1),
        )
        .arg(
            Arg::with_name("user")
                .short("u")
                .long("user")
                .help("Sets the identity.")
                .takes_value(true)
                .display_order(1),
        )
        .arg(
            Arg::with_name("index")
                .short("i")
                .long("index")
                .help("Sets the password index.")
                .takes_value(true)
                .default_value("0")
                .validator(validate_index)
                .display_order(2),
        )
        .arg(
            Arg::with_name("master-password")
                .long("master-password")
                .help("Sets the master password.")
                .takes_value(true)
                .display_order(3),
        )
        .arg(
            Arg::with_name("new-line")
                .short("n")
                .help("Emit trailing newline character.")
                .display_order(4),
        )
        .get_matches();
    let mut scope = args.value_of("scope").unwrap();
    let user = args.value_of("user").unwrap_or_else(|| {
        let chunks: Vec<&str> = scope.split('@').collect();
        if chunks.len() != 2 {
            return "";
        }
        scope = chunks[1];
        chunks[0]
    });
    let master_password = match args.value_of("master-password") {
        Some(val) => String::from(val),
        None => prompt_password_stderr("Master Password: ")?,
    };
    let index = args.value_of("index").unwrap().parse().unwrap();

    match pswrd(scope, user, index, &master_password) {
        Ok(password) => {
            if args.is_present("new-line") {
                println!("{}", password);
            } else {
                print!("{}", password);
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("Failed to generate password: {}", err);
            Err(Error::from(ErrorKind::InvalidInput))
        }
    }
}

fn validate_index(v: String) -> Result<(), String> {
    if v.parse::<u32>().is_ok() {
        return Ok(());
    }
    Err(format!("{} is not a positive number", &*v))
}
