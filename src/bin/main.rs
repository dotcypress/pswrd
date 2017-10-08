extern crate clap;
extern crate pswrd;
extern crate rpassword;

use clap::{Arg, App};
use pswrd::pswrd;
use rpassword::prompt_password_stderr;

fn main() {
    run().unwrap();
}

fn validate_index(v: String) -> Result<(), String> {
    if v.parse::<u32>().is_ok() {
        return Ok(());
    }
    Err(format!("{} isn't a positive number", &*v))
}

fn run() -> Result<(), String> {
    let args = App::new("pswrd")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vitaly Domnikov <dotcypress@gmail.com>")
        .about("Stateless password vault.")
        .arg(
            Arg::with_name("scope")
                .short("s")
                .long("scope")
                .help("Sets the password scope (domain, application name, etc.)")
                .takes_value(true)
                .required(true)
                .display_order(0)
                .index(1)
        )
        .arg(
            Arg::with_name("username")
                .short("u")
                .long("username")
                .help("Sets the username")
                .takes_value(true)
                .display_order(1)
        )
        .arg(
            Arg::with_name("index")
                .short("i")
                .long("index")
                .help("Sets the password index")
                .takes_value(true)
                .default_value("0")
                .validator(validate_index)
                .display_order(2)
        )
        .arg(
            Arg::with_name("master-password")
                .long("master-password")
                .help("Sets the master password")
                .takes_value(true)
                .display_order(3)
        )
        .arg(
            Arg::with_name("new-line")
                .short("n")
                .help("Print trailing newline character")
                .display_order(4)
        )
        .get_matches();
    let mut scope = args.value_of("scope").unwrap();
    let username = args.value_of("username").unwrap_or_else(|| {
        let chunks: Vec<&str> = scope.split("@").collect();
        if chunks.len() != 2 {
            return "";
        }
        scope = chunks[1];
        chunks[0]
    });
    let master_password = match args.value_of("master-password") {
        Some(val) => String::from(val),
        None => prompt_password_stderr("Master Password: ").unwrap(),
    };
    let index = args.value_of("index").unwrap().parse().unwrap();
    let password = pswrd(scope, username, &master_password, index);
    if args.is_present("new-line") {
        println!("{}", password);
    } else {
        print!("{}", password);
    }
    Ok(())
}