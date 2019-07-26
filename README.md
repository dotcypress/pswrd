# pswrd

🕶 Stateless password vault.

## Options

You can check by typing `pswrd --help`:

```
USAGE:
    pswrd [FLAGS] [OPTIONS] <scope>

FLAGS:
    -n               Emit trailing newline character.
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -u, --user <user>                          Sets the identity.
    -i, --index <index>                        Sets the password index. [default: 0]
        --master-password <master-password>    Sets the master password.

ARGS:
    <scope>    Sets the password scope (domain, application name, etc.)

EXAMPLES:

    Basic usage:
         pswrd foo@bar.tld

    Copy generated password to clipboard:
         pswrd foo@bar.tld | xclip
         pswrd foo@bar.tld | pbcopy

    Anvanced:
         pswrd -u foo bar.tld
         pswrd -u foo -s bar.tld
         pswrd -u=foo -s=bar.tld -i=3
         pswrd --user foo --scope bar.tld
```

## Installation

You can use the `cargo install` command:

    $ cargo install pswrd

or a classic build and run:

```bash
$ git clone https://github.com/dotcypress/pswrd
$ cd pswrd
$ cargo build --release
$ cp target/release/pswrd ~/.bin # assuming .bin is in your path
```

## v2.0 breaking сhanges

* Key derivation algorithm: `Argon2`
* Hash length: `16`
* Iterations: `192`
* Lanes: `8`
* Memory: `4096`
* Salt format: `pswrd:%scope%:%identity%:%index%`
