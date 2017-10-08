# pswrd

Stateless password vault.

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
```

## Installation

You can use the `cargo install` command:

    $ cargo install pswrd

or a classic build and run:

```bash
$ git clone https://gitlab.com/dotcypress/pswrd
$ cd pswrd
$ cargo build --release
$ cp target/release/pswrd ~/.bin # assuming .bin is in your path
```