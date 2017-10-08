extern crate crypto;

use crypto::pbkdf2::pbkdf2;
use crypto::sha2::Sha256;
use crypto::hmac::Hmac;

pub fn pswrd(scope: &str, username: &str, master_password: &str, password_index: u32) -> String {
    let mut mac = Hmac::new(Sha256::new(), &master_password.as_bytes());
    let mut password: [u8; 16] = [0; 16];
    pbkdf2(
        &mut mac,
        format!("{}{}", scope, username).as_bytes(),
        1000 + password_index,
        &mut password,
    );
    password
        .iter()
        .map(|x| ALPHABET_RFC1924[*x as usize % 85])
        .collect::<String>()
}

static ALPHABET_RFC1924: [&'static str; 85] = [
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "!",
    "#",
    "$",
    "%",
    "&",
    "(",
    ")",
    "*",
    "+",
    "-",
    ";",
    "<",
    "=",
    ">",
    "?",
    "@",
    "^",
    "_",
    "`",
    "{",
    "|",
    "}",
    "~",
];

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_payload() {
        assert_eq!(pswrd("", "", "", 0), "_RrXN0aOrE_)TUs1");
    }

    #[test]
    fn only_scope() {
        assert_eq!(pswrd("site.tld", "", "", 0), "h8RAYQo&>6qkA0C&");
    }

    #[test]
    fn only_username() {
        assert_eq!(pswrd("", "foo", "", 0), "zb4}08l1$hHgG9ag");
    }

    #[test]
    fn scope_and_username() {
        assert_eq!(pswrd("site.tld", "foo", "", 0), "F|ZT=5C(r|jZoAz6");
    }

    #[test]
    fn scope_and_username_and_index() {
        assert_eq!(pswrd("site.tld", "foo", "", 42), "qS#g&8h_{Ozwab$*");
    }

    #[test]
    fn wow_master_password() {
        assert_eq!(pswrd("site.tld", "foo", "1234", 42), "U()a#cvujhjrZn_Q");
    }
}