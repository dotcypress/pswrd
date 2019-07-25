extern crate crypto;

use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;
use crypto::sha2::Sha256;

/// Generates derived password for given scope and identity.
///
/// # Arguments
///
/// * `scope` - Slice with scope.
/// * `identity` - Slice with identity.
/// * `master_password` - Slice with scope.
/// * `password_index` - Password index.
///
/// # Example
///
/// ```rust
/// use pswrd::pswrd;
/// let password = pswrd("fbi.gov", "root", "Pa$$W0rd", 0);
/// assert_eq!(password, "#WmqQw6$yr%2Q8BV")
/// ```
pub fn pswrd(scope: &str, identity: &str, master_password: &str, password_index: u32) -> String {
    let mut mac = Hmac::new(Sha256::new(), &master_password.as_bytes());
    let mut password: [u8; 16] = [0; 16];
    pbkdf2(
        &mut mac,
        format!("{}{}", scope, identity).as_bytes(),
        password_index,
        &mut password,
    );
    password
        .iter()
        .map(|x| ALPHABET_RFC1924[*x as usize % 85])
        .collect::<String>()
}

static ALPHABET_RFC1924: [&'static str; 85] = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I",
    "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b",
    "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u",
    "v", "w", "x", "y", "z", "!", "#", "$", "%", "&", "(", ")", "*", "+", "-", ";", "<", "=", ">",
    "?", "@", "^", "_", "`", "{", "|", "}", "~",
];

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_payload() {
        assert_eq!(pswrd("", "", "", 0), "DBS$@#8A_0g6aGzc");
    }

    #[test]
    fn only_scope() {
        assert_eq!(pswrd("site.tld", "", "", 0), "#vq_dJww$nkU-6uO");
    }

    #[test]
    fn only_identity() {
        assert_eq!(pswrd("", "foo", "", 0), "DBpj;_E_qC<Usj7<");
    }

    #[test]
    fn scope_and_identity() {
        assert_eq!(pswrd("site.tld", "foo", "", 0), "c=!GOs2gD`5X|)Hp");
    }

    #[test]
    fn scope_and_identity_and_index() {
        assert_eq!(pswrd("site.tld", "foo", "", 42), "!C&pWC*gx!x|>Y;!");
    }

    #[test]
    fn wow_master_password() {
        assert_eq!(pswrd("site.tld", "foo", "1234", 42), "&1zCFWg}4Nh+iw^v");
    }
}
