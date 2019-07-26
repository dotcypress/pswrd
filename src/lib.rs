use argonautica::Hasher;

/// Generates derived password for given scope and identity.
///
/// # Arguments
///
/// * `scope` - Slice with scope.
/// * `identity` - Slice with identity.
/// * `password_index` - Password index.
/// * `master_password` - Slice with master password.
///
/// # Example
///
/// ```rust
/// use pswrd::pswrd;
/// let password = pswrd("fbi.gov", "root", 0, "Pa$$W0rd");
/// assert_eq!(password, "+h0kznTVve+g&3{v")
/// ```
pub fn pswrd(scope: &str, identity: &str, password_index: u32, master_password: &str) -> String {
    Hasher::default()
        .with_password(master_password)
        .with_salt(format!("pswrd:{}:{}:{}", scope, identity, password_index))
        .configure_hash_len(16)
        .configure_iterations(192)
        .opt_out_of_secret_key(true)
        .hash_raw()
        .unwrap()
        .raw_hash_bytes()
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
    fn generate_password() {
        assert_eq!(pswrd("fbi.gov", "root", 0, "Pa$$W0rd"), "+h0kznTVve+g&3{v");
    }

    #[test]
    fn only_scope() {
        assert_eq!(pswrd("site.tld", "", 0, "Pa$$W0rd"), "qDuQQ*(#$kh|YMVL");
    }

    #[test]
    fn only_identity() {
        assert_eq!(pswrd("", "foo", 0, "Pa$$W0rd"), "3wp+6K&pk*TGrUYz");
    }

    #[test]
    fn scope_and_identity() {
        assert_eq!(pswrd("site.tld", "foo", 0, "Pa$$W0rd"), "th-soX7v$O3&C{Wh");
    }

    #[test]
    fn scope_and_identity_and_index() {
        assert_eq!(pswrd("site.tld", "foo", 42, "Pa$$W0rd"), "U(<)~{3XJ(fyR9yp");
    }
}
