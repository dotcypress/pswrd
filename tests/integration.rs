use std::process::Command;

static WITHOUT_ARGS_OUTPUT: &'static str = "error: The following required arguments were not provided:
    <scope>

USAGE:
    pswrd <scope> --index <index>

For more information try --help
";

#[cfg(test)]
mod integration {
    use super::*;

    #[test]
    fn calling_pswrd_without_args() {
        let output = Command::new("./target/debug/pswrd").output().expect(
            "failed to execute process",
        );
        assert_eq!(String::from_utf8_lossy(&output.stderr), WITHOUT_ARGS_OUTPUT);
    }

    #[test]
    fn calling_pswrd_with_scope_only() {
        assert_eq!(
            run_pswrd(vec!["foo", "--master-password", "123"]),
            "W9~UfFs59IsPd>$W"
        );
    }

    #[test]
    fn calling_pswrd_with_scope_and_username() {
        assert_eq!(
            run_pswrd(vec!["bar.tld", "-u", "foo", "--master-password", "123"]),
            "B2QJ%8oiyosuu&$!"
        );
    }

    #[test]
    fn calling_pswrd_with_implicit_username() {
        assert_eq!(
            run_pswrd(vec!["foo@bar.tld", "--master-password", "123"]),
            "B2QJ%8oiyosuu&$!"
        );
    }

    fn run_pswrd(args: Vec<&str>) -> String {
        let output = Command::new("./target/debug/pswrd")
            .args(args)
            .output()
            .expect("failed to execute process");
        String::from_utf8_lossy(&output.stdout).into()
    }
}