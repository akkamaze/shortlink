/// The login hero's demo: one long link and how short it gets.
pub struct LengthDemo {
    pub long_url: &'static str,
}

pub fn login_demo() -> LengthDemo {
    LengthDemo {
        long_url: "https://link.synqloud.com/?utm_source=synq.li&utm_medium=short-link&utm_campaign=login-demo",
    }
}
