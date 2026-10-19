use openidconnect::url::Url;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Hosts providers serve profile pictures from. The CSP `img-src` must list
/// the same hosts, or the browser blocks the image.
pub const PICTURE_HOSTS: [&str; 2] = ["profile.line-scdn.net", "lh3.googleusercontent.com"];

/// A profile picture URL the page may show: https, on a provider's picture
/// host, with no credentials in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PictureUrl(Url);

impl PictureUrl {
    pub fn parse(raw: &str) -> Option<Self> {
        let url = Url::parse(raw).ok()?;

        let trusted = url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url
                .host_str()
                .is_some_and(|host| PICTURE_HOSTS.contains(&host));

        trusted.then_some(Self(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Serialize for PictureUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PictureUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        PictureUrl::parse(&raw).ok_or_else(|| D::Error::custom("untrusted picture URL"))
    }
}

#[cfg(test)]
mod tests {
    use super::PictureUrl;

    #[test]
    fn keeps_https_urls_on_provider_picture_hosts() {
        let url = "https://profile.line-scdn.net/0h1234abcd";

        assert_eq!(PictureUrl::parse(url).unwrap().as_str(), url);
        assert!(PictureUrl::parse("https://lh3.googleusercontent.com/a/xyz=s96-c").is_some());
    }

    #[test]
    fn drops_other_hosts_schemes_and_tricks() {
        for raw in [
            "http://profile.line-scdn.net/0h1234",
            "https://evil.example/0h1234",
            "https://profile.line-scdn.net.evil.example/x",
            "https://user:pass@profile.line-scdn.net/x",
            "https://profile.line-scdn.net:8443/x",
            "javascript:alert(1)",
            "not a url",
        ] {
            assert_eq!(PictureUrl::parse(raw), None, "{raw}");
        }
    }
}
