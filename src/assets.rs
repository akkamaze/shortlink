/// Changes whenever a file under `static/` changes, so a stylesheet URL
/// carrying it is new after every deploy that touched the styles.
pub const VERSION: &str = env!("ASSET_VERSION");
