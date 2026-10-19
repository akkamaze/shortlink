//! Sizes come from `static/css/tokens.css`, so every page shares one scale.

use std::{fs, path::Path};

/// Properties whose sizes must be tokens. Widths, borders and media queries
/// are left out: they belong to one component or cannot take a variable.
const SCALED: [&str; 11] = [
    "font-size",
    "line-height",
    "letter-spacing",
    "font-weight",
    "gap",
    "row-gap",
    "column-gap",
    "padding",
    "margin",
    "border-radius",
    "height",
];

fn stylesheets(dir: &Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            stylesheets(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "css") {
            found.push(path);
        }
    }
}

/// `calc(var(--space-4) * 2)` → `calc( * 2)`: what is left once tokens are removed.
fn without_tokens(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;

    while let Some(start) = rest.find("var(") {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find(')')
            .map_or(rest.len(), |at| start + at + 1);
        rest = &rest[end..];
    }

    out.push_str(rest);
    out
}

/// A literal size such as `14px`, `0.02em` or `1.08`. Zero, a 1px hairline,
/// a percentage of the parent and the multipliers inside `calc()` are fine.
fn has_literal_size(property: &str, value: &str) -> bool {
    let bare = without_tokens(value);
    let unitless_allowed = bare.contains("calc(");

    bare.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '%'))
        .filter(|word| !word.ends_with('%'))
        .filter(|word| word.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '.'))
        .filter(|word| word.chars().any(|c| c.is_ascii_digit()))
        .any(|word| {
            let number = word.trim_start_matches('-');
            let is_zero = number.trim_end_matches(|c: char| c.is_ascii_alphabetic()) == "0";
            let unitless = number.chars().all(|c| c.is_ascii_digit() || c == '.');

            !is_zero
                && number != "1px"
                && !(unitless && unitless_allowed && property != "font-weight")
        })
}

#[test]
fn stylesheets_take_sizes_from_the_tokens() {
    let mut files = Vec::new();
    stylesheets(Path::new("static/css"), &mut files);

    let mut offenders = Vec::new();
    // fonts.css declares the weights each font file covers, not a style.
    let styling = files
        .iter()
        .filter(|file| !file.ends_with("tokens.css") && !file.ends_with("fonts.css"));

    for file in styling {
        let css = fs::read_to_string(file).unwrap();

        for (number, line) in css.lines().enumerate() {
            let Some((property, value)) = line.trim().split_once(':') else {
                continue;
            };
            let property = property.trim();
            let scaled = SCALED
                .iter()
                .any(|name| property == *name || property.starts_with(&format!("{name}-")));

            if scaled && has_literal_size(property, value.trim_end_matches(';')) {
                offenders.push(format!("{}:{} {}", file.display(), number + 1, line.trim()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "use a token from tokens.css:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_check_tells_literals_from_tokens() {
    assert!(has_literal_size("padding", " 18px 22px"));
    assert!(has_literal_size("letter-spacing", " -0.035em"));
    assert!(has_literal_size("line-height", " 1.08"));
    assert!(has_literal_size("font-weight", " 550"));

    assert!(!has_literal_size("padding", " var(--space-4) 0"));
    assert!(!has_literal_size("margin", " 0 auto"));
    assert!(!has_literal_size("height", " 1px"));
    assert!(!has_literal_size("height", " 100%"));
    assert!(!has_literal_size(
        "padding",
        " 0 calc(var(--space-4) * 2 + var(--icon-md))"
    ));
    assert!(!has_literal_size(
        "max-height",
        " calc(var(--leading-sm) * 3)"
    ));
}
