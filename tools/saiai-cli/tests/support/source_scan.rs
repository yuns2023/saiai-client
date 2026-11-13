//! Text scanners over the client's production sources, shared by the
//! library's own contract tests and the SAIAI program's source contract
//! tests. Plain text processing: no access to the client library.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Production text of every CLI source below the kernel's `kernel/src` and
/// the SAIAI program's `src`, keyed by its path relative to that directory
/// (with `/`; a name in both is an error). Test-only files (`*_tests.*`) are
/// skipped.
pub(crate) fn cli_sources() -> BTreeMap<String, String> {
    fn collect(root: &Path, directory: &Path, sources: &mut BTreeMap<String, String>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, sources);
                continue;
            }
            let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
                continue;
            };
            let stem = path.file_stem().and_then(|value| value.to_str()).unwrap();
            if !matches!(extension, "rs" | "ps1" | "js") || stem.ends_with("_tests") {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|component| component.as_os_str().to_str().unwrap())
                .collect::<Vec<_>>()
                .join("/");
            let text = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
            sources.insert(relative, production_text(&text, extension));
        }
    }
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = BTreeMap::new();
    let kernel = kernel_files();
    for root in [package.join("kernel/src"), package.join("src")] {
        let mut found = BTreeMap::new();
        collect(&root, &root, &mut found);
        for (name, text) in found {
            assert!(
                root.ends_with("kernel/src") == kernel.contains(&name),
                "{name} is not where kernel_files() says"
            );
            assert!(
                sources.insert(name.clone(), text).is_none(),
                "{name} exists in both the kernel and the program"
            );
        }
    }
    sources
}

/// Source without comments and, for Rust, without `#[cfg(test)]` items.
pub(crate) fn production_text(text: &str, extension: &str) -> String {
    match extension {
        "rs" => remove_rust_test_items(&strip_rust_comments(text)),
        "ps1" => text
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

/// Byte ranges of Rust string and char literals (including raw strings).
pub(crate) fn rust_literal_ranges(text: &str) -> Vec<std::ops::Range<usize>> {
    let bytes = text.as_bytes();
    let is_ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut ranges = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index = block_comment_end(text, index);
            continue;
        }
        let raw_start = byte == b'r'
            && (index == 0
                || !is_ident(bytes[index - 1])
                || (bytes[index - 1] == b'b' && (index < 2 || !is_ident(bytes[index - 2]))));
        if raw_start {
            let hashes = bytes[index + 1..]
                .iter()
                .take_while(|byte| **byte == b'#')
                .count();
            if bytes.get(index + 1 + hashes) == Some(&b'"') {
                let terminator = format!("\"{}", "#".repeat(hashes));
                let body = index + 2 + hashes;
                let end = text[body..]
                    .find(&terminator)
                    .map_or(bytes.len(), |end| body + end + terminator.len());
                ranges.push(index..end);
                index = end;
                continue;
            }
        }
        if byte == b'"' {
            let mut end = index + 1;
            while end < bytes.len() && bytes[end] != b'"' {
                end += if bytes[end] == b'\\' { 2 } else { 1 };
            }
            ranges.push(index..(end + 1).min(bytes.len()));
            index = end + 1;
            continue;
        }
        if byte == b'\'' {
            // Char literal ('x', '\n', '\u{..}') versus a lifetime ('a).
            let rest = &text[index + 1..];
            let length = if rest.starts_with('\\') {
                rest.find('\'').map(|end| end + 1)
            } else {
                rest.chars()
                    .next()
                    .filter(|ch| rest[ch.len_utf8()..].starts_with('\''))
                    .map(|ch| ch.len_utf8() + 1)
            };
            if let Some(length) = length {
                ranges.push(index..index + 1 + length);
                index += 1 + length;
                continue;
            }
        }
        index += 1;
    }
    ranges
}

/// End of the (possibly nested) block comment starting at `start`.
pub(crate) fn block_comment_end(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut index = start;
    while index + 1 < bytes.len() {
        match (bytes[index], bytes[index + 1]) {
            (b'/', b'*') => {
                depth += 1;
                index += 2;
            }
            (b'*', b'/') => {
                depth -= 1;
                index += 2;
                if depth == 0 {
                    return index;
                }
            }
            _ => index += 1,
        }
    }
    bytes.len()
}

pub(crate) fn literal_mask(text: &str) -> Vec<bool> {
    let mut mask = vec![false; text.len()];
    for range in rust_literal_ranges(text) {
        mask[range].fill(true);
    }
    mask
}

pub(crate) fn strip_rust_comments(text: &str) -> String {
    let mask = literal_mask(text);
    let in_literal = |index: usize| mask[index];
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < text.len() {
        if !in_literal(index) && text[index..].starts_with("//") {
            index = text[index..]
                .find('\n')
                .map_or(text.len(), |end| index + end);
            continue;
        }
        if !in_literal(index) && text[index..].starts_with("/*") {
            index = block_comment_end(text, index);
            continue;
        }
        let ch = text[index..].chars().next().unwrap();
        output.push(ch);
        index += ch.len_utf8();
    }
    output
}

/// Removes every item annotated exactly `#[cfg(test)]` (module, fn, use, …)
/// and every standalone `#[test]` / `#[tokio::test]` / `#[tokio::test(…)]`
/// function, matching braces outside literals, and keeps everything after it.
/// Other test attributes (`#[test_case]`, `#[rstest]`) are not recognized.
pub(crate) fn remove_rust_test_items(text: &str) -> String {
    const MARKERS: [&str; 5] = [
        "#[cfg(test)]",
        "#[cfg(all(test, feature = \"contract\"))]",
        "#[test]",
        "#[tokio::test]",
        "#[tokio::test(",
    ];
    let mask = literal_mask(text);
    let in_literal = |index: usize| mask[index];
    let mut output = String::new();
    let mut copied = 0;
    let mut search = 0;
    while let Some((found, marker)) = MARKERS
        .iter()
        .filter_map(|marker| text[search..].find(marker).map(|found| (found, marker)))
        .min()
    {
        let start = search + found;
        if in_literal(start) {
            search = start + 1;
            continue;
        }
        let mut index = start + marker.len();
        // Braces end an item body; `;` ends an item only outside any
        // bracket, so `fn f(x: [u8; 1])` is not cut at the array length.
        let (mut braces, mut nested) = (0_usize, 0_usize);
        let mut end = text.len();
        while index < text.len() {
            if !in_literal(index) {
                match text.as_bytes()[index] {
                    b'(' | b'[' => nested += 1,
                    b')' | b']' => nested = nested.saturating_sub(1),
                    b'{' => braces += 1,
                    b'}' => {
                        braces = braces.saturating_sub(1);
                        if braces == 0 && nested == 0 {
                            end = index + 1;
                            break;
                        }
                    }
                    b';' if braces == 0 && nested == 0 => {
                        end = index + 1;
                        break;
                    }
                    _ => {}
                }
            }
            index += 1;
        }
        output.push_str(&text[copied..start]);
        copied = end;
        search = end;
    }
    output.push_str(&text[copied..]);
    output
}

/// Text of every function named `name` in production text (all `cfg`
/// variants), matched by braces outside literals. Supports the plain
/// `fn name(` signatures pinned here: no generics, no braces inside the
/// signature. Callers accept a needle found in any variant.
pub(crate) fn function_texts<'a>(text: &'a str, name: &str) -> Vec<&'a str> {
    let mask = literal_mask(text);
    let signature = format!("fn {name}(");
    let mut found = Vec::new();
    for (start, _) in text.match_indices(&signature) {
        if mask[start] {
            continue;
        }
        let mut depth = 0_usize;
        let mut end = text.len();
        for (index, byte) in text.bytes().enumerate().skip(start) {
            if mask[index] {
                continue;
            }
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = index + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        found.push(&text[start..end]);
    }
    found
}

/// Names (as in [`cli_sources`]) of the kernel's sources, below
/// `kernel/src`; every other source belongs to the SAIAI program.
pub(crate) fn kernel_files() -> std::collections::BTreeSet<String> {
    fn collect(root: &Path, directory: &Path, names: &mut std::collections::BTreeSet<String>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, names);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|component| component.as_os_str().to_str().unwrap())
                .collect::<Vec<_>>()
                .join("/");
            names.insert(relative);
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("kernel/src");
    let mut names = std::collections::BTreeSet::new();
    collect(&root, &root, &mut names);
    names
}
