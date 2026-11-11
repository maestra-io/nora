//! PyPI distribution file names: which ones NORA serves, and the version a client reads from
//! one. Defined once here, for the server and for the fuzz targets alike.

use crate::validation::ends_with_ci;

/// The archive extensions NORA serves for PyPI, in any case: the ones pip installs that
/// PyPI accepts (`.tar.gz`, `.zip`, `.whl`, and `.tgz`), and `.egg` for the installers that
/// still read eggs. pip's other archive formats are neither listed nor served.
pub const SERVED_EXTENSIONS: [&str; 5] = [".tar.gz", ".tgz", ".zip", ".whl", ".egg"];

/// The served extension a file name ends with, in any case.
pub fn served_extension(filename: &str) -> Option<&'static str> {
    SERVED_EXTENSIONS
        .iter()
        .copied()
        .find(|ext| ends_with_ci(filename, ext))
}

/// A project name per PEP 503: lowercase, every run of `-`, `_` and `.` one `-`.
pub fn pep503_normalize(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut in_separator_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_separator_run {
                normalized.push('-');
            }
            in_separator_run = true;
        } else {
            normalized.extend(c.to_lowercase());
            in_separator_run = false;
        }
    }
    normalized
}

/// The version of project `normalized_name` (PEP 503) a client reads from a file NORA serves,
/// as pip reads it (`LinkEvaluator.evaluate_link`): a wheel names the project in its first
/// `-` field and the version in its second, and so does an egg (setuptools); an sdist is
/// `<name>-<version>` where the name may be spelled as published or escaped, so the version
/// follows the first `-` before which the name normalizes to the project's, without a
/// trailing Python tag (`-py3.8`, which pip takes off). An extension in another case is read
/// as in lowercase. `None` for a file NORA does not serve, another project's file, or an
/// empty version.
pub fn parse_pypi_version(normalized_name: &str, filename: &str) -> Option<String> {
    let ext = served_extension(filename)?;
    let base = filename[..filename.len() - ext.len()].to_lowercase();
    let version = if ext == ".whl" || ext == ".egg" {
        let mut fields = base.split('-');
        let name = fields.next()?;
        let version = fields.next()?;
        (pep503_normalize(name) == normalized_name).then_some(version)?
    } else {
        let rest = base
            .match_indices('-')
            .find(|&(i, _)| pep503_normalize(&base[..i]) == normalized_name)
            .map(|(i, _)| &base[i + 1..])?;
        without_python_tag(rest)
    };
    if version.is_empty() {
        return None;
    }
    Some(version.to_string())
}

/// A version without the Python tag pip takes off an sdist's (`_py_version_re`:
/// `-py([123]\.?[0-9]?)$`).
fn without_python_tag(version: &str) -> &str {
    let Some(at) = version.rfind("-py") else {
        return version;
    };
    let tag = &version.as_bytes()[at + 3..];
    let python = match tag {
        [major] | [major, b'.'] => matches!(major, b'1'..=b'3'),
        [major, minor] | [major, b'.', minor] => {
            matches!(major, b'1'..=b'3') && minor.is_ascii_digit()
        }
        _ => false,
    };
    if python {
        &version[..at]
    } else {
        version
    }
}

/// One file of a project's index page, as upstream lists it and as NORA caches it.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// PEP 503 `data-requires-python`, unescaped (e.g. `>=3.8`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_python: Option<String>,
    /// PEP 592 `data-yanked`: `Some("")` is yanked without a reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yanked: Option<String>,
    /// PEP 658/714 `data-core-metadata` value: `true` or `sha256=<hex>`. Set only where
    /// nora can serve `<file>.metadata`: a stored copy, or the upstream's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_metadata: Option<String>,
    /// Upstream entries only: the file's absolute URL (no fragment) and the configured
    /// upstream that lists it, so a download or `.metadata` request is resolved from the
    /// cached index instead of refetching the project page (R2-27).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
}

/// Extract filename from PyPI download URL.
pub fn extract_filename(url: &str) -> Option<&str> {
    let url = url.split('#').next()?;
    let filename = url.rsplit('/').next()?;

    served_extension(filename).map(|_| filename)
}

/// Parse upstream PyPI simple index HTML into file entries.
///
/// Extracts filenames, optional `#sha256=` fragments and the PEP 503/592
/// `data-requires-python` / `data-yanked` attributes from `<a href="...">` links.
/// Filenames are percent-decoded (`%2B` -> `+`), the form the download route sees; each
/// `url` is the href without its fragment, still encoded, resolved against `page_url`
/// (relative hrefs of some mirrors: Tsinghua, USTC, Aliyun, #877).
pub fn parse_upstream_files(html: &str, page_url: &str) -> Vec<FileEntry> {
    let base = reqwest::Url::parse(page_url).ok();
    let mut files = Vec::new();
    let mut offset = 0;

    while let Some(href_start) = html[offset..].find("href=\"") {
        let value_start = offset + href_start + 6;
        let Some(href_len) = html[value_start..].find('"') else {
            break;
        };
        let url = &html[value_start..value_start + href_len];
        offset = value_start + href_len;
        if let Some(filename) = extract_filename(url) {
            // The anchor's attributes: from its `<a` to the first `>` outside quotes
            // (some mirrors leave `data-requires-python=">=3.8"` unescaped).
            let tag_start = html[..value_start].rfind("<a").unwrap_or(0);
            let mut quoted = false;
            let tag_end = html[offset + 1..]
                .char_indices()
                .find(|&(_, c)| {
                    quoted ^= c == '"';
                    c == '>' && !quoted
                })
                .map_or(html.len(), |(e, _)| offset + 1 + e);
            let tag = &html[tag_start..tag_end];
            let raw = url.split('#').next().unwrap_or(url);
            let resolved = if raw.starts_with("http://") || raw.starts_with("https://") {
                raw.to_string()
            } else {
                base.as_ref()
                    .and_then(|base| base.join(raw).ok())
                    .map_or_else(|| raw.to_string(), |u| u.to_string())
            };
            files.push(FileEntry {
                filename: percent_encoding::percent_decode_str(filename)
                    .decode_utf8_lossy()
                    .into_owned(),
                sha256: url.find("#sha256=").map(|pos| url[pos + 8..].to_string()),
                requires_python: html_attr(tag, "data-requires-python").map(html_unescape),
                yanked: html_attr(tag, "data-yanked").map(html_unescape),
                core_metadata: html_attr(tag, "data-core-metadata")
                    .or_else(|| html_attr(tag, "data-dist-info-metadata"))
                    .map(html_unescape),
                url: Some(resolved),
                upstream: None,
            });
        }
    }
    files
}

/// Value of a double-quoted attribute `name="..."` inside an HTML tag, raw (still escaped).
fn html_attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{name}=\"");
    let mut from = 0;
    while let Some(pos) = tag[from..].find(&needle) {
        let start = from + pos;
        from = start + needle.len();
        // Whole attribute name only: `data-yanked` must not match `xdata-yanked`.
        if tag[..start].ends_with(|c: char| c.is_ascii_whitespace()) {
            let end = tag[from..].find('"')?;
            return Some(&tag[from..from + end]);
        }
    }
    None
}

/// Reverse the entity escaping index pages apply to attribute values.
fn html_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&amp;", "&")
}
