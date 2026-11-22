//! apixray-core — структурный «рентген» API-ключей.
//!
//! ВАЖНО: библиотека делает только легитимный структурный анализ:
//! описание формата, сегменты, энтропия, декодирование JWT-полей БЕЗ проверки подписи.
//! Она НЕ подбирает, НЕ взламывает и НЕ обходит чужие ключи.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "0.1.0";

#[derive(Debug, Clone)]
pub struct Segment {
    pub index: usize,
    pub value: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct JwtInfo {
    pub header: String,
    pub payload: String,
    pub algorithm: String,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub masked: String,
    pub length: usize,
    pub provider: String,
    pub kind: String,
    pub entropy: f64,
    pub charset: Vec<String>,
    pub segments: Vec<Segment>,
    pub jwt: Option<JwtInfo>,
    pub risk: u8,
    pub verdict: String,
    pub recommendations: Vec<String>,
}

pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn jstr(input: &str) -> String {
    format!("\"{}\"", json_escape(input))
}

impl Analysis {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push('{');
        out.push_str(&format!("\"masked\":{},", jstr(&self.masked)));
        out.push_str(&format!("\"length\":{},", self.length));
        out.push_str(&format!("\"provider\":{},", jstr(&self.provider)));
        out.push_str(&format!("\"kind\":{},", jstr(&self.kind)));
        out.push_str(&format!("\"entropy\":{:.3},", self.entropy));
        out.push_str("\"charset\":[");
        out.push_str(
            &self
                .charset
                .iter()
                .map(|c| jstr(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("],\"segments\":[");
        let segs = self
            .segments
            .iter()
            .map(|s| {
                format!(
                    "{{\"index\":{},\"role\":{},\"value\":{}}}",
                    s.index,
                    jstr(&s.role),
                    jstr(&s.value)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&segs);
        out.push(']');
        match &self.jwt {
            Some(jwt) => {
                out.push_str(",\"jwt\":{");
                out.push_str(&format!("\"algorithm\":{},", jstr(&jwt.algorithm)));
                out.push_str(&format!("\"header\":{},", jstr(&jwt.header)));
                out.push_str(&format!("\"payload\":{}", jstr(&jwt.payload)));
                out.push('}');
            }
            None => out.push_str(",\"jwt\":null"),
        }
        out.push_str(&format!(",\"risk\":{},", self.risk));
        out.push_str(&format!("\"verdict\":{},", jstr(&self.verdict)));
        out.push_str("\"recommendations\":[");
        out.push_str(
            &self
                .recommendations
                .iter()
                .map(|r| jstr(r))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("]}");
        out
    }
}

fn mask(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    if chars.len() <= 10 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{}...{}", head, tail)
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for ch in input.chars() {
        *counts.entry(ch).or_insert(0) += 1;
    }
    let len = input.chars().count() as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn charset(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    if input.chars().any(|c| c.is_ascii_lowercase()) {
        out.push("lower".into());
    }
    if input.chars().any(|c| c.is_ascii_uppercase()) {
        out.push("upper".into());
    }
    if input.chars().any(|c| c.is_ascii_digit()) {
        out.push("digit".into());
    }
    if input.chars().any(|c| !c.is_ascii_alphanumeric()) {
        out.push("separator".into());
    }
    out
}

fn is_jwt(input: &str) -> bool {
    input.starts_with("eyJ") && input.split('.').count() == 3
}

fn detect_provider(input: &str) -> (&'static str, &'static str) {
    if input.starts_with("github_pat_") {
        ("GitHub", "fine-grained personal access token")
    } else if ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .any(|p| input.starts_with(p))
    {
        ("GitHub", "classic / OAuth token")
    } else if input.starts_with("sk-ant-") {
        ("Anthropic", "API key")
    } else if input.starts_with("sk-proj-") || input.starts_with("sk-") {
        ("OpenAI", "API key")
    } else if input.starts_with("AKIA") || input.starts_with("ASIA") {
        ("AWS", "Access Key ID")
    } else if input.starts_with("xox") {
        ("Slack", "workspace token")
    } else if input.starts_with("AIza") {
        ("Google", "API key")
    } else if input.starts_with("sk_live_")
        || input.starts_with("sk_test_")
        || input.starts_with("rk_live_")
    {
        ("Stripe", "secret / restricted key")
    } else if is_telegram_token(input) {
        ("Telegram", "bot token")
    } else if is_jwt(input) {
        ("JWT", "JSON Web Token")
    } else {
        ("Unknown", "opaque token")
    }
}

fn is_telegram_token(input: &str) -> bool {
    if let Some((id, secret)) = input.split_once(':') {
        !id.is_empty()
            && id.chars().all(|c| c.is_ascii_digit())
            && secret.len() >= 30
            && secret
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    } else {
        false
    }
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '-' => 62,
            '_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

fn jwt_field(raw: &str, key: &str) -> String {
    let needle = format!("\"{}\"", key);
    if let Some(pos) = raw.find(&needle) {
        let rest = &raw[pos + needle.len()..];
        if let Some(colon) = rest.find(':') {
            let value = rest[colon + 1..].trim_start();
            if let Some(stripped) = value.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    return stripped[..end].to_string();
                }
            }
            let end = value.find(|c| c == ',' || c == '}').unwrap_or(value.len());
            return value[..end].trim().to_string();
        }
    }
    "unknown".to_string()
}

fn decode_jwt(input: &str) -> Option<JwtInfo> {
    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let header = b64url_decode(parts[0])?;
    let payload = b64url_decode(parts[1])?;
    let header_text = String::from_utf8_lossy(&header).to_string();
    let payload_text = String::from_utf8_lossy(&payload).to_string();
    Some(JwtInfo {
        algorithm: jwt_field(&header_text, "alg"),
        header: header_text,
        payload: payload_text,
    })
}

fn build_segments(input: &str, jwt: &Option<JwtInfo>) -> Vec<Segment> {
    let mut out = Vec::new();
    if jwt.is_some() {
        for (i, part) in input.split('.').enumerate() {
            let role = match i {
                0 => "header (base64url)",
                1 => "payload (base64url)",
                _ => "signature (base64url)",
            };
            out.push(Segment {
                index: i,
                value: part.chars().take(28).collect::<String>() + if part.len() > 28 { "..." } else { "" },
                role: role.into(),
            });
        }
        return out;
    }
    let parts: Vec<&str> = input
        .split(|c| c == '-' || c == '_' || c == '.')
        .filter(|p| !p.is_empty())
        .collect();
    for (i, part) in parts.iter().enumerate() {
        let role = if i == 0 {
            "prefix / first segment"
        } else if i == parts.len() - 1 && parts.len() > 2 {
            "secret payload"
        } else {
            "middle segment"
        };
        out.push(Segment {
            index: i,
            value: if part.len() > 24 {
                format!("{}...", part.chars().take(24).collect::<String>())
            } else {
                (*part).to_string()
            },
            role: role.into(),
        });
    }
    out
}

/// Основной анализ строки. Ничего не подбирает и не проверяет подписи.
pub fn analyze(input: &str) -> Analysis {
    let trimmed = input.trim();
    let (provider, kind) = detect_provider(trimmed);
    let entropy = shannon_entropy(trimmed);
    let jwt = if is_jwt(trimmed) { decode_jwt(trimmed) } else { None };

    let mut risk: u8 = 0;
    if trimmed.len() < 16 {
        risk += 30;
    } else if trimmed.len() < 32 {
        risk += 10;
    }
    if entropy < 2.0 {
        risk += 40;
    } else if entropy < 3.0 {
        risk += 25;
    }
    if provider == "Unknown" {
        risk += 10;
    }
    let lower = trimmed.to_ascii_lowercase();
    if ["test", "fake", "dummy"].iter().any(|w| lower.contains(w)) {
        risk += 50;
    } else if ["example", "sample", "xxx"].iter().any(|w| lower.contains(w)) {
        risk += 30;
    }
    if let Some(info) = &jwt {
        if info.algorithm == "none" {
            risk += 50;
        }
    }
    let risk = risk.min(100);

    let verdict = if risk >= 60 {
        "похоже на тестовый/слабый или демонстрационный материал"
    } else if risk >= 35 {
        "есть подозрительные признаки — нужна ручная проверка"
    } else {
        "структура выглядит хорошо сформированной (без проверки подлинности)"
    };

    let mut recommendations = vec![
        "Никогда не коммитьте ключ в репозиторий".to_string(),
        "Если ключ был виден публично — ротируйте его".to_string(),
    ];
    if provider == "JWT" {
        recommendations.push(
            "Декод payload не доказывает подлинность: проверяйте подпись на сервере".into(),
        );
    }
    if risk >= 60 {
        recommendations.push("Это тестовый/слабый материал — не используйте в проде".into());
    }
    if provider == "Unknown" {
        recommendations.push("Неизвестный формат: уточните провайдера и область действия".into());
    }

    Analysis {
        masked: mask(trimmed),
        length: trimmed.chars().count(),
        provider: provider.into(),
        kind: kind.into(),
        entropy,
        charset: charset(trimmed),
        segments: build_segments(trimmed, &jwt),
        jwt,
        risk,
        verdict: verdict.into(),
        recommendations,
    }
}

pub fn analyze_json(input: &str) -> String {
    analyze(input).to_json()
}

pub fn scan_text(text: &str) -> Vec<Analysis> {
    const PREFIXES: &[&str] = &[
        "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-proj-", "sk-ant-", "sk-",
        "AKIA", "ASIA", "xox", "AIza", "sk_live_", "sk_test_", "rk_live_",
    ];

    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let mut matched: Option<(&str, usize)> = None;
        for prefix in PREFIXES {
            if text[i..].starts_with(prefix) {
                matched = Some((prefix, i + prefix.len()));
                break;
            }
        }
        if let Some((_prefix, mut end)) = matched {
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric()
                    || matches!(bytes[end], b'-' | b'_' | b'.'))
            {
                end += 1;
            }
            if let Ok(token) = std::str::from_utf8(&bytes[i..end]) {
                found.push(analyze(token));
            }
            i = end;
            continue;
        }
        if text[i..].starts_with("eyJ") {
            let mut end = i;
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            let candidate = &text[i..end];
            if is_jwt(candidate) {
                found.push(analyze(candidate));
            }
            i = end;
            continue;
        }
        i += 1;
    }
    found
}

pub fn scan_text_json(text: &str) -> String {
    let items: Vec<String> = scan_text(text).iter().map(|a| a.to_json()).collect();
    format!("[{}]", items.join(","))
}

struct Rng(u64);
impl Rng {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn alpha(&mut self, len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| ALPHABET[(self.next() % ALPHABET.len() as u64) as usize] as char)
            .collect()
    }
}

/// Генерация ЗАВЕДОМО ФЕЙКОВОГО ключа для тестов и демо.
/// Результат никогда не будет валидным ключом какого-либо провайдера.
pub fn generate_fake(provider: &str) -> String {
    let mut rng = Rng::new();
    match provider.to_ascii_lowercase().as_str() {
        "github" | "ghp" => format!("ghp_TEST{}", rng.alpha(20)),
        "github_pat" | "fine-grained" => format!("github_pat_TEST{}", rng.alpha(40)),
        "openai" | "sk" => format!("sk-proj-TEST{}", rng.alpha(24)),
        "anthropic" => format!("sk-ant-TEST{}", rng.alpha(24)),
        "aws" => format!("AKIATEST{}", rng.alpha(12)),
        "slack" => format!("xoxb-TEST-{}", rng.alpha(16)),
        "telegram" => format!("123456789:TEST{}", rng.alpha(33)),
        "google" => format!("AIzaTEST{}", rng.alpha(28)),
        "stripe" => format!("sk_test_TEST{}", rng.alpha(20)),
        "jwt" => format!("eyJTEST.{}.FAKESIGNATURE", rng.alpha(20)),
        _ => format!("TEST_KEY_{}", rng.alpha(24)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_github() {
        let token = format!("ghp_{}", "a".repeat(36));
        let a = analyze(&token);
        assert_eq!(a.provider, "GitHub");
        assert_eq!(a.risk >= 35, true);
    }

    #[test]
    fn decodes_jwt_structure() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJl";
        let a = analyze(token);
        assert_eq!(a.provider, "JWT");
        assert_eq!(a.jwt.unwrap().algorithm, "HS256");
    }

    #[test]
    fn fake_is_marked() {
        let token = generate_fake("github");
        assert!(token.starts_with("ghp_TEST"));
        assert!(analyze(&token).risk >= 60);
    }

    #[test]
    fn scan_finds_two() {
        let text = format!("a={} b={}", generate_fake("github"), generate_fake("aws"));
        assert_eq!(scan_text(&text).len(), 2);
    }
}
