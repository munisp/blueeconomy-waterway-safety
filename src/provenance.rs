//! Fleet provenance signature scheme (Workstream B gateway profile).
//!
//! `provenance.signature` is a JWS compact serialization (EdDSA/Ed25519)
//! over the JCS-canonicalized (RFC 8785) JSON of the full document excluding
//! the signature field. The JWS protected header is
//! `{"alg":"EdDSA","kid":"<producer>-<epoch>"}`. The producer private key
//! arrives through the `PROVENANCE_SIGNING_KEY` environment variable
//! (base64url Ed25519 keypair or seed); the gateway fails closed at startup
//! when it is absent or invalid. Consumers resolve the public half from the
//! fleet key directory ({kid: base64url-ed25519-pubkey}).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Producer identity carried in signed documents.
pub const PRODUCER: &str = "waterway-safety";
/// Provenance key id; the fleet key directory carries the matching public key.
pub const SIGNING_KEY_ID: &str = "waterway-safety-1";
/// Environment variable with the base64url Ed25519 private key (64-byte
/// keypair or 32-byte seed).
pub const ENV_SIGNING_KEY: &str = "PROVENANCE_SIGNING_KEY";

/// A structured provenance failure. `code` is stable for alerting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProvenanceError {}

fn error(code: &'static str, message: impl Into<String>) -> ProvenanceError {
    ProvenanceError {
        code,
        message: message.into(),
    }
}

/// Signs provenance payloads with one producer key.
#[derive(Clone, Debug)]
pub struct ProvenanceSigner {
    kid: String,
    key: SigningKey,
}

impl ProvenanceSigner {
    /// Validates the key id and private key material (64-byte keypair or
    /// 32-byte seed).
    pub fn new(kid: &str, key_bytes: &[u8]) -> Result<Self, ProvenanceError> {
        validate_kid(kid)?;
        let key = match key_bytes.len() {
            64 => {
                let encoded: &[u8; 64] = key_bytes
                    .try_into()
                    .map_err(|_| error("invalid_key", "keypair must be 64 bytes"))?;
                SigningKey::from_keypair_bytes(encoded)
                    .map_err(|_| error("invalid_key", "Ed25519 keypair bytes are inconsistent"))?
            }
            32 => {
                let seed: &[u8; 32] = key_bytes
                    .try_into()
                    .map_err(|_| error("invalid_key", "seed must be 32 bytes"))?;
                SigningKey::from_bytes(seed)
            }
            _ => {
                return Err(error(
                    "invalid_key",
                    "Ed25519 private key must be 64 bytes (keypair) or 32 bytes (seed)",
                ))
            }
        };
        Ok(Self {
            kid: kid.to_owned(),
            key,
        })
    }

    /// Resolves the signer from `PROVENANCE_SIGNING_KEY`. Fail-closed: an
    /// absent, undecodable or wrongly sized key is a startup error.
    pub fn from_env() -> Result<Self, ProvenanceError> {
        Self::from_env_with(SIGNING_KEY_ID, |name| std::env::var(name).ok())
    }

    /// Test seam for environment resolution.
    pub fn from_env_with(
        kid: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ProvenanceError> {
        let value = lookup(ENV_SIGNING_KEY)
            .map(|raw| raw.trim().to_owned())
            .filter(|raw| !raw.is_empty())
            .ok_or_else(|| {
                error(
                    "missing_signing_key",
                    format!("{ENV_SIGNING_KEY} is required; provenance signing is mandatory"),
                )
            })?;
        let key_bytes = URL_SAFE_NO_PAD.decode(value.as_bytes())
            .map_err(|_| error("invalid_signing_key", "signing key is not base64url"))?;
        Self::new(kid, &key_bytes)
    }

    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// Base64url public half, for key-directory assembly and tests.
    pub fn public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.verifying_key().as_bytes())
    }

    /// Produces the JWS compact serialization of `payload` with the
    /// protected header `{"alg":"EdDSA","kid":<kid>}`.
    pub fn sign(&self, payload: &[u8]) -> String {
        let header = format!(r#"{{"alg":"EdDSA","kid":"{}"}}"#, self.kid);
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.as_bytes()),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = self.key.sign(input.as_bytes());
        format!(
            "{}.{}",
            input,
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }
}

/// Verifies one JWS compact serialization against `payload` with the given
/// verifying key (consumer-side; used by gateway tests and future pier-side
/// verification).
pub fn verify(
    verifying_key: &VerifyingKey,
    expected_kid: &str,
    payload: &[u8],
    jws: &str,
) -> Result<(), ProvenanceError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(error(
            "malformed_jws",
            "JWS compact serialization must have three non-empty segments",
        ));
    }
    let header_raw = URL_SAFE_NO_PAD.decode(parts[0].as_bytes())
        .map_err(|_| error("malformed_jws", "protected header is not base64url"))?;
    let header: serde_json::Value = serde_json::from_slice(&header_raw)
        .map_err(|_| error("malformed_jws", "protected header is not JSON"))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Err(error("unexpected_algorithm", "JWS alg is not EdDSA"));
    }
    if header.get("kid").and_then(|v| v.as_str()) != Some(expected_kid) {
        return Err(error("unknown_kid", "JWS kid is not the expected key id"));
    }
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2].as_bytes())
        .map_err(|_| error("malformed_jws", "signature is not base64url"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| error("malformed_jws", "signature is not an Ed25519 signature"))?;
    // The signed input is re-derived from the supplied payload: a JWS whose
    // payload segment does not match the expected payload fails here.
    let input = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(payload)
    );
    verifying_key
        .verify(input.as_bytes(), &signature)
        .map_err(|_| error("signature_verification_failed", "provenance signature does not verify"))
}

fn validate_kid(kid: &str) -> Result<(), ProvenanceError> {
    if kid.is_empty()
        || kid.len() > 128
        || kid.trim() != kid
        || kid.chars().any(|c| c == '"' || c == '.' || c.is_whitespace())
    {
        return Err(error(
            "invalid_key_id",
            "key id must be canonical non-empty text of at most 128 bytes without dots or whitespace",
        ));
    }
    Ok(())
}

/// Canonicalizes one JSON value per RFC 8785 (JCS): UTF-16-ordered object
/// keys, minimal string escapes, ECMAScript number rendering.
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>, ProvenanceError> {
    let mut output = Vec::new();
    canonical_value(value, &mut output)?;
    Ok(output)
}

fn canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), ProvenanceError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(flag) => {
            output.extend_from_slice(if *flag { b"true" } else { b"false" })
        }
        serde_json::Value::Number(number) => {
            output.extend_from_slice(canonical_number(number)?.as_bytes())
        }
        serde_json::Value::String(text) => canonical_string(text, output),
        serde_json::Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                canonical_value(item, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| {
                let au: Vec<u16> = a.encode_utf16().collect();
                let bu: Vec<u16> = b.encode_utf16().collect();
                au.cmp(&bu)
            });
            output.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                canonical_string(key, output);
                output.push(b':');
                canonical_value(&map[*key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn canonical_string(text: &str, output: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push(b'"');
    for character in text.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{08}' => output.extend_from_slice(b"\\b"),
            '\u{0c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                let code = c as u32;
                output.extend_from_slice(b"\\u00");
                output.push(HEX[((code >> 4) & 0xf) as usize]);
                output.push(HEX[(code & 0xf) as usize]);
            }
            c => {
                let mut buffer = [0u8; 4];
                output.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    output.push(b'"');
}

/// Renders one JSON number per the ECMAScript Number-to-String algorithm.
fn canonical_number(number: &serde_json::Number) -> Result<String, ProvenanceError> {
    if let Some(unsigned) = number.as_u64() {
        // u64 max is below 1e21, so the plain integer form is always JCS.
        return Ok(unsigned.to_string());
    }
    if let Some(signed) = number.as_i64() {
        return Ok(signed.to_string());
    }
    let value = number.as_f64().ok_or_else(|| {
        error("invalid_number", "JSON number is not representable as a double")
    })?;
    if value == 0.0 {
        return Ok("0".to_owned());
    }
    if !value.is_finite() {
        return Err(error("invalid_number", "non-finite numbers are not JSON"));
    }
    let (sign, magnitude) = if value < 0.0 {
        ("-", -value)
    } else {
        ("", value)
    };
    // Shortest round-trip decimal via Rust's LowerExp formatting.
    let shortest = format!("{magnitude:e}");
    let (mantissa, exponent_text) = shortest
        .split_once('e')
        .ok_or_else(|| error("invalid_number", "exponent form expected"))?;
    let exponent: i32 = exponent_text
        .parse()
        .map_err(|_| error("invalid_number", "exponent is not an integer"))?;
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    // value = digits * 10^(n-k); n is the decimal point position.
    let n = exponent + 1;
    let rendered = if k <= n && n <= 21 {
        format!("{}{}", digits, "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{}", "0".repeat((-n) as usize), digits)
    } else {
        let exponent_value = n - 1;
        let exponent_sign = if exponent_value < 0 { "-" } else { "+" };
        let mantissa_out = if k > 1 {
            format!("{}.{}", &digits[..1], &digits[1..])
        } else {
            digits.clone()
        };
        format!("{}e{}{}", mantissa_out, exponent_sign, exponent_value.abs())
    };
    Ok(format!("{sign}{rendered}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_signer() -> ProvenanceSigner {
        let seed = [7u8; 32];
        ProvenanceSigner::new(SIGNING_KEY_ID, SigningKey::from_bytes(&seed).as_bytes())
            .expect("valid seed")
    }

    #[test]
    fn sign_verify_round_trip() {
        let signer = test_signer();
        let payload = br#"{"a":1}"#;
        let jws = signer.sign(payload);
        let verifying = signer.key.verifying_key();
        verify(&verifying, SIGNING_KEY_ID, payload, &jws).expect("round trip");
    }

    #[test]
    fn tampered_payload_fails() {
        let signer = test_signer();
        let jws = signer.sign(br#"{"a":1}"#);
        let verifying = signer.key.verifying_key();
        let outcome = verify(&verifying, SIGNING_KEY_ID, br#"{"a":2}"#, &jws)
            .expect_err("tampered payload must not verify");
        assert_eq!(outcome.code, "signature_verification_failed");
    }

    #[test]
    fn unknown_kid_and_bad_algorithm_fail() {
        let signer = test_signer();
        let payload = br#"{"a":1}"#;
        let jws = signer.sign(payload);
        let verifying = signer.key.verifying_key();
        let outcome = verify(&verifying, "other-producer-1", payload, &jws)
            .expect_err("unexpected kid must fail");
        assert_eq!(outcome.code, "unknown_kid");
        let parts: Vec<&str> = jws.split('.').collect();
        let forged_header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"waterway-safety-1"}"#);
        let forged = format!("{}.{}.{}", forged_header, parts[1], parts[2]);
        let outcome = verify(&verifying, SIGNING_KEY_ID, payload, &forged)
            .expect_err("non-EdDSA must fail");
        assert_eq!(outcome.code, "unexpected_algorithm");
    }

    #[test]
    fn startup_refusal_without_key() {
        let outcome = ProvenanceSigner::from_env_with(SIGNING_KEY_ID, |_| None)
            .expect_err("absent key must fail closed");
        assert_eq!(outcome.code, "missing_signing_key");
        let outcome = ProvenanceSigner::from_env_with(SIGNING_KEY_ID, |_| {
            Some("!!!not-base64!!!".to_owned())
        })
        .expect_err("undecodable key must fail closed");
        assert_eq!(outcome.code, "invalid_signing_key");
        let outcome = ProvenanceSigner::from_env_with(SIGNING_KEY_ID, |_| {
            Some(URL_SAFE_NO_PAD.encode(b"too-short"))
        })
        .expect_err("wrongly sized key must fail closed");
        assert_eq!(outcome.code, "invalid_key");
    }

    #[test]
    fn env_round_trip() {
        let signer = test_signer();
        let encoded = URL_SAFE_NO_PAD.encode(signer.key.to_keypair_bytes());
        let loaded = ProvenanceSigner::from_env_with(SIGNING_KEY_ID, |_| Some(encoded.clone()))
            .expect("keypair loads");
        assert_eq!(loaded.public_key_base64url(), signer.public_key_base64url());
    }

    #[test]
    fn jcs_canonicalizes_objects_strings_numbers() {
        let document: serde_json::Value = serde_json::from_str(
            r#"{"b":1,"a":"quote\" nl\n","A":[3,2,1],"n":1e2,"f":0.000001,"e":1e-7,"big":1e21,"z":-0.0}"#,
        )
        .expect("fixture parses");
        let canonical = canonicalize(&document).expect("canonicalizes");
        let expected = r#"{"A":[3,2,1],"a":"quote\" nl\n","b":1,"big":1e+21,"e":1e-7,"f":0.000001,"n":100,"z":0}"#;
        assert_eq!(String::from_utf8(canonical).unwrap(), expected);
    }
}
