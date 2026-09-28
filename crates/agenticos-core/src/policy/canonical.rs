//! Canonical deterministic serialization (RFC 8785 JCS profile) and SHA-256
//! helpers for approval-token binding shapes.
//!
//! Implements the canonicalization rules from ADR-0007 as referenced by
//! Phase 3.0 §14: lexicographically sorted object keys, no whitespace,
//! strict number handling (`NaN`/`Infinity` rejected, negative zero
//! rejected, integers constrained to the I-JSON ±(2⁵³−1) range), raw UTF-8
//! output, and preserved array order.
//!
//! Note on key ordering: ADR-0007 requires UTF-16 code-unit ordering.
//! For valid Unicode strings (lone surrogates rejected), UTF-8 byte-wise
//! ordering coincides with UTF-16 code-unit ordering, so byte-wise sorting
//! satisfies the requirement while operating on Rust `str` values.

use super::error::PolicyError;

/// Largest integer exactly representable in IEEE 754 double precision.
const MAX_IJSON_INT: i64 = 9_007_199_254_740_991;
const MIN_IJSON_INT: i64 = -9_007_199_254_740_991;

/// Serialize a JSON value to its canonical byte representation.
///
/// Optional `None` values must already be omitted by the caller (equivalent
/// to Serde `skip_serializing_if = "Option::is_none"`); this function
/// operates on materialized `serde_json::Value`s.
pub fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, PolicyError> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

/// Convenience wrapper returning the canonical UTF-8 string.
pub fn canonical_json_string(value: &serde_json::Value) -> Result<String, PolicyError> {
    let bytes = canonical_json_bytes(value)?;
    String::from_utf8(bytes).map_err(|_| PolicyError::CanonicalizationFailed {
        reason: "canonical bytes are not valid UTF-8".to_string(),
    })
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), PolicyError> {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(n) => write_canonical_number(n, out)?,
        serde_json::Value::String(s) => {
            validate_string(s)?;
            // serde_json string escaping matches the RFC 8785 profile:
            // `"` and `\` escaped, U+0000..U+001F via \b \t \n \f \r or
            // \u00XX, `/` left unescaped, all other Unicode raw UTF-8.
            let escaped =
                serde_json::to_string(s).map_err(|_| PolicyError::CanonicalizationFailed {
                    reason: "string serialization failed".to_string(),
                })?;
            out.extend_from_slice(escaped.as_bytes());
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            // Byte-wise key sort == UTF-16 code-unit sort for valid strings.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                validate_string(key)?;
                let escaped = serde_json::to_string(key).map_err(|_| {
                    PolicyError::CanonicalizationFailed {
                        reason: "object key serialization failed".to_string(),
                    }
                })?;
                out.extend_from_slice(escaped.as_bytes());
                out.push(b':');
                write_canonical(&map[*key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_canonical_number(n: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), PolicyError> {
    if let Some(u) = n.as_u64() {
        if u as i128 > MAX_IJSON_INT as i128 {
            return Err(PolicyError::CanonicalizationFailed {
                reason: "integer outside I-JSON ±(2^53-1) range".to_string(),
            });
        }
        out.extend_from_slice(u.to_string().as_bytes());
        return Ok(());
    }
    if let Some(i) = n.as_i64() {
        if !(MIN_IJSON_INT..=MAX_IJSON_INT).contains(&i) {
            return Err(PolicyError::CanonicalizationFailed {
                reason: "integer outside I-JSON ±(2^53-1) range".to_string(),
            });
        }
        out.extend_from_slice(i.to_string().as_bytes());
        return Ok(());
    }
    if let Some(f) = n.as_f64() {
        if !f.is_finite() {
            return Err(PolicyError::CanonicalizationFailed {
                reason: "non-finite number rejected".to_string(),
            });
        }
        if f == 0.0 && f.is_sign_negative() {
            return Err(PolicyError::CanonicalizationFailed {
                reason: "negative zero rejected per RFC 8785 erratum".to_string(),
            });
        }
        // Shortest round-trip representation (ECMAScript semantics).
        out.extend_from_slice(ryu_format(f).as_bytes());
        return Ok(());
    }
    Err(PolicyError::CanonicalizationFailed {
        reason: "unrepresentable number".to_string(),
    })
}

/// Shortest-round-trip f64 formatting without additional dependencies.
fn ryu_format(f: f64) -> String {
    // `serde_json::Number` Display uses the shortest-representation
    // algorithm (ECMAScript semantics). `f` is finite here by construction.
    serde_json::Number::from_f64(f)
        .map(|n| n.to_string())
        .unwrap_or_else(|| "0".to_string())
}

/// Reject lone surrogates, which must never appear in canonical output.
fn validate_string(s: &str) -> Result<(), PolicyError> {
    // Rust `str` is guaranteed valid Unicode scalar values, so lone
    // surrogates cannot be present. This check documents the invariant.
    if s.chars().any(|c| (0xD800..0xE000).contains(&(c as u32))) {
        return Err(PolicyError::CanonicalizationFailed {
            reason: "lone surrogate rejected".to_string(),
        });
    }
    Ok(())
}

/// Compute raw SHA-256 over bytes (via the approved `sha2` dependency).
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Deterministic lowercase hexadecimal formatting (manual; no `hex` crate
/// per Amendment 3.0.1).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0F) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sorted_arrays_preserved() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"b":1,"a":[3,2,1],"c":{"y":1,"x":2}}"#).unwrap();
        assert_eq!(
            canonical_json_string(&value).unwrap(),
            r#"{"a":[3,2,1],"b":1,"c":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn string_escaping_profile() {
        // No whitespace, `/` unescaped, control chars escaped, raw UTF-8 kept.
        let value: serde_json::Value = serde_json::from_str("{\"s\":\"a/b\\né\"}").unwrap();
        assert_eq!(
            canonical_json_string(&value).unwrap(),
            "{\"s\":\"a/b\\né\"}"
        );
        let control: serde_json::Value = serde_json::from_str("{\"s\":\"\\u0001\"}").unwrap();
        assert_eq!(
            canonical_json_string(&control).unwrap(),
            "{\"s\":\"\\u0001\"}"
        );
    }

    #[test]
    fn negative_zero_rejected() {
        let value: serde_json::Value = serde_json::from_str("-0.0").unwrap();
        assert!(canonical_json_bytes(&value).is_err());
    }

    #[test]
    fn out_of_range_integers_rejected() {
        let big = serde_json::Value::from(9_007_199_254_740_992u64);
        assert!(canonical_json_bytes(&big).is_err());
        let ok = serde_json::Value::from(9_007_199_254_740_991i64);
        assert_eq!(canonical_json_string(&ok).unwrap(), "9007199254740991");
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
