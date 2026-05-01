//! AGX egress policy — CIDR allowlist for sandbox TCP/UDP
//! outbound (plan §5.17).
//!
//! Wire format: JSON the AGX side ships via
//! `krun_set_egress_policy(ctx, policy_json)`. The shape
//! mirrors `agx_net::EgressPolicy`. Kept in libkrun-local code
//! because the devices crate can't depend on agx_net.
//!
//! Default policy when no rule matches: deny.
//!
//! Used by the TSI muxer's connect path
//! (`tsi_stream::TsiStreamProxy::connect`) on every guest-
//! initiated outbound TCP connect. Allow → proceed with the
//! kernel `connect()`; Deny → return ECONNREFUSED to the
//! guest.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EgressRule {
    pub prefix_len: u8,
    pub base: IpAddr,
    pub port_range: Option<(u16, u16)>,
    pub verdict: EgressVerdict,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EgressVerdict {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    pub rules: Vec<EgressRule>,
}

impl EgressPolicy {
    /// Evaluate `(addr, port)` against the policy. First match
    /// wins; default is Deny.
    pub fn evaluate(&self, addr: IpAddr, port: u16) -> EgressVerdict {
        for rule in &self.rules {
            if matches_rule(rule, addr, port) {
                return rule.verdict;
            }
        }
        EgressVerdict::Deny
    }

    /// Parse JSON of the form produced by
    /// `agx_net::EgressPolicy`. Hand-rolled JSON parsing so we
    /// don't pull serde into the libkrun build (and so the
    /// dependency story is self-contained).
    ///
    /// Expected shape:
    /// ```json
    /// {"rules":[
    ///   {"prefix_len":8,"base":"127.0.0.0","port_range":null,"verdict":"allow"},
    ///   {"prefix_len":32,"base":"10.0.2.2","port_range":[8443,8443],"verdict":"allow"},
    ///   {"prefix_len":0,"base":"0.0.0.0","port_range":null,"verdict":"deny"}
    /// ]}
    /// ```
    pub fn from_json(json: &str) -> Result<Self, String> {
        let mut p = Parser::new(json);
        p.skip_ws();
        p.expect_char('{')?;
        p.skip_ws();
        // Find "rules"
        p.expect_str("\"rules\"")?;
        p.skip_ws();
        p.expect_char(':')?;
        p.skip_ws();
        p.expect_char('[')?;
        let mut rules = Vec::new();
        p.skip_ws();
        if p.peek() != Some(']') {
            loop {
                p.skip_ws();
                let rule = p.parse_rule()?;
                rules.push(rule);
                p.skip_ws();
                match p.peek() {
                    Some(',') => {
                        p.advance(1);
                    }
                    Some(']') => break,
                    Some(c) => return Err(format!("expected , or ], got {c:?}")),
                    None => return Err("unexpected EOF in rules".into()),
                }
            }
        }
        p.expect_char(']')?;
        // We tolerate trailing fields, just skip until '}'.
        Ok(EgressPolicy { rules })
    }
}

fn matches_rule(rule: &EgressRule, addr: IpAddr, port: u16) -> bool {
    if !cidr_contains(rule.base, rule.prefix_len, addr) {
        return false;
    }
    if let Some((lo, hi)) = rule.port_range {
        if port < lo || port > hi {
            return false;
        }
    }
    true
}

fn cidr_contains(base: IpAddr, prefix_len: u8, addr: IpAddr) -> bool {
    match (base, addr) {
        (IpAddr::V4(b), IpAddr::V4(a)) => v4_contains(b, prefix_len, a),
        (IpAddr::V6(b), IpAddr::V6(a)) => v6_contains(b, prefix_len, a),
        _ => false,
    }
}

fn v4_contains(base: Ipv4Addr, prefix_len: u8, addr: Ipv4Addr) -> bool {
    if prefix_len > 32 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let mask: u32 = (!0u32).checked_shl(32 - prefix_len as u32).unwrap_or(0);
    let base_u: u32 = base.into();
    let addr_u: u32 = addr.into();
    (base_u & mask) == (addr_u & mask)
}

fn v6_contains(base: Ipv6Addr, prefix_len: u8, addr: Ipv6Addr) -> bool {
    if prefix_len > 128 {
        return false;
    }
    if prefix_len == 0 {
        return true;
    }
    let base_u: u128 = base.into();
    let addr_u: u128 = addr.into();
    let mask: u128 = (!0u128)
        .checked_shl(128 - prefix_len as u32)
        .unwrap_or(0);
    (base_u & mask) == (addr_u & mask)
}

// ─────────────────────────── JSON parser ───────────────────────────

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(s: &'a str) -> Self {
        Self {
            s: s.as_bytes(),
            pos: 0,
        }
    }
    fn peek(&self) -> Option<char> {
        self.s.get(self.pos).map(|b| *b as char)
    }
    fn advance(&mut self, n: usize) {
        self.pos += n;
    }
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\n' || c == '\t' || c == '\r' {
                self.advance(1);
            } else {
                break;
            }
        }
    }
    fn expect_char(&mut self, want: char) -> Result<(), String> {
        match self.peek() {
            Some(c) if c == want => {
                self.advance(1);
                Ok(())
            }
            other => Err(format!("expected {want:?}, got {other:?}")),
        }
    }
    fn expect_str(&mut self, want: &str) -> Result<(), String> {
        if self.s[self.pos..].starts_with(want.as_bytes()) {
            self.advance(want.len());
            Ok(())
        } else {
            Err(format!(
                "expected literal {want:?} at pos {} (rest {:?})",
                self.pos,
                std::str::from_utf8(&self.s[self.pos..self.pos.saturating_add(20).min(self.s.len())])
                    .unwrap_or("")
            ))
        }
    }
    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_char('"')?;
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == '"' {
                let s = std::str::from_utf8(&self.s[start..self.pos])
                    .map_err(|_| "non-utf8 string".to_string())?
                    .to_string();
                self.advance(1);
                return Ok(s);
            }
            self.advance(1);
        }
        Err("unterminated string".into())
    }
    fn parse_u64(&mut self) -> Result<u64, String> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.advance(1);
            } else {
                break;
            }
        }
        let s =
            std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| "bad number".to_string())?;
        s.parse().map_err(|e| format!("number: {e}"))
    }
    fn parse_rule(&mut self) -> Result<EgressRule, String> {
        self.skip_ws();
        self.expect_char('{')?;
        let mut prefix_len: Option<u8> = None;
        let mut base: Option<IpAddr> = None;
        let mut port_range: Option<Option<(u16, u16)>> = None;
        let mut verdict: Option<EgressVerdict> = None;
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect_char(':')?;
            self.skip_ws();
            match key.as_str() {
                "prefix_len" => {
                    prefix_len = Some(self.parse_u64()? as u8);
                }
                "base" => {
                    let s = self.parse_string()?;
                    base = Some(s.parse().map_err(|e| format!("base addr: {e}"))?);
                }
                "port_range" => {
                    self.skip_ws();
                    if self.peek() == Some('n') {
                        // null
                        self.expect_str("null")?;
                        port_range = Some(None);
                    } else {
                        self.expect_char('[')?;
                        self.skip_ws();
                        let lo = self.parse_u64()? as u16;
                        self.skip_ws();
                        self.expect_char(',')?;
                        self.skip_ws();
                        let hi = self.parse_u64()? as u16;
                        self.skip_ws();
                        self.expect_char(']')?;
                        port_range = Some(Some((lo, hi)));
                    }
                }
                "verdict" => {
                    let s = self.parse_string()?;
                    verdict = Some(match s.as_str() {
                        "allow" => EgressVerdict::Allow,
                        "deny" => EgressVerdict::Deny,
                        other => return Err(format!("unknown verdict: {other}")),
                    });
                }
                other => return Err(format!("unknown rule field: {other}")),
            }
            self.skip_ws();
            match self.peek() {
                Some(',') => {
                    self.advance(1);
                    continue;
                }
                Some('}') => {
                    self.advance(1);
                    break;
                }
                other => return Err(format!("expected , or }} in rule, got {other:?}")),
            }
        }
        Ok(EgressRule {
            prefix_len: prefix_len.ok_or("rule missing prefix_len")?,
            base: base.ok_or("rule missing base")?,
            port_range: port_range.unwrap_or(None),
            verdict: verdict.ok_or("rule missing verdict")?,
        })
    }
}

// ─────────────────────────── Tests ───────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_policy_denies_everything() {
        let p = EgressPolicy::default();
        assert_eq!(
            p.evaluate(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
            EgressVerdict::Deny
        );
    }

    #[test]
    fn parses_simple_policy() {
        let json = r#"{"rules":[
            {"prefix_len":8,"base":"127.0.0.0","port_range":null,"verdict":"allow"},
            {"prefix_len":32,"base":"10.0.2.2","port_range":[8443,8443],"verdict":"allow"},
            {"prefix_len":0,"base":"0.0.0.0","port_range":null,"verdict":"deny"}
        ]}"#;
        let p = EgressPolicy::from_json(json).unwrap();
        assert_eq!(p.rules.len(), 3);
        // Loopback allowed.
        assert_eq!(
            p.evaluate(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
            EgressVerdict::Allow
        );
        // MITM port allowed.
        assert_eq!(
            p.evaluate(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)), 8443),
            EgressVerdict::Allow
        );
        assert_eq!(
            p.evaluate(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2)), 8444),
            EgressVerdict::Deny
        );
        // External denied.
        assert_eq!(
            p.evaluate(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
            EgressVerdict::Deny
        );
    }

    #[test]
    fn parses_v6_policy() {
        let json = r#"{"rules":[
            {"prefix_len":128,"base":"::1","port_range":null,"verdict":"allow"}
        ]}"#;
        let p = EgressPolicy::from_json(json).unwrap();
        assert_eq!(
            p.evaluate(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
            EgressVerdict::Allow
        );
        assert_eq!(
            p.evaluate(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)), 80),
            EgressVerdict::Deny
        );
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(EgressPolicy::from_json("not json").is_err());
        assert!(EgressPolicy::from_json("{\"rules\":\"not an array\"}").is_err());
    }
}
