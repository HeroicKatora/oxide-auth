//! Defines the Scope type and parsing/formatting according to the rfc.
use std::{cmp, fmt, str};

use std::collections::HashSet;

/// Scope of a bearer token, a set of scope-tokens encoded with separation by spaces
#[derive(PartialEq, Eq)]
pub struct Scope {
    tokens: HashSet<String>,
}

impl Scope {
    fn invalid_scope_char(ch: char) -> bool {
        match ch {
            '\x21' => false,
            ch if ch >= '\x23' && ch <= '\x5b' => false,
            ch if ch >= '\x5d' && ch <= '\x7e' => false,
            ' ' => false, // Space seperator is a valid char
            _ => true,
        }
    }

    /// Determines if this scope has enough privileges to access some resource requiring the scope
    /// on the right side. This operation is equivalent to comparision via `<=`.
    pub fn privileged_to(&self, rhs: &Scope) -> bool {
        self.tokens.is_subset(&rhs.tokens)
    }
}

pub struct ParseScopeErr;

impl str::FromStr for Scope {
    type Err = ParseScopeErr;

    fn from_str(string: &str) -> Result<Scope, ParseScopeErr> {
        if string.find(Scope::invalid_scope_char).is_some() {
            return Err(ParseScopeErr)
        }
        let tokens = string.split(' ').filter(|s| s.len() > 0);
        Ok(Scope{ tokens: tokens.map(|r| r.to_string()).collect() })
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        for (i, entry) in self.tokens.iter().enumerate() {
            if  i < self.tokens.len() { fmt.write_str(" ")?; }
            fmt.write_str(entry)?;
        }
        Ok(())
    }
}

impl cmp::PartialOrd for Scope {
    fn partial_cmp(&self, rhs: &Self) -> Option<cmp::Ordering> {
        let intersect_count = self.tokens.intersection(&rhs.tokens).count();
        if intersect_count == self.tokens.len() && intersect_count == rhs.tokens.len() {
            Some(cmp::Ordering::Equal)
        } else if intersect_count == self.tokens.len() {
            Some(cmp::Ordering::Less)
        } else if intersect_count == rhs.tokens.len() {
            Some(cmp::Ordering::Greater)
        } else {
            None
        }
    }
}
