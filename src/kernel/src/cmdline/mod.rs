// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Helper for creating valid kernel command line strings.

use std::ffi::CString;
use std::fmt;
use std::result;

/// The error type for command line building operations.
#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    /// Failed to copy to guest memory.
    CommandLineCopy,
    /// Command line string overflows guest memory.
    CommandLineOverflow,
    /// Operation would have resulted in a non-printable ASCII character.
    InvalidAscii,
    /// Key/Value Operation would have had a space in it.
    HasSpace,
    /// Key/Value Operation would have had an equals sign in it.
    HasEquals,
    /// Operation would have made the command line too large.
    TooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Error::CommandLineCopy => "Failed to copy the command line string to guest memory",
                Error::CommandLineOverflow => "Command line string overflows guest memory",
                Error::InvalidAscii => "Command line string contains non-printable ASCII character",
                Error::HasSpace => "Command line string contains a space",
                Error::HasEquals => "Command line string contains an equals sign",
                Error::TooLarge => "Command line inserting string would make command line too long",
            }
        )
    }
}

/// Specialized Result type for command line operations.
pub type Result<T> = result::Result<T, Error>;

fn valid_char(c: char) -> bool {
    matches!(c, ' '..='~')
}

fn valid_str(s: &str) -> Result<()> {
    if s.chars().all(valid_char) {
        Ok(())
    } else {
        Err(Error::InvalidAscii)
    }
}

fn valid_element(s: &str) -> Result<()> {
    if !s.chars().all(valid_char) {
        Err(Error::InvalidAscii)
    } else if s.contains(' ') {
        Err(Error::HasSpace)
    } else if s.contains('=') {
        Err(Error::HasEquals)
    } else {
        Ok(())
    }
}

/// A builder for a kernel command line string that validates the string as its being built. A
/// `CString` can be constructed from this directly using `CString::new`.
#[derive(Clone, Debug)]
pub struct Cmdline {
    line: String,
    capacity: usize,
}

impl Cmdline {
    /// Constructs an empty Cmdline with the given capacity, which includes the nul terminator.
    /// Capacity must be greater than 0.
    pub fn new(capacity: usize) -> Cmdline {
        assert_ne!(capacity, 0);
        Cmdline {
            line: String::with_capacity(capacity),
            capacity,
        }
    }

    fn has_capacity(&self, more: usize) -> Result<()> {
        let needs_space = usize::from(!self.line.is_empty());
        if self.line.len() + more + needs_space < self.capacity {
            Ok(())
        } else {
            Err(Error::TooLarge)
        }
    }

    fn start_push(&mut self) {
        if !self.line.is_empty() {
            self.line.push(' ');
        }
    }

    fn end_push(&mut self) {
        // This assert is always true because of the `has_capacity` check that each insert method
        // uses.
        assert!(self.line.len() < self.capacity);
    }

    /// Returns the length of the command line.
    pub fn len(&self) -> usize {
        self.line.len()
    }

    /// Returns whether the command line is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validates and inserts a key value pair into this command line.
    pub fn insert<T: AsRef<str>>(&mut self, key: T, val: T) -> Result<()> {
        let k = key.as_ref();
        let v = val.as_ref();

        valid_element(k)?;
        valid_element(v)?;
        self.has_capacity(k.len() + v.len() + 1)?;

        self.start_push();
        self.line.push_str(k);
        self.line.push('=');
        self.line.push_str(v);
        self.end_push();

        Ok(())
    }

    /// Validates and inserts a string to the end of the current command line.
    pub fn insert_str<T: AsRef<str>>(&mut self, slug: T) -> Result<()> {
        let s = slug.as_ref();
        valid_str(s)?;

        self.has_capacity(s.len())?;

        self.start_push();
        self.line.push_str(s);
        self.end_push();

        Ok(())
    }

    /// Returns the cmdline in progress without nul termination.
    pub fn as_str(&self) -> &str {
        self.line.as_str()
    }

    /// Returns the cmdline in progress as CString.
    pub fn as_cstring(&self) -> Result<CString> {
        CString::new(self.line.clone()).map_err(|_| Error::InvalidAscii)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_hello_world() {
        let mut cl = Cmdline::new(100);
        assert_eq!(cl.as_str(), "");
        assert!(cl.insert("hello", "world").is_ok());
        assert_eq!(cl.as_str(), "hello=world");
        assert_eq!(cl.len(), "hello=world".len());
        assert!(!cl.is_empty());

        // Test clone.
        let cl2 = cl.clone();
        assert_eq!(cl2.as_str(), cl.as_str());
    }

    #[test]
    fn insert_multi() {
        let mut cl = Cmdline::new(100);
        assert!(cl.insert("hello", "world").is_ok());
        assert!(cl.insert("foo", "bar").is_ok());
        assert_eq!(cl.as_str(), "hello=world foo=bar");
    }

    #[test]
    fn insert_space() {
        let mut cl = Cmdline::new(100);
        assert_eq!(cl.insert("a ", "b"), Err(Error::HasSpace));
        assert_eq!(cl.insert("a", "b "), Err(Error::HasSpace));
        assert_eq!(cl.insert("a ", "b "), Err(Error::HasSpace));
        assert_eq!(cl.insert(" a", "b"), Err(Error::HasSpace));
        assert_eq!(cl.as_str(), "");
    }

    #[test]
    fn insert_equals() {
        let mut cl = Cmdline::new(100);
        assert_eq!(cl.insert("a=", "b"), Err(Error::HasEquals));
        assert_eq!(cl.insert("a", "b="), Err(Error::HasEquals));
        assert_eq!(cl.insert("a=", "b "), Err(Error::HasEquals));
        assert_eq!(cl.insert("=a", "b"), Err(Error::HasEquals));
        assert_eq!(cl.insert("a", "=b"), Err(Error::HasEquals));
        assert_eq!(cl.as_str(), "");
    }

    #[test]
    fn insert_emoji() {
        assert_eq!(valid_str("💖"), Err(Error::InvalidAscii));

        let mut cl = Cmdline::new(100);
        assert_eq!(cl.insert("heart", "💖"), Err(Error::InvalidAscii));
        assert_eq!(cl.insert("💖", "love"), Err(Error::InvalidAscii));
        assert_eq!(cl.as_str(), "");
    }

    #[test]
    fn insert_string() {
        let mut cl = Cmdline::new(13);
        assert_eq!(cl.as_str(), "");
        assert!(cl.insert_str("noapic").is_ok());
        assert_eq!(cl.as_str(), "noapic");
        assert!(cl.insert_str("nopci").is_ok());
        assert_eq!(cl.as_str(), "noapic nopci");
        assert_eq!(cl.as_str(), cl.as_cstring().unwrap().to_str().unwrap());
    }

    #[test]
    fn insert_too_large() {
        let mut cl = Cmdline::new(4);
        assert_eq!(cl.insert("hello", "world"), Err(Error::TooLarge));
        assert_eq!(cl.insert("a", "world"), Err(Error::TooLarge));
        assert_eq!(cl.insert("hello", "b"), Err(Error::TooLarge));
        assert!(cl.insert("a", "b").is_ok());
        assert_eq!(cl.insert("a", "b"), Err(Error::TooLarge));
        assert_eq!(cl.insert_str("a"), Err(Error::TooLarge));
        assert_eq!(cl.as_str(), "a=b");

        let mut cl = Cmdline::new(10);
        assert!(cl.insert("ab", "ba").is_ok()); // adds 5 length
        assert_eq!(cl.insert("c", "da"), Err(Error::TooLarge)); // adds 5 (including space) length
        assert!(cl.insert("c", "d").is_ok()); // adds 4 (including space) length
    }

    #[test]
    fn display_errors() {
        assert_eq!(
            Error::CommandLineCopy.to_string().as_str(),
            "Failed to copy the command line string to guest memory"
        );
        assert_eq!(
            Error::CommandLineOverflow.to_string().as_str(),
            "Command line string overflows guest memory"
        );
        assert_eq!(
            Error::InvalidAscii.to_string().as_str(),
            "Command line string contains non-printable ASCII character"
        );
        assert_eq!(
            Error::HasSpace.to_string().as_str(),
            "Command line string contains a space"
        );
        assert_eq!(
            Error::HasEquals.to_string().as_str(),
            "Command line string contains an equals sign"
        );
        assert_eq!(
            Error::TooLarge.to_string().as_str(),
            "Command line inserting string would make command line too long"
        );
    }
}
