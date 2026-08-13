//! Terminal escape-sequence normalization, applied at line ingest.
//!
//! A log format's anchor is its shape — a leading timestamp, a level, a
//! bracketed request id. Terminal colour codes are presentation, not format,
//! and they sit in front of exactly the bytes an anchor matches: a source that
//! writes `ESC[2m2026-08-06T…` never matches a pattern derived from its plain
//! text, so every one of its lines looks like a continuation and the whole
//! stream collapses into a single unbounded event. The codes are also pure
//! storage cost — nothing downstream reads them.
//!
//! Stripping happens once, where a line enters the agent, so the payload
//! matched against start patterns is the same payload that gets buffered and
//! shipped. A line with no escape byte is returned untouched and unmoved.
//!
//! Recognised sequences:
//! - CSI — `ESC [`, parameters, then a final byte in `0x40..=0x7E` (SGR
//!   colour, cursor movement, erase-line).
//! - OSC — `ESC ]`, then a payload terminated by BEL or ST (`ESC \`).
//! - Any other two-byte escape, and a trailing lone `ESC`.
//!
//! An unterminated sequence consumes the rest of the line: a truncated
//! control sequence has no readable text left in it either.

use std::borrow::Cow;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

/// Strip escape sequences from an owned line, in place. A line with no `ESC`
/// byte is returned as-is, with no copy and no reallocation.
pub fn strip_owned(mut line: Vec<u8>) -> Vec<u8> {
    if !contains_escape(&line) {
        return line;
    }
    strip_in_place(&mut line);
    line
}

/// Strip escape sequences from borrowed text. Borrows through unchanged when
/// there is nothing to strip.
pub fn strip_str(line: &str) -> Cow<'_, str> {
    if !contains_escape(line.as_bytes()) {
        return Cow::Borrowed(line);
    }
    let mut bytes = line.as_bytes().to_vec();
    strip_in_place(&mut bytes);
    Cow::Owned(String::from_utf8_lossy(&bytes).into_owned())
}

fn contains_escape(bytes: &[u8]) -> bool {
    bytes.contains(&ESC)
}

/// Compact the line by copying every non-escape byte down over the sequences
/// being dropped. Removal only, so the write cursor never passes the read
/// cursor and the buffer is merely truncated at the end.
fn strip_in_place(line: &mut Vec<u8>) {
    let mut write = 0;
    let mut read = 0;

    while read < line.len() {
        if line[read] == ESC {
            read = escape_end(line, read);
            continue;
        }
        line[write] = line[read];
        write += 1;
        read += 1;
    }

    line.truncate(write);
}

/// Index just past the escape sequence that starts at `start` (an `ESC`).
///
/// The scan never splits a multi-byte character: UTF-8 lead and continuation
/// bytes are all `>= 0x80`, outside both the CSI final-byte range and the OSC
/// terminators, so a sequence boundary always lands between characters.
fn escape_end(bytes: &[u8], start: usize) -> usize {
    match bytes.get(start + 1) {
        Some(b'[') => {
            let mut i = start + 2;
            while i < bytes.len() && !matches!(bytes[i], 0x40..=0x7e) {
                i += 1;
            }
            // Consume the final byte as well when the sequence was terminated.
            (i + 1).min(bytes.len())
        }
        Some(b']') => {
            let mut i = start + 2;
            while i < bytes.len() {
                match bytes[i] {
                    BEL => return i + 1,
                    ESC if bytes.get(i + 1) == Some(&b'\\') => return i + 2,
                    _ => i += 1,
                }
            }
            bytes.len()
        }
        Some(_) => start + 2,
        None => start + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_sgr_colour_so_the_timestamp_leads_the_line() {
        let coloured = "\x1b[2m2026-08-06T15:03:17Z\x1b[0m \x1b[32m INFO\x1b[0m msg";
        let stripped = strip_str(coloured);

        assert_eq!(stripped, "2026-08-06T15:03:17Z  INFO msg");
        assert!(
            regex::Regex::new(r"^\d{4}-").unwrap().is_match(&stripped),
            "a mined start pattern must anchor the stripped line"
        );
        assert!(
            !regex::Regex::new(r"^\d{4}-").unwrap().is_match(coloured),
            "negative control: the same pattern cannot anchor the coloured line"
        );
    }

    /// Kill-test: a line with no escape byte must come back byte-identical
    /// AND untouched — same allocation, so normalization costs nothing on the
    /// overwhelming majority of lines.
    #[test]
    fn line_without_escapes_is_returned_unmoved() {
        let line = b"2026-08-06 INFO plain line with [brackets] and 0x1b spelled out".to_vec();
        let before = line.as_ptr();
        let expected = line.clone();

        let stripped = strip_owned(line);

        assert_eq!(stripped, expected);
        assert_eq!(
            stripped.as_ptr(),
            before,
            "no reallocation for a clean line"
        );
        assert!(matches!(strip_str("plain text"), Cow::Borrowed(_)));
    }

    #[test]
    fn strips_csi_cursor_and_erase_sequences() {
        assert_eq!(strip_str("before\x1b[2Kafter"), "beforeafter");
        assert_eq!(strip_str("\x1b[1;31;40mred\x1b[m"), "red");
        assert_eq!(strip_str("\x1b[H\x1b[Jcleared"), "cleared");
    }

    #[test]
    fn strips_osc_terminated_by_bel_or_st() {
        assert_eq!(strip_str("\x1b]0;window title\x07body"), "body");
        assert_eq!(strip_str("\x1b]8;;https://example.com\x1b\\link"), "link");
    }

    #[test]
    fn strips_two_byte_and_dangling_escapes() {
        // Charset select and reverse-index are two-byte escapes.
        assert_eq!(strip_str("\x1b(Btext"), "Btext");
        assert_eq!(strip_str("a\x1bMb"), "ab");
        // A line cut mid-sequence loses the remainder; there is no text in it.
        assert_eq!(strip_str("tail\x1b"), "tail");
        assert_eq!(strip_str("tail\x1b[3"), "tail");
    }

    #[test]
    fn preserves_multibyte_text_around_sequences() {
        assert_eq!(strip_str("\x1b[33m✔ héllo → done\x1b[0m"), "✔ héllo → done");
    }

    #[test]
    fn stripping_is_idempotent() {
        let once = strip_str("\x1b[32mgreen\x1b[0m").into_owned();
        assert_eq!(strip_str(&once), once);
    }

    #[test]
    fn invalid_utf8_bytes_survive_stripping() {
        let mut line = b"\x1b[32m".to_vec();
        line.extend_from_slice(&[0xC0, 0xFF, 0xFE]);
        assert_eq!(strip_owned(line), vec![0xC0, 0xFF, 0xFE]);
    }
}
