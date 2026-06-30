use std::io::{self, BufRead};

use encoding_rs::{UTF_16BE, UTF_16LE};

/// Byte encoding of the source file, detected from a leading byte-order mark at
/// open. Drives how lines are split (terminator code-unit width) and how raw
/// line bytes are decoded to UTF-8 before emit. This is byte handling only --
/// no log-content parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum LineEncoding {
    /// No BOM: treated as UTF-8 (or any single-byte superset). Passthrough.
    #[default]
    Utf8,
    /// Leading `EF BB BF`: UTF-8 with a BOM. The BOM is stripped from the first
    /// emitted line only.
    Utf8Bom,
    /// Leading `FF FE`: UTF-16 little-endian.
    Utf16Le,
    /// Leading `FE FF`: UTF-16 big-endian.
    Utf16Be,
}

impl LineEncoding {
    /// Width of one code unit in source bytes.
    fn code_unit_width(self) -> usize {
        match self {
            LineEncoding::Utf8 | LineEncoding::Utf8Bom => 1,
            LineEncoding::Utf16Le | LineEncoding::Utf16Be => 2,
        }
    }

    /// The source bytes of the line-feed (`\n`) code unit. Splitting scans for
    /// this sequence on code-unit-aligned boundaries.
    fn newline_terminator(self) -> &'static [u8] {
        match self {
            LineEncoding::Utf8 | LineEncoding::Utf8Bom => &[b'\n'],
            LineEncoding::Utf16Le => &[0x0A, 0x00],
            LineEncoding::Utf16Be => &[0x00, 0x0A],
        }
    }
}

/// Detect the line encoding from the first few bytes of a file (a byte-order
/// mark). `head` should be the first up-to-3 bytes of the file. The BOM bytes
/// remain part of the source byte stream -- detection never consumes them.
pub(super) fn detect_encoding(head: &[u8]) -> LineEncoding {
    if head.starts_with(&[0xEF, 0xBB, 0xBF]) {
        LineEncoding::Utf8Bom
    } else if head.starts_with(&[0xFF, 0xFE]) {
        LineEncoding::Utf16Le
    } else if head.starts_with(&[0xFE, 0xFF]) {
        LineEncoding::Utf16Be
    } else {
        LineEncoding::Utf8
    }
}

/// Outcome of a single-line read from the underlying reader.
pub(super) struct LineReadOutcome {
    /// Total bytes advanced past in the underlying reader, including any
    /// overflow bytes that were truncated from `line_buf`. The caller adds
    /// this to the tailer's current-file offset.
    pub(super) consumed: usize,
    /// True if the line exceeded the cap and bytes after `max_bytes` were
    /// discarded from `line_buf` (but still consumed from the reader).
    pub(super) truncated: bool,
}

/// Read one line (source bytes up to and including the terminating line-feed
/// code unit) into `line_buf`, capturing at most `max_bytes` bytes. If the line
/// is longer than the cap, captures the first `max_bytes` source bytes and
/// keeps draining until the terminator so subsequent reads start at a fresh
/// logical line.
///
/// `encoding` selects the terminator: a single `0x0A` for UTF-8, or the 2-byte
/// `\n` code unit for UTF-16 (`0A 00` LE, `00 0A` BE). The 2-byte terminator
/// (or a partial trailing code unit) may straddle a `fill_buf` chunk boundary;
/// a leftover code unit prefix is carried across iterations so a code unit is
/// never split. `consumed` always counts SOURCE bytes, including the full
/// terminator -- the caller's offset stays source-relative.
///
/// The returned `line_buf` holds raw SOURCE bytes; decode it with `decode_line`
/// before trimming/emitting.
pub(super) fn read_one_line<R: BufRead>(
    reader: &mut R,
    line_buf: &mut Vec<u8>,
    max_bytes: usize,
    encoding: LineEncoding,
) -> io::Result<LineReadOutcome> {
    let width = encoding.code_unit_width();
    let terminator = encoding.newline_terminator();
    let mut consumed = 0;
    let mut truncated = false;
    // Source bytes read past from the reader that form an incomplete trailing
    // code unit at a chunk boundary. These are already accounted in `consumed`
    // and appended to `line_buf` (subject to the cap); they are re-scanned as
    // the prefix of the next chunk so a code unit is never split.
    let mut carry: Vec<u8> = Vec::new();

    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            // EOF. A trailing partial code unit (carry) has already been
            // consumed and captured; report whatever we advanced past.
            return Ok(LineReadOutcome {
                consumed,
                truncated,
            });
        }

        // Logical scan position is `carry.len()` source bytes into the current
        // line's tail. We need to find, on a code-unit-aligned boundary, the
        // first complete terminator within carry ++ chunk. We only ever consume
        // from `chunk`; `carry` is already consumed.
        let carry_len = carry.len();
        let joined_len = carry_len + chunk.len();

        // Iterate code-unit-aligned positions across the joined view. `pos` is
        // an offset into the joined `carry ++ chunk` stream. On a match,
        // `terminator_end_in_chunk` is the chunk offset just past the
        // terminator's last byte (carry bytes are never re-consumed).
        let mut terminator_end_in_chunk: Option<usize> = None;
        let mut pos = 0usize;
        while pos + width <= joined_len {
            let unit_is_terminator = terminator.iter().enumerate().all(|(i, &tb)| {
                let abs = pos + i;
                let byte = if abs < carry_len {
                    carry[abs]
                } else {
                    chunk[abs - carry_len]
                };
                byte == tb
            });
            if unit_is_terminator {
                // The terminator spans joined offsets [pos, pos+width). Since
                // carry is always shorter than one code unit, pos+width always
                // exceeds carry_len, so this end is a valid (>=1) chunk offset.
                terminator_end_in_chunk = Some(pos + width - carry_len);
                break;
            }
            pos += width;
        }

        if let Some(end_in_chunk) = terminator_end_in_chunk {
            // Capture chunk[..end_in_chunk] into line_buf (subject to cap),
            // consume it, and finish.
            append_capped(line_buf, &chunk[..end_in_chunk], max_bytes, &mut truncated);
            reader.consume(end_in_chunk);
            consumed += end_in_chunk;
            return Ok(LineReadOutcome {
                consumed,
                truncated,
            });
        }

        // No terminator in the joined view. Capture the chunk and rebuild the
        // carry from it FIRST -- both read the live `chunk` borrow, so they must
        // happen before `reader.consume` takes a fresh mutable borrow. Consuming
        // the ENTIRE chunk guarantees forward progress (a 1-byte BufReader can
        // never stall). The trailing bytes of `carry ++ chunk` that do not yet
        // complete a code unit (`joined_len % width`) become the new carry so
        // the next chunk completes them -- a code unit is never split.
        append_capped(line_buf, chunk, max_bytes, &mut truncated);
        let chunk_len = chunk.len();

        let trailing_partial = joined_len % width;
        // The trailing partial bytes are the last `trailing_partial` bytes of
        // the joined `carry ++ chunk` view. Rebuild carry from them; these
        // bytes are already (about to be) in `consumed` and `line_buf`, kept
        // only to re-scan alignment against the next chunk.
        let mut joined_tail: Vec<u8> = Vec::with_capacity(trailing_partial);
        if trailing_partial > 0 {
            let start = joined_len - trailing_partial;
            for abs in start..joined_len {
                let byte = if abs < carry_len {
                    carry[abs]
                } else {
                    chunk[abs - carry_len]
                };
                joined_tail.push(byte);
            }
        }

        reader.consume(chunk_len);
        consumed += chunk_len;
        carry = joined_tail;
    }
}

/// Append `src` to `line_buf` honoring the `max_bytes` cap, setting
/// `truncated` if any source bytes had to be dropped from the buffer. Dropped
/// bytes are still considered consumed by the caller (cap is measured in source
/// bytes).
fn append_capped(line_buf: &mut Vec<u8>, src: &[u8], max_bytes: usize, truncated: &mut bool) {
    let remaining_cap = max_bytes.saturating_sub(line_buf.len());
    let take_n = remaining_cap.min(src.len());
    if take_n < src.len() {
        *truncated = true;
    }
    line_buf.extend_from_slice(&src[..take_n]);
}

/// Decode a raw source line (as filled by `read_one_line`) into UTF-8 bytes,
/// in place. After this returns, `buf` holds valid UTF-8 ready for
/// `trim_line_ending` and emit. Byte handling only -- no content parsing.
///
/// - `Utf8`: left untouched (passthrough; may already be valid UTF-8 or an
///   arbitrary single-byte superset, preserved exactly as today).
/// - `Utf8Bom`: a leading `EF BB BF` is stripped when present. Pass
///   `is_first_line = true` only for the first line of the file, where the BOM
///   lives.
/// - `Utf16Le` / `Utf16Be`: decoded with `encoding_rs` (no BOM handling -- the
///   BOM code unit is part of the first line's bytes and is dropped by the
///   decoder's replacement of the leading U+FEFF; see note below).
pub(super) fn decode_line(buf: &mut Vec<u8>, encoding: LineEncoding, is_first_line: bool) {
    match encoding {
        LineEncoding::Utf8 => {}
        LineEncoding::Utf8Bom => {
            if is_first_line && buf.starts_with(&[0xEF, 0xBB, 0xBF]) {
                buf.drain(..3);
            }
        }
        LineEncoding::Utf16Le | LineEncoding::Utf16Be => {
            let enc = if encoding == LineEncoding::Utf16Le {
                UTF_16LE
            } else {
                UTF_16BE
            };
            // decode_without_bom_handling does NOT strip a leading U+FEFF; on
            // the first line the BOM code unit decodes to U+FEFF (a zero-width
            // no-break space). Strip it explicitly so the emitted text is clean.
            let (decoded, _had_errors) = enc.decode_without_bom_handling(buf);
            let text = decoded.as_ref();
            let text = if is_first_line {
                text.strip_prefix('\u{FEFF}').unwrap_or(text)
            } else {
                text
            };
            let bytes = text.as_bytes().to_vec();
            *buf = bytes;
        }
    }
}

/// Strip a trailing `\n` and optionally a preceding `\r` from the buffer.
/// Leaves empty buffers empty; a buffer containing only line terminators
/// becomes empty (emitted as an empty log line). Runs on DECODED UTF-8 bytes,
/// so a UTF-16 CRLF (`0D 00 0A 00`) that decoded to `\r\n` trims cleanly.
pub(super) fn trim_line_ending(buf: &mut Vec<u8>) {
    if buf.last().copied() == Some(b'\n') {
        buf.pop();
        if buf.last().copied() == Some(b'\r') {
            buf.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    /// Drive read_one_line over a reader with an artificially tiny BufReader
    /// capacity so terminators and code units straddle chunk boundaries.
    fn read_all_lines(bytes: &[u8], encoding: LineEncoding, cap: usize) -> (Vec<Vec<u8>>, usize) {
        let mut reader = BufReader::with_capacity(cap, bytes);
        let mut lines = Vec::new();
        let mut total_consumed = 0usize;
        let mut first = true;
        loop {
            let mut buf = Vec::new();
            let outcome = read_one_line(&mut reader, &mut buf, 1 << 20, encoding).unwrap();
            if outcome.consumed == 0 {
                break;
            }
            total_consumed += outcome.consumed;
            decode_line(&mut buf, encoding, first);
            first = false;
            trim_line_ending(&mut buf);
            lines.push(buf);
        }
        (lines, total_consumed)
    }

    fn utf16le(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    fn utf16be(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    }

    #[test]
    fn utf16le_bom_decodes_danish() {
        // BOM + "æøå\nsecond\n"
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend_from_slice(&utf16le("æøå\nsecond\n"));
        // Tiny cap forces the 2-byte terminator across chunk boundaries.
        for cap in [1usize, 2, 3, 5, 8, 16, 1024] {
            let (lines, consumed) = read_all_lines(&bytes, LineEncoding::Utf16Le, cap);
            assert_eq!(lines.len(), 2, "cap={cap}");
            assert_eq!(lines[0], "æøå".as_bytes(), "cap={cap}");
            assert_eq!(lines[1], b"second", "cap={cap}");
            assert!(!lines[0].contains(&0), "no interleaved NUL, cap={cap}");
            assert_eq!(consumed, bytes.len(), "consumed source bytes, cap={cap}");
        }
    }

    #[test]
    fn utf16be_bom_decodes_danish() {
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend_from_slice(&utf16be("æøå\nsecond\n"));
        for cap in [1usize, 2, 3, 5, 8, 16, 1024] {
            let (lines, consumed) = read_all_lines(&bytes, LineEncoding::Utf16Be, cap);
            assert_eq!(lines.len(), 2, "cap={cap}");
            assert_eq!(lines[0], "æøå".as_bytes(), "cap={cap}");
            assert_eq!(lines[1], b"second", "cap={cap}");
            assert!(!lines[0].contains(&0), "no interleaved NUL, cap={cap}");
            assert_eq!(consumed, bytes.len(), "consumed source bytes, cap={cap}");
        }
    }

    #[test]
    fn plain_utf8_passthrough() {
        let bytes = b"hello\nworld\n";
        let (lines, consumed) = read_all_lines(bytes, LineEncoding::Utf8, 4);
        assert_eq!(lines, vec![b"hello".to_vec(), b"world".to_vec()]);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn utf8_bom_stripped_first_line_only() {
        // BOM + "first\nbom?\n" -- BOM only stripped from line 1.
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"first\nbom?\n");
        let (lines, consumed) = read_all_lines(&bytes, LineEncoding::Utf8Bom, 4);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], b"first");
        assert_eq!(lines[1], b"bom?");
        assert_eq!(consumed, bytes.len());

        // A BOM mid-stream (e.g. line 2 begins with EF BB BF) is NOT stripped.
        let mut bytes2 = vec![0xEF, 0xBB, 0xBF];
        bytes2.extend_from_slice(b"a\n");
        bytes2.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        bytes2.extend_from_slice(b"b\n");
        let (lines2, _) = read_all_lines(&bytes2, LineEncoding::Utf8Bom, 64);
        assert_eq!(lines2[0], b"a");
        assert_eq!(lines2[1], vec![0xEF, 0xBB, 0xBF, b'b']);
    }

    #[test]
    fn utf16le_crlf_no_stray_cr() {
        // "line\r\n" in UTF-16LE => ... 0D 00 0A 00. Decodes to "line\r\n",
        // trim removes both \r and \n.
        let bytes = utf16le("line\r\nnext\r\n");
        for cap in [1usize, 2, 3, 4, 7, 1024] {
            let (lines, consumed) = read_all_lines(&bytes, LineEncoding::Utf16Le, cap);
            assert_eq!(lines.len(), 2, "cap={cap}");
            assert_eq!(lines[0], b"line", "no stray CR, cap={cap}");
            assert_eq!(lines[1], b"next", "cap={cap}");
            assert_eq!(consumed, bytes.len(), "cap={cap}");
        }
    }

    #[test]
    fn detect_encoding_boms() {
        assert_eq!(detect_encoding(&[0xEF, 0xBB, 0xBF]), LineEncoding::Utf8Bom);
        assert_eq!(detect_encoding(&[0xFF, 0xFE]), LineEncoding::Utf16Le);
        assert_eq!(detect_encoding(&[0xFE, 0xFF]), LineEncoding::Utf16Be);
        assert_eq!(detect_encoding(b"plain"), LineEncoding::Utf8);
        assert_eq!(detect_encoding(&[]), LineEncoding::Utf8);
        // A lone 0xFF (no 0xFE) is not a UTF-16LE BOM.
        assert_eq!(detect_encoding(&[0xFF]), LineEncoding::Utf8);
    }
}
