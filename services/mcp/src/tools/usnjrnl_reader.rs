//! Bounded streaming reader for carved `$UsnJrnl:$J` records.
//!
//! Only the NTFS record decoder from `ntfs-core` is required here. Keeping this
//! small adapter local avoids pulling the upstream reporting stack (and its
//! unrelated `SQLite` dependency) into the evidence-facing MCP binary.

use std::io::{self, Read, Seek, SeekFrom};

use ntfs_core::usn::{parse_usn_record_v2, parse_usn_record_v3, UsnRecord};

const BUFFER_BYTES: usize = 64 * 1024;
const MIN_RECORD_BYTES: usize = 8;
const MAX_RECORD_BYTES: usize = 64 * 1024;

pub(super) struct UsnJournalReader<R: Read + Seek> {
    reader: R,
    buffer: Vec<u8>,
    buffer_len: usize,
    buffer_offset: usize,
    stream_position: u64,
    total_size: u64,
    done: bool,
}

impl<R: Read + Seek> UsnJournalReader<R> {
    pub(super) fn new(mut reader: R) -> io::Result<Self> {
        let total_size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            reader,
            buffer: vec![0; BUFFER_BYTES],
            buffer_len: 0,
            buffer_offset: 0,
            stream_position: 0,
            total_size,
            done: false,
        })
    }

    fn fill_buffer(&mut self) -> io::Result<bool> {
        if self.stream_position >= self.total_size {
            self.done = true;
            return Ok(false);
        }

        if self.buffer_offset > 0 && self.buffer_offset < self.buffer_len {
            let remaining = self.buffer_len - self.buffer_offset;
            self.buffer
                .copy_within(self.buffer_offset..self.buffer_len, 0);
            self.buffer_len = remaining;
        } else if self.buffer_offset >= self.buffer_len {
            self.buffer_len = 0;
        }
        self.buffer_offset = 0;

        let available = BUFFER_BYTES - self.buffer_len;
        if available == 0 {
            return Ok(true);
        }
        let read = self
            .reader
            .read(&mut self.buffer[self.buffer_len..self.buffer_len + available])?;
        if read == 0 {
            self.done = true;
            return Ok(self.buffer_len > 0);
        }
        self.buffer_len += read;
        self.stream_position += read as u64;
        Ok(true)
    }

    fn ensure_bytes(&mut self, required: usize) -> io::Result<bool> {
        while self.buffer_len.saturating_sub(self.buffer_offset) < required {
            let before = (self.buffer_len, self.buffer_offset, self.stream_position);
            if !self.fill_buffer()? {
                return Ok(false);
            }
            let after = (self.buffer_len, self.buffer_offset, self.stream_position);
            if after == before {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn skip_zero_padding(&mut self) -> io::Result<bool> {
        loop {
            if !self.ensure_bytes(MIN_RECORD_BYTES)? {
                return Ok(false);
            }
            let next = &self.buffer[self.buffer_offset..self.buffer_offset + 8];
            if next.iter().any(|byte| *byte != 0) {
                return Ok(true);
            }
            self.buffer_offset += 8;
        }
    }
}

impl<R: Read + Seek> Iterator for UsnJournalReader<R> {
    type Item = io::Result<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done && self.buffer_offset >= self.buffer_len {
                return None;
            }
            match self.skip_zero_padding() {
                Ok(true) => {}
                Ok(false) => return None,
                Err(error) => {
                    self.done = true;
                    self.buffer_offset = self.buffer_len;
                    return Some(Err(error));
                }
            }

            let header = &self.buffer[self.buffer_offset..self.buffer_offset + 8];
            let record_len =
                u32::from_le_bytes(header[0..4].try_into().expect("four-byte length")) as usize;
            if !(MIN_RECORD_BYTES..=MAX_RECORD_BYTES).contains(&record_len) {
                self.buffer_offset += 8;
                continue;
            }
            match self.ensure_bytes(record_len) {
                Ok(true) => {}
                Ok(false) => {
                    self.buffer_offset = self.buffer_offset.saturating_add(8);
                    continue;
                }
                Err(error) => {
                    self.done = true;
                    self.buffer_offset = self.buffer_len;
                    return Some(Err(error));
                }
            }

            let version = u16::from_le_bytes([
                self.buffer[self.buffer_offset + 4],
                self.buffer[self.buffer_offset + 5],
            ]);
            let record_end = self.buffer_offset + record_len;
            let record = &self.buffer[self.buffer_offset..record_end];
            self.buffer_offset = self.buffer_offset.saturating_add((record_len + 7) & !7);

            let parsed = match version {
                2 => parse_usn_record_v2(record),
                3 => parse_usn_record_v3(record),
                _ => continue,
            };
            if let Ok(record) = parsed {
                return Some(Ok(record));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::UsnJournalReader;
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    struct PersistentReadError;

    struct PartialThenError {
        delivered_header: bool,
    }

    impl Read for PersistentReadError {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic read failure"))
        }
    }

    impl Seek for PersistentReadError {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            Ok(match position {
                SeekFrom::End(_) => 8,
                _ => 0,
            })
        }
    }

    impl Read for PartialThenError {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.delivered_header {
                return Err(io::Error::other("synthetic follow-up failure"));
            }
            self.delivered_header = true;
            let mut header = Vec::with_capacity(8);
            header.extend_from_slice(&16_u32.to_le_bytes());
            header.extend_from_slice(&2_u16.to_le_bytes());
            header.extend_from_slice(&[0_u8; 2]);
            buffer[..header.len()].copy_from_slice(&header);
            Ok(header.len())
        }
    }

    impl Seek for PartialThenError {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            Ok(match position {
                SeekFrom::End(_) => 16,
                _ => 0,
            })
        }
    }

    #[test]
    fn hostile_invalid_headers_do_not_recurse_or_hang() {
        let invalid_headers = [0xff_u8; 8].repeat(100_000);
        let mut reader = UsnJournalReader::new(Cursor::new(invalid_headers)).unwrap();
        assert!(reader.next().is_none());
    }

    #[test]
    fn persistent_io_error_is_emitted_once_then_iteration_stops() {
        let mut reader = UsnJournalReader::new(PersistentReadError).unwrap();
        assert!(reader.next().expect("one error").is_err());
        assert!(reader.next().is_none());
    }

    #[test]
    fn error_after_partial_record_is_emitted_once_then_iteration_stops() {
        let source = PartialThenError {
            delivered_header: false,
        };
        let mut reader = UsnJournalReader::new(source).unwrap();
        assert!(reader.next().expect("one error").is_err());
        assert!(reader.next().is_none());
    }
}
