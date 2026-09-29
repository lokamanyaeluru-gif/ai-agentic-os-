//! Bounded rolling ring buffer for diagnostic stdio stream capture.
//!
//! Enforces a strict memory ceiling (default 64 KiB) per diagnostic stream.
//! If output exceeds the ceiling, older bytes are discarded while preserving
//! the most recent bytes without memory exhaustion.

use std::collections::VecDeque;

/// Standard capacity for supervisor worker diagnostic capture (64 KiB).
pub const DEFAULT_LOG_BUFFER_CAPACITY: usize = 64 * 1024;

/// Rolling FIFO byte buffer with fixed maximum capacity.
#[derive(Debug, Clone)]
pub struct RollingLogBuffer {
    buffer: VecDeque<u8>,
    capacity: usize,
    total_bytes_received: usize,
}

impl Default for RollingLogBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_LOG_BUFFER_CAPACITY)
    }
}

impl RollingLogBuffer {
    /// Creates a new rolling buffer with the specified capacity in bytes.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "Capacity must be greater than zero");
        Self {
            buffer: VecDeque::with_capacity(capacity.min(4096)),
            capacity,
            total_bytes_received: 0,
        }
    }

    /// Appends incoming bytes to the buffer, discarding oldest bytes if capacity is exceeded.
    pub fn push(&mut self, data: &[u8]) {
        self.total_bytes_received += data.len();

        if data.len() >= self.capacity {
            // Data itself exceeds entire capacity: keep only trailing `capacity` bytes
            self.buffer.clear();
            let start = data.len() - self.capacity;
            self.buffer.extend(&data[start..]);
            return;
        }

        let overflow = (self.buffer.len() + data.len()).saturating_sub(self.capacity);
        if overflow > 0 {
            self.buffer.drain(..overflow);
        }

        self.buffer.extend(data);
    }

    /// Returns the currently stored bytes as a contiguous Vec<u8>.
    pub fn as_bytes(&self) -> Vec<u8> {
        let (first, second) = self.buffer.as_slices();
        let mut out = Vec::with_capacity(first.len() + second.len());
        out.extend_from_slice(first);
        out.extend_from_slice(second);
        out
    }

    /// Converts the current buffer content into a lossy UTF-8 string.
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.as_bytes()).to_string()
    }

    /// Returns the number of bytes currently stored in the buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns true if the buffer contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Returns the total number of bytes received over the stream's lifetime.
    pub fn total_bytes_received(&self) -> usize {
        self.total_bytes_received
    }

    /// Returns true if bytes were truncated due to exceeding capacity.
    pub fn was_truncated(&self) -> bool {
        self.total_bytes_received > self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_pushes_within_capacity() {
        let mut buf = RollingLogBuffer::new(10);
        buf.push(b"hello");
        buf.push(b" world");
        assert_eq!(buf.as_bytes(), b"ello world");
        assert_eq!(buf.len(), 10);
        assert_eq!(buf.total_bytes_received(), 11);
        assert!(buf.was_truncated());
    }

    #[test]
    fn test_large_push_exceeds_capacity() {
        let mut buf = RollingLogBuffer::new(5);
        buf.push(b"abcdefghij");
        assert_eq!(buf.as_bytes(), b"fghij");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.total_bytes_received(), 10);
    }

    #[test]
    fn test_exact_capacity() {
        let mut buf = RollingLogBuffer::new(5);
        buf.push(b"12345");
        assert_eq!(buf.as_bytes(), b"12345");
        assert!(!buf.was_truncated());
    }
}
