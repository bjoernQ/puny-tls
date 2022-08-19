#[derive(Debug, Clone)]
pub struct Buffer<const C: usize> {
    data: [u8; C],
    len: usize,
    write_index: usize,
    read_index: usize,
}

impl<const C: usize> Buffer<C> {
    pub fn new() -> Buffer<C> {
        Buffer {
            data: [0u8; C],
            len: 0,
            write_index: 0,
            read_index: 0,
        }
    }

    pub fn get_unchecked(&self, index: usize) -> u8 {
        self.data[index]
    }

    pub fn new_from_slice(slice: &[u8]) -> Buffer<C> {
        let mut res = Buffer {
            data: [0u8; C],
            len: slice.len(),
            write_index: slice.len(),
            read_index: 0,
        };

        res.data[..slice.len()].copy_from_slice(slice);
        res
    }

    pub fn slice(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    pub fn remaining_slice(&self) -> &[u8] {
        &self.data[self.read_index..self.len]
    }

    pub fn already_consumed_slice(&self) -> &[u8] {
        &self.data[..self.read_index]
    }

    pub fn push(&mut self, bytes: &[u8]) -> usize {
        let fitting = usize::min(bytes.len(), C - self.write_index);
        self.data[self.write_index..][..fitting].copy_from_slice(&bytes[..fitting]);
        self.len += fitting;
        self.write_index += fitting;

        if fitting != bytes.len() {
            panic!("buffer overflow");
        }

        fitting
    }

    pub fn push_byte(&mut self, byte: u8) {
        self.push(&[byte]);
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_full(&self) -> bool {
        self.len == C
    }

    pub fn is_exhausted(&self) -> bool {
        self.read_index >= self.len
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.write_index = 0;
        self.read_index = 0
    }

    pub fn split_right(self, index: usize) -> Buffer<C> {
        Buffer::new_from_slice(&self.data[index..self.len])
    }

    pub fn read(&mut self) -> Option<u8> {
        let res = if self.read_index < self.len {
            Some(self.data[self.read_index])
        } else {
            None
        };

        if res.is_some() {
            self.read_index += 1;
        }

        res
    }
}

impl<const C: usize> core::fmt::Write for Buffer<C> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        self.push(bytes);
        Ok(())
    }
}

impl<const C: usize> AsMut<[u8]> for Buffer<C> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.slice_mut()
    }
}

impl<const C: usize> AsRef<[u8]> for Buffer<C> {
    fn as_ref(&self) -> &[u8] {
        self.slice()
    }
}

impl<const C: usize> aes_gcm::aead::Buffer for Buffer<C> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        self.push(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.len = len - 1;
    }
}
