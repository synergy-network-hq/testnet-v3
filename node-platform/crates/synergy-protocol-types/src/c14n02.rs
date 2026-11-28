//! QACE-C14N-02 primitives (QACE v0.4 pp108–109), shared by typed schemas.
//! No JSON, generic object hashing, profile inference or cryptographic primitive.
//! Each owner supplies its exact ordered schema and authenticated finite bounds.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    SizeLimit,
    CountLimit,
    InvalidAscii,
    InvalidBoolean,
    InvalidOption,
    Truncated,
    TrailingBytes,
    Allocation,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "C14N-02 rejected: {self:?}")
    }
}
impl std::error::Error for Error {}

pub struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
    error: Option<Error>,
}
impl Encoder {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum: max_bytes,
            error: None,
        }
    }
    /// Exact QACE H wrapper, once: U16(2), length-prefixed ASCII domain, value.
    /// The selected owning profile pins the literal tag; this is not selection.
    pub fn with_domain(tag: &str, max_bytes: usize) -> Result<Self, Error> {
        let mut out = Self::new(max_bytes);
        if tag.is_empty() {
            return Err(Error::InvalidAscii);
        }
        out.u16(2)?;
        out.ascii(tag, 128)?;
        Ok(out)
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.error.get_or_insert(error);
        Err(self.error.unwrap())
    }
    fn reserve(&mut self, extra: usize) -> Result<(), Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self
            .bytes
            .len()
            .checked_add(extra)
            .is_none_or(|n| n > self.maximum)
        {
            return self.fail(Error::SizeLimit);
        }
        if self.bytes.try_reserve_exact(extra).is_err() {
            return self.fail(Error::Allocation);
        }
        Ok(())
    }
    pub fn fixed<const N: usize>(&mut self, value: &[u8; N]) -> Result<(), Error> {
        self.reserve(N)?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.fixed(&[value])
    }
    pub fn u16(&mut self, value: u16) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }
    pub fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }
    pub fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }
    pub fn u128(&mut self, value: u128) -> Result<(), Error> {
        self.fixed(&value.to_be_bytes())
    }
    pub fn boolean(&mut self, value: bool) -> Result<(), Error> {
        self.u8(u8::from(value))
    }
    pub fn bytes(&mut self, value: &[u8], maximum: usize) -> Result<(), Error> {
        if value.len() > maximum || u32::try_from(value.len()).is_err() {
            return self.fail(Error::SizeLimit);
        }
        let Some(extra) = value.len().checked_add(4) else {
            return self.fail(Error::SizeLimit);
        };
        self.reserve(extra)?;
        self.bytes
            .extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }
    pub fn ascii(&mut self, value: &str, maximum: usize) -> Result<(), Error> {
        if !value.is_ascii() || value.contains('\0') {
            return self.fail(Error::InvalidAscii);
        }
        self.bytes(value.as_bytes(), maximum)
    }
    pub fn option<T>(
        &mut self,
        value: &Option<T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        match value {
            None => self.u8(0),
            Some(v) => {
                self.u8(1)?;
                if let Err(e) = encode(self, v) {
                    return self.fail(e);
                };
                Ok(())
            }
        }
    }
    pub fn vector<T>(
        &mut self,
        values: &[T],
        maximum: usize,
        mut encode: impl FnMut(&mut Self, &T) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if values.len() > maximum || u32::try_from(values.len()).is_err() {
            return self.fail(Error::CountLimit);
        }
        self.u32(values.len() as u32)?;
        for value in values {
            if let Err(e) = encode(self, value) {
                return self.fail(e);
            }
        }
        Ok(())
    }
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        self.error.map_or(Ok(self.bytes), Err)
    }
}

pub struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
    maximum: usize,
    error: Option<Error>,
}
impl<'a> Decoder<'a> {
    pub fn new(input: &'a [u8], max_bytes: usize) -> Result<Self, Error> {
        if input.len() > max_bytes {
            return Err(Error::SizeLimit);
        }
        Ok(Self {
            input,
            position: 0,
            maximum: max_bytes,
            error: None,
        })
    }
    fn fail<T>(&mut self, error: Error) -> Result<T, Error> {
        self.error.get_or_insert(error);
        Err(self.error.unwrap())
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let Some(end) = self.position.checked_add(length) else {
            return self.fail(Error::Truncated);
        };
        if end > self.input.len() {
            return self.fail(Error::Truncated);
        }
        let result = &self.input[self.position..end];
        self.position = end;
        Ok(result)
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Truncated)
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    pub fn u128(&mut self) -> Result<u128, Error> {
        Ok(u128::from_be_bytes(self.fixed()?))
    }
    pub fn boolean(&mut self) -> Result<bool, Error> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => self.fail(Error::InvalidBoolean),
        }
    }
    pub fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let length = self.u32()? as usize;
        if length > maximum {
            return self.fail(Error::SizeLimit);
        }
        self.take(length)
    }
    pub fn ascii(&mut self, maximum: usize) -> Result<&'a str, Error> {
        let value = self.bytes(maximum)?;
        if !value.is_ascii() || value.contains(&0) {
            return self.fail(Error::InvalidAscii);
        }
        std::str::from_utf8(value).map_err(|_| Error::InvalidAscii)
    }
    pub fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => match decode(self) {
                Ok(v) => Ok(Some(v)),
                Err(e) => self.fail(e),
            },
            _ => self.fail(Error::InvalidOption),
        }
    }
    /// The schema supplies its finite count bound and minimum element wire size.
    /// Check count, remaining bytes and destination allocation BEFORE reserving.
    pub fn vector<T>(
        &mut self,
        maximum: usize,
        min_item_wire_bytes: usize,
        mut decode: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let count = self.u32()? as usize;
        if count > maximum || (count > 0 && min_item_wire_bytes == 0) {
            return self.fail(Error::CountLimit);
        }
        if count
            .checked_mul(min_item_wire_bytes)
            .is_none_or(|n| n > self.remaining())
        {
            return self.fail(Error::Truncated);
        }
        if count
            .checked_mul(std::mem::size_of::<T>())
            .is_none_or(|n| n > self.maximum)
        {
            return self.fail(Error::SizeLimit);
        }
        let mut result = Vec::new();
        if result.try_reserve_exact(count).is_err() {
            return self.fail(Error::Allocation);
        }
        for _ in 0..count {
            match decode(self) {
                Ok(value) => result.push(value),
                Err(e) => return self.fail(e),
            }
        }
        Ok(result)
    }
    pub fn remaining(&self) -> usize {
        self.input.len() - self.position
    }
    pub fn finish(self) -> Result<(), Error> {
        if let Some(e) = self.error {
            Err(e)
        } else if self.remaining() != 0 {
            Err(Error::TrailingBytes)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independently_spelled_primitive_vector_and_exact_wrapper() {
        let mut e = Encoder::with_domain("X", 256).unwrap();
        e.u16(0x0102).unwrap();
        e.u32(0x03040506).unwrap();
        e.u64(7).unwrap();
        e.u128(8).unwrap();
        e.boolean(true).unwrap();
        e.option::<u8>(&None, |e, v| e.u8(*v)).unwrap();
        e.option(&Some(9u8), |e, v| e.u8(*v)).unwrap();
        e.vector(&[10u8, 11], 2, |e, v| e.u8(*v)).unwrap();
        let bytes = e.finish().unwrap();
        let mut expected = vec![0, 2, 0, 0, 0, 1, b'X', 1, 2, 3, 4, 5, 6];
        expected.extend([0, 0, 0, 0, 0, 0, 0, 7]);
        expected.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        expected.extend([1, 0, 1, 9, 0, 0, 0, 2, 10, 11]);
        assert_eq!(bytes, expected);
        let mut d = Decoder::new(&bytes, 256).unwrap();
        assert_eq!(d.u16().unwrap(), 2);
        assert_eq!(d.ascii(1).unwrap(), "X");
        assert_eq!(d.u16().unwrap(), 0x0102);
        assert_eq!(d.u32().unwrap(), 0x03040506);
        assert_eq!(d.u64().unwrap(), 7);
        assert_eq!(d.u128().unwrap(), 8);
        assert!(d.boolean().unwrap());
        assert_eq!(d.option(|d| d.u8()).unwrap(), None);
        assert_eq!(d.option(|d| d.u8()).unwrap(), Some(9));
        assert_eq!(d.vector(2, 1, |d| d.u8()).unwrap(), [10, 11]);
        d.finish().unwrap();
    }
    #[test]
    fn resource_and_canonical_failures_poison_finalization() {
        let mut e = Encoder::new(3);
        assert_eq!(e.u32(1), Err(Error::SizeLimit));
        assert_eq!(e.finish(), Err(Error::SizeLimit));
        let mut e = Encoder::new(32);
        assert_eq!(e.ascii("a\0b", 3), Err(Error::InvalidAscii));
        assert!(e.finish().is_err());
        let mut e = Encoder::new(32);
        assert_eq!(
            e.vector(&[1u8, 2], 1, |e, v| e.u8(*v)),
            Err(Error::CountLimit)
        );
        assert!(e.finish().is_err());
        let mut d = Decoder::new(&[2], 8).unwrap();
        assert_eq!(d.boolean(), Err(Error::InvalidBoolean));
        assert!(d.finish().is_err());
        let mut d = Decoder::new(&[2], 8).unwrap();
        assert_eq!(d.option(|d| d.u8()), Err(Error::InvalidOption));
        assert!(d.finish().is_err());
        let mut d = Decoder::new(&[0, 0, 0, 2, 1], 64).unwrap();
        assert_eq!(d.vector(2, 1, |d| d.u8()), Err(Error::Truncated));
        assert!(d.finish().is_err());
        let mut d = Decoder::new(&[0xff; 4], 64).unwrap();
        assert_eq!(d.vector(2, 1, |d| d.u8()), Err(Error::CountLimit));
        assert!(d.finish().is_err());
        assert_eq!(
            Decoder::new(&[1], 1).unwrap().finish(),
            Err(Error::TrailingBytes)
        );
        assert!(Decoder::new(&[1, 2], 1).is_err());
    }
}
