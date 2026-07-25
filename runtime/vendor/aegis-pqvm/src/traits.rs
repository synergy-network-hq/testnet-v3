/// Common trait for Key Encapsulation Mechanisms.
pub trait KeyEncapsulation {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn keypair(&self) -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(&self, pk: &Self::PublicKey) -> (Self::SharedSecret, Self::Ciphertext);
    fn decapsulate(&self, ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Self::SharedSecret;
}

/// Common trait for signature schemes.
pub trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;

    fn keypair(&self) -> (Self::PublicKey, Self::SecretKey);
    fn sign(&self, message: &[u8], secret_key: &Self::SecretKey) -> Self::Signature;
    fn verify(
        &self,
        message: &[u8],
        signature: &Self::Signature,
        public_key: &Self::PublicKey,
    ) -> bool;
}

/// Trait used for on-boot self tests.
pub trait SelfTest {
    fn run_self_tests() -> Result<(), &'static str>;
}
