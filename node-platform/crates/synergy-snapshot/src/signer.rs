use synergy_crypto::{
    AegisSigner, AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext,
};

pub trait SnapshotSigningProvider: AegisSigner {
    fn snapshot_key_id(&self) -> &KeyId;
    fn snapshot_algorithm(&self) -> SignatureAlgorithm;

    fn sign_snapshot(
        &self,
        context: &SigningContext,
        transcript: &[u8],
    ) -> Result<Signature, String> {
        self.sign(self.snapshot_key_id(), context, transcript)
            .map_err(|error| error.to_string())
    }
}

pub trait SnapshotVerificationProvider: AegisVerifier {
    fn governed_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, String>;
}
