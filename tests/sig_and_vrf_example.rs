// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

extern crate rand;

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use rand::{thread_rng, CryptoRng, RngCore};

// extern crate curve25519_dalek;
// use curve25519_dalek::constants as dalek_constants;
// use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
// use curve25519_dalek::scalar::Scalar;

use xsk233_ark::affine::{Xsk233Affine as G1Affine, Xsk233Affine};
use xsk233_ark::xsk233::Fr;

#[macro_use]
extern crate zkp;
pub use zkp::Transcript;

define_proof! {sig_proof, "Sig", (x), (A), (B) : A = (x * B) }
define_proof! {vrf_proof, "VRF", (x), (A, G, H), (B) : A = (x * B), G = (x * H) }

/// Defines how the construction interacts with the transcript.
trait TranscriptProtocol {
    fn append_message_example(&mut self, message: &[u8]);
    fn hash_to_group(self) -> G1Affine;
}

impl TranscriptProtocol for Transcript {
    fn append_message_example(&mut self, message: &[u8]) {
        self.append_message(b"msg", message);
    }
    fn hash_to_group(mut self) -> G1Affine {
        let mut bytes = [0u8; 8];
        self.challenge_bytes(b"output", &mut bytes);

        let field_value = Fr::from(i64::from_le_bytes(bytes));

        (G1Affine::generator() * field_value).into_affine()
    }
}

#[derive(Clone)]
pub struct SecretKey(Fr);

impl SecretKey {
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
        SecretKey(Fr::rand(rng))
    }
}

#[derive(Copy, Clone)]
pub struct PublicKey(G1Affine);

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(sk: &'a SecretKey) -> PublicKey {
        let pk = Xsk233Affine::generator() * sk.0;
        PublicKey(pk.into_affine())
    }
}

pub struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

impl From<SecretKey> for KeyPair {
    fn from(sk: SecretKey) -> KeyPair {
        let pk = PublicKey::from(&sk);
        KeyPair { sk, pk }
    }
}

pub struct Signature(sig_proof::BatchableProof<G1Affine>);

pub struct VrfOutput(G1Affine);

pub struct VrfProof(vrf_proof::CompactProof<Fr>);

impl KeyPair {
    fn public_key(&self) -> PublicKey {
        self.pk
    }

    fn sign(&self, sig_transcript: Transcript) -> Signature {
        let (proof, _points) = sig_proof::prove_batchable(
            sig_transcript,
            sig_proof::ProveAssignments {
                x: &self.sk.0,
                A: &self.pk.0,
                B: &G1Affine::generator(),
            },
        );

        Signature(proof)
    }

    #[allow(non_snake_case)]
    fn vrf(
        &self,
        mut function_transcript: Transcript,
        message: &[u8],
        proof_transcript: Transcript,
    ) -> (VrfOutput, VrfProof) {
        // Use function_transcript to hash the message to a point H
        function_transcript.append_message_example(message);
        let H = function_transcript.hash_to_group();

        // Compute the VRF output G and form a proof
        let G = (H * self.sk.0).into_affine();
        let (proof, points) = vrf_proof::prove_compact(
            proof_transcript,
            vrf_proof::ProveAssignments {
                x: &self.sk.0,
                A: &self.pk.0,
                B: &G1Affine::generator(),
                G: &G,
                H: &H,
            },
        );

        (VrfOutput(points.G), VrfProof(proof))
    }
}

impl Signature {
    fn verify_with_message(
        &self,
        message: &[u8],
        pubkey: &PublicKey,
        mut sig_transcript: Transcript,
    ) -> Result<(), ()> {
        sig_transcript.append_message_example(message);
        self.verify(pubkey, sig_transcript)
    }

    fn verify(&self, pubkey: &PublicKey, sig_transcript: Transcript) -> Result<(), ()> {
        sig_proof::verify_batchable(
            &self.0,
            sig_transcript,
            sig_proof::VerifyAssignments {
                A: &pubkey.0,
                B: &G1Affine::generator(),
            },
        )
        .map_err(|_discard_error_info_in_test_code| ())
    }
}

impl VrfOutput {
    #[allow(non_snake_case)]
    fn verify(
        &self,
        mut function_transcript: Transcript,
        message: &[u8],
        pubkey: &PublicKey,
        proof_transcript: Transcript,
        proof: &VrfProof,
    ) -> Result<(), ()> {
        // Use function_transcript to hash the message to a point H
        function_transcript.append_message_example(message);
        let H = function_transcript.hash_to_group();

        vrf_proof::verify_compact(
            &proof.0,
            proof_transcript,
            vrf_proof::VerifyAssignments {
                A: &pubkey.0,
                B: &G1Affine::generator(),
                G: &self.0,
                H: &H,
            },
        )
        .map_err(|_discard_error_info_in_test_code| ())
    }
}

#[test]
fn create_and_verify_sig() {
    let domain_sep = b"My Sig Application";
    let msg1 = b"Test Message 1";
    let msg2 = b"Test Message 2";

    let kp1 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk1 = kp1.public_key();
    let kp2 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk2 = kp2.public_key();

    let mut t1 = Transcript::new(domain_sep);
    t1.append_message_example(msg1);

    let mut t2 = Transcript::new(domain_sep);
    t2.append_message_example(msg2);

    let sig1 = kp1.sign(t1);
    let sig2 = kp2.sign(t2);

    // Check that each signature verifies
    assert!(sig1
        .verify_with_message(msg1, &pk1, Transcript::new(domain_sep),)
        .is_ok());
    assert!(sig2
        .verify_with_message(msg2, &pk2, Transcript::new(domain_sep),)
        .is_ok());

    // Check that verification with the wrong pubkey fails
    assert!(sig1
        .verify_with_message(msg1, &pk2, Transcript::new(domain_sep),)
        .is_err());
    assert!(sig2
        .verify_with_message(msg2, &pk1, Transcript::new(domain_sep),)
        .is_err());

    // Check that verification with the wrong message fails
    assert!(sig1
        .verify_with_message(msg2, &pk1, Transcript::new(domain_sep),)
        .is_err());
    assert!(sig2
        .verify_with_message(msg1, &pk2, Transcript::new(domain_sep),)
        .is_err());

    // Check that verification with the wrong domain separator fails
    assert!(sig1
        .verify_with_message(msg1, &pk1, Transcript::new(b"Wrong"),)
        .is_err());
    assert!(sig2
        .verify_with_message(msg2, &pk2, Transcript::new(b"Wrong"),)
        .is_err());
}

#[test]
#[ignore]
fn create_and_verify_bigsig() {
    let domain_sep = b"My Sig Application";
    let mut large_msg = Vec::new();
    large_msg.resize(4294967, 1u8);

    let kp = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk = kp.public_key();

    let mut t = Transcript::new(domain_sep);
    t.append_message_example(large_msg.as_slice());

    let sig = kp.sign(t);

    // Check that the signature verifies (& doesn't panic inside Merlin)
    assert!(sig
        .verify_with_message(&large_msg[..], &pk, Transcript::new(domain_sep),)
        .is_ok());
}

#[test]
fn counterparty_signature_chain() {
    let domain_sep = b"Counterparty Example";

    let msg1a = b"In this test, two counterparties exchange signatures.";
    let msg2a = b"However, the counterparties sign and verify messages";
    let msg1b = b"using stateful transcript objects.";
    let msg2b = b"When party 1 signs, the party 1 transcript changes;";
    let msg1c = b"when party 2 verifies, the party 2 transcript syncs.";
    let msg2c = b"In this way, the transcript states ratchet stateful signatures.";

    let kp1 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk1 = kp1.public_key();
    let kp2 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk2 = kp2.public_key();

    let mut trans1 = Transcript::new(domain_sep);
    let mut trans2 = Transcript::new(domain_sep);

    // Round a, Party 1 -----> Party 2
    trans1.append_message_example(msg1a);
    let sig1a = kp1.sign(trans1.clone());
    trans2.append_message_example(msg1a);
    assert!(sig1a.verify(&pk1, trans2.clone()).is_ok());
    // Round a, Party 2 -----> Party 1
    trans2.append_message_example(msg2a);
    let sig2a = kp2.sign(trans2.clone());
    trans1.append_message_example(msg2a);
    assert!(sig2a.verify(&pk2, trans1.clone()).is_ok());

    // Round b, Party 1 -----> Party 2
    trans1.append_message_example(msg1b);
    let sig1b = kp1.sign(trans1.clone());
    trans2.append_message_example(msg1b);
    assert!(sig1b.verify(&pk1, trans2.clone()).is_ok());
    // // Round b, Party 2 -----> Party 1
    trans2.append_message_example(msg2b);
    let sig2b = kp2.sign(trans2.clone());
    trans1.append_message_example(msg2b);
    assert!(sig2b.verify(&pk2, trans1.clone()).is_ok());

    // Round c, Party 1 -----> Party 2
    trans1.append_message_example(msg1c);
    let sig1c = kp1.sign(trans1.clone());
    trans2.append_message_example(msg1c);
    assert!(sig1c.verify(&pk1, trans2.clone()).is_ok());
    // Round c, Party 2 -----> Party 1
    trans2.append_message_example(msg2c);
    let sig2c = kp2.sign(trans2.clone());
    trans1.append_message_example(msg2c);
    assert!(sig2c.verify(&pk2, trans1.clone()).is_ok());
}

#[test]
fn create_and_verify_vrf() {
    let domain_sep = b"My VRF Application";
    let msg1 = b"Test Message 1";
    let msg2 = b"Test Message 2";

    let kp1 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk1 = kp1.public_key();
    let kp2 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk2 = kp2.public_key();

    let (output1, proof1) = kp1.vrf(
        Transcript::new(domain_sep),
        &msg1[..],
        Transcript::new(domain_sep),
    );

    let (output2, proof2) = kp2.vrf(
        Transcript::new(domain_sep),
        &msg2[..],
        Transcript::new(domain_sep),
    );

    // Check that each VRF output was correctly produced
    assert!(output1
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk1,
            Transcript::new(domain_sep),
            &proof1,
        )
        .is_ok());
    assert!(output2
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk2,
            Transcript::new(domain_sep),
            &proof2,
        )
        .is_ok());

    // Check that verification with the wrong pubkey fails
    assert!(output1
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk2, // swap pubkey
            Transcript::new(domain_sep),
            &proof1,
        )
        .is_err());
    assert!(output2
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk1, // swap pubkey
            Transcript::new(domain_sep),
            &proof2,
        )
        .is_err());

    // Check that verification with the wrong output fails
    assert!(output2 // swap output
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk1,
            Transcript::new(domain_sep),
            &proof1,
        )
        .is_err());
    assert!(output1 // swap output
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk2,
            Transcript::new(domain_sep),
            &proof2,
        )
        .is_err());

    // Check that verification with the wrong domain separator fails
    assert!(output1
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk1,
            Transcript::new(b"A different application"), // swap dom-sep
            &proof1,
        )
        .is_err());
    assert!(output2
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk2,
            Transcript::new(b"A different application"), // swap dom-sep
            &proof2,
        )
        .is_err());
}
