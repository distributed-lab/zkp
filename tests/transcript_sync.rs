#![allow(non_snake_case)]

#[macro_use]
extern crate zkp;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_xsk233::affine::Xsk233Affine as G1Affine;
use ark_xsk233::xsk233::Fr;
use rand::thread_rng;

use zkp::{toolbox::TranscriptProtocol, CompactProof, Transcript};

define_proof! {dleq, "Com(x, r1), Com(x, r2) Proof", (x, r1, r2), (A, B, H), (G) : A = (x * G + r1 * H), B = (x * G + r2 * H) }

#[test]
fn transcript_sync() {
    let G = G1Affine::generator();
    let H = G1Affine::rand(&mut thread_rng());

    // Prover's scope
    let mut transcript1 = Transcript::new(b"DLEQTest");

    let x = Fr::from(rand::random::<u64>());
    let r1 = Fr::from(rand::random::<u64>());
    let r2 = Fr::from(rand::random::<u64>());
    let A = (G * x + H * r1).into_affine();
    let B = (G * x + H * r2).into_affine();

    let (proof, points) = dleq::prove_compact(
        &mut transcript1,
        dleq::ProveAssignments {
            x: &x,
            r1: &r1,
            r2: &r2,
            A: &A,
            B: &B,
            G: &G,
            H: &H,
        },
    );

    let transcript_challenge_bytes_1 =
        <Transcript as TranscriptProtocol<G1Affine>>::get_challenge(&mut transcript1, b"DLEQTest");

    let proof_bytes = proof.to_bytes().unwrap();
    let parsed_proof: CompactProof<_> = CompactProof::from_bytes(&proof_bytes).unwrap();

    // Verifier logic
    let mut transcript2 = Transcript::new(b"DLEQTest");
    assert!(dleq::verify_compact(
        &parsed_proof,
        &mut transcript2,
        dleq::VerifyAssignments {
            A: &points.A,
            B: &points.B,
            G: &G,
            H: &H,
        },
    )
    .is_ok());

    let transcript_challenge_bytes_2 =
        <Transcript as TranscriptProtocol<G1Affine>>::get_challenge(&mut transcript2, b"DLEQTest");

    assert_eq!(transcript_challenge_bytes_1, transcript_challenge_bytes_2);

    let (proof, points) = dleq::prove_compact(
        &mut transcript2,
        dleq::ProveAssignments {
            x: &x,
            r1: &r1,
            r2: &r2,
            A: &A,
            B: &B,
            G: &G,
            H: &H,
        },
    );

    let proof_bytes = proof.to_bytes().unwrap();
    let parsed_proof: CompactProof<_> = CompactProof::from_bytes(&proof_bytes).unwrap();

    assert!(dleq::verify_compact(
        &parsed_proof,
        &mut transcript1,
        dleq::VerifyAssignments {
            A: &points.A,
            B: &points.B,
            G: &G,
            H: &H,
        },
    )
    .is_ok());

    let transcript_challenge_bytes_3 =
        <Transcript as TranscriptProtocol<G1Affine>>::get_challenge(&mut transcript1, b"DLEQTest");

    let transcript_challenge_bytes_4 =
        <Transcript as TranscriptProtocol<G1Affine>>::get_challenge(&mut transcript2, b"DLEQTest");

    assert_eq!(transcript_challenge_bytes_3, transcript_challenge_bytes_4);
    assert_ne!(transcript_challenge_bytes_1, transcript_challenge_bytes_3);
    assert_ne!(transcript_challenge_bytes_2, transcript_challenge_bytes_4);
}
