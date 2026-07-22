//! Issuer-Hiding, BBS-based anonymous credentials using BLS12-381.

pub mod blst_wrappers;

pub use blst_wrappers::{
    multi_pairing, G1Affine, G1Projective, G2Affine, G2Projective, PrecomputedScalar, Scalar,
};
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Supported algorithms for evaluating multi-scalar exponentiations.
/// There is no reason to use Basic (other than debugging)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiexpMode {
    /// Compute multiexponentiations using naive iterative sum.
    Basic,
    /// Compute multiexponentiations using Pippenger's algorithm.
    Advanced,
}

pub mod msm;
pub mod one_of_l_commitments;

pub use msm::{compute_C, multiexp_advanced, multiexp_basic};

/// Public parameters for the BBS scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub h: Vec<G1Projective>,
}

impl Parameters {
    /// Generate random parameters for supporting up to `message_count` messages.
    pub fn new(message_count: usize, mut rng: impl CryptoRngCore) -> Self {
        let g1 = G1Projective::generator();
        let g2 = G2Projective::generator();
        let h = (0..message_count).map(|_| G1Projective::random(&mut rng)).collect();
        Self { g1, g2, h }
    }
}

/// Authority's Secret Key for issuing BBS credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(pub Scalar);

impl SecretKey {
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        Self(Scalar::random(&mut rng))
    }

    pub fn public_key(&self, params: &Parameters) -> PublicKey {
        PublicKey { pk2: params.g2 * self.0, pk1: params.g1 * self.0 }
    }
}

/// Authority's Public Key for verifying credentials and proofs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub pk2: G2Projective,
    pub pk1: G1Projective,
}

/// A BBS credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub A: G1Projective,
    pub e: Scalar,
}

/// A zero-knowledge proof of selective disclosure of a BBS credential.
#[derive(Clone, Debug)]
pub struct SelectiveDisclosureProof {
    pub A_prime: G1Projective,
    pub C_bar: G1Projective,
    pub A_bar: G1Projective,
    pub challenge: Scalar,
    pub z_hidden_messages: BTreeMap<usize, Scalar>,
    pub z_e: Scalar,
    pub z_r1: Scalar,
    pub z_r2: Scalar,
}

// ============================================================================
// 1. Generate a BBS Credential
// ============================================================================
pub mod signing {
    use super::*;

    /// Issue a BBS credential on a vector of messages (scalars).
    pub fn generate_credential(
        params: &Parameters,
        sk: &SecretKey,
        messages: &[Scalar],
        mut rng: impl CryptoRngCore,
    ) -> Credential {
        assert_eq!(messages.len(), params.h.len(), "Message count must match parameters");

        let e = Scalar::random(&mut rng);
        let c = msm::compute_C(params, messages, MultiexpMode::Advanced);
        let x_plus_e = sk.0 + e;
        let x_plus_e_inv = x_plus_e.invert().expect("x + e should not be zero");
        let a = c * x_plus_e_inv;
        // This could be optimized by computing `a` using one MSM,
        // without computing `c` first

        Credential { A: a, e }
    }
}

// ============================================================================
// 2. Verify a BBS credential
// ============================================================================
pub mod verification {
    use super::*;

    /// Verify a BBS credential against a vector of messages.
    pub fn verify_credential(
        params: &Parameters,
        pk: &PublicKey,
        messages: &[Scalar],
        credential: &Credential,
    ) -> bool {
        if messages.len() != params.h.len() {
            return false;
        }

        let mut bases = Vec::with_capacity(2 + messages.len());
        let mut scalars = Vec::with_capacity(2 + messages.len());

        bases.push(params.g1);
        scalars.push(Scalar::one());

        for i in 0..messages.len() {
            bases.push(params.h[i]);
            scalars.push(messages[i]);
        }

        bases.push(credential.A);
        scalars.push(-credential.e);

        let a_e_plus_c = multiexp_advanced(&bases, &scalars);

        let g1_left = credential.A.to_affine();
        let g2_left = pk.pk2.to_affine();
        let g1_right_neg = (-a_e_plus_c).to_affine();
        let g2_right = params.g2.to_affine();

        let pairs = [(&g1_left, &g2_left), (&g1_right_neg, &g2_right)];
        multi_pairing(&pairs)
    }
}

// ============================================================================
// 3. Selective Disclosure Proofs
// ============================================================================
pub mod proving {
    use super::*;

    /// Helper function to compute the Fiat-Shamir challenge using Sha256.
    fn hash_to_challenge(
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        com1: &G1Projective,
        com2: &G1Projective,
        context: &[u8],
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(A_prime.to_affine().to_compressed());
        hasher.update(C_bar.to_affine().to_compressed());
        hasher.update(A_bar.to_affine().to_compressed());
        hasher.update(com1.to_affine().to_compressed());
        hasher.update(com2.to_affine().to_compressed());
        hasher.update(context);

        let result = hasher.finalize();
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(&result);
        buffer[31] &= 0x3f;
        Scalar::from_bytes(&buffer).unwrap_or(Scalar::one())
    }

    pub fn generate_selective_disclosure_proof(
        params: &Parameters,
        credential: &Credential,
        messages: &[Scalar],
        revealed_indices: &BTreeSet<usize>,
        context: &[u8],
        mut rng: impl CryptoRngCore,
    ) -> SelectiveDisclosureProof {
        let total_messages = messages.len();
        assert_eq!(total_messages, params.h.len());

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let r1_inv = r1.invert().expect("r1 should not be zero");
        let A_prime = credential.A * (r1 * r2);

        let mut bases = Vec::with_capacity(1 + messages.len());
        let mut scalars = Vec::with_capacity(1 + messages.len());

        bases.push(params.g1);
        scalars.push(r1);

        for i in 0..messages.len() {
            bases.push(params.h[i]);
            scalars.push(messages[i] * r1);
        }

        let C_bar = multiexp_advanced(&bases, &scalars);
        let A_bar = multiexp_advanced(&[C_bar, A_prime], &[r2, -credential.e]);

        let mut hidden_indices = BTreeSet::new();
        for i in 0..total_messages {
            if !revealed_indices.contains(&i) {
                hidden_indices.insert(i);
            }
        }

        let tau_r1 = Scalar::random(&mut rng);
        let tau_r2 = Scalar::random(&mut rng);
        let tau_e = Scalar::random(&mut rng);
        let mut tau_hidden = BTreeMap::new();
        for &j in &hidden_indices {
            tau_hidden.insert(j, Scalar::random(&mut rng));
        }

        let com1 = multiexp_advanced(&[C_bar, A_prime], &[tau_r2, -tau_e]);

        let mut bases = Vec::with_capacity(1 + hidden_indices.len());
        bases.push(C_bar);
        let mut scalars = Vec::with_capacity(1 + hidden_indices.len());
        scalars.push(tau_r1);
        for &j in &hidden_indices {
            bases.push(params.h[j]);
            scalars.push(-tau_hidden[&j]);
        }
        let com2 = multiexp_advanced(&bases, &scalars);

        let challenge = hash_to_challenge(&A_prime, &C_bar, &A_bar, &com1, &com2, context);

        let z_r1 = tau_r1 + challenge * r1_inv;
        let z_r2 = tau_r2 + challenge * r2;
        let z_e = tau_e + challenge * credential.e;
        let mut z_hidden_messages = BTreeMap::new();
        for &j in &hidden_indices {
            let z_m = tau_hidden[&j] + challenge * messages[j];
            z_hidden_messages.insert(j, z_m);
        }

        SelectiveDisclosureProof {
            A_prime,
            C_bar,
            A_bar,
            challenge,
            z_hidden_messages,
            z_e,
            z_r1,
            z_r2,
        }
    }
}

// ============================================================================
// 4. Selective Disclosure Verification Module
// ============================================================================
pub mod proof_verification {
    use super::*;

    /// Helper function to compute the cryptographic challenge using Sha256.
    fn hash_to_challenge(
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        com1: &G1Projective,
        com2: &G1Projective,
        context: &[u8],
    ) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(A_prime.to_affine().to_compressed());
        hasher.update(C_bar.to_affine().to_compressed());
        hasher.update(A_bar.to_affine().to_compressed());
        hasher.update(com1.to_affine().to_compressed());
        hasher.update(com2.to_affine().to_compressed());
        hasher.update(context);

        let result = hasher.finalize();
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(&result);
        buffer[31] &= 0x3f;
        Scalar::from_bytes(&buffer).unwrap_or(Scalar::one())
    }

    pub fn verify_selective_disclosure_proof(
        params: &Parameters,
        pk: &PublicKey,
        revealed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
        proof: &SelectiveDisclosureProof,
    ) -> bool {
        let computed_com1 = multiexp_advanced(
            &[proof.A_prime, proof.C_bar, proof.A_bar],
            &[-proof.z_e, proof.z_r2, -proof.challenge],
        );

        let mut bases = Vec::with_capacity(2 + params.h.len());
        let mut scalars = Vec::with_capacity(2 + params.h.len());

        bases.push(proof.C_bar);
        scalars.push(proof.z_r1);

        bases.push(params.g1);
        scalars.push(-proof.challenge);

        for i in 0..params.h.len() {
            bases.push(params.h[i]);
            if revealed_messages.contains_key(&i) {
                let m_i = revealed_messages[&i];
                scalars.push(-(m_i * proof.challenge));
            } else {
                let z_m = proof.z_hidden_messages[&i];
                scalars.push(-z_m);
            }
        }
        let computed_com2 = multiexp_advanced(&bases, &scalars);

        let computed_challenge = hash_to_challenge(
            &proof.A_prime,
            &proof.C_bar,
            &proof.A_bar,
            &computed_com1,
            &computed_com2,
            context,
        );

        computed_challenge == proof.challenge
    }
}

impl Credential {
    pub fn generate_credential(
        params: &Parameters,
        sk: &SecretKey,
        messages: &[Scalar],
        rng: impl CryptoRngCore,
    ) -> Self {
        signing::generate_credential(params, sk, messages, rng)
    }

    pub fn verify(&self, params: &Parameters, pk: &PublicKey, messages: &[Scalar]) -> bool {
        verification::verify_credential(params, pk, messages, self)
    }
}

impl SelectiveDisclosureProof {
    pub fn prove(
        params: &Parameters,
        credential: &Credential,
        messages: &[Scalar],
        revealed_indices: &BTreeSet<usize>,
        context: &[u8],
        rng: impl CryptoRngCore,
    ) -> Self {
        proving::generate_selective_disclosure_proof(
            params,
            credential,
            messages,
            revealed_indices,
            context,
            rng,
        )
    }

    pub fn verify(
        &self,
        params: &Parameters,
        pk: &PublicKey,
        revealed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
    ) -> bool {
        proof_verification::verify_selective_disclosure_proof(
            params,
            pk,
            revealed_messages,
            context,
            self,
        )
    }
}

// ============================================================================
// 5. Issuer-Hiding Anonymous Credentials
// ============================================================================
pub mod issuer_hiding {
    use super::*;

    /// Choose between four different schemes/modes.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum IssuerHidingMode {
        /// Naive OR proof -- fast verification variant
        NaiveFast,
        /// Naive OR proof -- short proof variant
        NaiveShort,
        /// Groth-Kohlweiss
        GK,
        /// Stacked Sigmas
        StackedSigmas,
    }

    /// Issuer-hiding proofs consist of a (randomized) credential show
    /// and a ZKPoK. The following is just the ZKPoK component.
    #[derive(Clone, Debug)]
    pub enum IssuerHidingZKPoK {
        NaiveFast {
            com1: [u8; 48],
            com2: [u8; 48],
            or_commitments: Vec<[u8; 48]>,
            or_challenges: Vec<Scalar>,
            or_responses: Vec<Scalar>,
            z_hidden_messages: BTreeMap<usize, Scalar>,
            z_e: Scalar,
            z_r1: Scalar,
            z_r2: Scalar,
        },
        NaiveShort {
            challenge: Scalar,
            or_challenges: Vec<Scalar>,
            or_responses: Vec<Scalar>,
            z_hidden_messages: BTreeMap<usize, Scalar>,
            z_e: Scalar,
            z_r1: Scalar,
            z_r2: Scalar,
        },
        GK {
            com1: Vec<[u8; 48]>,
            com4: Vec<[u8; 48]>,
            challenge: Scalar,
            f: Vec<Scalar>,
            z1: Vec<Scalar>,
            z2: Vec<Scalar>,
            z_star: Scalar,
            z_hidden_messages: BTreeMap<usize, Scalar>,
            z_e: Scalar,
            z_r1: Scalar,
            z_r2: Scalar,
        },
        StackedSigmas {
            params: Vec<[u8; 32]>,
            com: [u8; 32],
            decom: Vec<[u8; 32]>,
            challenge: Scalar,
            z: Scalar,
            z_hidden_messages: BTreeMap<usize, Scalar>,
            z_e: Scalar,
            z_r1: Scalar,
            z_r2: Scalar,
        },
    }

    /// An issuer-hiding proof.
    #[derive(Clone, Debug)]
    pub struct IssuerHidingProof {
        /// Randomized public key in G2 (\widetilde{pk})
        pub bpk: [u8; 96],
        /// Randomized public key in G1 (\widetilde{pk}')
        pub bpk_prime: [u8; 48],
        /// Credential show
        pub A_prime: [u8; 48],
        pub C_bar: [u8; 48],
        pub A_bar: [u8; 48],
        /// ZKPoK
        pub zkpok: IssuerHidingZKPoK,
    }

    /// Generate an issuer-hiding proof.
    pub fn generate_issuer_hiding_proof(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_indices: &BTreeSet<usize>,
        messages: &[Scalar],
        context: &[u8],
        credential: &Credential,
        my_pk_index: usize,
        mode: IssuerHidingMode,
        mut rng: impl rand_core::CryptoRngCore,
    ) -> IssuerHidingProof {
        assert_eq!(messages.len(), params.h.len());

        let l = policy.len();
        assert!(my_pk_index < l, "my_pk_index out of bounds");
        let my_pk = &policy[my_pk_index];

        // 1. Choose random t and compute randomized public keys
        let t = Scalar::random(&mut rng);
        // \widetilde{pk} = pk_i* + g2 * t
        let bpk = my_pk.pk2 + params.g2 * t;
        // \widetilde{pk}' = pk'_i* + g1 * t
        let bpk_prime = my_pk.pk1 + params.g1 * t;

        // 2. Compute adapted credential exponent e_tilde = e - t
        let tilde_e = credential.e - t;

        // 3. Choose random r1, r2
        // and compute blinded signature points A', C_bar, and \bar{A}
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let A_prime = credential.A * (r1 * r2);

        let mut bases = Vec::with_capacity(1 + messages.len());
        let mut scalars = Vec::with_capacity(1 + messages.len());

        bases.push(params.g1);
        scalars.push(r1);
        for i in 0..messages.len() {
            bases.push(params.h[i]);
            scalars.push(messages[i] * r1);
        }
        let C_bar = multiexp_advanced(&bases, &scalars);

        let A_bar = multiexp_advanced(&[C_bar, A_prime], &[r2, -tilde_e]);

        // 4. Generate the ZKPoK
        let zkpok = generate_issuer_hiding_zkpok(
            params,
            policy,
            disclosed_indices,
            messages,
            &A_prime,
            &C_bar,
            &A_bar,
            &bpk_prime,
            &r1,
            &r2,
            &tilde_e,
            &t,
            my_pk_index,
            context,
            mode,
            &mut rng,
        );

        IssuerHidingProof {
            bpk: bpk.to_affine().to_compressed(),
            bpk_prime: bpk_prime.to_affine().to_compressed(),
            A_prime: A_prime.to_affine().to_compressed(),
            C_bar: C_bar.to_affine().to_compressed(),
            A_bar: A_bar.to_affine().to_compressed(),
            zkpok,
        }
    }

    /// Generates the ZKPoK.
    pub fn generate_issuer_hiding_zkpok(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_indices: &BTreeSet<usize>,
        messages: &[Scalar],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        r1: &Scalar,
        r2: &Scalar,
        tilde_e: &Scalar,
        t: &Scalar,
        i_star: usize,
        context: &[u8],
        mode: IssuerHidingMode,
        rng: impl rand_core::CryptoRngCore,
    ) -> IssuerHidingZKPoK {
        match mode {
            IssuerHidingMode::NaiveFast => generate_issuer_hiding_zkpok_NaiveFast(
                params,
                policy,
                disclosed_indices,
                messages,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                r1,
                r2,
                tilde_e,
                t,
                i_star,
                context,
                rng,
            ),
            IssuerHidingMode::NaiveShort => generate_issuer_hiding_zkpok_NaiveShort(
                params,
                policy,
                disclosed_indices,
                messages,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                r1,
                r2,
                tilde_e,
                t,
                i_star,
                context,
                rng,
            ),
            IssuerHidingMode::GK => generate_issuer_hiding_zkpok_GK(
                params,
                policy,
                disclosed_indices,
                messages,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                r1,
                r2,
                tilde_e,
                t,
                i_star,
                context,
                rng,
            ),
            IssuerHidingMode::StackedSigmas => generate_issuer_hiding_zkpok_StackedSigmas(
                params,
                policy,
                disclosed_indices,
                messages,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                r1,
                r2,
                tilde_e,
                t,
                i_star,
                context,
                rng,
            ),
        }
    }

    /// Verify an issuer-hiding proof.
    pub fn verify_issuer_hiding_proof(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
        proof: &IssuerHidingProof,
        mode: IssuerHidingMode,
        mut rng: impl rand_core::CryptoRngCore,
    ) -> bool {
        let bpk_affine = match G2Affine::from_compressed(&proof.bpk) {
            Some(a) => a,
            None => return false,
        };
        let bpk = G2Projective::from(bpk_affine);

        let bpk_prime_affine = match G1Affine::from_compressed(&proof.bpk_prime) {
            Some(a) => a,
            None => return false,
        };
        let bpk_prime = G1Projective::from(bpk_prime_affine);

        let A_prime_affine = match G1Affine::from_compressed(&proof.A_prime) {
            Some(a) => a,
            None => return false,
        };
        let A_prime = G1Projective::from(A_prime_affine);

        let C_bar_affine = match G1Affine::from_compressed(&proof.C_bar) {
            Some(a) => a,
            None => return false,
        };
        let C_bar = G1Projective::from(C_bar_affine);

        let A_bar_affine = match G1Affine::from_compressed(&proof.A_bar) {
            Some(a) => a,
            None => return false,
        };
        let A_bar = G1Projective::from(A_bar_affine);

        if A_prime == G1Projective::identity() {
            return false;
        }

        // 1. Randomized check that e(g1, bpk) == e(bpk_prime, g2)
        // and e(A', bpk) == e(A_bar, g2). We choose a random scalar r
        // and check that e((A')^r g1, bpk) == e(A_bar^r bpk_prime, g2)
        let r = Scalar::random(&mut rng);
        let g1_left = (A_prime * r + params.g1).to_affine();
        let g2_left = bpk_affine;
        let g1_right_neg = (-(A_bar * r + bpk_prime)).to_affine();
        let g2_right = params.g2.to_affine();

        let pairs = [(&g1_left, &g2_left), (&g1_right_neg, &g2_right)];
        if !multi_pairing(&pairs) {
            return false;
        }

        // 2. Verify the ZKPoK
        verify_issuer_hiding_zkpok(
            params,
            policy,
            disclosed_messages,
            context,
            &A_prime,
            &C_bar,
            &A_bar,
            &bpk_prime,
            &proof.zkpok,
            mode,
            &mut rng,
        )
    }

    /// Verifies the ZKPoK.
    pub fn verify_issuer_hiding_zkpok(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        proof: &IssuerHidingZKPoK,
        mode: IssuerHidingMode,
        rng: impl rand_core::CryptoRngCore,
    ) -> bool {
        match (mode, proof) {
            (
                IssuerHidingMode::NaiveFast,
                IssuerHidingZKPoK::NaiveFast {
                    com1,
                    com2,
                    or_commitments,
                    or_challenges,
                    or_responses,
                    z_hidden_messages,
                    z_e,
                    z_r1,
                    z_r2,
                },
            ) => verify_issuer_hiding_zkpok_NaiveFast(
                params,
                policy,
                disclosed_messages,
                context,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                com1,
                com2,
                or_commitments,
                or_challenges,
                or_responses,
                z_hidden_messages,
                z_e,
                z_r1,
                z_r2,
                rng,
            ),
            (
                IssuerHidingMode::NaiveShort,
                IssuerHidingZKPoK::NaiveShort {
                    challenge,
                    or_challenges,
                    or_responses,
                    z_hidden_messages,
                    z_e,
                    z_r1,
                    z_r2,
                },
            ) => verify_issuer_hiding_zkpok_NaiveShort(
                params,
                policy,
                disclosed_messages,
                context,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                challenge,
                or_challenges,
                or_responses,
                z_hidden_messages,
                z_e,
                z_r1,
                z_r2,
            ),
            (
                IssuerHidingMode::GK,
                IssuerHidingZKPoK::GK {
                    com1,
                    com4,
                    challenge,
                    f,
                    z1,
                    z2,
                    z_star,
                    z_hidden_messages,
                    z_e,
                    z_r1,
                    z_r2,
                },
            ) => verify_issuer_hiding_zkpok_GK(
                params,
                policy,
                disclosed_messages,
                context,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                com1,
                com4,
                challenge,
                f,
                z1,
                z2,
                z_star,
                z_hidden_messages,
                z_e,
                z_r1,
                z_r2,
            ),
            (
                IssuerHidingMode::StackedSigmas,
                IssuerHidingZKPoK::StackedSigmas {
                    params: params_ss,
                    com: com_ss,
                    decom: decom_ss,
                    challenge,
                    z,
                    z_hidden_messages,
                    z_e,
                    z_r1,
                    z_r2,
                },
            ) => verify_issuer_hiding_zkpok_StackedSigmas(
                params,
                policy,
                disclosed_messages,
                context,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                params_ss,
                com_ss,
                decom_ss,
                challenge,
                z,
                z_hidden_messages,
                z_e,
                z_r1,
                z_r2,
            ),
            _ => false,
        }
    }

    // ============================================================================
    // Naive (aka CDN-style) OR proofs
    // ============================================================================

    // Helper to compute the Fiat-Shamir challenge for the Naive proofs.
    fn calculate_challenge_naive(
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        bpk_prime: &G1Projective,
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        com1: &G1Projective,
        com2: &G1Projective,
        or_commitments: &[G1Projective],
        context: &[u8],
    ) -> Scalar {
        let mut hasher = Sha256::new();

        for pk in policy {
            hasher.update(pk.pk1.to_affine().to_compressed());
        }

        for (&idx, msg) in disclosed_messages {
            hasher.update(&(idx as u64).to_be_bytes());
            hasher.update(&msg.to_bytes());
        }

        hasher.update(bpk_prime.to_affine().to_compressed());
        hasher.update(A_prime.to_affine().to_compressed());
        hasher.update(C_bar.to_affine().to_compressed());
        hasher.update(A_bar.to_affine().to_compressed());

        hasher.update(com1.to_affine().to_compressed());
        hasher.update(com2.to_affine().to_compressed());
        for com in or_commitments {
            hasher.update(com.to_affine().to_compressed());
        }

        hasher.update(context);

        let result = hasher.finalize();
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(&result);
        buffer[31] &= 0x3f;
        Scalar::from_bytes(&buffer).unwrap_or(Scalar::one())
    }

    fn generate_issuer_hiding_zkpok_Naive_common(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_indices: &BTreeSet<usize>,
        messages: &[Scalar],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        r1: &Scalar,
        r2: &Scalar,
        tilde_e: &Scalar,
        t: &Scalar,
        i_star: usize,
        context: &[u8],
        mut rng: impl rand_core::CryptoRngCore,
    ) -> (
        G1Projective,
        G1Projective,
        Vec<G1Projective>,
        Scalar,
        Vec<Scalar>,
        Vec<Scalar>,
        BTreeMap<usize, Scalar>,
        Scalar,
        Scalar,
        Scalar,
    ) {
        let l = policy.len();

        let tau_r1 = Scalar::random(&mut rng);
        let tau_r2 = Scalar::random(&mut rng);
        let tau_e = Scalar::random(&mut rng);

        let total_messages = messages.len();
        let mut hidden_indices = BTreeSet::new();
        for j in 0..total_messages {
            if !disclosed_indices.contains(&j) {
                hidden_indices.insert(j);
            }
        }

        let mut tau_hidden = BTreeMap::new();
        for &j in &hidden_indices {
            tau_hidden.insert(j, Scalar::random(&mut rng));
        }

        let com1 = multiexp_advanced(&[*C_bar, *A_prime], &[tau_r2, -tau_e]);

        let mut bases = Vec::with_capacity(1 + hidden_indices.len());
        bases.push(*C_bar);
        let mut scalars = Vec::with_capacity(1 + hidden_indices.len());
        scalars.push(tau_r1);
        for &j in &hidden_indices {
            bases.push(params.h[j]);
            scalars.push(-tau_hidden[&j]);
        }
        let com2 = multiexp_advanced(&bases, &scalars);

        let mut or_challenges = vec![Scalar::zero(); l];
        let mut or_responses = vec![Scalar::zero(); l];

        let mut or_commitments = Vec::with_capacity(l);
        let mut y = Vec::with_capacity(l);
        for pk in policy {
            y.push(*bpk_prime - pk.pk1);
        }

        let mut r_istar = Scalar::zero();
        for i in 0..l {
            if i == i_star {
                r_istar = Scalar::random(&mut rng);
                or_commitments.push(params.g1 * r_istar);
            } else {
                or_challenges[i] = Scalar::random(&mut rng);
                or_responses[i] = Scalar::random(&mut rng);
                or_commitments.push(multiexp_advanced(
                    &[y[i], params.g1],
                    &[or_challenges[i], or_responses[i]],
                ));
            }
        }

        let mut disclosed_messages = BTreeMap::new();
        for &idx in disclosed_indices {
            disclosed_messages.insert(idx, messages[idx]);
        }

        let challenge = calculate_challenge_naive(
            policy,
            &disclosed_messages,
            bpk_prime,
            A_prime,
            C_bar,
            A_bar,
            &com1,
            &com2,
            &or_commitments,
            context,
        );

        let r1_inv = r1.invert().expect("r1 should not be zero");
        let z_r1 = tau_r1 + challenge * r1_inv;
        let z_r2 = tau_r2 + challenge * r2;
        let z_e = tau_e + challenge * tilde_e;

        let mut z_hidden_messages = BTreeMap::new();
        for &j in &hidden_indices {
            let z_m = tau_hidden[&j] + challenge * messages[j];
            z_hidden_messages.insert(j, z_m);
        }

        let mut c_istar = challenge;
        for i in 0..l {
            c_istar -= or_challenges[i];
        }
        or_challenges[i_star] = c_istar;
        or_responses[i_star] = r_istar - c_istar * t;

        (
            com1,
            com2,
            or_commitments,
            challenge,
            or_challenges,
            or_responses,
            z_hidden_messages,
            z_e,
            z_r1,
            z_r2,
        )
    }

    fn generate_issuer_hiding_zkpok_NaiveFast(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_indices: &BTreeSet<usize>,
        messages: &[Scalar],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        r1: &Scalar,
        r2: &Scalar,
        tilde_e: &Scalar,
        t: &Scalar,
        i_star: usize,
        context: &[u8],
        rng: impl rand_core::CryptoRngCore,
    ) -> IssuerHidingZKPoK {
        let l = policy.len();
        let (
            com1,
            com2,
            or_commitments,
            _challenge,
            or_challenges,
            or_responses,
            z_hidden_messages,
            z_e,
            z_r1,
            z_r2,
        ) = generate_issuer_hiding_zkpok_Naive_common(
            params,
            policy,
            disclosed_indices,
            messages,
            A_prime,
            C_bar,
            A_bar,
            bpk_prime,
            r1,
            r2,
            tilde_e,
            t,
            i_star,
            context,
            rng,
        );
        IssuerHidingZKPoK::NaiveFast {
            com1: com1.to_affine().to_compressed(),
            com2: com2.to_affine().to_compressed(),
            or_commitments: or_commitments.iter().map(|c| c.to_affine().to_compressed()).collect(),
            or_challenges: or_challenges[0..l - 1].to_vec(),
            or_responses,
            z_hidden_messages,
            z_e,
            z_r1,
            z_r2,
        }
    }

    fn generate_issuer_hiding_zkpok_NaiveShort(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_indices: &BTreeSet<usize>,
        messages: &[Scalar],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        r1: &Scalar,
        r2: &Scalar,
        tilde_e: &Scalar,
        t: &Scalar,
        i_star: usize,
        context: &[u8],
        rng: impl rand_core::CryptoRngCore,
    ) -> IssuerHidingZKPoK {
        let l = policy.len();
        let (_, _, _, challenge, or_challenges, or_responses, z_hidden_messages, z_e, z_r1, z_r2) =
            generate_issuer_hiding_zkpok_Naive_common(
                params,
                policy,
                disclosed_indices,
                messages,
                A_prime,
                C_bar,
                A_bar,
                bpk_prime,
                r1,
                r2,
                tilde_e,
                t,
                i_star,
                context,
                rng,
            );
        IssuerHidingZKPoK::NaiveShort {
            challenge,
            or_challenges: or_challenges[0..l - 1].to_vec(),
            or_responses,
            z_hidden_messages,
            z_e,
            z_r1,
            z_r2,
        }
    }

    /// Verifies the ZKPoK.
    fn verify_issuer_hiding_zkpok_NaiveFast(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        com1: &[u8; 48],
        com2: &[u8; 48],
        or_commitments: &[[u8; 48]],
        or_challenges: &[Scalar],
        or_responses: &[Scalar],
        z_hidden_messages: &BTreeMap<usize, Scalar>,
        z_e: &Scalar,
        z_r1: &Scalar,
        z_r2: &Scalar,
        mut rng: impl rand_core::CryptoRngCore,
    ) -> bool {
        let l = policy.len();
        if or_commitments.len() != l || or_responses.len() != l || or_challenges.len() != l - 1 {
            return false;
        }

        let com1_projective = match G1Affine::from_compressed(com1) {
            Some(a) => G1Projective::from(a),
            None => return false,
        };
        let com2_projective = match G1Affine::from_compressed(com2) {
            Some(a) => G1Projective::from(a),
            None => return false,
        };
        let mut or_commitments_projective = Vec::with_capacity(l);
        for com in or_commitments {
            let com_proj = match G1Affine::from_compressed(com) {
                Some(a) => G1Projective::from(a),
                None => return false,
            };
            or_commitments_projective.push(com_proj);
        }

        // 1. Compute challenge from proof commitments
        let challenge = calculate_challenge_naive(
            policy,
            disclosed_messages,
            bpk_prime,
            A_prime,
            C_bar,
            A_bar,
            &com1_projective,
            &com2_projective,
            &or_commitments_projective,
            context,
        );

        // Do randomized verification, collecting terms.
        let randomizer1 = Scalar::random(&mut rng);
        let randomizer2 = Scalar::random(&mut rng);
        let mut randomizer3 = Vec::with_capacity(l);
        for _ in 0..l {
            randomizer3.push(Scalar::random(&mut rng));
        }

        let mut bases = Vec::with_capacity(6 + params.h.len() + 2 * l);
        let mut scalars = Vec::with_capacity(6 + params.h.len() + 2 * l);

        // com1 verification terms
        bases.push(*A_prime);
        scalars.push(-*z_e * randomizer1);

        bases.push(*C_bar);
        // the second term is due to the presence of C_bar in com2
        scalars.push(*z_r2 * randomizer1 + *z_r1 * randomizer2);

        bases.push(*A_bar);
        scalars.push(-challenge * randomizer1);

        bases.push(com1_projective);
        scalars.push(-randomizer1);

        // com2 verification terms
        bases.push(com2_projective);
        scalars.push(-randomizer2);

        // g1 is used in com2 and in OR-proofs
        let mut g1_scalar = -challenge * randomizer2;
        for i in 0..l {
            g1_scalar += or_responses[i] * randomizer3[i];
        }
        bases.push(params.g1);
        scalars.push(g1_scalar);

        // h[i] terms (used in com2)
        for i in 0..params.h.len() {
            bases.push(params.h[i]);
            if disclosed_messages.contains_key(&i) {
                let m_i = disclosed_messages[&i];
                scalars.push(-(m_i * challenge * randomizer2));
            } else {
                let z_m = z_hidden_messages[&i];
                scalars.push(-z_m * randomizer2);
            }
        }

        // OR-proof commitments
        let mut c_l = challenge;
        for &c_i in or_challenges {
            c_l -= c_i;
        }

        for i in 0..l {
            let y_i = *bpk_prime - policy[i].pk1;
            let c_i = if i < l - 1 { or_challenges[i] } else { c_l };

            bases.push(y_i);
            scalars.push(c_i * randomizer3[i]);

            bases.push(or_commitments_projective[i]);
            scalars.push(-randomizer3[i]);
        }

        multiexp_advanced(&bases, &scalars) == G1Projective::identity()
    }

    fn verify_issuer_hiding_zkpok_NaiveShort(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        challenge: &Scalar,
        or_challenges: &[Scalar],
        or_responses: &[Scalar],
        z_hidden_messages: &BTreeMap<usize, Scalar>,
        z_e: &Scalar,
        z_r1: &Scalar,
        z_r2: &Scalar,
    ) -> bool {
        let l = policy.len();
        if or_responses.len() != l || or_challenges.len() != l - 1 {
            return false;
        }

        let computed_com1 =
            multiexp_advanced(&[*A_prime, *C_bar, *A_bar], &[-*z_e, *z_r2, -*challenge]);

        let mut bases = Vec::with_capacity(2 + params.h.len());
        let mut scalars = Vec::with_capacity(2 + params.h.len());

        bases.push(*C_bar);
        scalars.push(*z_r1);

        bases.push(params.g1);
        scalars.push(-*challenge);

        for i in 0..params.h.len() {
            bases.push(params.h[i]);
            if disclosed_messages.contains_key(&i) {
                let m_i = disclosed_messages[&i];
                scalars.push(-(m_i * *challenge));
            } else {
                let z_m = z_hidden_messages[&i];
                scalars.push(-z_m);
            }
        }
        let computed_com2 = multiexp_advanced(&bases, &scalars);

        // 2. Reconstruct OR-proof commitments
        let mut c_l = *challenge;
        for &c_i in or_challenges {
            c_l -= c_i;
        }

        let mut y = Vec::with_capacity(l);
        for pk in policy {
            y.push(*bpk_prime - pk.pk1);
        }

        let mut computed_or_commitments = Vec::with_capacity(l);
        for i in 0..l {
            let c_i = if i < l - 1 { or_challenges[i] } else { c_l };
            computed_or_commitments
                .push(multiexp_advanced(&[y[i], params.g1], &[c_i, or_responses[i]]));
        }

        // 3. Compute challenge hash and verify
        let computed_challenge = calculate_challenge_naive(
            policy,
            disclosed_messages,
            bpk_prime,
            A_prime,
            C_bar,
            A_bar,
            &computed_com1,
            &computed_com2,
            &computed_or_commitments,
            context,
        );

        computed_challenge == *challenge
    }

    // ============================================================================
    // GK proofs
    // ============================================================================

    // Polynomial multiplication.
    fn poly_mul(poly1: &[Scalar], poly2: &[Scalar]) -> Vec<Scalar> {
        let mut result = vec![Scalar::zero(); poly1.len() + poly2.len() - 1];
        for (i, &c1) in poly1.iter().enumerate() {
            for (j, &c2) in poly2.iter().enumerate() {
                result[i + j] += c1 * c2;
            }
        }
        result
    }

    // Helper to compute the Fiat-Shamir challenge for GK proofs.
    fn calculate_challenge_gk(
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        bpk_prime: &G1Projective,
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        com1: &G1Projective,
        com2: &G1Projective,
        com1_gk: &[G1Projective],
        com2_gk: &[G1Projective],
        com3_gk: &[G1Projective],
        com4_gk: &[G1Projective],
        context: &[u8],
    ) -> Scalar {
        let mut hasher = Sha256::new();

        for pk in policy {
            hasher.update(pk.pk1.to_affine().to_compressed());
        }

        for (&idx, msg) in disclosed_messages {
            hasher.update(&(idx as u64).to_be_bytes());
            hasher.update(&msg.to_bytes());
        }

        hasher.update(bpk_prime.to_affine().to_compressed());
        hasher.update(A_prime.to_affine().to_compressed());
        hasher.update(C_bar.to_affine().to_compressed());
        hasher.update(A_bar.to_affine().to_compressed());

        hasher.update(com1.to_affine().to_compressed());
        hasher.update(com2.to_affine().to_compressed());

        for com in com1_gk {
            hasher.update(com.to_affine().to_compressed());
        }
        for com in com2_gk {
            hasher.update(com.to_affine().to_compressed());
        }
        for com in com3_gk {
            hasher.update(com.to_affine().to_compressed());
        }
        for com in com4_gk {
            hasher.update(com.to_affine().to_compressed());
        }

        hasher.update(context);

        let result = hasher.finalize();
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(&result);
        buffer[31] &= 0x3f;
        Scalar::from_bytes(&buffer).unwrap_or(Scalar::one())
    }

    fn generate_issuer_hiding_zkpok_GK(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_indices: &BTreeSet<usize>,
        messages: &[Scalar],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        r1: &Scalar,
        r2: &Scalar,
        tilde_e: &Scalar,
        t: &Scalar,
        i_star: usize,
        context: &[u8],
        mut rng: impl rand_core::CryptoRngCore,
    ) -> IssuerHidingZKPoK {
        let l_org = policy.len();
        let logl = (l_org as f64).log2().ceil() as usize;
        let l = 1 << logl; // least power of 2 greater than or equal to l_org
        let mut y = Vec::with_capacity(l);
        for pk in policy {
            y.push(*bpk_prime - pk.pk1);
        }
        while y.len() < l {
            y.push(y[l_org - 1].clone());
        }

        let tau_r1 = Scalar::random(&mut rng);
        let tau_r2 = Scalar::random(&mut rng);
        let tau_e = Scalar::random(&mut rng);

        let total_messages = messages.len();
        let mut hidden_indices = BTreeSet::new();
        for j in 0..total_messages {
            if !disclosed_indices.contains(&j) {
                hidden_indices.insert(j);
            }
        }

        let mut tau_hidden = BTreeMap::new();
        for &j in &hidden_indices {
            tau_hidden.insert(j, Scalar::random(&mut rng));
        }

        let com1_orig = multiexp_advanced(&[*C_bar, *A_prime], &[tau_r2, -tau_e]);

        let mut bases = Vec::with_capacity(1 + hidden_indices.len());
        bases.push(*C_bar);
        let mut scalars = Vec::with_capacity(1 + hidden_indices.len());
        scalars.push(tau_r1);
        for &j in &hidden_indices {
            bases.push(params.h[j]);
            scalars.push(-tau_hidden[&j]);
        }
        let com2_orig = multiexp_advanced(&bases, &scalars);

        let i_star_bits: Vec<u8> = (0..logl).map(|j| ((i_star >> j) & 1) as u8).collect();

        let mut r = Vec::with_capacity(logl);
        let mut s = Vec::with_capacity(logl);
        let mut t_gk = Vec::with_capacity(logl);
        let mut a = Vec::with_capacity(logl);

        let mut com1_gk = Vec::with_capacity(logl);
        let mut com2_gk = Vec::with_capacity(logl);
        let mut com3_gk = Vec::with_capacity(logl);

        for j in 0..logl {
            r.push(Scalar::random(&mut rng));
            s.push(Scalar::random(&mut rng));
            t_gk.push(Scalar::random(&mut rng));
            a.push(Scalar::random(&mut rng));

            let (com1, com3) = if i_star_bits[j] == 1 {
                (
                    params.g1 * r[j] + params.h[0],
                    multiexp_advanced(&[params.g1, params.h[0]], &[t_gk[j], a[j]]),
                )
            } else {
                (params.g1 * r[j], params.g1 * t_gk[j])
            };
            let com2 = multiexp_advanced(&[params.g1, params.h[0]], &[s[j], a[j]]);

            com1_gk.push(com1);
            com2_gk.push(com2);
            com3_gk.push(com3);
        }

        let mut p = vec![vec![Scalar::zero(); logl + 1]; l];
        for i in 0..l {
            let mut current_poly = vec![Scalar::one()];
            for j in 0..logl {
                let bit = (i >> j) & 1;
                let f = if bit == 1 {
                    vec![a[j], Scalar::from(i_star_bits[j] as u64)]
                } else {
                    vec![-a[j], Scalar::from((1 - i_star_bits[j]) as u64)]
                };
                current_poly = poly_mul(&current_poly, &f);
            }
            p[i] = current_poly;
        }

        let mut rho = Vec::with_capacity(logl);
        let mut com4_gk = Vec::with_capacity(logl);
        for k in 0..logl {
            rho.push(Scalar::random(&mut rng));

            let mut bases_gk = Vec::with_capacity(1 + l);
            let mut scalars_gk = Vec::with_capacity(1 + l);
            bases_gk.push(params.g1);
            scalars_gk.push(rho[k]);
            for i in 0..l {
                bases_gk.push(y[i]);
                scalars_gk.push(p[i][k]);
            }
            com4_gk.push(multiexp_advanced(&bases_gk, &scalars_gk));
        }

        let mut disclosed_messages = BTreeMap::new();
        for &idx in disclosed_indices {
            disclosed_messages.insert(idx, messages[idx]);
        }

        let challenge = calculate_challenge_gk(
            &policy,
            &disclosed_messages,
            bpk_prime,
            A_prime,
            C_bar,
            A_bar,
            &com1_orig,
            &com2_orig,
            &com1_gk,
            &com2_gk,
            &com3_gk,
            &com4_gk,
            context,
        );

        let r1_inv = r1.invert().expect("r1 should not be zero");
        let z_r1 = tau_r1 + challenge * r1_inv;
        let z_r2 = tau_r2 + challenge * r2;
        let z_e = tau_e + challenge * tilde_e;

        let mut z_hidden_messages = BTreeMap::new();
        for &j in &hidden_indices {
            let z_m = tau_hidden[&j] + challenge * messages[j];
            z_hidden_messages.insert(j, z_m);
        }

        let mut f_resp = Vec::with_capacity(logl);
        let mut z1_resp = Vec::with_capacity(logl);
        let mut z2_resp = Vec::with_capacity(logl);

        for j in 0..logl {
            let bit_scalar = Scalar::from(i_star_bits[j] as u64);
            let fj = challenge * bit_scalar + a[j];
            let z1 = challenge * r[j] + s[j];
            let z2 = (challenge - fj) * r[j] + t_gk[j];

            f_resp.push(fj);
            z1_resp.push(z1);
            z2_resp.push(z2);
        }

        let mut sum_rho_c = Scalar::zero();
        let mut c_pow = Scalar::one();
        for k in 0..logl {
            sum_rho_c += rho[k] * c_pow;
            c_pow *= challenge;
        }
        let z_star = t * c_pow - sum_rho_c;

        let com1_gk_compressed = com1_gk.iter().map(|c| c.to_affine().to_compressed()).collect();
        let com4_gk_compressed = com4_gk.iter().map(|c| c.to_affine().to_compressed()).collect();

        IssuerHidingZKPoK::GK {
            com1: com1_gk_compressed,
            com4: com4_gk_compressed,
            challenge,
            f: f_resp,
            z1: z1_resp,
            z2: z2_resp,
            z_star,
            z_hidden_messages,
            z_e,
            z_r1,
            z_r2,
        }
    }

    fn verify_issuer_hiding_zkpok_GK(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        com1: &[[u8; 48]],
        com4: &[[u8; 48]],
        challenge: &Scalar,
        f: &[Scalar],
        z1: &[Scalar],
        z2: &[Scalar],
        z_star: &Scalar,
        z_hidden_messages: &BTreeMap<usize, Scalar>,
        z_e: &Scalar,
        z_r1: &Scalar,
        z_r2: &Scalar,
    ) -> bool {
        let l_org = policy.len();
        let logl = (l_org as f64).log2().ceil() as usize;
        let l = 1 << logl;
        let mut y = Vec::with_capacity(l);
        for pk in policy {
            y.push(*bpk_prime - pk.pk1);
        }
        while y.len() < l {
            y.push(y[l_org - 1].clone());
        }

        if com1.len() != logl
            || com4.len() != logl
            || f.len() != logl
            || z1.len() != logl
            || z2.len() != logl
        {
            return false;
        }

        // Decompress com1 and com4
        let mut com1_gk = Vec::with_capacity(logl);
        for c in com1 {
            let proj = match G1Affine::from_compressed(c) {
                Some(a) => G1Projective::from(a),
                None => return false,
            };
            com1_gk.push(proj);
        }
        let mut com4_gk = Vec::with_capacity(logl);
        for c in com4 {
            let proj = match G1Affine::from_compressed(c) {
                Some(a) => G1Projective::from(a),
                None => return false,
            };
            com4_gk.push(proj);
        }

        // Reconstruct com2_gk and com3_gk
        let mut com2_gk = Vec::with_capacity(logl);
        let mut com3_gk = Vec::with_capacity(logl);
        for j in 0..logl {
            let com2 = multiexp_advanced(
                &[params.g1, params.h[0], com1_gk[j]],
                &[z1[j], f[j], -*challenge],
            );
            com2_gk.push(com2);

            let com3 = multiexp_advanced(&[params.g1, com1_gk[j]], &[z2[j], f[j] - *challenge]);
            com3_gk.push(com3);
        }

        // Reconstruct com1_orig and com2_orig
        let com1_orig =
            multiexp_advanced(&[*A_prime, *C_bar, *A_bar], &[-*z_e, *z_r2, -*challenge]);

        let mut bases = Vec::with_capacity(2 + params.h.len());
        let mut scalars = Vec::with_capacity(2 + params.h.len());
        bases.push(*C_bar);
        scalars.push(*z_r1);
        bases.push(params.g1);
        scalars.push(-*challenge);
        for i in 0..params.h.len() {
            bases.push(params.h[i]);
            if disclosed_messages.contains_key(&i) {
                let m_i = disclosed_messages[&i];
                scalars.push(-(m_i * *challenge));
            } else {
                let z_m = z_hidden_messages[&i];
                scalars.push(-z_m);
            }
        }
        let com2_orig = multiexp_advanced(&bases, &scalars);

        // Compute challenge and verify
        let computed_challenge = calculate_challenge_gk(
            &policy,
            disclosed_messages,
            bpk_prime,
            A_prime,
            C_bar,
            A_bar,
            &com1_orig,
            &com2_orig,
            &com1_gk,
            &com2_gk,
            &com3_gk,
            &com4_gk,
            context,
        );
        if computed_challenge != *challenge {
            return false;
        }

        // Compute p_val_i
        let mut p_val = Vec::with_capacity(l);
        for i in 0..l {
            let mut val = Scalar::one();
            for j in 0..logl {
                let bit = (i >> j) & 1;
                if bit == 1 {
                    val *= f[j];
                } else {
                    val *= *challenge - f[j];
                }
            }
            p_val.push(val);
        }

        // Batch MSM for GK main check
        let mut bases_gk = Vec::with_capacity(l + logl + 1);
        let mut scalars_gk = Vec::with_capacity(l + logl + 1);

        for i in 0..l {
            bases_gk.push(y[i]);
            scalars_gk.push(p_val[i]);
        }

        let mut c_pow = Scalar::one();
        for k in 0..logl {
            bases_gk.push(com4_gk[k]);
            scalars_gk.push(-c_pow);
            c_pow *= challenge;
        }

        bases_gk.push(params.g1);
        scalars_gk.push(-*z_star);

        let sum_gk = multiexp_advanced(&bases_gk, &scalars_gk);
        sum_gk == G1Projective::identity()
    }

    // ============================================================================
    // Stacked sigmas proofs
    // ============================================================================

    // Helper to compute the Fiat-Shamir challenge.
    fn calculate_challenge_stacked_sigmas(
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        bpk_prime: &G1Projective,
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        com1: &G1Projective,
        com2: &G1Projective,
        params_ss: &[RistrettoPoint],
        com_ss: &RistrettoPoint,
        context: &[u8],
    ) -> Scalar {
        let mut hasher = Sha256::new();

        for pk in policy {
            hasher.update(pk.pk1.to_affine().to_compressed());
        }

        for (&idx, msg) in disclosed_messages {
            hasher.update(&(idx as u64).to_be_bytes());
            hasher.update(&msg.to_bytes());
        }

        hasher.update(bpk_prime.to_affine().to_compressed());
        hasher.update(A_prime.to_affine().to_compressed());
        hasher.update(C_bar.to_affine().to_compressed());
        hasher.update(A_bar.to_affine().to_compressed());

        hasher.update(com1.to_affine().to_compressed());
        hasher.update(com2.to_affine().to_compressed());

        for p in params_ss {
            hasher.update(p.compress().as_bytes());
        }
        hasher.update(com_ss.compress().as_bytes());

        hasher.update(context);

        let result = hasher.finalize();
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(&result);
        buffer[31] &= 0x3f;
        Scalar::from_bytes(&buffer).unwrap_or(Scalar::one())
    }

    fn generate_issuer_hiding_zkpok_StackedSigmas(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_indices: &BTreeSet<usize>,
        messages: &[Scalar],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        r1: &Scalar,
        r2: &Scalar,
        tilde_e: &Scalar,
        t: &Scalar,
        i_star: usize,
        context: &[u8],
        mut rng: impl rand_core::CryptoRngCore,
    ) -> IssuerHidingZKPoK {
        let l_org = policy.len();
        assert!(i_star < l_org, "i_star out of bounds");
        let logl = (l_org as f64).log2().ceil() as usize;
        let l = 1 << logl;
        let mut y = Vec::with_capacity(l);
        for pk in policy {
            y.push(*bpk_prime - pk.pk1);
        }
        while y.len() < l {
            y.push(y[l_org - 1].clone());
        }

        let tau_r1 = Scalar::random(&mut rng);
        let tau_r2 = Scalar::random(&mut rng);
        let tau_e = Scalar::random(&mut rng);

        let total_messages = messages.len();
        let mut hidden_indices = BTreeSet::new();
        for j in 0..total_messages {
            if !disclosed_indices.contains(&j) {
                hidden_indices.insert(j);
            }
        }

        let mut tau_hidden = BTreeMap::new();
        for &j in &hidden_indices {
            tau_hidden.insert(j, Scalar::random(&mut rng));
        }

        let com1 = multiexp_advanced(&[*C_bar, *A_prime], &[tau_r2, -tau_e]);

        let mut bases = Vec::with_capacity(1 + hidden_indices.len());
        bases.push(*C_bar);
        let mut scalars = Vec::with_capacity(1 + hidden_indices.len());
        scalars.push(tau_r1);
        for &j in &hidden_indices {
            bases.push(params.h[j]);
            scalars.push(-tau_hidden[&j]);
        }
        let com2 = multiexp_advanced(&bases, &scalars);

        let r_istar = Scalar::random(&mut rng);
        let A_istar = params.g1 * r_istar;

        let (params_ss, secrets_ss, com_ss, r_ss, path_T) =
            one_of_l_commitments::commit_1_of_l(logl, i_star, &A_istar, &mut rng);

        let mut disclosed_messages = BTreeMap::new();
        for &idx in disclosed_indices {
            disclosed_messages.insert(idx, messages[idx]);
        }

        let challenge = calculate_challenge_stacked_sigmas(
            &policy,
            &disclosed_messages,
            bpk_prime,
            A_prime,
            C_bar,
            A_bar,
            &com1,
            &com2,
            &params_ss,
            &com_ss,
            context,
        );

        let r1_inv = r1.invert().expect("r1 should not be zero");
        let z_r1 = tau_r1 + challenge * r1_inv;
        let z_r2 = tau_r2 + challenge * r2;
        let z_e = tau_e + challenge * tilde_e;

        let mut z_hidden_messages = BTreeMap::new();
        for &j in &hidden_indices {
            let z_m = tau_hidden[&j] + challenge * messages[j];
            z_hidden_messages.insert(j, z_m);
        }

        let z_resp = r_istar - challenge * t;

        let pre_challenge = challenge.precompute();
        let pre_z_resp = z_resp.precompute();
        let g1_z_resp = params.g1 * &pre_z_resp;
        let mut A = Vec::with_capacity(l);
        for i in 0..l_org {
            if i == i_star {
                A.push(A_istar);
            } else {
                A.push(y[i] * &pre_challenge + g1_z_resp);
            }
        }
        while A.len() < l {
            A.push(A[l_org - 1].clone());
        }

        let decom_ss =
            one_of_l_commitments::open_1_of_l(&params_ss, &secrets_ss, i_star, &r_ss, &path_T, &A);

        let params_ss_compressed = params_ss.iter().map(|p| p.compress().to_bytes()).collect();
        let com_ss_compressed = com_ss.compress().to_bytes();
        let decom_ss_compressed = decom_ss.iter().map(|s| s.to_bytes()).collect();

        IssuerHidingZKPoK::StackedSigmas {
            params: params_ss_compressed,
            com: com_ss_compressed,
            decom: decom_ss_compressed,
            challenge,
            z: z_resp,
            z_hidden_messages,
            z_e,
            z_r1,
            z_r2,
        }
    }

    fn verify_issuer_hiding_zkpok_StackedSigmas(
        params: &Parameters,
        policy: &[PublicKey],
        disclosed_messages: &BTreeMap<usize, Scalar>,
        context: &[u8],
        A_prime: &G1Projective,
        C_bar: &G1Projective,
        A_bar: &G1Projective,
        bpk_prime: &G1Projective,
        params_ss: &[[u8; 32]],
        com_ss: &[u8; 32],
        decom_ss: &[[u8; 32]],
        challenge: &Scalar,
        z: &Scalar,
        z_hidden_messages: &BTreeMap<usize, Scalar>,
        z_e: &Scalar,
        z_r1: &Scalar,
        z_r2: &Scalar,
    ) -> bool {
        let l_org = policy.len();
        let logl = (l_org as f64).log2().ceil() as usize;
        let l = 1 << logl;

        if params_ss.len() != logl || decom_ss.len() != logl {
            return false;
        }

        let mut y = Vec::with_capacity(l);
        for pk in policy {
            y.push(*bpk_prime - pk.pk1);
        }
        while y.len() < l {
            y.push(y[l_org - 1].clone());
        }

        // Decompress Ristretto points and scalars
        let mut params_ss_points = Vec::with_capacity(logl);
        for p in params_ss {
            let point = match CompressedRistretto(*p).decompress() {
                Some(pt) => pt,
                None => return false,
            };
            params_ss_points.push(point);
        }

        let com_ss_point = match CompressedRistretto(*com_ss).decompress() {
            Some(pt) => pt,
            None => return false,
        };

        let mut decom_ss_scalars = Vec::with_capacity(logl);
        for s in decom_ss {
            let scalar =
                match Option::<RistrettoScalar>::from(RistrettoScalar::from_canonical_bytes(*s)) {
                    Some(sc) => sc,
                    None => return false,
                };
            decom_ss_scalars.push(scalar);
        }

        // 1. Reconstruct G1 points A_i = y_i^c * g1^z
        let pre_challenge = challenge.precompute();
        let pre_z = z.precompute();
        let g1_z = params.g1 * &pre_z;
        let mut A = Vec::with_capacity(l);
        for i in 0..l_org {
            A.push(y[i] * &pre_challenge + g1_z);
        }
        while A.len() < l {
            A.push(A[l_org - 1].clone());
        }

        // 2. Reconstruct commitments (same as NaiveShort/GK)
        let computed_com1 =
            multiexp_advanced(&[*A_prime, *C_bar, *A_bar], &[-*z_e, *z_r2, -*challenge]);

        let mut bases = Vec::with_capacity(2 + params.h.len());
        let mut scalars = Vec::with_capacity(2 + params.h.len());

        bases.push(*C_bar);
        scalars.push(*z_r1);

        bases.push(params.g1);
        scalars.push(-*challenge);

        for i in 0..params.h.len() {
            bases.push(params.h[i]);
            if disclosed_messages.contains_key(&i) {
                let m_i = disclosed_messages[&i];
                scalars.push(-(m_i * *challenge));
            } else {
                let z_m = z_hidden_messages[&i];
                scalars.push(-z_m);
            }
        }
        let computed_com2 = multiexp_advanced(&bases, &scalars);

        // 3. Verify challenge
        let computed_challenge = calculate_challenge_stacked_sigmas(
            &policy,
            disclosed_messages,
            bpk_prime,
            A_prime,
            C_bar,
            A_bar,
            &computed_com1,
            &computed_com2,
            &params_ss_points,
            &com_ss_point,
            context,
        );
        if computed_challenge != *challenge {
            return false;
        }

        // 4. Reconstruct Ristretto tree and verify root
        one_of_l_commitments::verify_1_of_l(&params_ss_points, &com_ss_point, &decom_ss_scalars, &A)
    }
}
