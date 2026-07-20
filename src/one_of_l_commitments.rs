// 1-of-l commitment for Stacking Sigmas, using Ristretto-255.

use crate::blst_wrappers::G1Projective;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as RistrettoScalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256, Sha512};

pub fn hash_to_ristretto_scalar(data: &[u8]) -> RistrettoScalar {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&result);
    RistrettoScalar::from_bytes_mod_order_wide(&bytes)
}

/// 32-byte, 8-round balanced Feistel network using SHA-256.
fn feistel_step(input: &[u8; 32]) -> [u8; 32] {
    let mut left = [0u8; 16];
    let mut right = [0u8; 16];
    left.copy_from_slice(&input[0..16]);
    right.copy_from_slice(&input[16..32]);

    for round in 0..8u32 {
        let mut hasher = Sha256::new();
        hasher.update(&right);
        hasher.update(&round.to_le_bytes());
        let digest = hasher.finalize();

        let mut new_right = [0u8; 16];
        for k in 0..16 {
            new_right[k] = left[k] ^ digest[k];
        }
        left = right;
        right = new_right;
    }

    let mut output = [0u8; 32];
    output[0..16].copy_from_slice(&left);
    output[16..32].copy_from_slice(&right);
    output
}

/// Inverse of the Feistel network.
fn inverse_feistel_step(input: &[u8; 32]) -> [u8; 32] {
    let mut left = [0u8; 16];
    let mut right = [0u8; 16];
    left.copy_from_slice(&input[0..16]);
    right.copy_from_slice(&input[16..32]);

    for round in (0..8u32).rev() {
        let mut hasher = Sha256::new();
        hasher.update(&left);
        hasher.update(&round.to_le_bytes());
        let digest = hasher.finalize();

        let mut prev_left = [0u8; 16];
        for k in 0..16 {
            prev_left[k] = right[k] ^ digest[k];
        }
        right = left;
        left = prev_left;
    }

    let mut output = [0u8; 32];
    output[0..16].copy_from_slice(&left);
    output[16..32].copy_from_slice(&right);
    output
}

/// Permutes a Ristretto point by repeatedly applying a Feistel network
/// to the point until another valid point is obtained.
pub fn permutation(point: &RistrettoPoint) -> RistrettoPoint {
    let mut bytes = point.compress().to_bytes();
    loop {
        bytes = feistel_step(&bytes);
        if let Some(valid_point) = CompressedRistretto(bytes).decompress() {
            return valid_point;
        }
    }
}

pub fn inverse_permutation(point: &RistrettoPoint) -> RistrettoPoint {
    let mut bytes = point.compress().to_bytes();
    loop {
        bytes = inverse_feistel_step(&bytes);
        if let Some(valid_point) = CompressedRistretto(bytes).decompress() {
            return valid_point;
        }
    }
}

// Merge of Setup and Commit.
pub fn commit_1_of_l(
    d: usize,
    i_star: usize,
    A_istar: &G1Projective,
    rng: &mut impl CryptoRngCore,
) -> (
    Vec<RistrettoPoint>,
    Vec<RistrettoScalar>,
    RistrettoPoint,
    Vec<RistrettoScalar>,
    Vec<RistrettoPoint>,
) {
    let mut params_ss = Vec::with_capacity(d); // h0 values
    let mut secrets_ss = Vec::with_capacity(d); // trapdoors
    for j in 0..d {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let s_j = RistrettoScalar::from_bytes_mod_order_wide(&bytes);
        secrets_ss.push(s_j);

        // i_star is the path on which binding holds.
        let bit = (i_star >> j) & 1;
        let h_0 = if bit == 0 {
            let h_1 = RistrettoPoint::mul_base(&s_j);
            inverse_permutation(&h_1)
        } else {
            RistrettoPoint::mul_base(&s_j)
        };

        params_ss.push(h_0);
    }

    let mut r_ss = Vec::with_capacity(d); // commitment randomness
    for _ in 0..d {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let r_j = RistrettoScalar::from_bytes_mod_order_wide(&bytes);
        r_ss.push(r_j);
    }

    let mut path_T: Vec<RistrettoPoint> = Vec::with_capacity(d);
    for j in 0..d {
        let bit = (i_star >> j) & 1;
        let h_j = if bit == 0 {
            params_ss[j]
        } else {
            permutation(&params_ss[j])
        };
        let val_j = if j == 0 {
            hash_to_ristretto_scalar(&A_istar.to_affine().to_compressed())
        } else {
            hash_to_ristretto_scalar(path_T[j - 1].compress().as_bytes())
        };
        // compute h_j * val_j + Basepoint * r_j
        let next_T = RistrettoPoint::vartime_double_scalar_mul_basepoint(&val_j, &h_j, &r_ss[j]);
        path_T.push(next_T);
    }

    let com_ss = path_T[d - 1];
    (params_ss, secrets_ss, com_ss, r_ss, path_T)
}

pub fn open_1_of_l(
    params: &[RistrettoPoint],
    secrets: &[RistrettoScalar],
    i_star: usize,
    r_ss: &[RistrettoScalar],
    path_T: &[RistrettoPoint],
    A: &[G1Projective],
) -> Vec<RistrettoScalar> {
    let d = params.len();
    assert_eq!(secrets.len(), d, "secrets length must equal d");
    assert_eq!(r_ss.len(), d, "r_ss length must equal d");
    assert_eq!(path_T.len(), d, "path_T length must equal d");
    assert_eq!(A.len(), 1 << d, "A length must equal 2^d");

    let mut T = vec![vec![RistrettoPoint::identity(); 1]; d + 1];
    for j in 1..=d {
        T[j] = vec![RistrettoPoint::identity(); 1 << (d - j)];
    }

    let mut decom_ss = Vec::with_capacity(d);

    for j in 1..=d {
        let k_star_prev = i_star >> (j - 1);
        let sibling_idx = k_star_prev ^ 1;

        let hash_sibling = if j == 1 {
            hash_to_ristretto_scalar(&A[sibling_idx].to_affine().to_compressed())
        } else {
            hash_to_ristretto_scalar(T[j - 1][sibling_idx].compress().as_bytes())
        };

        let decom = r_ss[j - 1] - secrets[j - 1] * hash_sibling;
        decom_ss.push(decom);

        let k_star_j = i_star >> j;
        for k in 0..(1 << (d - j)) {
            if k == k_star_j {
                T[j][k] = path_T[j - 1];
            } else {
                let hash_left = if j == 1 {
                    hash_to_ristretto_scalar(&A[2 * k].to_affine().to_compressed())
                } else {
                    hash_to_ristretto_scalar(T[j - 1][2 * k].compress().as_bytes())
                };
                let hash_right = if j == 1 {
                    hash_to_ristretto_scalar(&A[2 * k + 1].to_affine().to_compressed())
                } else {
                    hash_to_ristretto_scalar(T[j - 1][2 * k + 1].compress().as_bytes())
                };
                let h0 = params[j - 1];
                let h1 = permutation(&h0);
                T[j][k] = RistrettoPoint::vartime_multiscalar_mul(
                    &[decom, hash_left, hash_right],
                    &[RISTRETTO_BASEPOINT_POINT, h0, h1],
                );
            }
        }
    }
    decom_ss
}

pub fn verify_1_of_l(
    params: &[RistrettoPoint],
    com: &RistrettoPoint,
    decom: &[RistrettoScalar],
    A: &[G1Projective],
) -> bool {
    let d = params.len();
    if decom.len() != d || A.len() != (1 << d) {
        return false;
    }

    let mut T = vec![vec![RistrettoPoint::identity(); 1]; d + 1];
    for j in 1..=d {
        T[j] = vec![RistrettoPoint::identity(); 1 << (d - j)];
    }

    for j in 1..=d {
        let h0 = params[j - 1];
        let h1 = permutation(&h0);
        let dec = decom[j - 1];
        for k in 0..(1 << (d - j)) {
            let hash_left = if j == 1 {
                hash_to_ristretto_scalar(&A[2 * k].to_affine().to_compressed())
            } else {
                hash_to_ristretto_scalar(T[j - 1][2 * k].compress().as_bytes())
            };
            let hash_right = if j == 1 {
                hash_to_ristretto_scalar(&A[2 * k + 1].to_affine().to_compressed())
            } else {
                hash_to_ristretto_scalar(T[j - 1][2 * k + 1].compress().as_bytes())
            };
            T[j][k] = RistrettoPoint::vartime_multiscalar_mul(
                &[dec, hash_left, hash_right],
                &[RISTRETTO_BASEPOINT_POINT, h0, h1],
            );
        }
    }

    T[d][0] == *com
}
