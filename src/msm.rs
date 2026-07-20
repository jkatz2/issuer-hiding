use crate::blst_wrappers::{G1Projective, Scalar};
use crate::{MultiexpMode, Parameters};
use blst::*;

/// Compute `\sum h_i * m_i` using naive iterative algorithm.
pub fn multiexp_basic(bases: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    assert_eq!(bases.len(), scalars.len(), "Bases and scalars must have same length");
    let mut res = G1Projective::identity();
    for (b, s) in bases.iter().zip(scalars.iter()) {
        res = res + (*b * *s);
    }
    res
}

/// Compute `\sum x_i * G_i` using Pippenger's algorithm from blst.
pub fn multiexp_advanced(bases: &[G1Projective], scalars: &[Scalar]) -> G1Projective {
    let n = bases.len();
    assert_eq!(n, scalars.len(), "Bases and scalars must have same length");

    if n == 0 {
        return G1Projective::identity();
    }
    if n == 1 {
        return bases[0] * scalars[0];
    }
    if n < 4 {
        return multiexp_basic(bases, scalars);
    }

    // if n \geq 4 then use Pippenger's algorithm
    // Convert bases (projective) to blst_p1_affine
    let bases_p1: Vec<blst_p1> = bases.iter().map(|b| b.0).collect();
    let mut bases_affine = vec![blst_p1_affine::default(); n];
    let p_ptrs: [*const blst_p1; 2] = [bases_p1.as_ptr(), std::ptr::null()];
    unsafe {
        blst_p1s_to_affine(bases_affine.as_mut_ptr(), &p_ptrs[0], n);
    }

    // Convert scalars to little-endian bytes
    let mut scalar_bytes = Vec::with_capacity(n * 32);
    for s in scalars {
        let mut sc = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut sc, &s.0);
        }
        scalar_bytes.extend_from_slice(&sc.b);
    }

    if n < 32 {
        // For small n, use single-threaded Pippenger to avoid thread-pool overhead
        unsafe {
            let scratch_size = blst_p1s_mult_pippenger_scratch_sizeof(n);
            let mut scratch = vec![0u64; scratch_size / 8];
            let mut ret = blst_p1::default();
            let p_ptrs: [*const blst_p1_affine; 2] = [bases_affine.as_ptr(), std::ptr::null()];
            let s_ptrs: [*const u8; 2] = [scalar_bytes.as_ptr(), std::ptr::null()];
            blst_p1s_mult_pippenger(
                &mut ret,
                p_ptrs.as_ptr(),
                n,
                s_ptrs.as_ptr(),
                255,
                scratch.as_mut_ptr(),
            );
            G1Projective(ret)
        }
    } else {
        // Use blst's multi-threaded Pippenger wrapper for large n
        use blst::MultiPoint;
        G1Projective(bases_affine.as_slice().mult(&scalar_bytes, 255))
    }
}

/// Compute `C = g1 + \sum h_i * m_i` using the chosen multi-exponentiation subroutine.
pub fn compute_C(params: &Parameters, messages: &[Scalar], mode: MultiexpMode) -> G1Projective {
    let n = messages.len();
    assert_eq!(n, params.h.len(), "Message count must match parameter capacity");
    let sum = match mode {
        MultiexpMode::Basic => multiexp_basic(&params.h, messages),
        MultiexpMode::Advanced => multiexp_advanced(&params.h, messages),
    };
    params.g1 + sum
}
