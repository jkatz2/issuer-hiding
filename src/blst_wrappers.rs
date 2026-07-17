use blst::*;
use std::mem::MaybeUninit;
use rand_core::CryptoRngCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub blst_fr);

impl Scalar {
    pub fn zero() -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_from_uint64(ret.as_mut_ptr(), [0, 0, 0, 0].as_ptr());
            Self(ret.assume_init())
        }
    }

    pub fn one() -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_from_uint64(ret.as_mut_ptr(), [1, 0, 0, 0].as_ptr());
            Self(ret.assume_init())
        }
    }

    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let mut scalar = blst_scalar::default();
            unsafe {
                blst_scalar_from_lendian(&mut scalar, bytes.as_ptr());
                if blst_scalar_fr_check(&scalar) {
                    let mut fr = blst_fr::default();
                    blst_fr_from_scalar(&mut fr, &scalar);
                    return Self(fr);
                }
            }
        }
    }

    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_inverse(ret.as_mut_ptr(), &self.0);
            Some(Self(ret.assume_init()))
        }
    }

    pub fn is_zero(&self) -> bool {
        self.0.l.iter().all(|&x| x == 0)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut scalar = blst_scalar::default();
        let mut bytes = [0u8; 32];
        unsafe {
            blst_scalar_from_fr(&mut scalar, &self.0);
            blst_lendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_lendian(&mut scalar, bytes.as_ptr());
            if blst_scalar_fr_check(&scalar) {
                let mut fr = blst_fr::default();
                blst_fr_from_scalar(&mut fr, &scalar);
                Some(Self(fr))
            } else {
                None
            }
        }
    }
}

impl core::ops::Add for Scalar {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_add(ret.as_mut_ptr(), &self.0, &other.0);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::Sub for Scalar {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_sub(ret.as_mut_ptr(), &self.0, &other.0);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::Mul for Scalar {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_mul(ret.as_mut_ptr(), &self.0, &other.0);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::Neg for Scalar {
    type Output = Self;
    fn neg(self) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_cneg(ret.as_mut_ptr(), &self.0, true);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::Add<&Scalar> for Scalar {
    type Output = Self;
    fn add(self, other: &Scalar) -> Self {
        self + *other
    }
}

impl core::ops::Sub<&Scalar> for Scalar {
    type Output = Self;
    fn sub(self, other: &Scalar) -> Self {
        self - *other
    }
}

impl core::ops::Mul<&Scalar> for Scalar {
    type Output = Self;
    fn mul(self, other: &Scalar) -> Self {
        self * *other
    }
}

impl core::ops::Mul<Scalar> for &Scalar {
    type Output = Scalar;
    fn mul(self, other: Scalar) -> Scalar {
        *self * other
    }
}

impl core::ops::AddAssign for Scalar {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl core::ops::AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, other: &Scalar) {
        *self = *self + *other;
    }
}

impl core::ops::SubAssign for Scalar {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl core::ops::SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, other: &Scalar) {
        *self = *self - *other;
    }
}

impl core::ops::MulAssign for Scalar {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl core::ops::MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, other: &Scalar) {
        *self = *self * *other;
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_fr_from_uint64(ret.as_mut_ptr(), [val, 0, 0, 0].as_ptr());
            Self(ret.assume_init())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Projective(pub blst_p1);

impl G1Projective {
    pub fn identity() -> Self {
        Self(blst_p1::default())
    }

    pub fn generator() -> Self {
        unsafe { Self(*blst_p1_generator()) }
    }

    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        let k = Scalar::random(&mut rng);
        Self::generator() * k
    }

    pub fn to_affine(&self) -> G1Affine {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p1_to_affine(ret.as_mut_ptr(), &self.0);
            G1Affine(ret.assume_init())
        }
    }

    pub fn double(&self) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p1_double(ret.as_mut_ptr(), &self.0);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::Add for G1Projective {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p1_add_or_double(ret.as_mut_ptr(), &self.0, &other.0);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::Sub for G1Projective {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        self + (-other)
    }
}

impl core::ops::Neg for G1Projective {
    type Output = Self;
    fn neg(self) -> Self {
        unsafe {
            let mut ret = self.0;
            blst_p1_cneg(&mut ret, true);
            Self(ret)
        }
    }
}

impl core::ops::Mul<Scalar> for G1Projective {
    type Output = Self;
    fn mul(self, other: Scalar) -> Self {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &other.0);
            let mut ret = MaybeUninit::uninit();
            blst_p1_mult(ret.as_mut_ptr(), &self.0, scalar.b.as_ptr(), 255);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::AddAssign for G1Projective {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Affine(pub blst_p1_affine);

impl G1Affine {
    pub fn to_compressed(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        unsafe {
            blst_p1_affine_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes
    }

    pub fn from_compressed(bytes: &[u8; 48]) -> Option<Self> {
        let mut p = blst_p1_affine::default();
        unsafe {
            let err = blst_p1_uncompress(&mut p, bytes.as_ptr());
            if err == BLST_ERROR::BLST_SUCCESS {
                Some(Self(p))
            } else {
                None
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Projective(pub blst_p2);

impl G2Projective {
    pub fn identity() -> Self {
        Self(blst_p2::default())
    }

    pub fn generator() -> Self {
        unsafe { Self(*blst_p2_generator()) }
    }

    pub fn to_affine(&self) -> G2Affine {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p2_to_affine(ret.as_mut_ptr(), &self.0);
            G2Affine(ret.assume_init())
        }
    }
}

impl core::ops::Mul<Scalar> for G2Projective {
    type Output = Self;
    fn mul(self, other: Scalar) -> Self {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &other.0);
            let mut ret = MaybeUninit::uninit();
            blst_p2_mult(ret.as_mut_ptr(), &self.0, scalar.b.as_ptr(), 255);
            Self(ret.assume_init())
        }
    }
}

impl core::ops::Add for G2Projective {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p2_add_or_double(ret.as_mut_ptr(), &self.0, &other.0);
            Self(ret.assume_init())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Affine(pub blst_p2_affine);

impl G2Affine {
    pub fn to_compressed(&self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        unsafe {
            blst_p2_affine_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes
    }

    pub fn from_compressed(bytes: &[u8; 96]) -> Option<Self> {
        let mut p = blst_p2_affine::default();
        unsafe {
            let err = blst_p2_uncompress(&mut p, bytes.as_ptr());
            if err == BLST_ERROR::BLST_SUCCESS {
                Some(Self(p))
            } else {
                None
            }
        }
    }
}

pub fn multi_pairing(pairs: &[(&G1Affine, &G2Affine)]) -> bool {
    let mut ps = Vec::with_capacity(pairs.len());
    let mut qs = Vec::with_capacity(pairs.len());
    for (p, q) in pairs {
        ps.push(p.0);
        qs.push(q.0);
    }
    let ml = blst_fp12::miller_loop_n(&qs, &ps);
    let mut fe = blst_fp12::default();
    unsafe {
        blst_final_exp(&mut fe, &ml);
    }
    fe == blst_fp12::default()
}

impl From<G1Affine> for G1Projective {
    fn from(affine: G1Affine) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p1_from_affine(ret.as_mut_ptr(), &affine.0);
            Self(ret.assume_init())
        }
    }
}

impl From<G2Affine> for G2Projective {
    fn from(affine: G2Affine) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p2_from_affine(ret.as_mut_ptr(), &affine.0);
            Self(ret.assume_init())
        }
    }
}

#[derive(Clone, Debug)]
pub struct PrecomputedScalar(pub blst_scalar);

impl Scalar {
    pub fn precompute(&self) -> PrecomputedScalar {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &self.0);
        }
        PrecomputedScalar(scalar)
    }
}

impl core::ops::Mul<&PrecomputedScalar> for G1Projective {
    type Output = Self;
    fn mul(self, other: &PrecomputedScalar) -> Self {
        unsafe {
            let mut ret = MaybeUninit::uninit();
            blst_p1_mult(ret.as_mut_ptr(), &self.0, other.0.b.as_ptr(), 255);
            Self(ret.assume_init())
        }
    }
}
