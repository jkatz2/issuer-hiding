use bbs_anonymous_credentials::{
    issuer_hiding::{generate_issuer_hiding_proof, verify_issuer_hiding_proof, IssuerHidingMode},
    multiexp_advanced, multiexp_basic, proof_verification, proving, signing, verification,
    MultiexpMode, Parameters, SecretKey,
};
use bbs_anonymous_credentials::{G1Projective, Scalar};
use rand::{thread_rng, Rng};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn test_bbs_anonymous_credential_flow() {
    let mut rng = thread_rng();
    let message_count = 6;

    // 1. Setup Parameters and Keys
    let params = Parameters::new(message_count, &mut rng);
    let secret_key = SecretKey::random(&mut rng);
    let public_key = secret_key.public_key(&params);

    // 2. Prepare Messages
    let messages: Vec<Scalar> = (0..message_count).map(|_| Scalar::random(&mut rng)).collect();

    // 3. Issue and verify credential
    let credential = signing::generate_credential(&params, &secret_key, &messages, &mut rng);
    assert!(
        verification::verify_credential(&params, &public_key, &messages, &credential,),
        "Issued credential should verify successfully"
    );

    // 4. Generate selective-disclosure ZK proof; each attribute is disclosed
    //    with probability 0.5
    let mut revealed_indices = BTreeSet::new();
    for i in 0..message_count {
        if rng.gen_bool(0.5) {
            revealed_indices.insert(i);
        }
    }

    let context = b"testing123";

    let proof = proving::generate_selective_disclosure_proof(
        &params,
        &credential,
        &messages,
        &revealed_indices,
        context,
        &mut rng,
    );

    // 5. Verify selective-disclosure ZK proof
    let mut revealed_messages = BTreeMap::new();
    for &idx in &revealed_indices {
        revealed_messages.insert(idx, messages[idx]);
    }

    assert!(
        proof_verification::verify_selective_disclosure_proof(
            &params,
            &public_key,
            &revealed_messages,
            context,
            &proof,
        ),
        "Selective disclosure proof should verify successfully"
    );

    // 6. Verification with tampered context or message should fail
    let context2 = b"testing124";
    assert!(
        !proof_verification::verify_selective_disclosure_proof(
            &params,
            &public_key,
            &revealed_messages,
            context2,
            &proof,
        ),
        "Proof verification should fail if context is modified"
    );
    let mut tampered_messages = revealed_messages.clone();
    tampered_messages.insert(1, Scalar::from(999u64));
    assert!(
        !proof_verification::verify_selective_disclosure_proof(
            &params,
            &public_key,
            &tampered_messages,
            context,
            &proof,
        ),
        "Proof verification should fail if revealed message is modified"
    );
}

#[test]
fn test_issuer_hiding_flow() {
    for _ in 0..5 {
        let mut rng = rand::thread_rng();
        let message_count = 4;
        let params = Parameters::new(message_count, &mut rng);

        // Create policy with l keys
        let l = 7;
        let mut secret_keys = Vec::new();
        let mut policy = Vec::new();
        for _ in 0..l {
            let sk = SecretKey::random(&mut rng);
            let pk = sk.public_key(&params);
            secret_keys.push(sk);
            policy.push(pk);
        }

        // Issuer is chosen randomly from policy keys
        let my_pk_index = rng.gen_range(0..l);
        let messages: Vec<Scalar> = (0..message_count).map(|_| Scalar::random(&mut rng)).collect();
        let credential =
            signing::generate_credential(&params, &secret_keys[my_pk_index], &messages, &mut rng);

        // Disclose indices 1 and 3
        let mut disclosed_indices = BTreeSet::new();
        disclosed_indices.insert(1);
        disclosed_indices.insert(3);

        let mut disclosed_messages = BTreeMap::new();
        disclosed_messages.insert(1, messages[1]);
        disclosed_messages.insert(3, messages[3]);

        let context = b"test_context";

        for &mode in &[
            IssuerHidingMode::NaiveFast,
            IssuerHidingMode::NaiveShort,
            IssuerHidingMode::GK,
            IssuerHidingMode::StackedSigmas,
        ] {
            // Generate proof
            let proof = generate_issuer_hiding_proof(
                &params,
                &policy,
                &disclosed_indices,
                &messages,
                context,
                &credential,
                my_pk_index,
                mode,
                &mut rng,
            );

            // Verify proof
            let verified = verify_issuer_hiding_proof(
                &params,
                &policy,
                &disclosed_messages,
                context,
                &proof,
                mode,
                &mut rng,
            );
            assert!(verified, "Proof verification failed for mode {:?}", mode);

            // Verify with invalid context fails
            let verified_invalid_context = verify_issuer_hiding_proof(
                &params,
                &policy,
                &disclosed_messages,
                b"wrong_context",
                &proof,
                mode,
                &mut rng,
            );
            assert!(
                !verified_invalid_context,
                "Proof should not verify with wrong context for mode {:?}",
                mode
            );

            // Verify with wrong disclosed messages fails
            let mut wrong_disclosed_messages = disclosed_messages.clone();
            wrong_disclosed_messages.insert(1, Scalar::random(&mut rng)); // corrupt one message
            let verified_corrupted_msg = verify_issuer_hiding_proof(
                &params,
                &policy,
                &wrong_disclosed_messages,
                context,
                &proof,
                mode,
                &mut rng,
            );
            assert!(
                !verified_corrupted_msg,
                "Proof should not verify with corrupted message for mode {:?}",
                mode
            );

            // Verify with a policy that does NOT contain the issuer's key fails
            let mut wrong_policy = policy.clone();
            let fresh_sk = SecretKey::random(&mut rng);
            wrong_policy[my_pk_index] = fresh_sk.public_key(&params);
            let verified_wrong_policy = verify_issuer_hiding_proof(
                &params,
                &wrong_policy,
                &disclosed_messages,
                context,
                &proof,
                mode,
                &mut rng,
            );
            assert!(
                !verified_wrong_policy,
                "Proof should not verify if issuer key is not in policy for mode {:?}",
                mode
            );
        }
    }
}
