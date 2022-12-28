use std::io::Write;

use serde::Serialize;
use schnorr_fun::{
    frost::{self, FrostKey},
    Message, fun::{Scalar, marker::Normal},
};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

#[derive(Serialize)]
struct FrostKeyPair {
    frost_key: FrostKey<Normal>,
    secret_share: Scalar,
}

fn frost_keygen(threshold: usize, n_parties: usize) {
    // Use randomness from ThreadRng to create synthetic nonces -- harder to make a mistake.
    let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();
    // We need an RNG for key generation
    let mut rng = rand::thread_rng();
    // Generate our secret scalar polynomial we'll use in the key generation protocol
    let my_secret_poly = frost::generate_scalar_poly(threshold, &mut rng);
    let my_public_poly = frost::to_point_poly(&my_secret_poly);
    let my_poly_str = serde_json::to_string(&my_public_poly).unwrap();

    // Get our participant index
    print!("Enter our participant index: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    let our_index = line.trim().parse::<usize>().expect("valid index");

    println!("Share our public polynomial: (index {}) - {}", our_index, my_poly_str);

    // Receive the point polys from other participants
    let mut public_polys = vec![];
    println!("Fetch others' polynomials...");
    for i in 0..n_parties {
        if i == our_index {
            public_polys.push(my_public_poly.clone());
            continue
        }
        let their_poly = loop {
            print!("Paste the polynomial for participant {}: ", i);
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            match serde_json::from_str(&line) {
                Ok(poly) => break poly,
                Err(e) => eprint!("{:?}", e),
            };
        };
        public_polys.push(their_poly);
    }
    println!("\n\n");

    let keygen = frost.new_keygen(public_polys).expect("something wrong with what was provided by other parties");
    // Generate secret shares for others and proof-of-possession to protect against rogue key attacks.
    let (my_shares, my_pop) = frost.create_shares(&keygen, my_secret_poly);

    for (i, share) in my_shares.iter().enumerate() {
        if i == our_index {
            continue
        }
        println!("Secretly send these to participant {}: \nShare: {}\nProof-of-Possession: {}\n", i, share, my_pop.clone());
    }
    println!("\n\n");

    // Receive the point polys from other participants
    let mut shares = vec![];
    let mut pops = vec![];
    println!("Fetch others' secret shares and proofs-of-possession...");
    for i in 0..n_parties {
        if i == our_index {
            shares.push(my_shares[i].clone());
            pops.push(my_pop.clone());
            continue
        }
        let received_share = loop {
            print!("Paste the secret share from participant {}: ", i);
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            match serde_json::from_str(&line) {
                Ok(share) => break share,
                Err(e) => eprint!("{:?}", e),
            };
        };
        shares.push(received_share);
        
        let received_pop = loop {
            print!("Paste the proof-of-posession from participant {}: ", i);
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            match serde_json::from_str(&line) {
                Ok(pop) => break pop,
                Err(e) => eprint!("{:?}", e),
            };
        };
        pops.push(received_pop);
    }
    println!("\n\n");

    // finish keygen by verifying the shares we received, verifying all proofs-of-possession,
    // and calculate our long-lived secret share of the joint FROST key.
    let (secret_share, frost_key) = frost
        .finish_keygen(
            keygen.clone(),
            our_index,
            shares,
            pops,
        )
        .unwrap();

    let frost_kp = FrostKeyPair { frost_key, secret_share };

    print!("Enter a name for this FROST key (saved to file): ");
    let _ = std::io::stdout().flush();
    let mut frost_key_name = String::new();
    std::io::stdin().read_line(&mut frost_key_name).unwrap();
    std::fs::write(format!("{}.frost", frost_key_name), serde_json::to_string(&frost_kp).unwrap()).expect("Unable to save frost file to disk");
    
    // // We're ready to do some signing, so convert to xonly key
    // let frost_key = frost_key.into_xonly_key();
    // let message =  Message::plain("my-app", b"chancellor on brink of second bailout for banks");
    // // Generate nonces for this signing session.
    // // ⚠ session_id must be different for every signing attempt
    // let session_id = b"signing-ominous-message-about-banks-attempt-1".as_slice();
    // let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(&frost_key, &my_secret_share, session_id);
    // let my_nonce = frost.gen_nonce(&mut nonce_rng);
    // // share your public nonce with the other signing participant(s)
    // // receive public nonces from other signers
    // let nonces = vec![(0, my_nonce.public()), (2, received_nonce3)];
    // // start a sign session with these nonces for a message
    // let session = frost.start_sign_session(&frost_key, nonces, message);
    // // create a partial signature using our secret share and secret nonce
    // let my_sig = frost.sign(&frost_key, &session, 0, &my_secret_share, my_nonce);
    // // receive the partial signature(s) from the other participant(s) and verify
    // assert!(frost.verify_signature_share(&frost_key, &session, 2, sig3));
    // // combine signature shares into a single signature that is valid under the FROST key
    // let combined_sig = frost.combine_signature_shares(&frost_key, &session, vec![my_sig, sig3]);
    // assert!(frost.schnorr.verify(
    //     &frost_key.public_key(),
    //     message,
    //     &combined_sig
    // ));
}


fn main() {
    frost_keygen(2, 2)
}