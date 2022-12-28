use std::{io::Write, str::FromStr, ops::Range, collections::BTreeMap};

use serde::{Serialize, Deserialize};
use schnorr_fun::{
    frost::{self, FrostKey},
    Message, fun::{Scalar, marker::{Normal, Zero, Secret}, Point}, Signature,
};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

#[derive(Serialize)]
struct FrostKeyPair {
    frost_key: FrostKey<Normal>,
    secret_share: Scalar,
}

fn get_things_from_parties<T: for<'a> Deserialize<'a>>(prompt: &str, our_index: usize, parties: Range<usize>) -> BTreeMap<usize, T> {
    let mut items = BTreeMap::new();
    for i in parties {
        if i == our_index {
            continue
        }
        let their_poly: T = loop {
            print!("{} {}: ", prompt, i);
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            
            let trimmed_line = line.trim().to_string();
            let quoted_line = if trimmed_line.contains('"') {
                trimmed_line
            } else {
                format!(r#""{}""#, trimmed_line)
            };
            println!("{}", &quoted_line);

            match serde_json::from_str(&quoted_line) {
                Ok(poly) => break poly,
                Err(e) => eprintln!("{:?}", e),
            };
        };
        items.insert(i, their_poly);
    }
    println!("\n");
    items
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
    println!("\n\n");

    let mut public_polys = get_things_from_parties::<Vec<Point>>("Paste the polynomial for participant", our_index, 0..n_parties);
    public_polys.insert(our_index, my_public_poly);

    let keygen = frost.new_keygen(public_polys.into_iter().map(|(_, poly)| poly).collect()).expect("something wrong with what was provided by other parties");
    // Generate secret shares for others and proof-of-possession to protect against rogue key attacks.
    let (my_shares, my_pop) = frost.create_shares(&keygen, my_secret_poly);

    for (i, share) in my_shares.iter().enumerate() {
        if i == our_index {
            continue
        }
        println!("Secretly send these to participant {}:\n\tSecret Share: {}\n\t Proof-of-Possession: {}\n", i, serde_json::to_string(share).unwrap(), serde_json::to_string(&my_pop).unwrap());
    }
    println!("\n\n");

    let mut shares = get_things_from_parties::<Scalar<Secret, Zero>>("Paste the Secret Share from participant", our_index, 0..n_parties);
    shares.insert(our_index, my_shares[our_index].clone());

    let mut pops = get_things_from_parties::<Signature>("Paste the Proof-of-Possession from participant", our_index, 0..n_parties);
    pops.insert(our_index, my_pop);

    // finish keygen by verifying the shares we received, verifying all proofs-of-possession,
    // and calculate our long-lived secret share of the joint FROST key.
    let (secret_share, frost_key) = frost
        .finish_keygen(
            keygen.clone(),
            our_index,
            shares.into_iter().map(|(_, share)| share).collect(),
            pops.into_iter().map(|(_, pop)| pop).collect(),
        )
        .unwrap();

    let frost_kp = FrostKeyPair { frost_key, secret_share };

    print!("Enter a name for this FROST key (saved to file): ");
    let _ = std::io::stdout().flush();
    let mut frost_key_name_input = String::new();
    std::io::stdin().read_line(&mut frost_key_name_input).unwrap();
    let frost_key_name = frost_key_name_input.trim();
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