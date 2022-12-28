use std::{io::Write, collections::BTreeMap};

use serde::{Serialize, Deserialize};
use schnorr_fun::{
    frost::{self, FrostKey},
    Message, fun::{Scalar, marker::{Normal, Zero, Secret, Public, NonZero}, Point}, Signature, musig::Nonce,
};
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

#[derive(Serialize, Deserialize)]
struct FrostKeyPair {
    frost_key: FrostKey<Normal>,
    secret_share: Scalar,
    our_index: usize,
}

fn get_things_from_parties<T: for<'a> Deserialize<'a>>(prompt: &str, our_index: usize, parties: Vec<usize>) -> BTreeMap<usize, T> {
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

    let mut public_polys = get_things_from_parties::<Vec<Point>>("Paste the polynomial for participant", our_index, (0..n_parties).collect());
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

    let mut shares = get_things_from_parties::<Scalar<Secret, Zero>>("Paste the Secret Share from participant", our_index, (0..n_parties).collect());
    shares.insert(our_index, my_shares[our_index].clone());

    let mut pops = get_things_from_parties::<Signature>("Paste the Proof-of-Possession from participant", our_index, (0..n_parties).collect());
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

    let frost_kp = FrostKeyPair { frost_key, secret_share, our_index };

    print!("Enter a name for this FROST key (saved to file): ");
    let _ = std::io::stdout().flush();
    let mut frost_key_name_input = String::new();
    std::io::stdin().read_line(&mut frost_key_name_input).unwrap();
    let frost_key_name = frost_key_name_input.trim();
    std::fs::write(format!("{}.frost", frost_key_name), serde_json::to_string(&frost_kp).unwrap()).expect("Unable to save frost file to disk");
    

}


fn sign(frost_keypair: FrostKeyPair, message: &str, signing_parties: Vec<usize>) -> Signature {
    let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();
    // // We're ready to do some signing, so convert to xonly key
    let frost_key = frost_keypair.frost_key.into_xonly_key();
    let message: Message<Public> =  Message::plain("frostr", message.as_bytes());
    // // Generate nonces for this signing session.
    // // ⚠ session_id must be different for every signing attempt
    let session_id = b"my extremely unique sid".as_slice();
    let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(&frost_key, &frost_keypair.secret_share, session_id);
    let my_nonce = frost.gen_nonce(&mut nonce_rng);
    // share your public nonce with the other signing participant(s)
    println!("Share your public nonce with the other signers: {}", serde_json::to_string(&my_nonce.public()).unwrap());

    // receive public nonces from other signers
    let mut nonces = get_things_from_parties::<Nonce<NonZero>>("Paste the Public Nonce from participant", frost_keypair.our_index, signing_parties.clone());
    nonces.insert(frost_keypair.our_index, my_nonce.public());


    let nonces = nonces.into_iter().collect();
    // start a sign session with these nonces for a message
    let session = frost.start_sign_session(&frost_key, nonces, message);
    // create a partial signature using our secret share and secret nonce
    let my_sig = frost.sign(&frost_key, &session, frost_keypair.our_index, &frost_keypair.secret_share, my_nonce);

    let mut sig_shares = get_things_from_parties::<Scalar<Public, Zero>>("Paste the Signature Share from participant", frost_keypair.our_index, signing_parties.clone());
    if signing_parties.contains(&frost_keypair.our_index) {
        sig_shares.insert(frost_keypair.our_index, my_sig);
    }

    for (i, share) in sig_shares.clone().into_iter() {
        // receive the partial signature(s) from the other participant(s) and verify
        assert!(frost.verify_signature_share(&frost_key, &session, i, share));
    }

    // combine signature shares into a single signature that is valid under the FROST key
    let combined_sig = frost.combine_signature_shares(&frost_key, &session, sig_shares.into_iter().map(|(_, sig)| sig).collect());
    assert!(frost.schnorr.verify(
        &frost_key.public_key(),
        message,
        &combined_sig
    ));

    combined_sig
}




fn main() {
    loop {
        print!("Choose an option:\n\r0) New Frost Keygen\n\r1) Sign using existing FROST key\n\nSelection:");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        let choice = line.trim().to_string();
        if choice == "0" {
            print!("How many parties will there be? (N): ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let n_parties = line.trim().parse::<usize>().unwrap();

            print!("What will the threshold be? (T where T <= N): ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let threshold = line.trim().parse::<usize>().unwrap();

            frost_keygen(threshold, n_parties)

        } else if choice == "1" {
            print!("Type the name of the frost key you wish to use: ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let frost_key_name = line.trim();

            let frost_key_str = std::fs::read_to_string(format!("{}.frost", frost_key_name)).expect("Unable to read file");
            let frost_keypair: FrostKeyPair = serde_json::from_str(&frost_key_str).unwrap();

            print!("Enter the message you wish to sign (as a group!): ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let message_str = line.trim();

            let mut signers = vec![];
            while signers.len() < frost_keypair.frost_key.threshold() {
                print!("Enter the index of a signer ({} remaining): ", frost_keypair.frost_key.threshold() - signers.len());
                let _ = std::io::stdout().flush();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                let signer_index = line.trim().parse::<usize>().unwrap();
                signers.push(signer_index);
            }

            let signature = sign(frost_keypair, message_str, signers);
            println!("Final FROST signature: {}", signature)
        } else {
            eprintln!("Wrong choice!");
        }
    }
}