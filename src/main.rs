// FROSTR
//
// This code is an absolute mess
// If you're interested in FROST I would highly recommend reading:
// https://docs.rs/schnorr_fun/latest/schnorr_fun/frost/index.html

use std::{collections::BTreeMap, io::Write};

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use schnorr_fun::{
    frost::{self, FrostKey},
    fun::{
        marker::{EvenY, NonZero, Public, Secret, Zero},
        Point, Scalar,
    },
    musig::Nonce,
    Message, Signature,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use websocket::ClientBuilder;

// Helper function which `prompt`s for some user input and serializes the required info from parties, skipping our own index
fn get_things_from_parties<T: for<'a> Deserialize<'a>>(
    prompt: &str,
    our_index: usize,
    parties: Vec<usize>,
) -> BTreeMap<usize, T> {
    let mut items = BTreeMap::new();
    for i in parties {
        if i == our_index {
            continue;
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

#[derive(Serialize, Deserialize)]
struct FrostKeyPair {
    frost_key: FrostKey<EvenY>,
    secret_share: Scalar,
    our_index: usize,
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

    println!(
        "Share our public polynomial\n\t(index {}): {}",
        our_index, my_poly_str
    );
    println!("\n\n");

    let mut public_polys = get_things_from_parties::<Vec<Point>>(
        "Paste the polynomial for participant",
        our_index,
        (0..n_parties).collect(),
    );
    public_polys.insert(our_index, my_public_poly);

    let keygen = frost
        .new_keygen((0..n_parties).map(|i| public_polys.get(&i).expect("got poly from party").clone()).collect())
        .expect("something wrong with what was provided by other parties");
    // Generate secret shares for others and proof-of-possession to protect against rogue key attacks.
    let (my_shares, my_pop) = frost.create_shares(&keygen, my_secret_poly);

    for (i, share) in my_shares.iter().enumerate() {
        if i == our_index {
            continue;
        }
        println!("Secretly send these to participant {}:\n\tSecret Share: {}\n\tProof-of-Possession: {}\n", i, serde_json::to_string(share).unwrap(), serde_json::to_string(&my_pop).unwrap());
    }
    println!("\n\n");

    let mut shares = get_things_from_parties::<Scalar<Secret, Zero>>(
        "Paste the Secret Share from participant",
        our_index,
        (0..n_parties).collect(),
    );
    shares.insert(our_index, my_shares[our_index].clone());

    let mut pops = get_things_from_parties::<Signature>(
        "Paste the Proof-of-Possession from participant",
        our_index,
        (0..n_parties).collect(),
    );
    pops.insert(our_index, my_pop);

    // finish keygen by verifying the shares we received, verifying all proofs-of-possession,
    // and calculate our long-lived secret share of the joint FROST key.
    let (secret_share, frost_key) = frost
        .finish_keygen(
            keygen.clone(),
            our_index,
            (0..n_parties).map(|i| shares.get(&i).expect("got share from party").clone()).collect(),
            (0..n_parties).map(|i| pops.get(&i).expect("got pop from party").clone()).collect(),
        )
        .unwrap();

    let frost_kp = FrostKeyPair {
        frost_key: frost_key.into_xonly_key(),
        secret_share,
        our_index,
    };

    print!("Enter a name for this FROST key (saved to file): ");
    let _ = std::io::stdout().flush();
    let mut frost_key_name_input = String::new();
    std::io::stdin()
        .read_line(&mut frost_key_name_input)
        .unwrap();
    let frost_key_name = frost_key_name_input.trim();
    std::fs::write(
        format!("{}.frost", frost_key_name),
        serde_json::to_string(&frost_kp).unwrap(),
    )
    .expect("Unable to save frost file to disk");
}

fn sign(
    frost_keypair: &FrostKeyPair,
    message: Message<Public>,
    signing_parties: Vec<usize>,
) -> Signature {
    let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();
    // // Generate nonces for this signing session.
    // // ⚠ session_id must be different for every signing attempt
    let mut session_id = [0u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut session_id);

    let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(
        &frost_keypair.frost_key,
        &frost_keypair.secret_share,
        &session_id,
    );
    let my_nonce = frost.gen_nonce(&mut nonce_rng);
    // share your public nonce with the other signing participant(s)
    println!(
        "Share your public nonce with the other signers:\n\t(index {}): {}",
        frost_keypair.our_index,
        serde_json::to_string(&my_nonce.public()).unwrap()
    );
    println!("\n\n");

    // receive public nonces from other signers
    let mut nonces = get_things_from_parties::<Nonce<NonZero>>(
        "Paste the Public Nonce from participant",
        frost_keypair.our_index,
        signing_parties.clone(),
    );
    nonces.insert(frost_keypair.our_index, my_nonce.public());

    let nonces = nonces.into_iter().collect();
    // start a sign session with these nonces for a message
    let session = frost.start_sign_session(&frost_keypair.frost_key, nonces, message);
    // create a partial signature using our secret share and secret nonce
    let my_sig = frost.sign(
        &frost_keypair.frost_key,
        &session,
        frost_keypair.our_index,
        &frost_keypair.secret_share,
        my_nonce,
    );
    println!(
        "Send your Signature Share to all of the other signers:\n\t(index {}): {}\n",
        frost_keypair.our_index,
        serde_json::to_string(&my_sig).unwrap()
    );
    let mut sig_shares = get_things_from_parties::<Scalar<Public, Zero>>(
        "Paste the Signature Share from participant",
        frost_keypair.our_index,
        signing_parties.clone(),
    );
    if signing_parties.contains(&frost_keypair.our_index) {
        sig_shares.insert(frost_keypair.our_index, my_sig);
    }

    for (i, share) in sig_shares.clone().into_iter() {
        // receive the partial signature(s) from the other participant(s) and verify
        assert!(frost.verify_signature_share(&frost_keypair.frost_key, &session, i, share));
    }

    // combine signature shares into a single signature that is valid under the FROST key
    let combined_sig = frost.combine_signature_shares(
        &frost_keypair.frost_key,
        &session,
        signing_parties.iter().map(|i| sig_shares.get(&i).expect("got sig share from party").clone()).collect()
    );
    assert!(frost.schnorr.verify(
        &frost_keypair.frost_key.public_key(),
        message,
        &combined_sig
    ));

    combined_sig
}

struct UnsignedEvent {
    id: String,
    pubkey: Point<EvenY>,
    created_at: i64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    //hacky and gross
    hash_bytes: Vec<u8>,
}

impl UnsignedEvent {
    fn new_unsigned(
        pubkey: Point<EvenY>,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
        created_at: i64,
    ) -> Self {
        let serialized_event = json!([0, pubkey, created_at, kind, json!(tags), content]);
        println!(
            "This is the FROSTR event to be created: {}\n",
            &serialized_event
        );

        let mut hash = Sha256::default();
        hash.update(serialized_event.to_string().as_bytes());
        let hash_result = hash.finalize();
        let hash_result_str = format!("{:x}", hash_result);
        // let schnorr_message: Message<Public> = Message::raw(&hash_result[..]);

        Self {
            id: hash_result_str,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            hash_bytes: hash_result.to_vec(),
        }
    }

    fn add_signature(self, signature: Signature) -> SignedEvent {
        SignedEvent {
            id: self.id,
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags,
            content: self.content,
            sig: signature,
        }
    }
}

#[derive(Serialize)]
struct SignedEvent {
    id: String,
    pubkey: Point<EvenY>,
    created_at: i64,
    kind: u64,
    tags: Vec<Vec<String>>,
    content: String,
    sig: Signature,
}

// Adapted from https://github.com/rot13maxi/moe-bot/
fn publish_to_relay(relay: &str, message: &websocket::Message) -> Result<(), String> {
    let mut client = ClientBuilder::new(relay)
        .map_err(|err| format!("Could not create client: {}", err.to_string()))?
        .connect(None)
        .map_err(|err| format!("Could not connect to relay {}: {}", relay, err.to_string()))?;
    client
        .send_message(message)
        .map_err(|err| format!("could not send message to relay: {}", err.to_string()))?;
    Ok(())
}

// Adapted from https://github.com/rot13maxi/moe-bot/
fn broadcast_event(event: SignedEvent) {
    let event_json = json!(event).to_string();
    dbg!("{}", &event_json);

    let event_msg = json!(["EVENT", event]).to_string();
    dbg!("{}", &event_msg);
    let message = websocket::Message::text(event_msg);
    for relay in vec![
        "wss://relay.damus.io",
        "wss://nostr.zebedee.cloud",
        "wss://relay.nostr.ch",
        "wss://nostr-pub.wellorder.net",
        "wss://nostr-pub.semisol.dev",
        "wss://nostr.oxtr.dev",
    ] {
        match publish_to_relay(relay, &message) {
            Ok(_) => println!("sent message to {}", relay),
            Err(e) => eprintln!("{}", e),
        };
    }
}

fn main() {
    loop {
        println!(
            "
╱╭━━━╮╱╭━━━╮╱╭━━━╮╱╭━━━╮╱╭━━━━╮╱╭━━━╮
╱┃╭━━╯╱┃╭━╮┃╱┃╭━╮┃╱┃╭━╮┃╱┃╭╮╭╮┃╱┃╭━╮┃
╱┃╰━━╮╱┃╰━╯┃╱┃┃╱┃┃╱┃╰━━╮╱╰╯┃┃╰╯╱┃╰━╯┃
╱┃╭━━╯╱┃╭╮╭╯╱┃┃╱┃┃╱╰━━╮┃╱╱╱┃┃╱╱╱┃╭╮╭╯
╱┃┃╱╱╱╱┃┃┃╰╮╱┃╰━╯┃╱┃╰━╯┃╱╱╱┃┃╱╱╱┃┃┃╰╮
╱╰╯╱╱╱╱╰╯╰━╯╱╰━━━╯╱╰━━━╯╱╱╱╰╯╱╱╱╰╯╰━╯
"
        );
        println!("** Extremely unsafe and violently untested **");
        println!("Note that all indices start from 0.\n");
        print!("Choose an option:\n\t0) New FROST Keygen\n\t1) Create FROSTR post\n\nSelection: ");
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

            let frost_key_str = std::fs::read_to_string(format!("{}.frost", frost_key_name))
                .expect("Unable to read file");
            let frost_keypair: FrostKeyPair = serde_json::from_str(&frost_key_str).unwrap();

            print!("Enter the nostr message you wish to sign (as a group!): ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let nostr_post_str = line.trim().to_string();

            print!("Enter the agreed upon unix epoch time for the nostr event: ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let event_time = line.trim().to_string().parse::<i64>().unwrap();

            let mut signers = vec![];
            while signers.len() < frost_keypair.frost_key.threshold() {
                print!(
                    "Enter the index of a signer ({} remaining): ",
                    frost_keypair.frost_key.threshold() - signers.len()
                );
                let _ = std::io::stdout().flush();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                let signer_index = line.trim().parse::<usize>().unwrap();
                signers.push(signer_index);
            }

            let unsigned_frostr_event = UnsignedEvent::new_unsigned(
                frost_keypair.frost_key.public_key(),
                1,
                Vec::new(),
                nostr_post_str,
                event_time,
            );

            let schnorr_message = Message::raw(unsigned_frostr_event.hash_bytes.as_slice());
            let signature = sign(&frost_keypair, schnorr_message, signers);
            println!("Final FROST signature: {}", signature.clone());

            let frostr_event = unsigned_frostr_event.add_signature(signature);

            print!("Do you wish to broadcast this event? (y/n): ");
            let _ = std::io::stdout().flush();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
            let response = line.trim();
            if response.to_lowercase() == "y" {
                broadcast_event(frostr_event);
            }
        } else {
            eprintln!("Invalid choice!");
        }
    }
}
