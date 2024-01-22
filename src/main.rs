// FROSTR
//
// This code is an absolute mess
// If you're interested in FROST I would highly recommend reading:
// https://docs.rs/schnorr_fun/latest/schnorr_fun/frost/index.html

use std::{collections::BTreeMap, io::Write, num::NonZeroU32};

use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use schnorr_fun::fun::{
    marker::{EvenY, NonZero, Public, Secret, Zero},
    Point, Scalar,
};
use schnorr_fun::{
    frost::{self, FrostKey},
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
    our_index: Scalar<Public>,
    parties: &BTreeMap<usize, Scalar<Public>>,
) -> BTreeMap<Scalar<Public>, T> {
    let mut items = BTreeMap::new();
    for (label, party_index) in parties {
        if *party_index == our_index {
            continue;
        }
        let their_poly: T = loop {
            print!("{} {}: ", prompt, label);
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
        items.insert(*party_index, their_poly);
    }
    println!("\n");
    items
}

#[derive(Serialize, Deserialize)]
struct FrostKeyPair {
    frost_key: FrostKey<EvenY>,
    secret_share: Scalar,
    our_index: Scalar<Public>,
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

    println!("During keygen, copy and paste the things in brackets or quotes in new lines and share them to the correct recipient.");
    println!("It's rather hacky so make sure you enter the correct thing from the correct party at each stage.");

    // Get our participant index
    print!("\nEnter our participant index.\n⚠ Participant indexes must be chosen (1, 2, ...).\nNon-zero and unique.\nMy Index: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    let entered_index = line.trim().parse::<usize>().expect("valid index") as u32;

    let our_index = Scalar::from_non_zero_u32(
        NonZeroU32::try_from(entered_index).expect("Participant index can't be zero!"),
    )
    .public();

    let parties: BTreeMap<_, _> = (0..n_parties)
        .map(|party_index| {
            (
                party_index + 1,
                Scalar::from_non_zero_u32(
                    NonZeroU32::try_from(party_index as u32 + 1).expect("non-zero"),
                )
                .public(),
            )
        })
        .collect();

    println!("Share our public polynomial\n{}", my_poly_str);
    println!("\n\n");

    let mut public_polys = get_things_from_parties::<Vec<_>>(
        "Paste the polynomial for participant",
        our_index,
        &parties,
    );
    public_polys.insert(our_index, my_public_poly);

    let keygen = frost
        .new_keygen(public_polys)
        .expect("something wrong with what was provided by other parties");
    // Generate secret shares for others and proof-of-possession to protect against rogue key attacks.
    let pop_message = Message::raw(b"");
    let (my_shares, my_pop): (BTreeMap<Scalar<Public>, Scalar<Secret, Zero>>, Signature) =
        frost.create_shares_and_pop(&keygen, &my_secret_poly, pop_message);

    for (label, index) in parties.iter() {
        // for (i, share) in my_shares.iter() {
        if *index == our_index {
            continue;
        }
        println!(
            "Secretly send these to participant {}:\n\tSecret Share:\n{}\n\tProof-of-Possession:\n{}\n",
            label,
            serde_json::to_string(my_shares.get(&index).unwrap()).unwrap(),
            serde_json::to_string(&my_pop).unwrap()
        );
    }
    println!("\n\n");

    let mut shares = get_things_from_parties::<Scalar<Secret, Zero>>(
        "Paste the Secret Share from participant",
        our_index,
        &parties,
    );
    shares.insert(our_index, my_shares[&our_index].clone());

    let mut pops = get_things_from_parties::<Signature>(
        "Paste the Proof-of-Possession from participant",
        our_index,
        &parties,
    );
    pops.insert(our_index, my_pop);

    let collected_shares = parties
        .values()
        .map(|index| {
            (
                *index,
                (
                    shares
                        .get(index)
                        .expect("must have share from this party")
                        .clone(),
                    pops.get(index)
                        .expect("must have pop from this party")
                        .clone(),
                ),
            )
        })
        .collect();

    // finish keygen by verifying the shares we received, verifying all proofs-of-possession,
    // and calculate our long-lived secret share of the joint FROST key.
    let (secret_share, frost_key) = frost
        .finish_keygen(keygen.clone(), our_index, collected_shares, pop_message)
        .unwrap();

    let frost_kp = FrostKeyPair {
        frost_key: frost_key.into_xonly_key(),
        secret_share,
        our_index,
    };

    print!("Enter a name for this FROST key (saved to file - don't overwrite another party's keyfile..): ");
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
    signing_parties: &BTreeMap<usize, Scalar<Public>>,
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
        "Share your public nonce with the other signers:\n{}",
        serde_json::to_string(&my_nonce.public()).unwrap()
    );
    println!("\n\n");

    // receive public nonces from other signers
    let mut nonces = get_things_from_parties::<Nonce<NonZero>>(
        "Paste the Public Nonce from participant",
        frost_keypair.our_index,
        &signing_parties,
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
        "Send your Signature Share to all of the other signers:\n{}\n",
        serde_json::to_string(&my_sig).unwrap()
    );
    let mut sig_shares = get_things_from_parties::<Scalar<Public, Zero>>(
        "Paste the Signature Share from participant",
        frost_keypair.our_index,
        &signing_parties,
    );
    if signing_parties
        .values()
        .any(|idx| idx == &frost_keypair.our_index)
    {
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
        signing_parties
            .values()
            .map(|party_index| {
                sig_shares
                    .get(&party_index)
                    .expect("got sig share from party")
                    .clone()
            })
            .collect(),
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

            let mut signers = BTreeMap::new();
            while signers.len() < frost_keypair.frost_key.threshold() {
                print!(
                    "Enter the index of a signer ({} remaining): ",
                    frost_keypair.frost_key.threshold() - signers.len()
                );
                let _ = std::io::stdout().flush();
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                let signer_index = line.trim().parse::<usize>().unwrap();
                let party_index = Scalar::from_non_zero_u32(
                    NonZeroU32::try_from(signer_index as u32).expect("signer index can't be zero"),
                )
                .public();
                signers.insert(signer_index, party_index);
            }

            let unsigned_frostr_event = UnsignedEvent::new_unsigned(
                frost_keypair.frost_key.public_key(),
                1,
                Vec::new(),
                nostr_post_str,
                event_time,
            );

            let schnorr_message = Message::raw(unsigned_frostr_event.hash_bytes.as_slice());
            let signature = sign(&frost_keypair, schnorr_message, &signers);
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
