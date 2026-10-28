use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use futures::StreamExt;
use keystone_core::{
    content::{ContentRecord, ContentStore, content_dht_key},
    follow::{
        FollowPayload, FollowStore, RevocationPayload, create_follow, create_revocation,
        revocation_dht_key,
    },
    identity::{Identity, SignedMessage},
    network::{KeystoneBehaviourEvent, build_swarm_with_keypair, keypair_from_identity},
    protocol::{ChunkRequest, ChunkResponse, ContentResponse, FollowRequest, FollowResponse},
};
use libp2p::{
    Multiaddr, PeerId, identify, kad, mdns, multiaddr::Protocol, relay, request_response,
    swarm::SwarmEvent,
};

const DEFAULT_KEY_FILE: &str = "keystone.key";
// The bootstrap node is not compiled in: it is whoever runs one, given as a multiaddr ending in
// its peer id. Without one the node finds peers on the local network only (mDNS).
const BOOTSTRAP_ENV: &str = "KEYSTONE_BOOTSTRAP";
// Flags that take a value. The key file is the first argument that is neither one of these
// nor a value given to one.
const VALUE_FLAGS: [&str; 5] = ["--find", "--follow", "--publish", "--fetch", "--bootstrap"];

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn key_path(args: &[String]) -> PathBuf {
    let mut rest = args.iter().skip(1);
    while let Some(a) = rest.next() {
        if VALUE_FLAGS.contains(&a.as_str()) {
            rest.next();
        } else if !a.starts_with("--") {
            return PathBuf::from(a);
        }
    }
    PathBuf::from(DEFAULT_KEY_FILE)
}

fn bootstrap_setting(args: &[String], env: Option<String>) -> Option<String> {
    flag_value(args, "--bootstrap")
        .or(env)
        .filter(|s| !s.trim().is_empty())
}

/// The address to dial, and the circuit address through it: the bootstrap node doubles as a
/// circuit relay, the fallback when this node is behind NAT.
fn parse_bootstrap(addr: &str) -> Result<(Multiaddr, Multiaddr), String> {
    let dial: Multiaddr = addr
        .parse()
        .map_err(|e| format!("bootstrap address {addr:?} is not a multiaddr: {e}"))?;
    if !matches!(dial.iter().last(), Some(Protocol::P2p(_))) {
        return Err(format!(
            "bootstrap address {addr:?} must end in /p2p/<peer id>"
        ));
    }
    let circuit = dial.clone().with(Protocol::P2pCircuit);
    Ok((dial, circuit))
}

fn load_or_create_identity(path: &PathBuf) -> Result<Identity, Box<dyn std::error::Error>> {
    if path.exists() {
        let password = rpassword::prompt_password("Enter password: ")?;
        let identity = Identity::load_encrypted(path, &password)?;
        println!("Identity loaded.");
        Ok(identity)
    } else {
        println!("No identity found at {}.", path.display());
        println!("Creating a new identity...");
        let password = rpassword::prompt_password("Set a password: ")?;
        let confirm = rpassword::prompt_password("Confirm password: ")?;
        if password != confirm {
            return Err("Passwords do not match.".into());
        }
        let identity = Identity::generate();
        identity.save_encrypted(path, &password)?;
        println!("New identity created and saved to {}.", path.display());
        Ok(identity)
    }
}

fn start_chunk_fetch(
    swarm: &mut libp2p::Swarm<keystone_core::network::KeystoneBehaviour>,
    content_store: &ContentStore,
    hash: &str,
    publisher: PeerId,
    active_fetches: &mut HashMap<String, ContentRecord>,
    fetch_peers: &mut HashMap<String, PeerId>,
    pending_fetches: &mut HashMap<PeerId, Vec<String>>,
) {
    // Resume: if we already have a partial record, request only pending chunks.
    // Otherwise, just request chunk 0 — the response tells us total_size and
    // chunk_size, which we need before we can set up the full ContentRecord.
    fetch_peers.insert(hash.to_string(), publisher);

    if let Some(record) = content_store.load_meta(hash) {
        let pending = record.pending_chunks();
        println!("[~] Resuming fetch — {} chunk(s) remaining", pending.len());
        active_fetches.insert(hash.to_string(), record);
        if swarm.is_connected(&publisher) {
            for idx in pending {
                swarm.behaviour_mut().chunks.send_request(
                    &publisher,
                    ChunkRequest {
                        hash: hash.to_string(),
                        chunk_index: idx,
                    },
                );
            }
        } else {
            pending_fetches
                .entry(publisher)
                .or_default()
                .push(hash.to_string());
            let _ = swarm.dial(publisher);
        }
    } else if swarm.is_connected(&publisher) {
        swarm.behaviour_mut().chunks.send_request(
            &publisher,
            ChunkRequest {
                hash: hash.to_string(),
                chunk_index: 0,
            },
        );
    } else {
        pending_fetches
            .entry(publisher)
            .or_default()
            .push(hash.to_string());
        let _ = swarm.dial(publisher);
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    let query_mode = args.iter().any(|a| a == "--query");
    let revoke_mode = args.iter().any(|a| a == "--revoke");

    let find_key = flag_value(&args, "--find");

    let follow_key = flag_value(&args, "--follow");

    let publish_path = flag_value(&args, "--publish").map(PathBuf::from);

    let fetch_hash = flag_value(&args, "--fetch");

    let key_path = key_path(&args);
    // A bad address is a mistake to stop on, not something to quietly run without.
    let bootstrap = bootstrap_setting(&args, std::env::var(BOOTSTRAP_ENV).ok())
        .map(|a| parse_bootstrap(&a))
        .transpose()?;

    let identity = load_or_create_identity(&key_path)?;
    let libp2p_keypair = keypair_from_identity(&identity)?;
    let agent = format!("keystone/1.0/{}", identity.public_key_hex());
    let mut swarm = build_swarm_with_keypair(libp2p_keypair, &agent)?;
    swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));

    // Each node gets its own content directory derived from the key file name.
    // Prevents two nodes running in the same directory from clobbering each
    // other's files during fetch (begin_fetch truncates the file to pre-allocate).
    let content_dir = key_path
        .file_stem()
        .map(|s| format!("{}_content", s.to_string_lossy()))
        .unwrap_or_else(|| "content".to_string());
    let content_store = ContentStore::new(&content_dir)?;
    let mut follow_store = FollowStore::new();
    let mut dialed: HashSet<PeerId> = HashSet::new();
    let mut requested: HashSet<PeerId> = HashSet::new();

    let mut find_query_id: Option<kad::QueryId> = None;
    let mut revocation_checks: HashMap<kad::QueryId, String> = HashMap::new();
    let mut revoke_published = false;

    // DHT query id → hash being fetched
    let mut content_fetch_queries: HashMap<kad::QueryId, String> = HashMap::new();
    // hash → in-progress ContentRecord
    let mut active_fetches: HashMap<String, ContentRecord> = HashMap::new();
    // hash → peer we're fetching from
    let mut fetch_peers: HashMap<String, PeerId> = HashMap::new();
    // peer → hashes to fetch once connected
    let mut pending_fetches: HashMap<PeerId, Vec<String>> = HashMap::new();

    println!("\n=== Keystone Node ===");
    println!("Public key : {}", identity.public_key_hex());
    println!("Peer ID    : {}", swarm.local_peer_id());

    let publish_hash: Option<String> = if let Some(ref path) = publish_path {
        let bytes = std::fs::read(path)?;
        let hash = content_store.store(&bytes)?;
        println!("\n[+] Stored locally : {hash}");
        println!("    File           : {}", path.display());
        println!("    Size           : {} bytes", bytes.len());
        println!("    Will announce to DHT once connected...");
        Some(hash)
    } else {
        None
    };

    if let Some(ref followee_pubkey) = follow_key {
        let record = create_follow(&identity, followee_pubkey);
        follow_store.add(record).unwrap();
        println!(
            "\n[f] Follow recorded : {} → {}",
            &identity.public_key_hex()[..12],
            &followee_pubkey[..12.min(followee_pubkey.len())]
        );
    }

    if revoke_mode {
        println!("\n[!] Revoke mode — will publish revocation once DHT is reachable.");
    }

    if let Some(ref hash) = fetch_hash {
        println!("\n[?] Will fetch: {}...", &hash[..16.min(hash.len())]);
    }

    if query_mode {
        println!("\n[?] Query mode — will request follows from any discovered peer\n");
    } else {
        println!(
            "    Serving {} follow record(s). Waiting for peers...\n",
            follow_store.len()
        );
    }

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;

    match bootstrap {
        Some((dial, relay_circuit)) => {
            match swarm.dial(dial) {
                Ok(_) => println!("[b] Dialing bootstrap node..."),
                Err(e) => println!("[b] Bootstrap dial failed: {e} (continuing with mDNS only)"),
            }

            // Request a relay reservation so peers behind NAT can be reached via the bootstrap relay.
            match swarm.listen_on(relay_circuit) {
                Ok(_) => println!("[r] Relay reservation requested..."),
                Err(e) => println!("[r] Relay reservation failed: {e}"),
            }
        }
        None => println!(
            "[b] No bootstrap node (--bootstrap or {BOOTSTRAP_ENV}); local network only (mDNS)"
        ),
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                let s = address.to_string();
                if s.starts_with("/ip4/127.")
                    || s.starts_with("/ip4/192.")
                    || s.starts_with("/ip4/100.64")
                {
                    println!("Listening  : {}/p2p/{}", address, swarm.local_peer_id());
                }
            }

            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                if let Some(hashes) = pending_fetches.remove(&peer_id) {
                    for hash in hashes {
                        println!("[>] Requesting chunk 0 of {hash} from {peer_id}");
                        swarm.behaviour_mut().chunks.send_request(
                            &peer_id,
                            ChunkRequest {
                                hash,
                                chunk_index: 0,
                            },
                        );
                    }
                }
            }

            SwarmEvent::Behaviour(event) => match event {
                KeystoneBehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                    for (peer_id, addr) in peers {
                        swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, addr.clone());
                        swarm.add_peer_address(peer_id, addr.clone());
                        if query_mode && dialed.insert(peer_id) {
                            println!("[m] Discovered peer  : {peer_id}");
                            let _ = swarm.dial(addr);
                        }
                    }
                }

                KeystoneBehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                }) => {
                    for addr in &info.listen_addrs {
                        swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, addr.clone());
                    }

                    let peer_keystone_key = info
                        .agent_version
                        .strip_prefix("keystone/1.0/")
                        .map(|s| s.to_string());

                    if let Some(ref pubkey) = peer_keystone_key {
                        println!("[i] Peer identity  : {}", &pubkey[..16]);
                    }

                    let _ = swarm.behaviour_mut().kad.bootstrap();

                    let id_record = libp2p::kad::Record::new(
                        libp2p::kad::RecordKey::new(&identity.public_key_hex()),
                        swarm.local_peer_id().to_bytes(),
                    );
                    let _ = swarm
                        .behaviour_mut()
                        .kad
                        .put_record(id_record, libp2p::kad::Quorum::One);

                    if let Some(ref hash) = publish_hash {
                        let content_record = libp2p::kad::Record::new(
                            libp2p::kad::RecordKey::new(&content_dht_key(hash)),
                            swarm.local_peer_id().to_bytes(),
                        );
                        let _ = swarm
                            .behaviour_mut()
                            .kad
                            .put_record(content_record, libp2p::kad::Quorum::One);
                        println!("[+] Content announced to DHT: {}...", &hash[..16]);
                    }

                    if revoke_mode && !revoke_published {
                        let revocation = create_revocation(&identity, "Key compromised by owner");
                        let value = serde_json::to_vec(&revocation).unwrap_or_default();
                        let rev_record = libp2p::kad::Record::new(
                            libp2p::kad::RecordKey::new(&revocation_dht_key(
                                &identity.public_key_hex(),
                            )),
                            value,
                        );
                        let _ = swarm
                            .behaviour_mut()
                            .kad
                            .put_record(rev_record, libp2p::kad::Quorum::One);
                        println!("[!] Revocation published to DHT.");
                        revoke_published = true;
                    }

                    if let Some(ref key) = find_key
                        && find_query_id.is_none()
                    {
                        let dht_key = libp2p::kad::RecordKey::new(key);
                        find_query_id = Some(swarm.behaviour_mut().kad.get_record(dht_key));
                        println!("[?] DHT query fired — waiting for result...");
                    }

                    if let Some(ref hash) = fetch_hash
                        && content_fetch_queries.values().all(|h| h != hash)
                    {
                        let dht_key = libp2p::kad::RecordKey::new(&content_dht_key(hash));
                        let qid = swarm.behaviour_mut().kad.get_record(dht_key);
                        content_fetch_queries.insert(qid, hash.clone());
                        println!("[?] Looking up content on DHT...");
                    }

                    if query_mode && requested.insert(peer_id) {
                        println!("[>] Requesting follows from {peer_id}");
                        swarm
                            .behaviour_mut()
                            .follows
                            .send_request(&peer_id, FollowRequest);
                    }
                }

                // --- Follow protocol ---
                KeystoneBehaviourEvent::Follows(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Request { channel, .. },
                }) => {
                    let response = FollowResponse {
                        records: follow_store.all().to_vec(),
                    };
                    swarm
                        .behaviour_mut()
                        .follows
                        .send_response(channel, response)
                        .ok();
                    println!(
                        "[<] Follow request from {peer} — sent {} record(s)",
                        follow_store.len()
                    );
                }

                KeystoneBehaviourEvent::Follows(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                }) => {
                    println!(
                        "\n[<] {} follow record(s) from {peer}",
                        response.records.len()
                    );
                    for record in &response.records {
                        match record.verify() {
                            Ok(()) => {
                                println!("  [✓] Signature valid");
                                if let Ok(p) =
                                    serde_json::from_str::<FollowPayload>(&record.content)
                                {
                                    println!("      follower : {}", &p.follower[..16]);
                                    println!("      followee : {}", &p.followee[..16]);
                                    let fk = libp2p::kad::RecordKey::new(&revocation_dht_key(
                                        &p.follower,
                                    ));
                                    let qid = swarm.behaviour_mut().kad.get_record(fk);
                                    revocation_checks.insert(qid, p.follower.clone());
                                    let fk = libp2p::kad::RecordKey::new(&revocation_dht_key(
                                        &p.followee,
                                    ));
                                    let qid = swarm.behaviour_mut().kad.get_record(fk);
                                    revocation_checks.insert(qid, p.followee.clone());
                                    println!("      [~] Checking revocation...");
                                }
                            }
                            Err(e) => println!("  [✗] Invalid signature: {e}"),
                        }
                    }
                    println!();
                }

                KeystoneBehaviourEvent::Follows(request_response::Event::OutboundFailure {
                    peer,
                    error,
                    ..
                }) => {
                    println!("[!] Follow request to {peer} failed: {error}");
                }

                // --- Content protocol (small files, backward compat) ---
                KeystoneBehaviourEvent::Content(request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                }) => {
                    let data = content_store.get(&request.hash);
                    let found = data.is_some();
                    swarm
                        .behaviour_mut()
                        .content
                        .send_response(channel, ContentResponse { data })
                        .ok();
                    println!(
                        "[<] Content request from {peer} — {}",
                        if found { "sent" } else { "not found" }
                    );
                }

                KeystoneBehaviourEvent::Content(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                }) => match response.data {
                    Some(bytes) => match content_store.store(&bytes) {
                        Ok(hash) => println!("[✓] Content from {peer} saved: {content_dir}/{hash}"),
                        Err(e) => println!("[!] Failed to store content: {e}"),
                    },
                    None => println!("[!] Peer {peer} does not have the content"),
                },

                KeystoneBehaviourEvent::Content(request_response::Event::OutboundFailure {
                    peer,
                    error,
                    ..
                }) => {
                    println!("[!] Content request to {peer} failed: {error}");
                }

                // --- Chunked transfer protocol ---
                KeystoneBehaviourEvent::Chunks(request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                }) => {
                    let response =
                        match content_store.serve_chunk(&request.hash, request.chunk_index) {
                            Some((data, total_size, chunk_size)) => ChunkResponse {
                                hash: request.hash.clone(),
                                chunk_index: request.chunk_index,
                                total_size,
                                chunk_size,
                                data: Some(data),
                            },
                            None => ChunkResponse {
                                hash: request.hash.clone(),
                                chunk_index: request.chunk_index,
                                total_size: 0,
                                chunk_size: 0,
                                data: None,
                            },
                        };
                    swarm
                        .behaviour_mut()
                        .chunks
                        .send_response(channel, response)
                        .ok();
                    println!(
                        "[<] Chunk {} of {} requested by {peer}",
                        request.chunk_index,
                        &request.hash[..16]
                    );
                }

                KeystoneBehaviourEvent::Chunks(request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                }) => {
                    let ChunkResponse {
                        hash,
                        chunk_index,
                        total_size,
                        chunk_size,
                        data,
                    } = response;

                    match data {
                        None => {
                            println!(
                                "[!] Peer {peer} doesn't have chunk {chunk_index} of {}...",
                                &hash[..16]
                            );
                        }
                        Some(chunk_data) => {
                            // Set up ContentRecord on first chunk received
                            if !active_fetches.contains_key(&hash) {
                                match content_store.begin_fetch(&hash, total_size, chunk_size) {
                                    Ok(record) => {
                                        active_fetches.insert(hash.clone(), record);
                                    }
                                    Err(e) => {
                                        println!("[!] begin_fetch failed: {e}");
                                        continue;
                                    }
                                }
                            }

                            // Write chunk and update state
                            let (is_done, total_chunks) = {
                                let record = active_fetches.get_mut(&hash).unwrap();
                                if let Err(e) =
                                    content_store.write_chunk(record, chunk_index, &chunk_data)
                                {
                                    println!("[!] write_chunk failed: {e}");
                                }
                                (record.is_complete(), record.chunks.len())
                            };

                            let done_count =
                                total_chunks - active_fetches[&hash].pending_chunks().len();
                            println!("[~] {}... chunk {}/{total_chunks}", &hash[..16], done_count);

                            // On first chunk response, fire requests for all remaining chunks
                            if chunk_index == 0 && total_chunks > 1 {
                                let publisher = fetch_peers.get(&hash).copied().unwrap_or(peer);
                                for i in 1..total_chunks as u64 {
                                    swarm.behaviour_mut().chunks.send_request(
                                        &publisher,
                                        ChunkRequest {
                                            hash: hash.clone(),
                                            chunk_index: i,
                                        },
                                    );
                                }
                            }

                            if is_done {
                                let verified = {
                                    let record = active_fetches.get(&hash).unwrap();
                                    content_store.verify_complete(record).unwrap_or(false)
                                };

                                if verified {
                                    let record = active_fetches.remove(&hash).unwrap();
                                    content_store.finish_fetch(&record);
                                    fetch_peers.remove(&hash);
                                    println!("\n[✓] Transfer complete and verified!");
                                    println!("    Hash : {hash}");
                                    println!("    Size : {total_size} bytes");
                                    println!("    Saved: {content_dir}/{hash}\n");
                                } else {
                                    active_fetches.remove(&hash);
                                    fetch_peers.remove(&hash);
                                    let _ = std::fs::remove_file(format!("{content_dir}/{hash}"));
                                    let _ =
                                        std::fs::remove_file(format!("{content_dir}/{hash}.meta"));
                                    println!("[✗] Hash mismatch after reassembly — file discarded");
                                }
                            }
                        }
                    }
                }

                KeystoneBehaviourEvent::Chunks(request_response::Event::OutboundFailure {
                    peer,
                    error,
                    ..
                }) => {
                    println!("[!] Chunk request to {peer} failed: {error}");
                }

                // --- Relay ---
                KeystoneBehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
                ) => {
                    println!("[r] Relay reservation accepted — routable via {relay_peer_id}");
                    println!("    Peers behind NAT can now reach this node.");
                }

                // --- DHT results ---
                KeystoneBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                    id,
                    result: kad::QueryResult::GetRecord(result),
                    step,
                    ..
                }) => match result {
                    Ok(kad::GetRecordOk::FoundRecord(record)) => {
                        if let Some(pubkey) = revocation_checks.remove(&id) {
                            println!("\n  [!] WARNING: key {}... may be REVOKED", &pubkey[..16]);
                            if let Ok(signed) =
                                serde_json::from_slice::<SignedMessage>(&record.record.value)
                            {
                                if signed.verify().is_ok() {
                                    if let Ok(p) =
                                        serde_json::from_str::<RevocationPayload>(&signed.content)
                                    {
                                        println!("      Reason    : {}", p.reason);
                                        println!("      Revoked at: {} (unix)", p.timestamp);
                                    }
                                } else {
                                    println!("      (revocation signature invalid — ignored)");
                                }
                            }
                        } else if let Some(hash) = content_fetch_queries.remove(&id) {
                            match PeerId::from_bytes(&record.record.value) {
                                Ok(publisher) => {
                                    println!("[✓] Content on DHT — publisher: {publisher}");
                                    start_chunk_fetch(
                                        &mut swarm,
                                        &content_store,
                                        &hash,
                                        publisher,
                                        &mut active_fetches,
                                        &mut fetch_peers,
                                        &mut pending_fetches,
                                    );
                                }
                                Err(_) => {
                                    println!("[!] Content record found but peer ID unreadable")
                                }
                            }
                        } else if find_query_id == Some(id) {
                            find_query_id = None;
                            match PeerId::from_bytes(&record.record.value) {
                                Ok(found_peer_id) => {
                                    let key_str =
                                        String::from_utf8_lossy(record.record.key.as_ref());
                                    println!("\n[✓] Identity found!");
                                    println!(
                                        "    Public key : {}...",
                                        &key_str[..16.min(key_str.len())]
                                    );
                                    println!("    Peer ID    : {found_peer_id}\n");
                                }
                                Err(_) => {
                                    println!("[!] Found record but could not decode peer ID.")
                                }
                            }
                        }
                    }

                    Ok(_) => {
                        if step.last {
                            revocation_checks.remove(&id);
                            content_fetch_queries.remove(&id);
                        }
                    }

                    Err(kad::GetRecordError::NotFound { .. }) if step.last => {
                        if let Some(hash) = content_fetch_queries.remove(&id) {
                            println!("[✗] Content not found on DHT: {}", &hash[..16]);
                            println!("    Publisher may be offline.");
                        } else if revocation_checks.remove(&id).is_none()
                            && find_query_id == Some(id)
                        {
                            println!("[✗] Identity not found.");
                        }
                    }

                    Err(e) if step.last => println!("[!] DHT error: {e:?}"),
                    _ => {}
                },

                _ => {}
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "12D3KooWCruYnFTDrFoNPtHpaGPcWm4NvfzjyS7uVqWCBimievS2";

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("node")
            .chain(list.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn bootstrap_gives_dial_and_relay_addresses() {
        let addr = format!("/ip4/192.0.2.7/tcp/9000/p2p/{PEER}");
        let (dial, circuit) = parse_bootstrap(&addr).unwrap();
        assert_eq!(dial.to_string(), addr);
        assert_eq!(circuit.to_string(), format!("{addr}/p2p-circuit"));
    }

    #[test]
    fn bootstrap_needs_a_peer_id_at_the_end() {
        for bad in [
            "",
            "not a multiaddr",
            "/ip4/192.0.2.7/tcp/9000",
            "/ip4/192.0.2.7/tcp/9000/p2p-circuit",
        ] {
            assert!(parse_bootstrap(bad).is_err(), "{bad:?}");
        }
        let circuit_already = format!("/ip4/192.0.2.7/tcp/9000/p2p/{PEER}/p2p-circuit");
        assert!(parse_bootstrap(&circuit_already).is_err());
    }

    #[test]
    fn bootstrap_flag_wins_over_environment() {
        let flag = format!("/ip4/192.0.2.7/tcp/9000/p2p/{PEER}");
        let env = format!("/ip4/198.51.100.9/tcp/9000/p2p/{PEER}");
        let a = args(&["--bootstrap", &flag]);
        assert_eq!(bootstrap_setting(&a, Some(env.clone())), Some(flag));
        assert_eq!(bootstrap_setting(&args(&[]), Some(env.clone())), Some(env));
        assert_eq!(bootstrap_setting(&args(&[]), None), None);
        assert_eq!(bootstrap_setting(&args(&[]), Some("  ".into())), None);
    }

    #[test]
    fn key_path_skips_flag_values() {
        let key = "ab".repeat(32);
        let addr = format!("/ip4/192.0.2.7/tcp/9000/p2p/{PEER}");
        assert_eq!(
            key_path(&args(&["--find", &key])),
            PathBuf::from(DEFAULT_KEY_FILE)
        );
        assert_eq!(
            key_path(&args(&["--bootstrap", &addr, "me.key"])),
            PathBuf::from("me.key")
        );
        assert_eq!(
            key_path(&args(&["--query", "me.key", "--follow", &key])),
            PathBuf::from("me.key")
        );
        assert_eq!(key_path(&args(&[])), PathBuf::from(DEFAULT_KEY_FILE));
    }
}
