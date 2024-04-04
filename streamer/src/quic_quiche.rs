use {
    crate::{quic::QuicServerError, streamer::StakedNodes,
        nonblocking::quic::ALPN_TPU_PROTOCOL_ID,
        tls_certificates::new_dummy_x509_certificate,
    },
    crossbeam_channel::Sender,
    quiche::{Connection, ConnectionId},
    ring::rand::SystemRandom,
    solana_perf::packet::PacketBatch,
    rustls::PrivateKey,
    solana_sdk::{
        packet::PACKET_DATA_SIZE,
        quic::{NotifyKeyUpdate, QUIC_MAX_TIMEOUT, QUIC_MAX_UNSTAKED_CONCURRENT_STREAMS},
        signature::Keypair,
    },
    pem::Pem,
    std::{
        io::Write,
        collections::HashMap,
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        thread,
        time::{Duration},
    },
    tokio::runtime::Runtime,
};

pub const MAX_STAKED_CONNECTIONS: usize = 2000;
pub const MAX_UNSTAKED_CONNECTIONS: usize = 500;

pub struct SpawnServerResult {
    pub thread: thread::JoinHandle<()>,
}

/*fn run_server() -> Result<(), QuicServerError> {
    Ok(())
}*/

fn validate_token<'a>(
    src: &std::net::SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    info!("{:?} string: {:?}", token, String::from_utf8_lossy(token));

    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

fn mint_token(hdr: &quiche::Header, src: &std::net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

#[derive(Default)]
struct Counters {
    header_parse_failed: usize,
    send: usize,
    send_errors: usize,
    connection_send_errors: usize,
    retry_fail: usize,
    connection_accept_failure: usize,
    token_validate_fail: usize,
}

fn quic_process_loop() {}

fn process_new_packet_for_connection(conn: &mut Connection, buf: &mut [u8], from: SocketAddr, local_addr: SocketAddr, len: usize) {
    let recv_info = quiche::RecvInfo {
        from,
        to: local_addr,
    };
    match conn.recv(&mut buf[..len], recv_info) {
        Ok(v) => {
            info!("read {} bytes?", v);
        }
        Err(e) => {
            error!("{} recv failed: {:?}", conn.trace_id(), e);
        }
    };
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_server(
    thread_name: &'static str,
    metrics_name: &'static str,
    socket: UdpSocket,
    keypair: &Keypair,
    packet_sender: Sender<PacketBatch>,
    exit: Arc<AtomicBool>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    wait_for_chunk_timeout: Duration,
    coalesce: Duration,
) -> Result<SpawnServerResult, QuicServerError> {
    let (cert, priv_key) = new_dummy_x509_certificate(keypair);
    let thread = thread::Builder::new()
        .name(thread_name.into())
        .spawn(move || {
            let mut counters = Counters::default();
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
            config.verify_peer(false);

            let alpn_protocols = vec![ALPN_TPU_PROTOCOL_ID];
            config.set_application_protos(&alpn_protocols).unwrap();

            // Set the certificate and private key.
            //let (cert, priv_key) = new_dummy_x509_certificate(keypair);
            let cert_chain_pem_parts = vec![Pem {
                tag: "CERTIFICATE".to_string(),
                contents: cert.0.clone(),
            }];
            let cert_chain_pem = pem::encode_many(&cert_chain_pem_parts);

	    // Create a PEM block
	    let pem = Pem {
		tag: String::from("PRIVATE KEY"), // Tag used for private keys
		contents: priv_key.0,
	    };
	    // Encode to PEM format
	    let pem_str = pem::encode(&pem);

            // Create temporary files to write the certificate and private key data.
            let mut cert_file = tempfile::NamedTempFile::new().unwrap();
            let mut priv_key_file = tempfile::NamedTempFile::new().unwrap();

            // Write the certificate and private key data to the temporary files.
            cert_file.write_all(&cert_chain_pem.into_bytes()).unwrap();
            cert_file.flush().unwrap();

            priv_key_file.write_all(&pem_str.into_bytes()).unwrap();
            priv_key_file.flush().unwrap();

            config.load_cert_chain_from_pem_file(cert_file.path().to_str().unwrap()).unwrap();
            config.load_priv_key_from_pem_file(priv_key_file.path().to_str().unwrap()).unwrap();

            let local_addr = socket.local_addr().unwrap();
            info!("server addr: {:?}", local_addr);

            let rng = SystemRandom::new();
            let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

            // HashMap to store connections for each peer.
            let mut connections: HashMap<ConnectionId, Connection> = HashMap::new();
            // Buffer to hold incoming data.
            let mut buf = [0; 4096];
            let mut out = [0; 4096];
            let mut g_packet_batch = None;

            while !exit.load(Ordering::Relaxed) {
                let timeout = connections.values().filter_map(|c| c.timeout()).min();
                info!("timeout? {:?}", timeout);

                match socket.recv_from(&mut buf) {
                    Ok((len, from)) => {
                        match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                            Ok(hdr) => {
                                info!("got packet({}) from: {} {:?}", len, from, hdr.ty);
                                // Check if there's an existing connection for this peer, or create a new one.
                                if hdr.ty == quiche::Type::Initial {
                                    match connections.get_mut(&hdr.dcid) {
                                        None => {
                                            let token = hdr.token.as_ref().unwrap();

                                            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                                            let scid = ConnectionId::from_ref(
                                                &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN],
                                            );
                                            info!("new connection! {:?} {:?}", from, scid);

                                            // No token sent by client, create a new one.
                                            if token.is_empty() {
                                                let new_token = mint_token(&hdr, &from);

                                                info!("retry start!");
                                                match quiche::retry(
                                                    &hdr.scid,
                                                    &hdr.dcid,
                                                    &scid,
                                                    &new_token,
                                                    hdr.version,
                                                    &mut out,
                                                ) {
                                                    Ok(len) => {
                                                        let e =
                                                            socket.send_to(&out[..len], &from).unwrap();
                                                        info!("retry success! {:?} sent {} byte packet", e, len);
                                                    }
                                                    Err(e) => {
                                                        info!("retry fail!");
                                                        counters.retry_fail += 1;
                                                    }
                                                }
                                            }

                                            let odcid = validate_token(&from, token);
                                            if odcid.is_some() {
                                                info!("token validate success!");
                                                match quiche::accept(
                                                    &scid,
                                                    odcid.as_ref(),
                                                    local_addr,
                                                    from,
                                                    &mut config,
                                                ) {
                                                    Ok(conn) => {
                                                        info!("inserting connection?");
                                                        connections.insert(hdr.dcid, conn);
                                                    }
                                                    Err(e) => {
                                                        info!("fail create connection?: {:?}", e);
                                                        counters.connection_accept_failure += 1;
                                                    }
                                                }
                                            } else {
                                                info!("token validate fail");
                                                counters.token_validate_fail += 1;
                                            }
                                        }
                                        Some(conn) => {
                                            info!(
                                                "processing initial packet from established connection: {}",
                                                from
                                            );
                                            process_new_packet_for_connection(conn, &mut buf, from, local_addr, len);
                                        }
                                    }
                                } else {
                                    info!(
                                        "processing packet from established connection: {}",
                                        from
                                    );
                                    if let Some(conn) = connections.get_mut(&hdr.dcid) {
                                        process_new_packet_for_connection(conn, &mut buf, from, local_addr, len);
                                    }
                                }
                            }
                            Err(e) => {
                                counters.header_parse_failed += 1;
                            }
                        };
                    }
                    Err(e) => {
                        info!("error recv? {:?}", e);
                    }
                }

                info!("processing {} connections", connections.len());
                // Handle streams and process outgoing packets for each connection.
                for conn in connections.values_mut() {
                    info!("processing connection id: {:?} is_established: {} is_resumed: {} is_in_early_data: {} is_server: {} is_closed: {} is_draining: {} error: {:?}",
                        conn.trace_id(),
                        conn.is_established(),
                        conn.is_resumed(),
                        conn.is_in_early_data(),
                        conn.is_server(),
                        conn.is_closed(),
                        conn.is_draining(),
                        conn.peer_error(),
                        );
                    info!("stats: {:?}", conn.stats());
                    // Process incoming streams.
                    for stream_id in conn.readable() {
                        info!("processing stream {}", stream_id);
                        loop {
                            let mut packet_batch = match g_packet_batch.take() {
                                Some(b) => b,
                                None => PacketBatch::with_capacity(1),
                            };
                            match conn.stream_recv(stream_id, &mut packet_batch[0].buffer_mut()) {
                                Ok((read, fin)) => {
                                    info!(
                                        "Received data on stream {}: {}",
                                        stream_id,
                                        String::from_utf8_lossy(&buf[..read])
                                    );
                                    //packet_batch[0].buffer_mut()[..read].copy_from_slice(buf[..read]);
                                    let _e = packet_sender.send(packet_batch);
                                }
                                Err(e) => {
                                    g_packet_batch = Some(packet_batch);
                                    info!("stream error: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }

                    info!("processing connection sends");
                    // Process outgoing packets.
                    match conn.send(&mut buf) {
                        Ok((write, send_info)) => {
                            info!("sending {} bytes to {:?}", write, send_info.to);
                            // Send the payload back to the source.
                            match socket.send_to(&out[..write], &send_info.to) {
                                Ok(_) => {
                                    counters.send += 1;
                                }
                                Err(e) => {
                                    counters.send_errors += 1;
                                }
                            }
                        }
                        Err(quiche::Error::Done) => {}
                        Err(e) => {
                            info!("conn send error? {:?}", e);
                            counters.connection_send_errors += 1;
                        }
                    }
                }
                connections.retain(|_, ref mut c| {
                    if c.is_closed() {
                        info!("connection closed: {:?}", c.destination_id());
                    }
                    !c.is_closed()
                });
            }
        })
        .unwrap();

    Ok(SpawnServerResult { thread })
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::nonblocking::quic::{test::*, DEFAULT_WAIT_FOR_CHUNK_TIMEOUT},
        crossbeam_channel::unbounded,
        solana_sdk::net::DEFAULT_TPU_COALESCE,
        std::net::SocketAddr,
    };

    fn rt(name: String) -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .thread_name(name)
            .enable_all()
            .build()
            .unwrap()
    }

    fn setup_quic_server() -> (
        std::thread::JoinHandle<()>,
        Arc<AtomicBool>,
        crossbeam_channel::Receiver<PacketBatch>,
        SocketAddr,
    ) {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let exit = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = unbounded();
        let keypair = Keypair::new();
        let server_address = s.local_addr().unwrap();
        let staked_nodes = Arc::new(RwLock::new(StakedNodes::default()));
        let SpawnServerResult { thread: t } = spawn_server(
            "solQuicTest",
            "quic_streamer_test",
            s,
            &keypair,
            sender,
            exit.clone(),
            1,
            staked_nodes,
            MAX_STAKED_CONNECTIONS,
            MAX_UNSTAKED_CONNECTIONS,
            DEFAULT_WAIT_FOR_CHUNK_TIMEOUT,
            DEFAULT_TPU_COALESCE,
        )
        .unwrap();
        (t, exit, receiver, server_address)
    }

    #[test]
    fn test_quic_quiche_server_exit() {
        let (t, exit, _receiver, _server_address) = setup_quic_server();
        exit.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }

    #[test]
    fn test_quic_quiche_timeout() {
        solana_logger::setup();
        let (t, exit, receiver, server_address) = setup_quic_server();
        let runtime = rt("solQuicTestRt".to_string());
        runtime.block_on(check_timeout(receiver, server_address));
        exit.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }

    #[test]
    fn test_quic_quiche_server_block_multiple_connections() {
        solana_logger::setup();
        let (t, exit, _receiver, server_address) = setup_quic_server();

        let runtime = rt("solQuicTestRt".to_string());
        runtime.block_on(check_block_multiple_connections(server_address));
        exit.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }

    #[test]
    fn test_quic_quiche_server_multiple_streams() {
        solana_logger::setup();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let exit = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = unbounded();
        let keypair = Keypair::new();
        let server_address = s.local_addr().unwrap();
        let staked_nodes = Arc::new(RwLock::new(StakedNodes::default()));
        let SpawnServerResult { thread: t } = spawn_server(
            "solQuicTest",
            "quic_streamer_test",
            s,
            &keypair,
            sender,
            exit.clone(),
            2,
            staked_nodes,
            MAX_STAKED_CONNECTIONS,
            MAX_UNSTAKED_CONNECTIONS,
            DEFAULT_WAIT_FOR_CHUNK_TIMEOUT,
            DEFAULT_TPU_COALESCE,
        )
        .unwrap();

        let runtime = rt("solQuicTestRt".to_string());
        runtime.block_on(check_multiple_streams(receiver, server_address));
        exit.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }

    #[test]
    fn test_quic_quiche_simple() {
        solana_logger::setup();
        let (t, exit, receiver, server_address) = setup_quic_server();

        let runtime = rt("solQuicTestRt".to_string());
        runtime.block_on(check_multiple_writes(receiver, server_address, None));
        exit.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }

    #[test]
    fn test_quic_server_unstaked_node_connect_failure() {
        solana_logger::setup();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let exit = Arc::new(AtomicBool::new(false));
        let (sender, _) = unbounded();
        let keypair = Keypair::new();
        let server_address = s.local_addr().unwrap();
        let staked_nodes = Arc::new(RwLock::new(StakedNodes::default()));
        let SpawnServerResult { thread: t } = spawn_server(
            "solQuicTest",
            "quic_streamer_test",
            s,
            &keypair,
            sender,
            exit.clone(),
            1,
            staked_nodes,
            MAX_STAKED_CONNECTIONS,
            0, // Do not allow any connection from unstaked clients/nodes
            DEFAULT_WAIT_FOR_CHUNK_TIMEOUT,
            DEFAULT_TPU_COALESCE,
        )
        .unwrap();

        let runtime = rt("solQuicTestRt".to_string());
        runtime.block_on(check_unstaked_node_connect_failure(server_address));
        exit.store(true, Ordering::Relaxed);
        t.join().unwrap();
    }
}
