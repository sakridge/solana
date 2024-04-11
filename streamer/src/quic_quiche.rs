use {
    crate::{
        buf::{EVENT_CNT, REASM_DEPTH},
        metrics::ServerMetrics,
        quic::{QuicServer, QuicServerError},
        reasm::Reasm,
        streamer::StakedNodes,
    },
    boring::{
        pkey::PKey,
        ssl::{SslContextBuilder, SslMethod, SslVersion},
        x509::X509,
    },
    crossbeam_channel::Sender,
    quiche::ConnectionId,
    rand::{
        rngs::{OsRng, SmallRng},
        Rng, RngCore, SeedableRng,
    },
    siphasher::sip::SipHasher24,
    solana_perf::packet::PacketBatch,
    solana_sdk::{packet::Packet, signature::Keypair},
    std::{
        cell::RefCell,
        collections::{BinaryHeap, HashMap},
        net::{SocketAddr, UdpSocket},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, RwLock,
        },
        time::Duration,
    },
};

pub struct ServerTile {
    local_addr: SocketAddr,
    socket: UdpSocket,
    metrics: Arc<ServerMetrics>,
    packet_batch: RefCell<PacketBatch>,
    q_initial: Vec<u16>,
    q_handshake: Vec<(u16, ICID)>,
    q_established: Vec<(u16, ICID)>,
    conns: HashMap<ICID, Conn>, // Should probably be a LinkedList
    conn_ids: HashMap<SCID, ICID>,
    max_connections: usize,
    rng: SmallRng,
    quiche_cfg: quiche::Config,
    next_icid: u64,

    // Connections pending serve (this is probably slow)
    pending_conns: BinaryHeap<ICID>,

    // Cheap mechanism to sign retry requests
    // Chosen over MAC or OTM functions for better performance
    retry_signer: SipHasher24,

    // Reassembler for fragmented transaction data
    reasm: Reasm,
    exit: Arc<AtomicBool>,
    packet_sender: Sender<PacketBatch>,
}

impl ServerTile {
    pub fn new(
        socket: UdpSocket,
        local_addr: SocketAddr,
        keypair: &Keypair,
        max_connections: usize,
        exit: Arc<AtomicBool>,
        packet_sender: Sender<PacketBatch>,
    ) -> Self {
        info!("new tile! {:?}", local_addr);
        let conns = HashMap::with_capacity(max_connections);
        let conn_ids = HashMap::with_capacity(max_connections * 4);

        // TODO should probably only sign this once
        let (cert_bytes, cert_key_bytes) = crate::cert::new_dummy_x509_certificate(keypair);
        let cert = X509::from_der(&cert_bytes).unwrap();
        let cert_key = PKey::private_key_from_der(&cert_key_bytes).unwrap();

        let mut tls_cfg = SslContextBuilder::new(SslMethod::tls_server()).unwrap();
        tls_cfg.set_certificate(&cert).unwrap();
        tls_cfg.set_private_key(&cert_key).unwrap();
        tls_cfg
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        tls_cfg
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();

        let mut quiche_cfg = quiche::Config::with_boring_ssl_ctx_builder(1, tls_cfg).unwrap();
        quiche_cfg.set_application_protos(&[b"solana-tpu"]).unwrap();
        quiche_cfg.set_initial_max_data(15000);
        quiche_cfg.set_initial_max_streams_uni(168);
        quiche_cfg.set_initial_max_stream_data_uni(crate::buf::TXN_MAX_SZ as u64);
        quiche_cfg.set_max_idle_timeout(3000u64);

        let packet_batch = RefCell::new(PacketBatch::with_capacity(128));

        Self {
            local_addr,
            socket,
            packet_batch,
            metrics: Arc::new(ServerMetrics::default()),
            q_initial: Vec::with_capacity(EVENT_CNT),
            q_handshake: Vec::with_capacity(EVENT_CNT),
            q_established: Vec::with_capacity(EVENT_CNT),
            conns,
            conn_ids,
            max_connections,
            rng: SmallRng::from_entropy(),
            quiche_cfg,
            next_icid: 0u64,
            pending_conns: BinaryHeap::with_capacity(EVENT_CNT),
            retry_signer: SipHasher24::new_with_keys(OsRng.next_u64(), OsRng.next_u64()),
            reasm: Reasm::new(REASM_DEPTH),
            exit,
            packet_sender,
        }
    }

    pub fn metrics(&self) -> Arc<ServerMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn run(&mut self) {
        info!("Run!");
        while !self.exit.load(Ordering::Relaxed) {
            self.poll();
        }
    }

    pub fn poll(&mut self) {
        self.q_initial.clear();
        self.q_handshake.clear();
        self.q_established.clear();
        self.pending_conns.clear();

        // TODO timeout management

        info!("receiving.. connections: {}", self.conns.len());
        let packet_count = {
            let mut pb = &mut self.packet_batch.borrow_mut();
            /*for p in pb.packets {
                p.meta.reset();
            }*/
            pb.truncate(0);
            crate::packet::recv_from(&mut pb, &self.socket, Duration::from_millis(10)).unwrap_or(0)
        };
        info!("packets {}", packet_count);

        self.metrics
            .rx_pkt_cnt
            .fetch_add(packet_count as u64, Ordering::Relaxed);

        // Triage packets, sorting them into different QoS classes
        'triage: for pkt_idx in 0..packet_count {
            let packet = &mut self.packet_batch.borrow_mut()[pkt_idx];
            //let from_ip_addr = packet.meta().addr;
            let from_udp_port = packet.meta().port;

            // If the packet comes from a suspiciously well-known port
            // number, it was likely bounced off a UDP server via a
            // reflection attack.
            let is_reflected = matches!(from_udp_port, 53 | 443 | 51820);
            //let is_global = crate::ip::is_global(&from_ip_addr);
            let is_global = false;

            if is_reflected || is_global {
                self.metrics
                    .rx_pkt_drop_martian_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // Parse the QUIC packet's header.
            let packet_size = packet.meta().size;
            let hdr = match quiche::Header::from_slice(&mut packet.buffer_mut()[..packet_size], 8) {
                Ok(v) => {
                    info!("good quic header! {:?}", v);
                    v
                }
                Err(e) => {
                    info!("bad quic header! {:?}", e);
                    self.metrics
                        .rx_pkt_drop_garbage_cnt
                        .fetch_add(1, Ordering::Relaxed);
                    continue 'triage;
                }
            };

            // Does a connection exist for that ICID?
            let icid: Option<ICID> = {
                let dcid_bytes: &[u8] = hdr.dcid.as_ref();
                let dcid = dcid_bytes.try_into().ok().map(u64::from_le_bytes);
                dcid.and_then(|v| self.conn_ids.get(&v).copied())
            };

            match (hdr.ty, icid) {
                (quiche::Type::Initial, None) => {
                    // Statelessly process connection requests
                    info!("initial packet: {}", pkt_idx);
                    self.q_initial.push(pkt_idx as u16);
                    continue 'triage;
                }
                // Packet pertains to some known conenction
                (quiche::Type::Short, Some(icid)) => {
                    self.q_established.push((pkt_idx as u16, icid))
                }
                (_, Some(icid)) => self.q_handshake.push((pkt_idx as u16, icid)),
                (_, None) => {
                    self.metrics
                        .rx_pkt_drop_unknown_cnt
                        .fetch_add(1, Ordering::Relaxed);
                    continue 'triage;
                }
            };
        }

        info!(
            "handling established: {:?} handshakes: {:?}",
            self.q_established, self.q_handshake
        );

        // Handle packets relating to established conns first, then
        // process handshaking
        'known: for (pkt_idx, icid) in self
            .q_established
            .drain(..)
            .chain(self.q_handshake.drain(..))
        {
            info!("handling known {}", pkt_idx);

            let packet = &mut self.packet_batch.borrow_mut()[pkt_idx as usize];

            let conn = match self.conns.get_mut(&icid) {
                Some(conn) => {
                    info!("found connection for packet: {}", pkt_idx);
                    conn
                }
                None => {
                    // This should never happen
                    self.conn_ids.remove(&icid);
                    self.metrics
                        .rx_pkt_drop_unknown_cnt
                        .fetch_add(1, Ordering::Relaxed);
                    continue 'known;
                }
            };

            // Upgrade reference to static lifetime to allow multiple
            // mutable borrows on the HashMap.  Assumes that conn is
            // not dropped from the hashmap in this scope.  Assumes that
            // this reference does not escape this scope.
            let conn = unsafe { (conn as *mut Conn).as_mut::<'static>().unwrap() };

            // TODO handle conn packet
            let quiche_conn = conn.conn.as_mut().unwrap();
            let from = packet.meta().socket_addr();
            let packet_size = packet.meta().size;
            match quiche_conn.recv(
                &mut packet.buffer_mut()[..packet_size],
                quiche::RecvInfo {
                    from,
                    to: self.local_addr,
                },
            ) {
                Ok(v) => {
                    info!("recv?: {}", v);
                    v
                }
                Err(_) => {
                    self.metrics
                        .rx_pkt_drop_garbage_cnt
                        .fetch_add(1, Ordering::Relaxed);
                    continue 'known;
                }
            };

            Self::update_scids(icid, quiche_conn, &mut self.conn_ids, &mut self.rng);
            self.pending_conns.push(icid);

            for stream_id in quiche_conn.readable() {
                // Allocate the oldest slot
                let reasm_id = (icid, stream_id);
                let (reasm_slot, evicted_slot) = self.reasm.acquire(reasm_id);

                // If the oldest slot is still occupied, free it.
                if let Some((evictee_icid, evictee_stream_id)) = evicted_slot {
                    // Make sure that the stream associated with this
                    // slot gets destroyed to prevent it from reclaiming
                    // a new slot.
                    if let Some(evictee_conn) = self.conns.get_mut(&evictee_icid) {
                        let _ = evictee_conn.conn.as_mut().unwrap().stream_shutdown(
                            evictee_stream_id,
                            quiche::Shutdown::Read,
                            0,
                        );
                        self.metrics
                            .tpu_txn_drop_cnt
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Read stream fragments into the newly allocated slot.
                let mut stream_buf = [0u8; 4096];
                'stream: while let Ok((read, fin)) =
                    quiche_conn.stream_recv(stream_id, &mut stream_buf)
                {
                    info!("received {} stream bytes fin?: {}", read, fin);
                    if !reasm_slot.append(&stream_buf[..read]) {
                        info!("bad reasm?");
                        // Transaction too large or too fragmented.
                        // TODO Consider stronger punishment.
                        let _data = self.reasm.finish(reasm_id);
                        let _ = quiche_conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0);
                        self.metrics
                            .tpu_txn_drop_cnt
                            .fetch_add(1, Ordering::Relaxed);
                        self.metrics
                            .rx_pkt_drop_garbage_cnt
                            .fetch_add(1, Ordering::Relaxed);
                        continue 'known; // ignore rest of packet
                    }
                    if fin {
                        // Transaction reassembled successfully.
                        // Free the slot.
                        info!("finish.. {:?}", reasm_id);
                        let data = self.reasm.finish(reasm_id);
                        self.metrics.tpu_txn_cnt.fetch_add(1, Ordering::Relaxed);
                        // TODO handle data
                        if let Err(e) = self.packet_sender.send(data) {
                            info!("Packet send error? {:?}", e);
                        }
                        break 'stream;
                    }
                }
            }
        }

        // Handle packets relating to connection requests
        'initial: for pkt_idx in self.q_initial.drain(..) {
            info!("handling init: {:?}", pkt_idx);
            let mut pb = self.packet_batch.borrow_mut();
            let packet = &mut pb[pkt_idx as usize];

            // Re-parse the packet header (TODO consider buffering)
            let packet_size = packet.meta().size;
            let hdr =
                quiche::Header::from_slice(&mut packet.buffer_mut()[..packet_size], 8).unwrap();
            if hdr.ty != quiche::Type::Initial {
                info!("bad initial?");
                self.metrics
                    .rx_pkt_drop_garbage_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue 'initial;
            }

            if !quiche::version_is_supported(hdr.version) {
                info!("version not supported? {}", hdr.version);
                self.metrics
                    .rx_pkt_drop_garbage_cnt
                    .fetch_add(1, Ordering::Relaxed);
                continue 'initial;
            }

            self.next_icid += 1;
            let new_icid = self.next_icid;

            let new_dcid_u: u64 = self.rng.gen();
            let new_dcid_b = new_dcid_u.to_le_bytes();
            let new_dcid = ConnectionId::from_ref(&new_dcid_b[..]);
            info!("accepting..?");
            let quiche_conn = quiche::accept(
                &new_dcid,
                None,
                self.local_addr,
                packet.meta().socket_addr(),
                &mut self.quiche_cfg,
            )
            .unwrap();
            let mut conn = Conn {
                conn: Some(quiche_conn), // expensive copy :(
            };
            let quiche_conn = conn.conn.as_mut().unwrap();

            // Handle coalesced packet content
            let from = packet.meta().socket_addr();
            match quiche_conn.recv(
                &mut packet.buffer_mut()[..packet_size],
                quiche::RecvInfo {
                    from,
                    to: self.local_addr,
                },
            ) {
                Ok(v) => {
                    info!("recv: {:?}", v);
                    v
                }
                Err(err) => {
                    info!("recv error: {:?}", err);
                    self.metrics
                        .rx_pkt_drop_garbage_cnt
                        .fetch_add(1, Ordering::Relaxed);
                    continue 'initial;
                }
            };

            self.conn_ids.insert(new_dcid_u as SCID, new_icid as ICID);
            Self::update_scids(new_icid, quiche_conn, &mut self.conn_ids, &mut self.rng);
            self.conns.insert(new_icid, conn);

            self.pending_conns.push(new_icid);
            self.metrics.quic_accept_cnt.fetch_add(1, Ordering::Relaxed);
        }

        // At this point, we read all incoming packets.
        // We can now reuse our receive buffer for sending.
        //self.packet_batch.truncate(0);

        // We assume that we won't ever generate more outgoing packets
        // than there are incoming packets.  (This is a reasonable
        // assumption because the TPU server has no outgoing traffic
        // other than QUIC mgmt things and ACKs)
        let mut send_pkt_cnt = 0usize;
        'respond: for icid in self.pending_conns.drain() {
            let conn = match self.conns.get_mut(&icid) {
                Some(conn) => conn,
                None => {
                    self.conn_ids.remove(&icid);
                    continue 'respond;
                }
            };
            let conn = conn.conn.as_mut().unwrap();

            let mut index = 0;
            'genpkt: loop {
                if send_pkt_cnt >= EVENT_CNT {
                    info!("send packet count {} {}", send_pkt_cnt, EVENT_CNT);
                    break 'respond;
                }
                let mut pb = self.packet_batch.borrow_mut();
                if index >= pb.len() {
                    pb.resize(index + 1, Packet::default());
                }
                let buf = pb[index].buffer_mut();
                match conn.send(&mut buf[..]) {
                    Ok((out_len, send_info)) => {
                        info!("generating packet {} {:?}", out_len, send_info.to);
                        pb[index].meta_mut().size = out_len;
                        pb[index].meta_mut().set_socket_addr(&send_info.to);
                    }
                    Err(quiche::Error::Done) => {
                        info!("done sending.. {} index: {}", send_pkt_cnt, index);
                        break 'genpkt;
                    }
                    Err(err) => panic!("send failed {}", err),
                };
                index += 1;
            }

            send_pkt_cnt += index;
        }

        info!("send_pkt_cnt: {}", send_pkt_cnt);
        if send_pkt_cnt == 0 {
            return; // nothing to do
        }

        let pb = self.packet_batch.borrow();
        let packets_and_senders: Vec<_> = (0..send_pkt_cnt)
            .into_iter()
            .map(|i| {
                info!(
                    "sending: {} to {}",
                    pb[i].meta().size,
                    pb[i].meta().socket_addr()
                );
                (
                    pb[i].data(..pb[i].meta().size).unwrap(),
                    pb[i].meta().socket_addr(),
                )
            })
            .collect();
        info!("sending {}", packets_and_senders.len());
        match crate::sendmmsg::batch_send(&self.socket, &packets_and_senders) {
            Ok(_) => {
                info!("sent {:?}", packets_and_senders.len());
            }
            Err(e) => {
                info!("Error: {:?}", e);
            }
        }

        /*match batch_send() {
            Err(e) => {
            },
            Ok(s) => {
                if s < pkt_cnt {
                    self.metrics
                        .tx_drop_cnt
                        .fetch_add(send_pkt_cnt as u64 - msg_cnt_s as u64, Ordering::Relaxed);
                } else {
                    self.metrics.tx_pkt_cnt.fetch_add(msg_cnt_s as u64, Ordering::Relaxed);
                }
            }
        }*/
    }

    fn update_scids(
        icid: ICID,
        conn: &mut quiche::Connection,
        conn_ids: &mut HashMap<SCID, ICID>,
        rng: &mut SmallRng,
    ) {
        // Remove retired SCIDs
        while let Some(retired_scid) = conn.retired_scid_next() {
            if let Some(scid) = parse_scid(&retired_scid) {
                conn_ids.remove(&scid);
            }
        }
        // Provide new SCIDs
        while conn.scids_left() > 0 {
            let scid_u: u64 = rng.gen();
            let scid_b = scid_u.to_le_bytes();
            let scid = ConnectionId::from_ref(&scid_b[..]);
            let reset_token: u128 = rng.gen();
            match conn.new_scid(&scid, reset_token, false) {
                Ok(_) => (),
                Err(quiche::Error::InvalidState) => continue, // already used
                Err(err) => panic!("Unexpected failure providing SCID: {}", err),
            };
            conn_ids.insert(scid_u as SCID, icid);
        }
    }
}

pub type ICID = u64;
pub type SCID = u64;

fn parse_scid(id: &ConnectionId) -> Option<u64> {
    let bytes = id.as_ref();
    if bytes.len() != 8 {
        return None;
    }
    Some(u64::from_le_bytes(bytes.try_into().unwrap()))
}

pub struct Server {
    pub metrics: Vec<Arc<ServerMetrics>>,
    tiles: Vec<ServerTile>,
    thread_handles: RefCell<Vec<std::thread::JoinHandle<()>>>,
}

pub struct ServerConfig {
    pub tile_count: usize,
    pub listen_addr: SocketAddr,
    pub max_connections: usize,
}

impl QuicServer for Server {
    fn join(&self) -> Option<()> {
        self.thread_handles.borrow_mut().drain(..).for_each(|t| {
            t.join().unwrap();
        });
        Some(())
    }
}

impl Server {
    pub fn new(
        config: &ServerConfig,
        keypair: &Keypair,
        sockets: Vec<UdpSocket>,
        exit: Arc<AtomicBool>,
        packet_sender: Sender<PacketBatch>,
    ) -> Result<Self, std::io::Error> {
        let tiles = sockets
            .into_iter()
            .map(|s| {
                ServerTile::new(
                    s,
                    config.listen_addr,
                    keypair,
                    config.max_connections,
                    exit.clone(),
                    packet_sender.clone(),
                )
            })
            .collect::<Vec<ServerTile>>();
        let metrics = tiles.iter().map(|tile| tile.metrics()).collect();

        Ok(Self {
            thread_handles: RefCell::new(Vec::with_capacity(tiles.len())),
            metrics,
            tiles,
        })
    }

    pub fn start(&mut self) {
        info!("start!");
        let tiles = std::mem::take(&mut self.tiles);
        tiles
            .into_iter()
            .map(|mut tile| {
                std::thread::spawn(move || {
                    tile.run();
                })
            })
            .for_each(|hdl| self.thread_handles.borrow_mut().push(hdl));
    }

    pub fn wait(&mut self) {
        self.thread_handles
            .borrow_mut()
            .drain(..)
            .for_each(|hdl| hdl.join().expect("Failed to join thread"));
    }
}

// This poor thing is ~20 kB.
pub struct Conn {
    pub conn: Option<quiche::Connection>,
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_server(
    thread_name: &'static str,
    metrics_name: &'static str,
    sock: UdpSocket,
    keypair: &Keypair,
    packet_sender: Sender<PacketBatch>,
    exit: Arc<AtomicBool>,
    max_connections_per_peer: usize,
    staked_nodes: Arc<RwLock<StakedNodes>>,
    max_staked_connections: usize,
    max_unstaked_connections: usize,
    wait_for_chunk_timeout: Duration,
    coalesce: Duration,
) -> Result<Box<dyn QuicServer>, QuicServerError> {
    let config = ServerConfig {
        tile_count: 1,
        listen_addr: "0.0.0.0:0".parse().unwrap(),
        max_connections: max_staked_connections,
    };
    let mut s = Server::new(&config, keypair, vec![sock], exit, packet_sender)
        .map_err(|_e| QuicServerError::Failed)?;
    s.start();
    Ok(Box::new(s))
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{
            nonblocking::quic::{test::*, DEFAULT_WAIT_FOR_CHUNK_TIMEOUT},
            quic::{MAX_STAKED_CONNECTIONS, MAX_UNSTAKED_CONNECTIONS},
        },
        crossbeam_channel::unbounded,
        solana_sdk::net::DEFAULT_TPU_COALESCE,
        std::{net::SocketAddr, sync::RwLock},
        tokio::runtime::Runtime,
    };

    fn rt(name: String) -> Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .thread_name(name)
            .enable_all()
            .build()
            .unwrap()
    }

    fn setup_quic_server() -> (
        Box<dyn QuicServer>,
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
        let quic_server = spawn_server(
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
        (quic_server, exit, receiver, server_address)
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
        let quic_server = spawn_server(
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
        quic_server.join().unwrap();
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
        let quic_server = spawn_server(
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
        quic_server.join().unwrap();
    }
}
