use packet::{Blob, BlobRecycler, PacketRecycler, SharedBlob, SharedPackets, NUM_BLOBS};
use result::Result;
use std::collections::VecDeque;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;

use erasure;
use packet::BLOB_SIZE;

pub type PacketReceiver = mpsc::Receiver<SharedPackets>;
pub type PacketSender = mpsc::Sender<SharedPackets>;
pub type BlobSender = mpsc::Sender<VecDeque<SharedBlob>>;
pub type BlobReceiver = mpsc::Receiver<VecDeque<SharedBlob>>;

fn recv_loop(
    sock: &UdpSocket,
    exit: &Arc<AtomicBool>,
    re: &PacketRecycler,
    channel: &PacketSender,
) -> Result<()> {
    loop {
        let msgs = re.allocate();
        let msgs_ = msgs.clone();
        loop {
            match msgs.write().unwrap().recv_from(sock) {
                Ok(()) => {
                    channel.send(msgs_)?;
                    break;
                }
                Err(_) => {
                    if exit.load(Ordering::Relaxed) {
                        re.recycle(msgs_);
                        return Ok(());
                    }
                }
            }
        }
    }
}

pub fn receiver(
    sock: UdpSocket,
    exit: Arc<AtomicBool>,
    recycler: PacketRecycler,
    channel: PacketSender,
) -> Result<JoinHandle<()>> {
    let timer = Duration::new(1, 0);
    sock.set_read_timeout(Some(timer))?;
    Ok(spawn(move || {
        let _ = recv_loop(&sock, &exit, &recycler, &channel);
        ()
    }))
}

fn recv_send(sock: &UdpSocket, recycler: &BlobRecycler, r: &BlobReceiver) -> Result<()> {
    let timer = Duration::new(1, 0);
    let mut msgs = r.recv_timeout(timer)?;
    Blob::send_to(recycler, sock, &mut msgs)?;
    Ok(())
}

pub fn responder(
    sock: UdpSocket,
    exit: Arc<AtomicBool>,
    recycler: BlobRecycler,
    r: BlobReceiver,
) -> JoinHandle<()> {
    spawn(move || loop {
        if recv_send(&sock, &recycler, &r).is_err() && exit.load(Ordering::Relaxed) {
            break;
        }
    })
}

//TODO, we would need to stick block authentication before we create the
//window.
// detect erasure packet
// detect packet to send to peer
fn recv_window(
    window: &mut Vec<Option<SharedBlob>>,
    recycler: &BlobRecycler,
    consumed: &mut usize,
    socket: &UdpSocket,
    s: &BlobSender,
) -> Result<()> {
    const HIST_BUCKET_SIZE:usize = 4;
    const NUM_CODING_BLOCKS:usize = 1;
    let mut window_hist = vec![0; window.len()/HIST_BUCKET_SIZE];
    let mut dq = Blob::recv_from(recycler, socket)?;
    while let Some(b) = dq.pop_front() {
        let b_ = b.clone();
        let mut p = b.write().unwrap();
        let pix = p.get_index()? as usize;
        let w = pix % NUM_BLOBS;
        println!("w: {} b: {:?} NUM_BLOBS: {} window.len: {}",
                 w, p, NUM_BLOBS, window.len());
        //TODO, after the block are authenticated
        //if we get different blocks at the same index
        //that is a network failure/attack
        {
            if window[w].is_none() {
                window[w] = Some(b_);
                let window_hist_idx = w % window_hist.len();
                window_hist[window_hist_idx] += 1;
            } else {
                debug!("duplicate blob at index {:}", w);
            }

            let num_non_coding = HIST_BUCKET_SIZE - NUM_CODING_BLOCKS;
            for (i, hist_val) in window_hist.iter().enumerate() {
                let coding_start = i+num_non_coding;
                let coding_end = coding_start + NUM_CODING_BLOCKS;
                // see if we have not all blocks in a bucket
                // but a minimum number to re-generate from coding
                if *hist_val != HIST_BUCKET_SIZE &&
                   *hist_val > (num_non_coding) {
                    // detect if we have non-null coding entries, if we do
                    // then we should use the coding blocks to decode
                    for j in coding_start..coding_end {
                        if !window[j].is_none() {
                            let mut erasures:Vec<i32> = Vec::new();
                            let mut data:Vec<Vec<u8>> = Vec::new();
                            let mut coding:Vec<Vec<u8>> = Vec::new();
                            let mut locks = Vec::new();
                            let mut locksprime = Vec::new();
                            for k in i..coding_end {
                                if !window[k].is_none() {
                                    locks[k] = window[k].clone().unwrap();
                                    locksprime[k] = Some(locks[k].read().unwrap());
                                }
                            }
                            for k in i..coding_start {
                                if locksprime[k].is_none() {
                                    data.push(vec![0; BLOB_SIZE]);
                                    erasures.push(k as i32);
                                } else {
                                    //data.push((*window[k].clone().unwrap().read().unwrap()).data.to_vec());
                                    data.push((locksprime[k].unwrap().clone()).data.to_vec());
                                }
                            }
                            /*for k in coding_start..coding_end {
                                if window[k].is_none() {
                                    coding.push(vec![0; BLOB_SIZE]);
                                    erasures.push(k as i32);
                                } else {
                                    coding.push((*window[k].clone().unwrap().read().unwrap()).data.to_vec());
                                }
                            }*/
                            erasures.push(-1);
                            erasure::decode_blocks(&data,
                                                   &coding,
                                                   &erasures);
                            break;
                        }
                    }
                }
            }
            //send a contiguous set of blocks
            let mut dq = VecDeque::new();
            loop {
                let k = *consumed % NUM_BLOBS;
                if window[k].is_none() {
                    break;
                }
                dq.push_back(window[k].clone().unwrap());
                window[k] = None;
                *consumed += 1;
            }
            if !dq.is_empty() {
                println!("sending {}", dq.len());
                s.send(dq)?;
            }
        }
    }
    Ok(())
}

pub fn window(
    sock: UdpSocket,
    exit: Arc<AtomicBool>,
    r: BlobRecycler,
    s: BlobSender,
) -> JoinHandle<()> {
    spawn(move || {
        let mut window = vec![None; NUM_BLOBS];
        let mut consumed = 0;
        let timer = Duration::new(1, 0);
        sock.set_read_timeout(Some(timer)).unwrap();
        loop {
            if recv_window(&mut window, &r, &mut consumed, &sock, &s).is_err()
                && exit.load(Ordering::Relaxed)
            {
                break;
            }
        }
    })
}

#[cfg(all(feature = "unstable", test))]
mod bench {
    extern crate test;
    use self::test::Bencher;
    use packet::{Packet, PacketRecycler, PACKET_DATA_SIZE};
    use result::Result;
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};
    use std::thread::sleep;
    use std::thread::{spawn, JoinHandle};
    use std::time::Duration;
    use std::time::SystemTime;
    use streamer::{receiver, PacketReceiver};

    use streamer::{allocate, recycle, Packet, PacketRecycler, Receiver};
    use packet::PACKET_SIZE;

    fn producer(
        addr: &SocketAddr,
        recycler: PacketRecycler,
        exit: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let send = UdpSocket::bind("0.0.0.0:0").unwrap();
        let msgs = recycler.allocate();
        let msgs_ = msgs.clone();
        msgs.write().unwrap().packets.resize(10, Packet::default());
        for w in msgs.write().unwrap().packets.iter_mut() {
            w.meta.size = PACKET_DATA_SIZE;
            w.meta.set_addr(&addr);
        }
        spawn(move || loop {
            if exit.load(Ordering::Relaxed) {
                return;
            }
            let mut num = 0;
            for p in msgs_.read().unwrap().packets.iter() {
                let a = p.meta.addr();
                send.send_to(&p.data[..p.meta.size], &a).unwrap();
                num += 1;
            }
            assert_eq!(num, 10);
        })
    }

    fn sink(
        recycler: PacketRecycler,
        exit: Arc<AtomicBool>,
        rvs: Arc<Mutex<usize>>,
        r: PacketReceiver,
    ) -> JoinHandle<()> {
        spawn(move || loop {
            if exit.load(Ordering::Relaxed) {
                return;
            }
            let timer = Duration::new(1, 0);
            match r.recv_timeout(timer) {
                Ok(msgs) => {
                    let msgs_ = msgs.clone();
                    *rvs.lock().unwrap() += msgs.read().unwrap().packets.len();
                    recycler.recycle(msgs_);
                }
                _ => (),
            }
        })
    }
    fn run_streamer_bench() -> Result<()> {
        let read = UdpSocket::bind("127.0.0.1:0")?;
        let addr = read.local_addr()?;
        let exit = Arc::new(AtomicBool::new(false));
        let pack_recycler = PacketRecycler::default();

        let (s_reader, r_reader) = channel();
        let t_reader = receiver(read, exit.clone(), pack_recycler.clone(), s_reader)?;
        let t_producer1 = producer(&addr, pack_recycler.clone(), exit.clone());
        let t_producer2 = producer(&addr, pack_recycler.clone(), exit.clone());
        let t_producer3 = producer(&addr, pack_recycler.clone(), exit.clone());

        let rvs = Arc::new(Mutex::new(0));
        let t_sink = sink(pack_recycler.clone(), exit.clone(), rvs.clone(), r_reader);

        let start = SystemTime::now();
        let start_val = *rvs.lock().unwrap();
        sleep(Duration::new(5, 0));
        let elapsed = start.elapsed().unwrap();
        let end_val = *rvs.lock().unwrap();
        let time = elapsed.as_secs() * 10000000000 + elapsed.subsec_nanos() as u64;
        let ftime = (time as f64) / 10000000000f64;
        let fcount = (end_val - start_val) as f64;
        println!("performance: {:?}", fcount / ftime);
        exit.store(true, Ordering::Relaxed);
        t_reader.join()?;
        t_producer1.join()?;
        t_producer2.join()?;
        t_producer3.join()?;
        t_sink.join()?;
        Ok(())
    }
    #[bench]
    pub fn streamer_bench(_bench: &mut Bencher) {
        run_streamer_bench().unwrap();
    }
}

#[cfg(test)]
mod test {
    use packet::{Blob, BlobRecycler, Packet, PacketRecycler, Packets, PACKET_DATA_SIZE};
    use std::collections::VecDeque;
    use std::io;
    use std::io::Write;
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::channel;
    use std::sync::Arc;
    use std::time::Duration;
    use streamer::{receiver, responder, window, BlobReceiver, PacketReceiver};
    use rand::{Rng, thread_rng};

    fn get_msgs(r: PacketReceiver, num: &mut usize) {
        for _t in 0..5 {
            let timer = Duration::new(1, 0);
            match r.recv_timeout(timer) {
                Ok(m) => *num += m.read().unwrap().packets.len(),
                e => println!("error {:?}", e),
            }
            if *num == 10 {
                break;
            }
        }
    }
    #[test]
    pub fn streamer_debug() {
        write!(io::sink(), "{:?}", Packet::default()).unwrap();
        write!(io::sink(), "{:?}", Packets::default()).unwrap();
        write!(io::sink(), "{:?}", Blob::default()).unwrap();
    }
    #[test]
    pub fn streamer_send_test() {
        let read = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = read.local_addr().unwrap();
        let send = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let exit = Arc::new(AtomicBool::new(false));
        let pack_recycler = PacketRecycler::default();
        let resp_recycler = BlobRecycler::default();
        let (s_reader, r_reader) = channel();
        let t_receiver = receiver(read, exit.clone(), pack_recycler.clone(), s_reader).unwrap();
        let (s_responder, r_responder) = channel();
        let t_responder = responder(send, exit.clone(), resp_recycler.clone(), r_responder);
        let mut msgs = VecDeque::new();
        for i in 0..10 {
            let b = resp_recycler.allocate();
            let b_ = b.clone();
            let mut w = b.write().unwrap();
            w.data[0] = i as u8;
            w.meta.size = PACKET_DATA_SIZE;
            w.meta.set_addr(&addr);
            msgs.push_back(b_);
        }
        s_responder.send(msgs).expect("send");
        let mut num = 0;
        get_msgs(r_reader, &mut num);
        assert_eq!(num, 10);
        exit.store(true, Ordering::Relaxed);
        t_receiver.join().expect("join");
        t_responder.join().expect("join");
    }

    fn get_blobs(r: BlobReceiver, num: &mut usize) {
        for _t in 0..5 {
            let timer = Duration::new(1, 0);
            match r.recv_timeout(timer) {
                Ok(m) => {
                    for (i, v) in m.iter().enumerate() {
                        println!("i: {} v: {:?}", i, v.read().unwrap());
                        assert_eq!(v.read().unwrap().get_index().unwrap() as usize, *num + i);
                    }
                    *num += m.len();
                }
                e => println!("error {:?}", e),
            }
            if *num == 10 {
                break;
            }
        }
    }

    #[test]
    pub fn window_send_test() {
        let read = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = read.local_addr().unwrap();
        let send = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let exit = Arc::new(AtomicBool::new(false));
        let resp_recycler = BlobRecycler::default();
        let (s_reader, r_reader) = channel();
        let t_receiver = window(read, exit.clone(), resp_recycler.clone(), s_reader);
        let (s_responder, r_responder) = channel();
        let t_responder = responder(send, exit.clone(), resp_recycler.clone(), r_responder);
        let mut msgs = VecDeque::new();
        for v in 0..10 {
            let i = 9 - v;
            let b = resp_recycler.allocate();
            let b_ = b.clone();
            let mut w = b.write().unwrap();
            w.set_index(i).unwrap();
            assert_eq!(i, w.get_index().unwrap());
            w.meta.size = PACKET_DATA_SIZE;
            w.meta.set_addr(&addr);
            msgs.push_back(b_);
        }
        s_responder.send(msgs).expect("send");
        let mut num = 0;
        get_blobs(r_reader, &mut num);
        assert_eq!(num, 10);
        exit.store(true, Ordering::Relaxed);
        t_receiver.join().expect("join");
        t_responder.join().expect("join");
    }

    #[test]
    pub fn window_missing_packets() {
        let read = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = read.local_addr().unwrap();
        let send = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let exit = Arc::new(AtomicBool::new(false));
        let resp_recycler = BlobRecycler::default();
        let (s_reader, r_reader) = channel();
        let t_receiver = window(read, exit.clone(), resp_recycler.clone(), s_reader);
        let (s_responder, r_responder) = channel();
        let t_responder = responder(send, exit.clone(), resp_recycler.clone(), r_responder);
        let mut msgs = VecDeque::new();
        let num_send: u64 = 10;
        let mut sends = [0; 9];
        for i in 0..sends.len() {
            sends[i as usize] = (i+1) as u64;
        }
        println!("sends: {:?}", sends);
        {
            let mut rng = thread_rng();
            for i in 0..sends.len() {
                let x: usize = rng.gen_range(0, (num_send-1) as usize);
                sends.swap(i, x);
            }
        }
        println!("sends: {:?}", sends);
        for v in sends.iter() {
            let i = num_send - 1 - *v;
            let b = resp_recycler.allocate();
            let b_ = b.clone();
            let mut w = b.write().unwrap();
            w.set_index(i).unwrap();
            assert_eq!(i, w.get_index().unwrap());
            w.meta.size = PACKET_DATA_SIZE;
            w.meta.set_addr(&addr);
            msgs.push_back(b_);
        }
        s_responder.send(msgs).expect("send");
        let mut num = 0;
        get_blobs(r_reader, &mut num);
        assert_eq!(num, num_send as usize);
        exit.store(true, Ordering::Relaxed);
        t_receiver.join().expect("join");
        t_responder.join().expect("join");
    }

}
