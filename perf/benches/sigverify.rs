#![feature(test)]

extern crate test;

use {
    log::*,
    rand::{thread_rng, Rng},
    solana_perf::{
        packet::{to_packet_batches, Packet, PacketBatch},
        recycler::Recycler,
        sigverify,
        test_tx::{test_tx, test_tx_with_num_sigs},
    },
    test::Bencher,
};

const NUM: usize = 1024;

#[bench]
fn bench_sigverify(bencher: &mut Bencher) {
    let tx = test_tx();
    let num_packets = NUM;

    // generate packet vector
    let mut batches = to_packet_batches(
        &std::iter::repeat(tx).take(num_packets).collect::<Vec<_>>(),
        128,
    );

    let recycler = Recycler::default();
    let recycler_out = Recycler::default();
    // verify packets
    bencher.iter(|| {
        let _ans =
            sigverify::ed25519_verify(&mut batches, &recycler, &recycler_out, false, num_packets);
    })
}

#[bench]
fn bench_sigverify_uneven(bencher: &mut Bencher) {
    solana_logger::setup();
    let tx = test_tx();

    let num_packets = NUM;
    let mut current_packets = 0;
    // generate packet vector
    let mut batches = vec![];
    while current_packets < num_packets {
        let mut len: usize = thread_rng().gen_range(1, 128);
        current_packets += len;
        if current_packets > num_packets {
            len -= current_packets - num_packets;
            current_packets = num_packets;
        }
        let mut batch = PacketBatch::with_capacity(len);
        batch.packets.resize(len, Packet::default());
        for packet in batch.packets.iter_mut() {
            let num_sigs: usize = thread_rng().gen_range(1, 10);
            let tx = test_tx_with_num_sigs(num_sigs);
            Packet::populate_packet(packet, None, &tx).expect("serialize request");
            if thread_rng().gen_ratio(5, 10) {
                packet.meta.set_discard(true);
            }
        }
        batches.push(batch);
    }
    info!("num_packets: {}", num_packets);

    let recycler = Recycler::default();
    let recycler_out = Recycler::default();
    // verify packets
    bencher.iter(|| {
        let _ans =
            sigverify::ed25519_verify(&mut batches, &recycler, &recycler_out, false, num_packets);
    })
}

#[bench]
fn bench_get_offsets(bencher: &mut Bencher) {
    let tx = test_tx();

    // generate packet vector
    let mut batches =
        to_packet_batches(&std::iter::repeat(tx).take(1024).collect::<Vec<_>>(), 1024);

    let recycler = Recycler::default();
    // verify packets
    bencher.iter(|| {
        let _ans = sigverify::generate_offsets(&mut batches, &recycler, false);
    })
}
