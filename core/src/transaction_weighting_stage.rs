use {
    rayon::prelude::*,
    solana_gossip::cluster_info::ClusterInfo,
    solana_perf::packet::PacketBatch,
    solana_runtime::bank_forks::BankForks,
    solana_streamer::streamer::{self, StreamerError},
    std::{
        collections::HashMap,
        net::IpAddr,
        sync::{
            mpsc::{Receiver, RecvTimeoutError, Sender},
            Arc, RwLock,
        },
        thread::{self, Builder, JoinHandle},
        time::Instant,
    },
};

pub struct TransactionWeightStage {
    thread_hdl: JoinHandle<()>,
}

impl TransactionWeightStage {
    pub fn new(
        packet_receiver: Receiver<PacketBatch>,
        sender: Sender<Vec<PacketBatch>>,
        bank_forks: Arc<RwLock<BankForks>>,
        cluster_info: Arc<ClusterInfo>,
    ) -> Self {
        let thread_hdl = Builder::new()
            .name("sol-tx-weight".to_string())
            .spawn(move || {
                let mut last_stakes = Instant::now();
                let mut ip_to_stake: HashMap<IpAddr, u64> = HashMap::new();
                loop {
                    if last_stakes.elapsed().as_millis() > 1000 {
                        let root_bank = bank_forks.read().unwrap().root_bank();
                        let staked_nodes = root_bank.staked_nodes();
                        ip_to_stake = cluster_info
                            .tvu_peers()
                            .into_iter()
                            .filter_map(|node| {
                                let stake = staked_nodes.get(&node.id)?;
                                Some((node.tvu.ip(), *stake))
                            })
                            .collect();
                        last_stakes = Instant::now();
                    }
                    match streamer::recv_packet_batches(&packet_receiver) {
                        Ok((mut batches, _num_packets, _recv_duration)) => {
                            Self::apply_weights(&mut batches, &ip_to_stake);
                            if let Err(e) = sender.send(batches) {
                                info!("Sender error: {:?}", e);
                            }
                        }
                        Err(e) => match e {
                            StreamerError::RecvTimeout(RecvTimeoutError::Disconnected) => break,
                            StreamerError::RecvTimeout(RecvTimeoutError::Timeout) => (),
                            _ => error!("error: {:?}", e),
                        },
                    }
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn apply_weights(batches: &mut [PacketBatch], ip_to_stake: &HashMap<IpAddr, u64>) {
        batches.into_par_iter().for_each(|batch| {
            batch.packets.par_iter_mut().for_each(|packet| {
                packet.meta.weight = *ip_to_stake.get(&packet.meta.addr().ip()).unwrap_or(&0);
            });
        });
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_perf::packet::Packet;

    #[test]
    fn test_apply_weights() {
        let packet = Packet::default();
        let packets = PacketBatch::new(vec![packet]);
        let ip_to_stake = HashMap::new();
        let mut vec_packets_batch = vec![packets];
        TransactionWeightStage::apply_weights(&mut vec_packets_batch, &ip_to_stake);
        vec_packets_batch[0]
            .packets
            .iter()
            .for_each(|packet| assert_eq!(packet.meta.weight, 0));
    }
}
