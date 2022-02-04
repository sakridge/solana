#![allow(clippy::integer_arithmetic)]
use {
    clap::{crate_description, crate_name, value_t, App, Arg},
    crossbeam_channel::unbounded,
    log::*,
    rand::{thread_rng, Rng},
    rayon::prelude::*,
    solana_entry::entry::{create_ticks, next_entry_mut},
    solana_ledger::{
        bank_forks_utils,
        blockstore::{entries_to_test_shreds, Blockstore},
        blockstore_processor::ProcessOptions,
        genesis_utils::{create_genesis_config, GenesisConfigInfo},
        get_tmp_ledger_path,
    },
    solana_measure::measure::Measure,
    solana_sdk::{
        hash::Hash,
        signature::{Keypair, Signature},
        system_transaction,
        transaction::Transaction,
    },
    std::sync::Arc,
};

fn make_accounts_txs(
    total_num_transactions: usize,
    hash: Hash,
    same_payer: bool,
) -> Vec<Transaction> {
    let to_pubkey = solana_sdk::pubkey::new_rand();
    let payer_key = Keypair::new();
    let dummy = system_transaction::transfer(&payer_key, &to_pubkey, 1, hash);
    (0..total_num_transactions)
        .into_par_iter()
        .map(|_| {
            let mut new = dummy.clone();
            let sig: Vec<u8> = (0..64).map(|_| thread_rng().gen::<u8>()).collect();
            if !same_payer {
                new.message.account_keys[0] = solana_sdk::pubkey::new_rand();
            }
            new.message.account_keys[1] = solana_sdk::pubkey::new_rand();
            new.signatures = vec![Signature::new(&sig[0..64])];
            new
        })
        .collect()
}

#[allow(clippy::cognitive_complexity)]
fn main() {
    solana_logger::setup();

    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(solana_version::version!())
        .arg(
            Arg::with_name("num_chunks")
                .long("num-chunks")
                .takes_value(true)
                .value_name("SIZE")
                .help("Number of transaction chunks."),
        )
        .arg(
            Arg::with_name("packets_per_chunk")
                .long("packets-per-chunk")
                .takes_value(true)
                .value_name("SIZE")
                .help("Packets per chunk"),
        )
        .arg(
            Arg::with_name("same_payer")
                .long("same-payer")
                .takes_value(false)
                .help("Use the same payer for transfers"),
        )
        .arg(
            Arg::with_name("iterations")
                .long("iterations")
                .takes_value(true)
                .help("Number of iterations"),
        )
        .arg(
            Arg::with_name("num_threads")
                .long("num-threads")
                .takes_value(true)
                .help("Number of iterations"),
        )
        .get_matches();

    let num_threads = value_t!(matches, "num_threads", usize).ok();
    //   a multiple of packet chunk duplicates to avoid races
    let num_chunks = value_t!(matches, "num_chunks", usize).unwrap_or(16);
    let packets_per_chunk = value_t!(matches, "packets_per_chunk", usize).unwrap_or(192);
    let _iterations = value_t!(matches, "iterations", usize).unwrap_or(1000);

    let total_num_transactions = num_chunks * packets_per_chunk;
    let mint_total = 1_000_000_000_000;
    let GenesisConfigInfo {
        genesis_config,
        mint_keypair,
        ..
    } = create_genesis_config(mint_total);

    let ticks_per_slot = genesis_config.ticks_per_slot;

    /*let bank0 = Bank::new_for_benches(&genesis_config);
    let mut bank_forks = BankForks::new(bank0);
    let mut bank = bank_forks.working_bank();*/

    info!("threads: {:?} txs: {}", num_threads, total_num_transactions);

    let same_payer = matches.is_present("same_payer");
    let transactions = make_accounts_txs(total_num_transactions, genesis_config.hash(), same_payer);

    let mut start_hash = genesis_config.hash();
    // fund all the accounts
    let mut entries0: Vec<_> = transactions
        .iter()
        .map(|tx| {
            let fund = system_transaction::transfer(
                &mint_keypair,
                &tx.message.account_keys[0],
                mint_total / total_num_transactions as u64,
                genesis_config.hash(),
            );
            next_entry_mut(&mut start_hash, 1, vec![fund])
        })
        .collect();

    let ticks0 = create_ticks(ticks_per_slot, 0, start_hash);
    start_hash = ticks0.last().unwrap().hash;
    entries0.extend(ticks0);

    let mut entries1 = vec![];
    for batch in transactions.chunks(packets_per_chunk) {
        let tx_entries = next_entry_mut(&mut start_hash, 1, batch.to_vec());
        entries1.push(tx_entries);
    }

    let ticks1 = create_ticks(ticks_per_slot, 0, start_hash);
    entries1.extend(ticks1);

    let ledger_path = get_tmp_ledger_path!();
    {
        let blockstore = Arc::new(
            Blockstore::open(&ledger_path).expect("Expected to be able to open database ledger"),
        );

        let shreds = entries_to_test_shreds(&entries0, 0, 0, true, 0);
        blockstore.insert_shreds(shreds, None, false).unwrap();

        let shreds = entries_to_test_shreds(&entries1, 1, 0, true, 0);
        blockstore.insert_shreds(shreds, None, false).unwrap();

        let account_paths = vec![std::path::PathBuf::from(
            std::env::var("FARF_DIR").unwrap_or_else(|_| "farf".to_string()),
        )];
        let (accounts_package_sender, _) = unbounded();
        let process_options = ProcessOptions {
            poh_verify: false,
            override_num_threads: num_threads,
            ..ProcessOptions::default()
        };
        info!("options: {:?}", process_options.poh_verify);
        let mut start = Measure::start("replay_time");
        let (_, _, _, _, processing_time) = bank_forks_utils::load(
            &genesis_config,
            &blockstore,
            account_paths,
            None,
            None,
            process_options,
            None,
            None,
            accounts_package_sender,
            None,
        )
        .unwrap();
        start.stop();
        info!(
            "{} ({}ms) transactions: {} tps: {:.2}",
            start,
            processing_time,
            transactions.len(),
            (1000.0f32 * transactions.len() as f32 / (processing_time as f32)),
        );
    }
    let _unused = Blockstore::destroy(&ledger_path);
}
