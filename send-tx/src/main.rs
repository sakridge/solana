use {
    clap::{crate_description, crate_name, value_t, values_t, values_t_or_exit, App, Arg},
    log::*,
    rand::{thread_rng, Rng},
    rayon::prelude::*,
    solana_clap_utils::{
        hidden_unless_forced, input_parsers::pubkey_of, input_validators::is_url_or_moniker,
    },
    solana_cli_config::{ConfigInput, CONFIG_FILE},
    solana_client::{rpc_request::TokenAccountsFilter, transaction_executor::TransactionExecutor},
};


use std::fs;
use std::io::{self, Read};
use std::path::Path;
use regex::Regex;

fn main() -> io::Result<()> {
    let path = Path::new("programs");
    let re = Regex::new(r"Program Id: ([A-Za-z0-9]+)").unwrap();

    loop {
        let programs = visit_dirs(path, &re)?;

        for p in programs {
            println!("{}", p);
        }
    }
    Ok(())
}

fn visit_dirs(dir: &Path, re: &Regex) -> io::Result<Vec<String>> {
    let mut answer = vec![];
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, re)?;
            } else {
                answer.extend(parse_file(&path, re)?);
            }
        }
    }
    Ok(answer)
}

fn parse_file(path: &Path, re: &Regex) -> io::Result<Vec<String>> {
    let mut file = fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let mut a = vec![];
    for cap in re.captures_iter(&contents) {
        a.push(cap[1].to_string())
    }

    Ok(a)
}
