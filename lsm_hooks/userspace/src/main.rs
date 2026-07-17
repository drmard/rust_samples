use aya::maps::HashMap;
use aya::programs::Lsm;
use aya::{Bpf, Btf};
use aya_log::BpfLogger;
use common::{FileRuleKey, FileRuleValue};
use common::{MAX_PATH_LEN, AUTH_OPEN, AUTH_READ, AUTH_WRITE, AUTH_EXEC};
use notify::{Config, Event, RecommendedWatcher, Watcher, RecursiveMode};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::mpsc::channel;

const RULES_FILE_PATH: &str = "/etc/lsm_hooks/ebpf_file_rules.txt";

fn main() -> Result<(), Box<dyn std::error::Error>> {

    env_logger::init();

    // loading BTF
    let btf = Btf::from_sys_fs()?;
    let mut bpf = Bpf::load_file_with_btf("bpf_program.o", &btf)?;

    BpfLogger::init(&mut bpf)?;

    // loading LSM hook
    let program: &mut Lsm = bpf.program_mut("file_open").unwrap().try_into()?;
    program.load()?;
    program.attach()?;

    println!("eBPF LSM program loaded and attached!");

    // get access to eBPF Map
    let mut rules_map: HashMap<_, FileRuleKey, FileRuleValue> =
        HashMap::try_from(bpf.map_mut("RULES").unwrap())?;

    // try to read File with rules first time
    if let Err(e) = reload_rules(&mut rules_map, RULES_FILE_PATH) {
        eprintln!("error. cannot read file with rules: {}", e);
    }

    // 5. Setting up monitoring of file with rules via notify
    let (tx, rx) = channel();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;
    
    // Monitoring the parent directory
    let config_path = Path::new(RULES_FILE_PATH);
    if let Some(parent) = config_path.parent() {
        watcher.watch(parent, RecursiveMode::NonRecursive)?;
    }

    println!("waiting for changes in {} ..", RULES_FILE_PATH);

    for res in rx {
        match res {
            Ok(Event { kind, .. }) if kind.is_modify() || kind.is_create() => {
                println!("File with rules has changed. Updating...");

                if let Err(e) = reload_rules(&mut rules_map, RULES_FILE_PATH) {
                    eprintln!("error updating rules: {}", e);
                }
            }
            _ => {}
        }
    }

    Ok(())
}

// updating rules in eBPF Map
fn reload_rules(rules_map: &mut HashMap<
    &mut aya::maps::MapData, FileRuleKey, FileRuleValue>, path: &str) ->
    io::Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    // overwrite/add new keys
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 5 {
            eprintln!("incorrect data format: {}", line);
            continue;
        }

        let file_path = parts[0];
        let open_allowed = parts[1] == "1";
        let read_allowed = parts[2] == "1";
        let write_allowed = parts[3] == "1";
        let exec_allowed = parts[4] == "1";

        // set flags
        let mut mask = 0u32;
        if open_allowed { mask |= AUTH_OPEN; }
        if read_allowed { mask |= AUTH_READ; }
        if write_allowed { mask |= AUTH_WRITE; }
        if exec_allowed { mask |= AUTH_EXEC; }

        // preparing key for new rule
        let mut path_bytes = [0u8; MAX_PATH_LEN];
        let src_bytes = file_path.as_bytes();
        let len = src_bytes.len().min(MAX_PATH_LEN - 1);
        path_bytes[..len].copy_from_slice(&src_bytes[..len]);

        let key = FileRuleKey { path: path_bytes };
        let value = FileRuleValue { allowed_mask: mask };

        if let Err(e) = rules_map.insert(key, value, 0) {
            eprintln!("cannot insert new rule for {}: {:?}", file_path, e);
        }
    }

    println!("the rules have been successfully applied");

    Ok(())
}

