use chrono::prelude::*;
use regex::Regex;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::Ipv4Addr;
use chrono::Duration;
use uuid::Uuid;
use std::collections::{HashMap, HashSet};

//const LOG_LOCATION: &str = "/root/trojan.log.1";
const LOG_LOCATION: &str = "/Users/xinyuye/github/rust-rotate/trojan.log.1";

const MERGE_INTERVAL: u32 = 600; //Logs are regrouped into 10min blocks

#[derive(Debug)]
struct LogGroup{
    date: DateTime<Utc>,
    ips: HashSet<Ipv4Addr>,
    targets: HashMap<String,(u64, u64)>,
}


#[derive(Debug)]
struct LogData{
    date: DateTime<Utc>,
    user: [u8; 28],
    ip: Ipv4Addr,
    target: String,
    size: (u64, u64),
}
fn main() {
    process_file().unwrap();
}

fn merge_date(mut date: DateTime<Utc>) -> DateTime<Utc>{
    date = date.checked_sub_signed(Duration::nanoseconds(date.timestamp_subsec_nanos() as i64) ).unwrap(); //returns NaiveTime.frac
    date = date.checked_sub_signed(Duration::seconds(date.timestamp() % MERGE_INTERVAL as i64) ).unwrap(); //returns NaiveTime.secs
    date
}

fn process_file() -> io::Result<()> {
    let f = File::open(LOG_LOCATION)?;
    let reader = BufReader::new(f);
    let mut counter = 0_u32;
    let re = Regex::new(r#"\[INFO\]  (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) user (\w{56}) from (\d+\.\d+\.\d+\.\d+):\d+ tunneling to ([a-zA-Z.0-9-]+):443 closed sent: ([\d.]+ [KMGP]?i?B) recv: ([\d.]+ [KMGP]?i?B)$"#).unwrap(); //this regexp expression will matchall logs that has bandwidth info.
    let mut buf_dict = HashMap::<[u8;28],LogGroup>::new();
    let mut last_date = chrono::MAX_DATETIME;//Matching domains asserts that domain is valid
    for line in reader.lines() {
        //TODO: Redirect warn messages to a separate file
        //filter [WARN] messages, they might contain non utf_8 characters
        if line.is_err() { continue; }
        let line_str = line.unwrap();
        if !line_str.starts_with("[INFO]") || !line_str.ends_with("B"){ continue; }
        let cap_res = re.captures(&line_str);
        if cap_res.is_none() {
            continue;
        }
        let cap = cap_res.unwrap();
        let mut date = Utc
            .datetime_from_str(cap.get(1).unwrap().as_str(), "%Y/%m/%d %H:%M:%S")
            .unwrap();
        let user = parse_sha224(cap.get(2).unwrap().as_str());
        let ip = cap.get(3).unwrap().as_str().parse::<Ipv4Addr>().unwrap();
        let target = cap.get(4).unwrap().as_str().to_string();
        let size = (calculate_size(cap.get(5).unwrap().as_str()), calculate_size(cap.get(6).unwrap().as_str()));
        // let mut log_line = LogData{
        //     date,
        //     user,
        //     ip,
        //     target,
        //     size
        // };
        date = merge_date(date);
        //add log to dict
        if date != last_date{ //dump all records in dict, create new one
            println!("{:?}", buf_dict);
            buf_dict.clear();
            last_date = date;
        }
        if buf_dict.contains_key(&user){
            let proc: &mut LogGroup = buf_dict.get_mut(&user).unwrap();
            proc.ips.insert(ip);
            proc.targets.entry(target).and_modify(|x| {x.0 += size.0; x.1 += size.1;} ).or_insert(size);
        }else{
            buf_dict.insert(user, LogGroup{
                date,
                ips: {let mut tmp = HashSet::new(); tmp.insert(ip); tmp },
                targets: {let mut tmp = HashMap::new(); tmp.insert(target, size); tmp}
            });
        }
    }
    Ok(())
}

fn group_domain(raw: &str) -> String {
    raw.to_string()
}

fn parse_sha224(raw: &str) -> [u8; 28] {
    let mut raw_iter = raw.chars();
    let mut ret = [0_u8; 28];
    for i in 0..28 {
        ret[i] = ((raw_iter.next().unwrap().to_digit(16).unwrap() << 4)
            + raw_iter.next().unwrap().to_digit(16).unwrap()) as u8;
    }
    ret
}

fn calculate_size(raw: &str) -> u64{
    //get unit
    let eval: Vec<&str> = raw.split(' ').collect();
    (eval[0].parse::<f64>().unwrap() * (match eval[1]{
        "B" => 1,
        "KiB" => 1024,
        "MiB" => 1_048_576,
        "GiB" => 1_073_741_824,
        //"PiB" => 1_125_899_906_842_624, impossible
        _ => 0
    } as f64) ) as u64
}