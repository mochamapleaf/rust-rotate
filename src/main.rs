use std::io;
use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;
use regex::Regex;
use chrono::prelude::*;

const LOG_LOCATION: &str = "/root/trojan.log.1";

const MERGE_INTERVAL: u32 = 600; //Logs are regrouped into 10min blocks

fn main() {
process_file().unwrap();
}

fn process_file() -> io::Result<()>{
let f = File::open(LOG_LOCATION)?;
let reader = BufReader::new(f);
let re = Regex::new(r#"\[INFO\]  (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) user (\w{56}) from (\d+\.\d+\.\d+\.\d+):\d+ tunneling to ([a-zA-Z.0-9-]+):443 closed sent: ([\d.]+ [KMGP]?i?B) recv: ([\d.]+ [KMGP]?i?B)$"#).unwrap(); //this regexp expression will matchall logs that has bandwidth info.
//Matching domains asserts that domain is valid
for line in reader.lines(){
let line_str = line?;
let cap_res = re.captures(&line_str);
if cap_res.is_none(){ continue; }
let cap = cap_res.unwrap();
let date = Utc.datetime_from_str(cap.get(1).unwrap().as_str(), "%Y/%m/%d %H:%M:%S").unwrap();
let user_hash = parse_sha224(cap.get(2).unwrap().as_str());
println!("date: {:?}, user: {:?}, ip: {}, target:{}, (up: {}, down: {})",date, user_hash, cap.get(3).unwrap().as_str(), cap.get(4).unwrap().as_str(), cap.get(5).unwrap().as_str(), cap.get(6).unwrap().as_str());
}
Ok(())
}

fn group_domain(raw: &str)->String{
raw.to_string()
}

fn parse_sha224(raw: &str) -> [u8; 28]{
println!("{}", raw);
let mut raw_iter = raw.chars();
let mut ret = [0_u8; 28];
for i in 0..28{
ret[i] = (raw_iter.next().unwrap().to_digit(16).unwrap() << 4 + raw_iter.next().unwrap().to_digit(16).unwrap()) as u8;
}
ret
}
