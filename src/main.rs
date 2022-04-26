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
use std::fmt;

const LOG_LOCATION: &str = "/root/trojan.log.1";
//const LOG_LOCATION: &str = "/Users/xinyuye/github/rust-rotate/trojan.log.1";
//const LOG_LOCATION: &str = "/home/xinyu/CLionProjects/rust-rotate/trojan.log.1";

const MERGE_INTERVAL: u32 = 600; //Logs are regrouped into 10min blocks

struct LogGroup{
    date: DateTime<Utc>,
    ips: HashSet<Ipv4Addr>,
    targets: HashMap<String,(u64, u64)>,
}

impl fmt::Debug for LogGroup{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        write!(f, "\ndate: {}, ips: {:?}\n", self.date, self.ips);
        let mut links: Vec<&String> = self.targets.keys().collect();
        links.sort_by_key(|&x| self.targets.get(x).unwrap().0);
        links.reverse();
        for i in links{
            let unit: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
            let mut upload_unit = 0_usize;
            let mut upload = self.targets.get(i).unwrap().0 as f64;
            while upload >= 1024.0{
                upload_unit += 1;
                upload /= 1024.0;
            }
            let mut download = self.targets.get(i).unwrap().1 as f64;
            let mut download_unit = 0_usize;
            while download >= 1024.0{
                download_unit+= 1;
                download /= 1024.0;
            }
            let mut temp_str = i.to_string();
            temp_str.truncate(19);
            temp_str.push(':');
            write!(f, "{:<20} up {:>6.2} {}, down {:>6.2} {}\n", temp_str, upload, unit[upload_unit], download, unit[download_unit]);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LogData{
    date: DateTime<Utc>,
    user: String,
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
    //let re = Regex::new(r#"^\[INFO\]  (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) user (\w{56}) from (\d+\.\d+\.\d+\.\d+):\d+ tunneling to ([a-zA-Z.0-9-]+):443 closed sent: ([\d.]+ [KMGP]?i?B) recv: ([\d.]+ [KMGP]?i?B)$"#).unwrap(); //this regexp expression will matchall logs that has bandwidth info.
    let mut buf_dict = HashMap::<String,LogGroup>::new();
    let mut last_date = chrono::MAX_DATETIME;//Matching domains asserts that domain is valid
    for line in reader.lines() {
        //TODO: Redirect warn messages to a separate file
        //filter [WARN] messages, they might contain non utf_8 characters
        if line.is_err() { continue; }//instead of continue, get the binary data to WARNING log first
        let line_str = line.unwrap();
        assert!(line_str.is_ascii());
        if line_str.as_bytes()[28..32] == *b"user"{ //流量数据
            let (date_str, remaining_str) = line_str.split_at(27);
            let mut date = Utc
                .datetime_from_str(date_str.split_at(7).1, "%Y/%m/%d %H:%M:%S")
                .unwrap();
            let (user_str, remaining_str) = remaining_str.split_at(62);
            let user = user_str.split_at(6).1.to_string();
            let remaining_vec: Vec<&str> = remaining_str.split(' ').collect();
            let ip = (remaining_vec[2].split_once(':').unwrap().0).parse::<Ipv4Addr>().unwrap();
            let mut target = (remaining_vec[5].split_once(':').unwrap().0).to_string();
            let size = (calculate_size(remaining_vec[8], remaining_vec[9]), calculate_size(remaining_vec[11], remaining_vec[12]));

            date = merge_date(date);
            target = group_domain(&target);
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

        }else if line_str.starts_with("[WARNING"){ //WARNING
            // add line to warning log
            continue; //TODO: WARNING LOG redirection
        }else{
            continue; //ignore other logs
        }
        // let mut log_line = LogData{
        //     date,
        //     user,
        //     ip,
        //     target,
        //     size
        // };

    }
    Ok(())
}

fn group_domain(raw: &str) -> String {
    if raw.ends_with("126.net")
    || raw.ends_with("163.com")
    || raw.ends_with("netease.com"){
        return "netease".to_string();
    }
    if raw.ends_with("bilibili.com"){
        return "bilibili".to_string();
    }
    raw.to_string()
}

fn calculate_size(raw: &str, unit: &str) -> u64{
    (raw.parse::<f64>().unwrap() * (match unit{
        "B" => 1,
        "KiB" => 1024,
        "MiB" => 1_048_576,
        "GiB" => 1_073_741_824,
        //"PiB" => 1_125_899_906_842_624, impossible
        _ => 0
    } as f64) ) as u64
}