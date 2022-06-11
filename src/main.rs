use chrono::prelude::*;
use chrono::Duration;
use mysql::prelude::*;
use mysql::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::{fmt, result};
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::Ipv4Addr;
use uuid::Uuid;
use std::env;

//const LOG_LOCATION: &str = "/root/trojan.log.1";
//const LOG_LOCATION: &str = "/Users/xinyuye/github/rust-rotate/trojan.log.1";
//const LOG_LOCATION: &str = "/home/xinyu/github/rust-rotate/trojan.log.1";

const MERGE_INTERVAL: u32 = 600; //Logs are regrouped into 10min blocks

#[tokio::main]
async fn main() -> core::result::Result<(), Box<dyn std::error::Error + Sync + Send + 'static>> {
    let args: Vec<String> = env::args().collect();
    let service_node = &args[1];
    let LOG_LOCATION:String = format!("/root/trojan-logs/{}/trojan.log",service_node);
    let my_client = MyClient::new().await?;
    let table = my_client.get_users().await?;
    process_file(&table, LOG_LOCATION.as_str(), service_node).unwrap();

    //println!("{}", get_public_ip().await?);
    Ok(())
}

struct MyClient {
    dynamodb_client: aws_sdk_dynamodb::Client,
    route53_client: aws_sdk_route53::Client,
}

use aws_config::meta::region::RegionProviderChain;
use aws_types::region::Region;

use sha2::{Digest, Sha224};

const DYNAMODB_REGION: &str = "ap-northeast-1";
const DYNAMODB_TABLE_NAME: &str = "vpn-clients";

impl MyClient {
    pub async fn new() -> core::result::Result<Self, Box<dyn std::error::Error + Sync + Send + 'static>> {
        //let region_provider = RegionProviderChain::first_try(Region::new("ap-northeast-1"));
        let region_provider = DYNAMODB_REGION;
        let shared_config = aws_config::from_env().region(region_provider).load().await;
        //check for error in config file
        //or override config directly in the above code
        //assert_eq!(...)
        //println!("{:?}", shared_config);
        Ok(MyClient {
            dynamodb_client: aws_sdk_dynamodb::Client::new(&shared_config),
            route53_client: aws_sdk_route53::Client::new(&shared_config),
        })
    }

    pub async fn get_users(
        &self,
    ) -> core::result::Result<
        HashMap<GenericArray<u8,generic_array::typenum::U28>, (Uuid, String)>,
        Box<dyn std::error::Error + Sync + Send + 'static>,
    > {
        // let resp = self.dynamodb_client.list_tables().send().await?;
        // println!("tables:{:?}", resp.table_names);
        // while resp.last_evaluated_table_name.is_some(){
        //   println!("tables:{:?}", resp.table_names);
        // }
        // //println!("lasteval {}", resp.last_evaluated_table_name.is_some());
        let mut ret: HashMap<_, _> = HashMap::new();

        //scan the table until last_evaluated_key is none
        let mut resp = self
            .dynamodb_client
            .scan()
            .table_name(DYNAMODB_TABLE_NAME)
            .send()
            .await?;
        loop{
            for i in resp.items.unwrap() {
                let username = i.get("username").unwrap().as_s().unwrap().to_owned();
                let uuid = Uuid::parse_str(i.get("password").unwrap().as_s().unwrap())?;
                //let hash = cal_sha224(uuid);
                let hash = cal_sha224(i.get("password").unwrap().as_s().unwrap().as_str());
                ret.insert(hash, (uuid, username));
            }
            if resp.last_evaluated_key.is_none() { break; }
            resp = self
                .dynamodb_client
                .scan()
                .table_name(DYNAMODB_TABLE_NAME)
                .set_exclusive_start_key(resp.last_evaluated_key)
                .send()
                .await?;
        }

        println!("{:x?}", ret);
        Ok(ret)
    }
}
use sha2::digest::generic_array::GenericArray;
//calculate sha224 just like how trojan-go does
//trojan-go calculates sha224 with string characters, not bytes of uuid
fn cal_sha224(data: &str) -> GenericArray<u8, generic_array::typenum::U28> {
    let mut hasher = Sha224::new();
    hasher.update(data.as_bytes());
    hasher.finalize()
}

fn generic_to_str(hash_arr: &GenericArray<u8,generic_array::typenum::U28>) -> String{
    let mut ret = String::new();
    for b in hash_arr.iter(){
        ret.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        ret.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    ret
}

fn convert_hash(hash_str: &str) -> GenericArray<u8, generic_array::typenum::U28> {
    let mut ret_arr = [0_u8; 28];
    let mut c = hash_str.chars();
    for i in 0..28{
        ret_arr[i] = (c.next().unwrap().to_digit(16).unwrap() << 4) as u8 | (c.next().unwrap().to_digit(16).unwrap()) as u8;
    }
    GenericArray::clone_from_slice(&ret_arr)
}

struct LogGroup {
    date: DateTime<Utc>,
    ips: HashSet<Ipv4Addr>,
    targets: HashMap<String, (u64, u64)>,
}

impl fmt::Debug for LogGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\ndate: {}, ips: {:?}\n", self.date, self.ips);
        let mut links: Vec<&String> = self.targets.keys().collect();
        links.sort_by_key(|&x| self.targets.get(x).unwrap().0);
        links.reverse();
        for i in links {
            let unit: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
            let mut upload_unit = 0_usize;
            let mut upload = self.targets.get(i).unwrap().0 as f64;
            while upload >= 1024.0 {
                upload_unit += 1;
                upload /= 1024.0;
            }
            let mut download = self.targets.get(i).unwrap().1 as f64;
            let mut download_unit = 0_usize;
            while download >= 1024.0 {
                download_unit += 1;
                download /= 1024.0;
            }
            let mut temp_str = i.to_string();
            temp_str.truncate(19);
            temp_str.push(':');
            write!(
                f,
                "{:<20} up {:>6.2} {}, down {:>6.2} {}\n",
                temp_str, upload, unit[upload_unit], download, unit[download_unit]
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
struct LogData {
    date: DateTime<Utc>,
    user: String,
    ip: Ipv4Addr,
    target: String,
    size: (u64, u64),
}

fn merge_date(mut date: DateTime<Utc>) -> DateTime<Utc> {
    date = date
        .checked_sub_signed(Duration::nanoseconds(date.timestamp_subsec_nanos() as i64))
        .unwrap(); //returns NaiveTime.frac
    date = date
        .checked_sub_signed(Duration::seconds(date.timestamp() % MERGE_INTERVAL as i64))
        .unwrap(); //returns NaiveTime.secs
    date
}

const MYSQL_URL: &str = "mysql://xinyu:Xiaoyao@localhost:3306/vpn_manager";
fn process_file(user_table: &HashMap<GenericArray<u8,generic_array::typenum::U28>, (Uuid, String)>, log_location: &str, service_node: &str) -> core::result::Result<(), Box<dyn std::error::Error + Sync + Send + 'static> > {
    let f = File::open(log_location)?;
    let reader = BufReader::new(f);
    let mut counter = 0_u32;
    //let re = Regex::new(r#"^\[INFO\]  (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) user (\w{56}) from (\d+\.\d+\.\d+\.\d+):\d+ tunneling to ([a-zA-Z.0-9-]+):443 closed sent: ([\d.]+ [KMGP]?i?B) recv: ([\d.]+ [KMGP]?i?B)$"#).unwrap(); //this regexp expression will matchall logs that has bandwidth info.
    let mut buf_dict = HashMap::<String, LogGroup>::new();
    let mut last_date = chrono::MAX_DATETIME; //Matching domains asserts that domain is valid
    let mysql_pool = Pool::new(mysql::Opts::from_url(MYSQL_URL).unwrap())?;
    let mut conn = mysql_pool.get_conn()?;
    for line in reader.lines() {
        //TODO: Redirect warn messages to a separate file
        //filter [WARN] messages, they might contain non utf_8 characters
        if line.is_err() {
            continue;
        } //instead of continue, get the binary data to WARNING log first
        let line_str = line.unwrap();
        assert!(line_str.is_ascii());
        if line_str.as_bytes()[28..32] == *b"user" {
            //流量数据
            let (date_str, remaining_str) = line_str.split_at(27);
            let mut date = Utc
                .datetime_from_str(date_str.split_at(7).1, "%Y/%m/%d %H:%M:%S")
                .unwrap();
            let (user_str, remaining_str) = remaining_str.split_at(62);
            let user = user_str.split_at(6).1.to_string();
            let remaining_vec: Vec<&str> = remaining_str.split(' ').collect();
            let ip = (remaining_vec[2].split_once(':').unwrap().0)
                .parse::<Ipv4Addr>()
                .unwrap();
            let mut target = (remaining_vec[5].split_once(':').unwrap().0).to_string();
            let size = (
                calculate_size(remaining_vec[8], remaining_vec[9]),
                calculate_size(remaining_vec[11], remaining_vec[12]),
            );

            date = merge_date(date);
            target = group_domain(&target);
            //add log to dict
            if date != last_date {
                //dump all records in dict, create new one
                for (user, log_group) in buf_dict.iter(){
                    let uuid = user_table.get(&convert_hash(user.as_str())).unwrap().0.to_string();
                    let username = user_table.get(&convert_hash(user.as_str())).unwrap().1.to_string();
                    conn.exec_batch(
                        r"INSERT INTO testing (logtime, username, uuid, target, up, down, ips, service_node) VALUES (:logtime, :username, :uuid, :target, :up, :down, :ips, :service_node)",
                        log_group.targets.iter().map(|(dest, (up, down))| params!{
                            "logtime" => log_group.date.format(r"%Y-%m-%d %H:%M:%S").to_string(), //mysql::Value doesn't implement 'From<chrono::Datetime<chrono::Utc>>'
                            "username" => &username,
                            "uuid" => &uuid,
                            "target" => dest,
                            "up" => up,
                            "down" => down,
                            "ips" => log_group.ips.iter().map(|ip| format!("{:?}", ip)).collect::<Vec<_>>().join(", "),
                            "service_node" => service_node
                        })
                    )?;
                    println!("Finished {:?}", log_group);
                }
                buf_dict.clear();
                last_date = date;
            }
            if buf_dict.contains_key(&user) {
                let proc: &mut LogGroup = buf_dict.get_mut(&user).unwrap();
                proc.ips.insert(ip);
                proc.targets
                    .entry(target)
                    .and_modify(|x| {
                        x.0 += size.0;
                        x.1 += size.1;
                    })
                    .or_insert(size);
            } else {
                buf_dict.insert(
                    user,
                    LogGroup {
                        date,
                        ips: {
                            let mut tmp = HashSet::new();
                            tmp.insert(ip);
                            tmp
                        },
                        targets: {
                            let mut tmp = HashMap::new();
                            tmp.insert(target, size);
                            tmp
                        },
                    },
                );
            }
        } else if line_str.starts_with("[WARNING") {
            //WARNING
            // add line to warning log
            continue; //TODO: WARNING LOG redirection
        } else {
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
    if raw.ends_with("126.net") || raw.ends_with("163.com") || raw.ends_with("netease.com") {
        return "netease".to_string();
    }
    if raw.ends_with("bilibili.com") {
        return "bilibili".to_string();
    }
    raw.to_string()
}

fn calculate_size(raw: &str, unit: &str) -> u64 {
    (raw.parse::<f64>().unwrap()
        * (match unit {
            "B" => 1,
            "KiB" => 1024,
            "MiB" => 1_048_576,
            "GiB" => 1_073_741_824,
            //"PiB" => 1_125_899_906_842_624, impossible
            _ => 0,
        } as f64)) as u64
}

