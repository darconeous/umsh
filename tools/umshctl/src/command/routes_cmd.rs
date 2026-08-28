//! `routes`: what this tool has learned about reaching other nodes.
//!
//! Reads the cache file rather than a radio, so it answers with nothing
//! attached — which is the state you are in when you want to know why
//! last night's `manage` took the path it did.

use anyhow::Result;

use crate::command::{format_duration, values::KeyArg};
use crate::output::{field, note, subfield};
use crate::routes::{ROUTE_TTL, RouteCache};

#[derive(Debug, clap::Subcommand)]
pub enum RoutesOp {
    /// The route remembered for one node.
    Show {
        #[arg(value_name = "KEY")]
        key: KeyArg,
    },
    /// Forget remembered routes, all of them or one node's.
    ///
    /// The next command to that node rediscovers the path, so this costs
    /// one flood and is the right answer when a repeater has moved.
    Clear {
        #[arg(value_name = "KEY")]
        key: Option<KeyArg>,
    },
}

pub fn run(op: Option<RoutesOp>) -> Result<()> {
    let mut cache = RouteCache::load();
    match op {
        None => list(&cache),
        Some(RoutesOp::Show { key }) => show(&cache, umsh::core::PublicKey(key.0)),
        Some(RoutesOp::Clear { key: Some(key) }) => {
            let key = umsh::core::PublicKey(key.0);
            if cache.remove(&key) {
                println!("forgot the route to {key}");
            } else {
                println!("no route was remembered for {key}");
            }
            cache.store()
        }
        Some(RoutesOp::Clear { key: None }) => {
            match cache.clear() {
                0 => println!("no routes were remembered"),
                1 => println!("forgot 1 route"),
                count => println!("forgot {count} routes"),
            }
            cache.store()
        }
    }
}

fn list(cache: &RouteCache) -> Result<()> {
    if cache.is_empty() {
        println!("no routes remembered");
        note("a route is learned from a reply, and remembered for a day");
        return Ok(());
    }
    // A key is 44 characters, which is wider than any value column, so
    // it heads its own entry rather than sharing a line with one.
    for (key, record) in cache.iter() {
        println!("{key}");
        subfield("route", crate::routes::describe(&record.route));
        subfield("learned", ago(record.age()));
        subfield("expires", within(record.age()));
    }
    Ok(())
}

fn show(cache: &RouteCache, key: umsh::core::PublicKey) -> Result<()> {
    let Some(record) = cache.get(&key) else {
        println!("no route remembered for {key}");
        note("the next command to it discovers one, and this remembers it");
        return Ok(());
    };
    println!("{key}");
    field("route", crate::routes::describe(&record.route));
    field("learned", ago(record.age()));
    field("expires", within(record.age()));
    Ok(())
}

fn ago(age: std::time::Duration) -> String {
    format!(
        "{} ago",
        format_duration(age.as_secs().min(u32::MAX.into()) as u32)
    )
}

fn within(age: std::time::Duration) -> String {
    match ROUTE_TTL.checked_sub(age) {
        Some(left) => format!("in {}", format_duration(left.as_secs() as u32)),
        None => "now".to_string(),
    }
}
