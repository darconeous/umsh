//! Routes remembered between invocations.
//!
//! The MAC learns a route from inbound traffic and keeps it in the peer
//! registry, which lives exactly as long as the `Mac` does — and this
//! tool builds a new one for every command. Without somewhere to put
//! them, two `manage` calls a second apart each flood the mesh to
//! discover the same path.
//!
//! So each session hands its learned routes to a file, and the next one
//! puts them back before it says anything. A route is a hint, not a
//! promise: a stale one costs a single failed exchange, after which the
//! MAC's own ack-timeout retry rediscovers the path and overwrites it.
//! That is why the file can be lost, truncated, or edited by hand
//! without breaking anything.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};

use umsh::core::{PublicKey, RouterHint};
use umsh::hal::Radio;
use umsh::mac::CachedRoute;

use crate::connection;

/// How long a remembered route is worth trying.
///
/// A day, because the meshes this tool works on are mostly repeaters
/// bolted to buildings, and a path good this morning is usually good
/// tonight. The cost of being wrong is one exchange, so there is no case
/// for expiring sooner and none for asking the user to tune it.
pub const ROUTE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// The file's first line, so a future format can be told apart from this
/// one without guessing.
const HEADER: &str = "# umshctl learned routes v1";

/// One remembered route and when it was learned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteRecord {
    pub route: CachedRoute,
    pub learned_at: SystemTime,
}

impl RouteRecord {
    /// How long ago this route was learned. Zero for a record stamped in
    /// the future, which a clock change can produce.
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.learned_at)
            .unwrap_or_default()
    }

    pub fn expired(&self) -> bool {
        self.age() >= ROUTE_TTL
    }
}

/// Every route this tool remembers.
#[derive(Debug, Default)]
pub struct RouteCache {
    entries: HashMap<[u8; 32], RouteRecord>,
    /// Keys this session deliberately forgot. Kept so that a merge with
    /// whatever another invocation wrote does not quietly put them back:
    /// forgetting is something somebody asked for, and it should not
    /// depend on who writes last.
    forgotten: Vec<[u8; 32]>,
    dirty: bool,
}

impl RouteCache {
    /// Read the remembered routes, dropping whatever has expired.
    ///
    /// A missing file is an empty cache, and so is an unreadable or
    /// malformed one: this is a cache, and refusing to run because it
    /// cannot be parsed would trade a slow command for no command.
    pub fn load() -> Self {
        let Some(path) = connection::routes_path() else {
            return Self::default();
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        let mut cache = Self::parse(&text);
        // Expiry is enforced on the way in, so nothing downstream has to
        // remember to ask.
        cache.entries.retain(|_, record| !record.expired());
        cache
    }

    fn parse(text: &str) -> Self {
        let mut entries = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // One unreadable line loses one route, not the file.
            if let Some((key, record)) = parse_line(line) {
                entries.insert(key, record);
            }
        }
        Self {
            entries,
            forgotten: Vec::new(),
            dirty: false,
        }
    }

    /// The route remembered for `peer`, if it has not expired.
    pub fn get(&self, peer: &PublicKey) -> Option<&RouteRecord> {
        self.entries.get(&peer.0).filter(|record| !record.expired())
    }

    /// Remember `route` for `peer`, stamped now.
    ///
    /// A route identical to the one already held keeps its original
    /// timestamp: the age is meant to say when the path was learned, not
    /// when it was last written down.
    pub fn record(&mut self, peer: &PublicKey, route: CachedRoute) {
        if let Some(existing) = self.entries.get(&peer.0)
            && existing.route == route
            && !existing.expired()
        {
            return;
        }
        self.forgotten.retain(|key| key != &peer.0);
        self.entries.insert(
            peer.0,
            RouteRecord {
                route,
                learned_at: SystemTime::now(),
            },
        );
        self.dirty = true;
    }

    /// Forget `peer`'s route, reporting whether one was held.
    pub fn remove(&mut self, peer: &PublicKey) -> bool {
        let removed = self.entries.remove(&peer.0).is_some();
        if !self.forgotten.contains(&peer.0) {
            self.forgotten.push(peer.0);
        }
        self.dirty |= removed;
        removed
    }

    /// Forget everything, reporting how many routes went.
    pub fn clear(&mut self) -> usize {
        let count = self.entries.len();
        for key in self.entries.keys() {
            if !self.forgotten.contains(key) {
                self.forgotten.push(*key);
            }
        }
        self.entries.clear();
        self.dirty |= count > 0;
        count
    }

    /// Every remembered route, newest first.
    pub fn iter(&self) -> Vec<(PublicKey, &RouteRecord)> {
        let mut all: Vec<(PublicKey, &RouteRecord)> = self
            .entries
            .iter()
            .map(|(key, record)| (PublicKey(*key), record))
            .collect();
        all.sort_by_key(|(key, record)| (std::cmp::Reverse(record.learned_at), key.0));
        all
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Copy the live MAC's routes into the cache.
    ///
    /// Only what changed is stamped, so an unchanged route keeps saying
    /// when it was learned rather than when it was last looked at.
    pub async fn harvest<R: Radio>(&mut self, handle: &crate::mesh::CtlHandle<'_, R>) {
        let mut peers = Vec::new();
        handle.for_each_peer(&mut |peer| peers.push(peer)).await;
        for peer in peers {
            match handle.peer_route(&peer).await {
                Some(route) => self.record(&peer, route),
                // A peer whose route the MAC dropped has had it
                // invalidated; keeping ours would put it straight back.
                None => {
                    self.remove(&peer);
                }
            }
        }
    }

    /// Write the cache back, merging whatever another invocation wrote
    /// while this one was running.
    ///
    /// Two shells against two radios is an ordinary way to use this
    /// tool, and last-writer-wins over the whole file would throw away
    /// the other's fresh routes. Merging by timestamp keeps the newer of
    /// each, which is the same rule the cache uses against itself.
    pub fn store(&mut self) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let Some(path) = connection::routes_path() else {
            // No state directory is not an error for a cache; the tool
            // simply forgets between runs, as it always used to.
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut merged = Self::load();
        merged
            .entries
            .retain(|key, _| !self.forgotten.contains(key));
        for (key, record) in &self.entries {
            let newer = merged
                .entries
                .get(key)
                .is_none_or(|existing| existing.learned_at <= record.learned_at);
            if newer {
                merged.entries.insert(*key, record.clone());
            }
        }
        std::fs::write(&path, merged.render())
            .with_context(|| format!("writing {}", path.display()))?;
        self.dirty = false;
        Ok(())
    }

    fn render(&self) -> String {
        let mut out = format!("{HEADER}\n");
        for (key, record) in self.iter() {
            let seconds = record
                .learned_at
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = writeln!(out, "{key} {} {seconds}", render_route(&record.route));
        }
        out
    }
}

/// A route as one field of kind and its parameters:
///
/// ```text
/// <key> direct <unix-seconds>
/// <key> source a1b2,c3d4 <unix-seconds>
/// <key> flood 5 68ac,9b21 <unix-seconds>
/// ```
///
/// A dash stands in for an empty hint or region list, so every form has
/// the same field count and a line can be read without counting.
fn render_route(route: &CachedRoute) -> String {
    match route {
        CachedRoute::Direct => "direct".to_string(),
        CachedRoute::Source(hints) => {
            format!("source {}", render_pairs(hints.iter().map(|hint| hint.0)))
        }
        CachedRoute::Flood { hops, regions } => {
            format!("flood {hops} {}", render_pairs(regions.iter().copied()))
        }
    }
}

fn render_pairs(pairs: impl Iterator<Item = [u8; 2]>) -> String {
    let rendered: Vec<String> = pairs
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect();
    if rendered.is_empty() {
        return "-".to_string();
    }
    rendered.join(",")
}

fn parse_pairs(text: &str) -> Option<Vec<[u8; 2]>> {
    if text == "-" {
        return Some(Vec::new());
    }
    text.split(',')
        .map(|pair| {
            let bytes = u16::from_str_radix(pair, 16).ok()?;
            (pair.len() == 4).then(|| bytes.to_be_bytes())
        })
        .collect()
}

fn parse_line(line: &str) -> Option<([u8; 32], RouteRecord)> {
    let mut fields = line.split_whitespace();
    let key = fields.next()?.parse::<PublicKey>().ok()?;
    let route = match fields.next()? {
        "direct" => CachedRoute::Direct,
        "source" => {
            let hints: Vec<RouterHint> = parse_pairs(fields.next()?)?
                .into_iter()
                .map(RouterHint)
                .collect();
            // A route longer than a packet can carry is not one to
            // truncate into something that goes somewhere else.
            CachedRoute::source(&hints)?
        }
        "flood" => {
            let hops = fields.next()?.parse::<u8>().ok()?;
            CachedRoute::flood(hops, &parse_pairs(fields.next()?)?)?
        }
        _ => return None,
    };
    let seconds = fields.next()?.parse::<u64>().ok()?;
    // A line with more fields than this format defines was written by
    // something else, and guessing at it would be worse than skipping it.
    if fields.next().is_some() {
        return None;
    }
    Some((
        key.0,
        RouteRecord {
            route,
            learned_at: UNIX_EPOCH + Duration::from_secs(seconds),
        },
    ))
}

/// How a route reads in a listing: what it does, not how it is encoded.
pub fn describe(route: &CachedRoute) -> String {
    match route {
        CachedRoute::Direct => "direct".to_string(),
        CachedRoute::Source(hints) if hints.is_empty() => "source route, no hops".to_string(),
        CachedRoute::Source(hints) => format!(
            "via {}",
            hints
                .iter()
                .map(|hint| format!("{:02x}{:02x}", hint.0[0], hint.0[1]))
                .collect::<Vec<_>>()
                .join(" > ")
        ),
        CachedRoute::Flood { hops, regions } if regions.is_empty() => {
            format!("flood, {hops} hops")
        }
        CachedRoute::Flood { hops, regions } => format!(
            "flood, {hops} hops, regions {}",
            regions
                .iter()
                .map(|code| umsh::core::RegionCode::from_bytes(*code).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        PublicKey([byte; 32])
    }

    fn record(route: CachedRoute, age: Duration) -> RouteRecord {
        RouteRecord {
            route,
            learned_at: SystemTime::now() - age,
        }
    }

    fn cache_of(entries: &[(PublicKey, RouteRecord)]) -> RouteCache {
        let mut cache = RouteCache::default();
        for (key, record) in entries {
            cache.entries.insert(key.0, record.clone());
        }
        cache
    }

    /// Forgetting is something somebody asked for, so a merge with
    /// another invocation's file must not put it back.
    #[test]
    fn a_forgotten_route_stays_forgotten_through_a_merge() {
        let mut cache = cache_of(&[
            (key(20), record(CachedRoute::Direct, Duration::from_secs(5))),
            (key(21), record(CachedRoute::Direct, Duration::from_secs(5))),
        ]);
        assert!(cache.remove(&key(20)));

        // What the other invocation left on disk, including the route
        // this session just forgot.
        let theirs = cache_of(&[
            (key(20), record(CachedRoute::Direct, Duration::ZERO)),
            (key(22), record(CachedRoute::Direct, Duration::ZERO)),
        ]);
        let mut merged = RouteCache::parse(&theirs.render());
        merged
            .entries
            .retain(|key, _| !cache.forgotten.contains(key));
        for (key, record) in &cache.entries {
            merged.entries.insert(*key, record.clone());
        }

        assert!(!merged.entries.contains_key(&key(20).0), "forgotten");
        assert!(merged.entries.contains_key(&key(21).0), "ours");
        assert!(merged.entries.contains_key(&key(22).0), "theirs");
    }

    /// Learning a route again after forgetting it is not a contradiction
    /// — the forget is spent.
    #[test]
    fn relearning_a_forgotten_route_un_forgets_it() {
        let mut cache = cache_of(&[(key(23), record(CachedRoute::Direct, Duration::ZERO))]);
        cache.remove(&key(23));
        assert!(cache.forgotten.contains(&key(23).0));
        cache.record(&key(23), CachedRoute::Direct);
        assert!(!cache.forgotten.contains(&key(23).0));
        assert!(cache.get(&key(23)).is_some());
    }

    #[test]
    fn every_route_shape_survives_the_round_trip() {
        let source =
            CachedRoute::source(&[RouterHint([0xA1, 0xB2]), RouterHint([0xC3, 0xD4])]).unwrap();
        let flood = CachedRoute::flood(5, &[[0x68, 0xAC], [0x9B, 0x21]]).unwrap();
        let cache = cache_of(&[
            (key(1), record(CachedRoute::Direct, Duration::from_secs(10))),
            (key(2), record(source.clone(), Duration::from_secs(20))),
            (key(3), record(flood.clone(), Duration::from_secs(30))),
        ]);

        let parsed = RouteCache::parse(&cache.render());
        assert_eq!(parsed.get(&key(1)).unwrap().route, CachedRoute::Direct);
        assert_eq!(parsed.get(&key(2)).unwrap().route, source);
        assert_eq!(parsed.get(&key(3)).unwrap().route, flood);
    }

    /// An empty hint or region list is a real state, and must not come
    /// back as a missing field or a route of a different shape.
    #[test]
    fn the_empty_forms_round_trip_as_themselves() {
        let empty_source = CachedRoute::source(&[]).unwrap();
        let plain_flood = CachedRoute::flood(3, &[]).unwrap();
        let cache = cache_of(&[
            (key(4), record(empty_source.clone(), Duration::ZERO)),
            (key(5), record(plain_flood.clone(), Duration::ZERO)),
        ]);

        let parsed = RouteCache::parse(&cache.render());
        assert_eq!(parsed.get(&key(4)).unwrap().route, empty_source);
        assert_eq!(parsed.get(&key(5)).unwrap().route, plain_flood);
    }

    #[test]
    fn an_expired_route_is_not_offered() {
        let cache = cache_of(&[
            (key(6), record(CachedRoute::Direct, Duration::from_secs(60))),
            (key(7), record(CachedRoute::Direct, ROUTE_TTL)),
        ]);
        assert!(cache.get(&key(6)).is_some());
        assert!(cache.get(&key(7)).is_none(), "a route at the TTL is spent");
    }

    /// The file is a cache somebody may have edited. One bad line costs
    /// one route.
    #[test]
    fn a_malformed_line_costs_only_itself() {
        let good = format!("{} direct 1000", key(8));
        let text = format!(
            "{HEADER}\n\
             {good}\n\
             not-a-key direct 1000\n\
             {} teleport 1000\n\
             {} source zzzz 1000\n\
             {} direct 1000 extra\n\
             \n\
             # a comment\n",
            key(9),
            key(10),
            key(11),
        );
        let parsed = RouteCache::parse(&text);
        assert_eq!(parsed.entries.len(), 1);
        assert!(parsed.entries.contains_key(&key(8).0));
    }

    /// The age is when the path was learned, not when it was last
    /// written down: an unchanged route keeps its stamp so a listing
    /// says something true about how old the path is.
    #[test]
    fn recording_the_same_route_again_does_not_refresh_its_age() {
        let mut cache = cache_of(&[(
            key(12),
            record(CachedRoute::Direct, Duration::from_secs(600)),
        )]);
        let before = cache.get(&key(12)).unwrap().learned_at;
        cache.record(&key(12), CachedRoute::Direct);
        assert_eq!(cache.get(&key(12)).unwrap().learned_at, before);
        assert!(!cache.dirty, "an unchanged route is not a reason to write");

        // A different route is news, and is stamped now.
        cache.record(&key(12), CachedRoute::flood(4, &[]).unwrap());
        assert!(cache.get(&key(12)).unwrap().learned_at > before);
        assert!(cache.dirty);
    }

    #[test]
    fn a_header_only_file_is_an_empty_cache() {
        assert!(RouteCache::parse(&format!("{HEADER}\n")).is_empty());
        assert!(RouteCache::parse("").is_empty());
    }
}
