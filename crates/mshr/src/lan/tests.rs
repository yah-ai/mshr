use std::time::Duration;

use iroh::address_lookup::EndpointData;
use iroh::{SecretKey, TransportAddr};

use super::*;

/// An unscoped record, as the public scope advertises it.
fn public(data: EndpointData) -> Record {
    Record { data, scope: None }
}

fn scoped(data: EndpointData, scope: &str) -> Record {
    Record {
        data,
        scope: Some(scope.to_string()),
    }
}

fn endpoint_data(addrs: &[&str]) -> EndpointData {
    let mut data = EndpointData::from(
        addrs
            .iter()
            .map(|a| a.parse::<SocketAddr>().unwrap())
            .collect::<BTreeSet<_>>(),
    );
    data.add_relay_url("https://relay.example.org./".parse().unwrap());
    data.set_user_data(Some("society:v1".parse().unwrap()));
    data
}

#[test]
fn instance_name_round_trips_and_fits_a_label() {
    let id = SecretKey::generate().public();
    let name = instance_name(&id);
    assert_eq!(name.len(), 52);
    assert!(name.len() <= 63);
    assert_eq!(parse_instance(&name), Some(id));
    assert_eq!(parse_instance(&format!("{name}._mshr._udp.local.")), Some(id));
    assert_eq!(parse_instance("printer"), None);
}

#[test]
fn advert_round_trips_through_txt() {
    let id = SecretKey::generate().public();
    let data = endpoint_data(&["[fe80::1]:6000", "192.168.1.20:5000", "10.0.0.2:5000"]);
    let advert = Advert::new(&id, &data, None).expect("has addrs");
    // v4 first: the SRV port is the v4 socket's.
    assert_eq!(advert.port, 5000);
    assert_eq!(advert.ips.len(), 3);
    let decoded =
        decode_txt(advert.txt.iter().map(|(k, v)| (k.as_str(), v.as_str()))).expect("decodes");
    assert_eq!(decoded, public(data));
}

#[test]
fn advert_skips_unspecified_and_relay_only() {
    let id = SecretKey::generate().public();
    assert!(Advert::new(&id, &endpoint_data(&["0.0.0.0:5000"]), None).is_none());
    let relay_only = EndpointData::from_iter([TransportAddr::Relay(
        "https://relay.example.org./".parse().unwrap(),
    )]);
    assert!(Advert::new(&id, &relay_only, None).is_none());
}

#[test]
fn decode_ignores_strangers() {
    assert!(decode_txt([("txtvers", "1"), ("a", "1.2.3.4:5"), ("ax", "1.2.3.4:5")]).is_none());
    assert!(decode_txt([("a0", "not an addr")]).is_none());
}

#[cfg(target_vendor = "apple")]
#[test]
fn txt_wire_round_trips() {
    let pairs = vec![
        ("a0".to_string(), "1.2.3.4:5".to_string()),
        ("user-data".to_string(), "x=y".to_string()),
    ];
    let wire = dnssd::encode_txt(&pairs);
    assert_eq!(wire[0] as usize, "a0=1.2.3.4:5".len());
    assert_eq!(dnssd::decode_txt_wire(&wire), pairs);
    // Value-less key, and a truncated trailing string.
    assert_eq!(
        dnssd::decode_txt_wire(b"\x04flag\x09a0=1"),
        vec![("flag".to_string(), String::new())]
    );
}

/// Poll `book` until it holds `id`, or give up.
async fn wait_for(book: &Book, id: &EndpointId) -> Option<EndpointData> {
    for _ in 0..100 {
        if let Some(d) = book.get(id) {
            return Some(d);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Loopback addresses keep these tests off the real LAN's interfaces'
/// reachability while still exercising the full register/browse/resolve
/// path through each responder.
fn test_pair() -> (EndpointId, EndpointData) {
    let id = SecretKey::generate().public();
    (id, endpoint_data(&["127.0.0.1:41641"]))
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live mDNSResponder; run with --ignored"]
async fn dnssd_to_dnssd() {
    let (a_id, a_data) = test_pair();
    let b = Book::new(SecretKey::generate().public());
    let a = dnssd::Backend::spawn(Book::new(a_id)).unwrap();
    let _b_backend = dnssd::Backend::spawn(b.clone()).unwrap();
    a.advertise(Advert::new(&a_id, &a_data, None));
    assert_eq!(wait_for(&b, &a_id).await, Some(a_data));
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live mDNSResponder + mdns-sd on 5353; run with --ignored"]
async fn dnssd_advert_seen_by_mdns_sd() {
    let (a_id, a_data) = test_pair();
    let b = Book::new(SecretKey::generate().public());
    let a = dnssd::Backend::spawn(Book::new(a_id)).unwrap();
    let _b_backend = mdns::Backend::spawn(b.clone()).unwrap();
    a.advertise(Advert::new(&a_id, &a_data, None));
    assert_eq!(wait_for(&b, &a_id).await, Some(a_data));
}

#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live mDNSResponder + mdns-sd on 5353; run with --ignored"]
async fn mdns_sd_advert_seen_by_dnssd() {
    let (a_id, a_data) = test_pair();
    let b = Book::new(SecretKey::generate().public());
    let a = mdns::Backend::spawn(Book::new(a_id)).unwrap();
    let _b_backend = dnssd::Backend::spawn(b.clone()).unwrap();
    a.advertise(Advert::new(&a_id, &a_data, None));
    assert_eq!(wait_for(&b, &a_id).await, Some(a_data));
}

/// Withdrawal propagates: the peer drops out of the other side's book.
#[cfg(target_vendor = "apple")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live mDNSResponder; run with --ignored"]
async fn dnssd_withdraw_is_seen() {
    let (a_id, a_data) = test_pair();
    let b = Book::new(SecretKey::generate().public());
    let a = dnssd::Backend::spawn(Book::new(a_id)).unwrap();
    let _b_backend = dnssd::Backend::spawn(b.clone()).unwrap();
    a.advertise(Advert::new(&a_id, &a_data, None));
    assert!(wait_for(&b, &a_id).await.is_some());
    drop(a);
    for _ in 0..100 {
        if b.get(&a_id).is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("withdrawn peer still in book");
}

async fn next_sighting(rx: &mut LanSightingsReceiver) -> LanSighting {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("sighting within 10s")
}

/// Subscribe replays the current peers, then streams changes; our own id
/// never shows up.
#[tokio::test]
async fn sightings_snapshot_then_changes() {
    let own = SecretKey::generate().public();
    let sightings = LanSightings::new();
    sightings.book.bind(own).unwrap();
    let (a, a_data) = test_pair();
    let (b, b_data) = test_pair();
    sightings.book.found(a, public(a_data.clone()));
    let mut rx = sightings.subscribe();
    sightings.book.found(own, public(a_data.clone()));
    sightings.book.found(b, public(b_data.clone()));
    // Identical re-announce: no event.
    sightings.book.found(b, public(b_data.clone()));
    sightings.book.lost(a);
    assert_eq!(
        next_sighting(&mut rx).await,
        LanSighting::Found(EndpointInfo::from_parts(a, a_data))
    );
    assert_eq!(
        next_sighting(&mut rx).await,
        LanSighting::Found(EndpointInfo::from_parts(b, b_data.clone()))
    );
    assert_eq!(next_sighting(&mut rx).await, LanSighting::Lost(a));
    assert_eq!(sightings.peers(), vec![EndpointInfo::from_parts(b, b_data)]);
}

/// A receiver that lags past the channel capacity is resynced, and still
/// learns about a peer that left while it was behind.
#[tokio::test]
async fn sightings_resync_after_lag_keeps_departures() {
    let sightings = LanSightings::new();
    sightings.book.bind(SecretKey::generate().public()).unwrap();
    let (gone, gone_data) = test_pair();
    sightings.book.found(gone, public(gone_data));
    let mut rx = sightings.subscribe();
    assert!(matches!(next_sighting(&mut rx).await, LanSighting::Found(i) if i.endpoint_id == gone));
    sightings.book.lost(gone);
    let mut stayed = Vec::new();
    for _ in 0..SIGHTINGS_CAPACITY + 8 {
        let (id, data) = test_pair();
        sightings.book.found(id, public(data));
        stayed.push(id);
    }
    let mut lost = Vec::new();
    let mut found = HashSet::new();
    while found.len() < stayed.len() {
        match next_sighting(&mut rx).await {
            LanSighting::Found(i) => {
                found.insert(i.endpoint_id);
            }
            LanSighting::Lost(id) => lost.push(id),
        }
    }
    assert_eq!(lost, vec![gone]);
    assert_eq!(found, stayed.into_iter().collect());
}

#[test]
fn lan_scope_is_validated() {
    assert!(LanScope::new("").is_err());
    assert!(LanScope::new("x".repeat(LanScope::MAX_LEN + 1)).is_err());
    assert!(LanScope::new("a\nb").is_err());
    let longest = LanScope::new("x".repeat(LanScope::MAX_LEN)).unwrap();
    // The longest scope still survives the advert's TXT size cut.
    let id = SecretKey::generate().public();
    let advert = Advert::new(&id, &endpoint_data(&["10.0.0.2:5000"]), Some(&longest)).unwrap();
    let decoded = decode_txt(advert.txt.iter().map(|(k, v)| (k.as_str(), v.as_str()))).unwrap();
    assert_eq!(decoded.scope.as_deref(), Some(longest.as_str()));
}

/// A scoped book keeps exactly its own scope; the public book keeps only
/// the unscoped. A peer that moves out of our scope is a departure.
#[tokio::test]
async fn sightings_are_filtered_by_exact_scope() {
    let band = LanScope::new("nt-run-1").unwrap();
    let scoped_book = LanSightings::new();
    scoped_book.book.bind(SecretKey::generate().public()).unwrap();
    scoped_book.set_scope(Some(band.clone()));
    let public_book = LanSightings::new();
    public_book.book.bind(SecretKey::generate().public()).unwrap();
    let mut rx = scoped_book.subscribe();

    let (mate, mate_data) = test_pair();
    let (stranger, stranger_data) = test_pair();
    let (open, open_data) = test_pair();
    for book in [&scoped_book.book, &public_book.book] {
        book.found(mate, scoped(mate_data.clone(), "nt-run-1"));
        book.found(stranger, scoped(stranger_data.clone(), "nt-run-2"));
        // Exact match: no case folding, no prefix match.
        book.found(stranger, scoped(stranger_data.clone(), "NT-RUN-1"));
        book.found(stranger, scoped(stranger_data.clone(), "nt-run-10"));
        book.found(open, public(open_data.clone()));
    }
    let ids = |s: &LanSightings| s.peers().into_iter().map(|p| p.endpoint_id).collect::<HashSet<_>>();
    assert_eq!(ids(&scoped_book), HashSet::from([mate]));
    assert_eq!(ids(&public_book), HashSet::from([open]));

    // The mate leaves our scope by re-announcing under another one.
    scoped_book.book.found(mate, scoped(mate_data.clone(), "nt-run-2"));
    assert_eq!(
        next_sighting(&mut rx).await,
        LanSighting::Found(EndpointInfo::from_parts(mate, mate_data))
    );
    assert_eq!(next_sighting(&mut rx).await, LanSighting::Lost(mate));
    assert!(scoped_book.peers().is_empty());
}

/// A live scope change re-filters what the lane already heard: a peer
/// advertising in the new scope is found at once, without waiting for its
/// next announcement, and one left behind is lost.
#[tokio::test]
async fn a_scope_change_refilters_what_was_already_heard() {
    let sightings = LanSightings::new();
    sightings.book.bind(SecretKey::generate().public()).unwrap();
    let (open, open_data) = test_pair();
    let (mate, mate_data) = test_pair();
    sightings.book.found(open, public(open_data.clone()));
    sightings.book.found(mate, scoped(mate_data.clone(), "band"));
    let mut rx = sightings.subscribe();
    assert_eq!(
        next_sighting(&mut rx).await,
        LanSighting::Found(EndpointInfo::from_parts(open, open_data.clone()))
    );

    sightings.set_scope(Some(LanScope::new("band").unwrap()));
    assert_eq!(next_sighting(&mut rx).await, LanSighting::Lost(open));
    assert_eq!(
        next_sighting(&mut rx).await,
        LanSighting::Found(EndpointInfo::from_parts(mate, mate_data))
    );
    assert_eq!(sightings.scope().as_ref().map(LanScope::as_str), Some("band"));

    // Setting the same scope again is not a change.
    sightings.set_scope(Some(LanScope::new("band").unwrap()));
    // Back to public: the mate is lost and the open peer found again.
    sightings.set_scope(None);
    assert_eq!(next_sighting(&mut rx).await, LanSighting::Lost(mate));
    assert_eq!(
        next_sighting(&mut rx).await,
        LanSighting::Found(EndpointInfo::from_parts(open, open_data))
    );
}

#[test]
fn sightings_serve_one_endpoint() {
    let sightings = LanSightings::new();
    let a = SecretKey::generate().public();
    sightings.book.bind(a).unwrap();
    assert!(sightings.book.bind(a).is_ok());
    assert_eq!(sightings.book.bind(SecretKey::generate().public()), Err(a));
}

/// Two full LanLookups over the platform backend: the subscriber sees the
/// other advertise (found) and withdraw on drop (lost).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live mDNS responder; run with --ignored"]
async fn lan_lookup_sightings_found_then_lost() {
    let (a_id, a_data) = test_pair();
    let sightings = LanSightings::new();
    let mut rx = sightings.subscribe();
    let _b = LanLookup::spawn_with(SecretKey::generate().public(), &sightings).unwrap();
    let a = LanLookup::spawn(a_id).unwrap();
    a.publish(&a_data);
    loop {
        if let LanSighting::Found(info) = next_sighting(&mut rx).await {
            if info.endpoint_id == a_id {
                assert_eq!(info.data, a_data);
                break;
            }
        }
    }
    drop(a);
    loop {
        if next_sighting(&mut rx).await == LanSighting::Lost(a_id) {
            break;
        }
    }
}

/// Two scoped LanLookups on the live backend: same scope finds, a
/// different scope and the public scope stay invisible.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live mDNS responder; run with --ignored"]
async fn lan_lookup_scopes_partition_the_lan() {
    let scoped = |s: &str| {
        let sightings = LanSightings::new();
        sightings.set_scope(Some(LanScope::new(s).unwrap()));
        sightings
    };
    let (mate_id, mate_data) = test_pair();
    let (other_id, other_data) = test_pair();
    let (open_id, open_data) = test_pair();
    let sightings = scoped("room-a");
    let mut rx = sightings.subscribe();
    let _me = LanLookup::spawn_with(SecretKey::generate().public(), &sightings).unwrap();
    let other = LanLookup::spawn_with(other_id, &scoped("room-b")).unwrap();
    other.publish(&other_data);
    let open = LanLookup::spawn(open_id).unwrap();
    open.publish(&open_data);
    // Published last, so by the time it is seen the others have had their
    // chance to leak in.
    tokio::time::sleep(Duration::from_secs(2)).await;
    // The mate starts public and moves into room-a live: its re-advert
    // under the new scope is what we find.
    let mate_sightings = LanSightings::new();
    let mate = LanLookup::spawn_with(mate_id, &mate_sightings).unwrap();
    mate.publish(&mate_data);
    tokio::time::sleep(Duration::from_millis(500)).await;
    mate_sightings.set_scope(Some(LanScope::new("room-a").unwrap()));
    loop {
        match next_sighting(&mut rx).await {
            LanSighting::Found(info) if info.endpoint_id == mate_id => break,
            LanSighting::Found(info) => panic!("saw {} outside our scope", info.endpoint_id),
            LanSighting::Lost(_) => {}
        }
    }
    let seen: Vec<_> = sightings.peers().into_iter().map(|p| p.endpoint_id).collect();
    assert_eq!(seen, vec![mate_id]);
}

/// The iroh-facing surface: a resolve started before the peer appears
/// yields it once it does.
#[tokio::test(flavor = "multi_thread")]
async fn resolve_yields_late_arrival() {
    use std::future::poll_fn;
    let book = Book::new(SecretKey::generate().public());
    let (id, data) = test_pair();
    let mut stream = Resolving {
        rx: book.subscribe(id),
        deadline: None,
    };
    let book2 = book.clone();
    let data2 = data.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        book2.found(id, public(data2));
    });
    let item = poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))
        .await
        .expect("item")
        .expect("ok");
    assert_eq!(item.endpoint_id(), id);
    assert_eq!(item.endpoint_info().data, data);
}
