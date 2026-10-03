//! Java owns UI, persistence and BLE. The existing mobile core owns wire semantics.
use jni::{JNIEnv, objects::{JClass, JString}, sys::jstring};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, OnceLock};
use umsh_mobile_core::*;
use umsh_mobile_core::mobile_mesh::MobileChannelRegistrationRecord;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
struct Engine {
    mesh: Arc<MobileMeshSession>,
    ulcp: Arc<MobileUlcpSession>,
    gatt: Arc<MobileGattReassembler>,
}
static ENGINE: OnceLock<Mutex<Option<Arc<Engine>>>> = OnceLock::new();
static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
fn runtime() -> &'static tokio::runtime::Runtime {
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("Tokio runtime"))
}
fn field(v: &Value, k: &str) -> Result<String> {
    Ok(v.get(k).and_then(Value::as_str).ok_or("Missing string field")?.to_owned())
}
fn bytes(v: &Value, k: &str) -> Result<Vec<u8>> { Ok(serde_json::from_value(v[k].clone())?) }
fn number(v: &Value, k: &str) -> Result<u64> { v[k].as_u64().ok_or_else(|| "Missing integer field".into()) }
fn dispatch(v: Value) -> Result<Value> {
    let op = field(&v, "op")?;
    match op.as_str() {
        "open" => {
            let identity = MobileIdentity::unlock(bytes(&v, "secret")?)?;
            let public = identity.public_identity();
            let counters = MobileCounterStore::new(field(&v, "counters")?)?;
            let mesh = runtime().block_on(MobileMeshSession::new(identity, counters))?;
            *ENGINE.get_or_init(|| Mutex::new(None)).lock().map_err(|_| "Engine lock")? = Some(Arc::new(Engine {
                mesh, ulcp: MobileUlcpSession::new(), gatt: MobileGattReassembler::new(),
            }));
            return Ok(serde_json::to_value(public)?);
        }
        "peer" => return Ok(serde_json::to_value(inspect_peer_identity(field(&v,"input")?)?)?),
        "channel" => {
            let input = field(&v,"input")?;
            let c = if input.starts_with("umsh:") { inspect_channel_uri(input)? } else { inspect_channel_name(input)? };
            let address = channel_conversation_address(c.key.clone())?;
            return Ok(json!({"preview": c, "address": address}));
        }
        "privateChannel" => {
            let key = generate_channel_key();
            return Ok(json!({"key": key, "address": channel_conversation_address(key.clone())?,
                "invitation": format_channel_invitation(key, None, Some(field(&v,"name")?), None, None)?}));
        }
        "decodeIdentity" => return Ok(serde_json::to_value(decode_node_identity(field(&v,"address")?, bytes(&v,"payload")?)?)?),
        "segments" => return Ok(serde_json::to_value(ulcp_gatt_segments(bytes(&v,"frame")?, u16::try_from(number(&v,"mtu")?)?)?)?),
        _ => {}
    }
    let e = ENGINE.get_or_init(|| Mutex::new(None)).lock().map_err(|_| "Engine lock")?.clone().ok_or("Identity is not open")?;
    let result = match op.as_str() {
        "begin" => { e.gatt.reset(); serde_json::to_value(e.ulcp.begin(Some(e.mesh.node_public_key()))?)? }
        "claim" => serde_json::to_value(e.ulcp.claim(e.mesh.node_public_key())?)?,
        "segment" => match e.gatt.push(bytes(&v,"data")?)? { Some(f) => serde_json::to_value(e.ulcp.consume(f)?)?, None => Value::Null },
        "reset" => { e.mesh.fail_outbound_transmissions()?; e.gatt.reset(); serde_json::to_value(e.ulcp.reset())? }
        "refresh" => serde_json::to_value(e.ulcp.refresh()?)?,
        "configure" => serde_json::to_value(e.ulcp.configure(serde_json::from_value(v["settings"].clone())?)?)?,
        "poll" => serde_json::to_value(e.mesh.poll_update())?,
        "receive" => { e.mesh.receive(serde_json::from_value(v["frame"].clone())?)?; Value::Null }
        "transmit" => serde_json::to_value(e.ulcp.transmit_raw(bytes(&v,"data")?, v["nocca"].as_bool().unwrap_or(false))?)?,
        "complete" => { e.mesh.complete_outbound_frame(number(&v,"id")?, v["sent"].as_bool().unwrap_or(false))?; Value::Null }
        "peers" => { runtime().block_on(e.mesh.register_peers(serde_json::from_value(v["addresses"].clone())?))?; Value::Null }
        "channels" => { let channels: Vec<MobileChannelRegistrationRecord> = serde_json::from_value(v["channels"].clone())?; runtime().block_on(e.mesh.register_channels(channels))?; Value::Null }
        "restore" => { runtime().block_on(e.mesh.restore_chat(serde_json::from_value(v["checkpoints"].clone())?))?; Value::Null }
        "compose" => serde_json::to_value(runtime().block_on(e.mesh.compose_text(field(&v,"address")?, u32::try_from(number(&v,"token")?)?, field(&v,"body")?))?)?,
        "commit" => { runtime().block_on(e.mesh.commit_chat_batch(number(&v,"batch")?))?; Value::Null }
        "reject" => { runtime().block_on(e.mesh.reject_chat_batch(number(&v,"batch")?, serde_json::from_value(v["checkpoints"].clone())?))?; Value::Null }
        "ack" => { e.mesh.acknowledge_chat_batch(number(&v,"batch")?)?; Value::Null }
        "archive" => { e.mesh.apply_chat_archive_result(u32::try_from(number(&v,"request")?)?, serde_json::from_value(v["kind"].clone())?, bytes(&v,"payload")?)?; Value::Null }
        "name" => { runtime().block_on(e.mesh.set_chat_display_name(field(&v,"name")?))?; Value::Null }
        "advertise" => { runtime().block_on(e.mesh.advertise_identity(Some(field(&v,"name")?), None))?; Value::Null }
        "discover" => { runtime().block_on(e.mesh.discover_identities(None,None,None,vec![]))?; Value::Null }
        "ping" => json!(e.mesh.ping(field(&v,"address")?, 8000)?),
        _ => return Err("Unknown operation".into()),
    };
    Ok(result)
}
fn stringify_sessions(value: &mut Value) {
    match value {
        Value::Object(map) => for (key, v) in map { if key == "session_id" { *v = Value::String(v.to_string()); } else { stringify_sessions(v); } },
        Value::Array(list) => for v in list { stringify_sessions(v); },
        _ => {}
    }
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_umsh_android_Core_call(mut env: JNIEnv, _: JClass, input: JString) -> jstring {
    // Never unwind through JNI, including invalid arguments or poisoned state.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value> {
        let text: String = env.get_string(&input)?.into();
        if text.len() > 1_048_576 { return Err("Request too large".into()); }
        dispatch(serde_json::from_str(&text)?)
    }));
    let output = match result {
        Ok(Ok(mut value)) => { stringify_sessions(&mut value); json!({"value": value}) },
        Ok(Err(err)) => json!({"error": err.to_string()}),
        Err(_) => json!({"error": "Native core failed; restart the app"}),
    };
    match env.new_string(output.to_string()) { Ok(s) => s.into_raw(), Err(_) => std::ptr::null_mut() }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn channel_and_identity_validation() {
        let a=dispatch(json!({"op":"channel","input":"PUBLIC"})).unwrap();
        let b=dispatch(json!({"op":"channel","input":"public"})).unwrap();
        assert_eq!(a["address"],b["address"]);
        assert_eq!(a["preview"]["key"].as_array().unwrap().len(),32);
        assert!(dispatch(json!({"op":"peer","input":"invalid"})).is_err());
    }
    #[test] fn gatt_round_trip() {
        let frame:Vec<u8>=(0..=255).collect();
        let segments=ulcp_gatt_segments(frame.clone(),20).unwrap();
        let receiver=MobileGattReassembler::new();
        let mut recovered=None;
        for s in segments { assert!(s.value.len()<=20); if let Some(f)=receiver.push(s.value).unwrap(){recovered=Some(f)} }
        assert_eq!(recovered,Some(frame));
    }
    #[test] fn real_mesh_round_trip_and_durable_compose_boundary() {
        runtime().block_on(async {
            let root=std::env::temp_dir().join(format!("umsh-android-test-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
            let ia=MobileIdentity::unlock(vec![21;32]).unwrap();
            let ib=MobileIdentity::unlock(vec![22;32]).unwrap();
            let aa=ia.public_identity().canonical_address;
            let ab=ib.public_identity().canonical_address;
            let a=MobileMeshSession::new(ia,MobileCounterStore::new(root.join("a").display().to_string()).unwrap()).await.unwrap();
            let b=MobileMeshSession::new(ib,MobileCounterStore::new(root.join("b").display().to_string()).unwrap()).await.unwrap();
            a.register_peers(vec![ab.clone()]).await.unwrap();b.register_peers(vec![aa]).await.unwrap();
            let batch=a.compose_text(ab,7,"Hello from Android".into()).await.unwrap();
            assert!(!batch.archives.is_empty());assert!(a.poll_update().outbound_frames.is_empty());
            a.commit_chat_batch(batch.batch_id).await.unwrap();
            let deadline=std::time::Instant::now()+std::time::Duration::from_secs(10);
            let mut received=false;let mut acknowledged=false;
            while !(received&&acknowledged) {
                for (source,dest) in [(&a,&b),(&b,&a)] {
                    let update=source.poll_update();
                    for frame in update.outbound_frames {source.complete_outbound_frame(frame.id,true).unwrap();dest.receive(MobileMeshRxRecord{data:frame.data,rssi_dbm:Some(-50),lqi:None,snr_cb:None,was_buffered:false,was_acknowledged:false,age_seconds:0}).unwrap();}
                    for m in &update.chat_mutations {if m.direction==Some(MobileChatDirection::Inbound)&&m.body.as_deref()==Some("Hello from Android"){received=true;}}
                    for d in &update.chat_deliveries {if d.state==MobileChatDeliveryState::Acknowledged {acknowledged=true;}}
                    if let Some(id)=update.chat_batch_id {assert_eq!(source.poll_update().chat_batch_id,Some(id));source.acknowledge_chat_batch(id).unwrap();}
                }
                assert!(std::time::Instant::now()<deadline,"Mesh round trip timed out");
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        });
    }
    #[test] fn session_ids_remain_lossless_in_java_json() {
        let mut value=json!({"events":[{"session_id":u64::MAX}]});stringify_sessions(&mut value);
        assert_eq!(value["events"][0]["session_id"],u64::MAX.to_string());
    }

}
