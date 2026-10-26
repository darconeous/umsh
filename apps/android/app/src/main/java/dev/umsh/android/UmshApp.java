package dev.umsh.android;
import android.app.Application;
import android.bluetooth.BluetoothDevice;
import android.content.Intent;
import android.os.*;
import org.json.*;
import java.util.*;
import java.util.concurrent.*;

public final class UmshApp extends Application implements BleRadio.Listener {
    final Handler main=new Handler(Looper.getMainLooper());Handler worker;Store store;Vault vault;BleRadio radio;
    final ExecutorService commands=Executors.newSingleThreadExecutor();
    volatile String status="Starting…",address="",error="";volatile boolean initialized,attached;volatile JSONObject snapshot=new JSONObject();
    final LinkedHashMap<String,BluetoothDevice> devices=new LinkedHashMap<>();
    Runnable observer;private final ArrayDeque<JSONObject> raw=new ArrayDeque<>();private JSONObject inFlight;
    private final Map<Integer,Long> deadlines=new HashMap<>();private long rawDeadline;private boolean linkReady;
    interface Work {void run()throws Exception;}
    @Override public void onCreate(){super.onCreate();store=new Store(this);vault=new Vault(this);HandlerThread thread=new HandlerThread("UMSH radio");thread.start();worker=new Handler(thread.getLooper());radio=new BleRadio(this,worker,this);
        work(()->{byte[] secret=vault.identity();try{address=Core.object("open","secret",Core.array(secret),"counters",new java.io.File(getNoBackupFilesDir(),"counters").getAbsolutePath()).getString("canonical_address");}finally{Arrays.fill(secret,(byte)0);}
            store.interrupted();Core.invoke("restore","checkpoints",store.checkpoints());register();Core.invoke("name","name",name());initialized=true;status="No radio connected";worker.post(pump);changed();});
    }
    String name(){return getSharedPreferences("settings",0).getString("name","Android node");}
    void name(String name)throws Exception{if(!getSharedPreferences("settings",0).edit().putString("name",name).commit())throw new Exception("Could not save profile");Core.invoke("name","name",name);changed();}
    void work(Work task){commands.execute(()->{try{task.run();}catch(Exception|LinkageError e){problem(e.getMessage());}});}
    void radioWork(Work task){worker.post(()->{try{task.run();}catch(Exception e){problem(e.getMessage());}});}
    void network(Work task){commands.execute(()->{try{task.run();}catch(Exception e){problem(e.getMessage());}});}
    void problem(String text){error=text==null?"Operation failed":text;changed();}
    void changed(){main.post(()->{if(observer!=null)observer.run();});}
    void register()throws Exception{
        JSONArray peers=new JSONArray(),channels=new JSONArray(),rows=store.conversations();for(int i=0;i<rows.length();i++){JSONObject r=rows.getJSONObject(i);
            if(r.getBoolean("channel")){if(!r.isNull("key_cipher"))channels.put(Core.obj("key",Core.array(vault.unseal(r.getString("key_cipher"))),"max_flood_hops",JSONObject.NULL));}
            else peers.put(r.getString("address"));
        }Core.invoke("peers","addresses",peers);Core.invoke("channels","channels",channels);
    }
    void addPeer(String input,String name)throws Exception{JSONObject p=Core.object("peer","input",input);String a=p.getString("canonical_address");store.conversation(a,name.trim().isEmpty()?a:name,false,null);if(!p.isNull("identity"))store.identity(a,p.getJSONObject("identity"));register();changed();}
    void addChannel(String input)throws Exception{JSONObject c=Core.object("channel","input",input),p=c.getJSONObject("preview");String n=p.isNull("display_name")?p.optString("canonical_name","Private channel"):p.getString("display_name");store.conversation(c.getString("address"),n,true,vault.seal(Core.bytes(p.getJSONArray("key"))));register();changed();}
    String privateChannel(String name)throws Exception{JSONObject c=Core.object("privateChannel","name",name);store.conversation(c.getString("address"),name,true,vault.seal(Core.bytes(c.getJSONArray("key"))));register();changed();return c.getString("invitation");}
    void send(String destination,String body)throws Exception{
        if(!attached)throw new Exception("Connect a radio before sending. Your draft is saved.");
        if(body.trim().isEmpty())throw new Exception("Write a message first");
        JSONObject batch=Core.object("compose","address",destination,"token",0,"body",body);
        try{store.composed(batch);}catch(Exception e){Core.invoke("reject","batch",batch.getLong("batch_id"),"checkpoints",store.checkpoints());throw e;}
        Core.invoke("commit","batch",batch.getLong("batch_id"));changed();
    }
    void connect(BluetoothDevice device){radioWork(()->{startForegroundService(new Intent(this,RadioService.class));radio.connect(device);});}
    void disconnect(){radioWork(()->{radio.disconnect();status="No radio connected";stopService(new Intent(this,RadioService.class));changed();});}
    @Override public void status(String text){status=text;changed();}
    @Override public void device(BluetoothDevice d,int rssi){synchronized(devices){devices.put(d.getAddress(),d);}changed();}
    @Override public void ready(){linkReady=true;radioWork(()->apply(Core.object("begin")));}
    @Override public void data(byte[] data){try{Object value=Core.invoke("segment","data",Core.array(data));if(value instanceof JSONObject)apply((JSONObject)value);}catch(Exception e){radio.disconnect();problem(e.getMessage());}}
    @Override public void lost(){linkReady=false;attached=false;raw.clear();inFlight=null;deadlines.clear();try{Core.invoke("reset");}catch(Exception e){problem(e.getMessage());}changed();}
    void apply(JSONObject update)throws Exception{
        long now=SystemClock.elapsedRealtime();
        if(!update.isNull("completed_control_transaction"))deadlines.remove(update.getInt("completed_control_transaction"));
        Set<Integer> pending=new HashSet<>();JSONArray ids=update.getJSONArray("pending_control_transactions");for(int i=0;i<ids.length();i++){int id=ids.getInt(i);pending.add(id);deadlines.putIfAbsent(id,now+8000);}deadlines.keySet().retainAll(pending);
        JSONObject next=update.getJSONObject("snapshot");String before=snapshot.optString("phase");snapshot=next;attached="Attached".equals(next.optString("phase"));
        String device=next.isNull("device_name")?"UMSH radio":next.getString("device_name");status=device+" · "+next.optString("phase");
        JSONArray frames=update.getJSONArray("outbound_frames");for(int i=0;i<frames.length();i++)radio.send(Core.bytes(frames.getJSONArray(i)));
        JSONArray received=update.getJSONArray("received_frames");for(int i=0;i<received.length();i++)Core.invoke("receive","frame",received.getJSONObject(i));
        JSONObject result=update.optJSONObject("raw_transmit_result");if(result!=null&&inFlight!=null){Core.invoke("complete","id",inFlight.getLong("id"),"sent","Sent".equals(result.getString("disposition")));inFlight=null;}
        if(!update.isNull("operation_error"))problem(update.getJSONObject("operation_error").optString("status_name","Radio operation failed"));
        if(!update.isNull("mismatched_response"))problem("Radio returned an unexpected answer. Check firmware compatibility.");
        if(!before.equals(next.optString("phase"))||!next.isNull("battery"))changed();
    }
    private final Runnable pump=new Runnable(){@Override public void run(){try{
        if(initialized){
            long now=SystemClock.elapsedRealtime();if(linkReady){for(long deadline:deadlines.values())if(now>deadline)throw new Exception("Radio control reply timed out. Reconnect the radio.");if(inFlight!=null&&now>rawDeadline)throw new Exception("Radio transmit timed out. Reconnect the radio.");}
            JSONObject update=Core.object("poll");JSONArray outbound=update.getJSONArray("outbound_frames");for(int i=0;i<outbound.length();i++)raw.add(outbound.getJSONObject(i));
            if(!update.isNull("chat_batch_id")){
                store.events(update);
                JSONArray lookups=update.getJSONArray("chat_archive_lookups");for(int i=0;i<lookups.length();i++){JSONObject lookup=lookups.getJSONObject(i);JSONArray payload=store.archive(lookup);Core.invoke("archive","request",lookup.getLong("request_id"),"kind",payload==null?"Unknown":"Found","payload",payload==null?new JSONArray():payload);}
                Core.invoke("ack","batch",update.getLong("chat_batch_id"));changed();
            }
            JSONArray adverts=update.getJSONArray("advertisement_events");for(int i=0;i<adverts.length();i++){JSONObject a=adverts.getJSONObject(i);JSONObject identity=Core.object("decodeIdentity","address",a.getString("peer_address"),"payload",a.getJSONArray("payload"));if(a.getBoolean("source_authenticated")||"Valid".equals(identity.optString("signature")))store.identity(a.getString("peer_address"),identity);}
            if(adverts.length()>0)changed();
            JSONArray pings=update.getJSONArray("ping_events");if(pings.length()>0){JSONObject p=pings.getJSONObject(0);status="Ping: "+p.getString("outcome")+(p.isNull("round_trip_milliseconds")?"":" · "+p.getLong("round_trip_milliseconds")+" ms");changed();}
            if(attached&&deadlines.isEmpty()&&inFlight==null&&!raw.isEmpty()){
                inFlight=raw.removeFirst();rawDeadline=now+30000;apply(Core.object("transmit","data",inFlight.getJSONArray("data"),"nocca",inFlight.getBoolean("nocca")));
            }else if(!linkReady&&!raw.isEmpty()){while(!raw.isEmpty())Core.invoke("complete","id",raw.removeFirst().getLong("id"),"sent",false);}
        }
    }catch(Exception e){radio.disconnect();problem(e.getMessage());}finally{worker.postDelayed(this,100);}}};
}
