package dev.umsh.android;
import android.content.*;
import android.database.Cursor;
import android.database.sqlite.*;
import org.json.*;
import java.util.*;

/** Checkpoints and archived wire payloads commit before a prepared send is released. */
final class Store extends SQLiteOpenHelper {
    Store(Context c){super(c,"umsh.db",null,1);setWriteAheadLoggingEnabled(true);}
    @Override public void onCreate(SQLiteDatabase db){
        db.execSQL("CREATE TABLE conversations(address TEXT PRIMARY KEY,name TEXT NOT NULL,channel INTEGER NOT NULL,key_cipher TEXT,draft TEXT NOT NULL DEFAULT '',identity TEXT)");
        db.execSQL("CREATE TABLE messages(id TEXT PRIMARY KEY,address TEXT NOT NULL,record TEXT NOT NULL,stamp INTEGER NOT NULL,state TEXT NOT NULL DEFAULT 'Pending')");
        db.execSQL("CREATE INDEX transcript ON messages(address,stamp)");
        db.execSQL("CREATE TABLE checkpoints(address TEXT PRIMARY KEY,record TEXT NOT NULL)");
        db.execSQL("CREATE TABLE archives(address TEXT NOT NULL,wire INTEGER NOT NULL,fragment INTEGER NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(address,wire,fragment))");
        db.execSQL("CREATE TABLE deliveries(id TEXT NOT NULL,fragment INTEGER NOT NULL,state TEXT NOT NULL,PRIMARY KEY(id,fragment))");
    }
    @Override public void onUpgrade(SQLiteDatabase db,int old,int next){throw new IllegalStateException("Unsupported database version");}
    synchronized void conversation(String address,String name,boolean channel,String encryptedKey) {
        SQLiteDatabase db=getWritableDatabase();ContentValues values=new ContentValues();
        values.put("address",address);values.put("name",name);values.put("channel",channel?1:0);values.put("key_cipher",encryptedKey);
        db.insertWithOnConflict("conversations",null,values,SQLiteDatabase.CONFLICT_IGNORE);
    }
    synchronized JSONArray conversations() throws Exception {
        JSONArray result=new JSONArray();try(Cursor c=getReadableDatabase().rawQuery("SELECT address,name,channel,key_cipher,draft,identity FROM conversations ORDER BY channel,name COLLATE NOCASE",null)){
            while(c.moveToNext())result.put(Core.obj("address",c.getString(0),"name",c.getString(1),"channel",c.getInt(2)==1,"key_cipher",c.getString(3),"draft",c.getString(4),"identity",c.isNull(5)?JSONObject.NULL:new JSONObject(c.getString(5))));
        }return result;
    }
    synchronized void draft(String address,String body){ContentValues v=new ContentValues();v.put("draft",body);getWritableDatabase().update("conversations",v,"address=?",new String[]{address});}
    synchronized void identity(String address,JSONObject identity)throws Exception{
        conversation(address,identity.optString("name",address),false,null);
        ContentValues v=new ContentValues();v.put("identity",identity.toString());
        if(!identity.isNull("name")&&!identity.optString("name").isEmpty())v.put("name",identity.getString("name"));
        getWritableDatabase().update("conversations",v,"address=?",new String[]{address});
    }
    synchronized JSONArray checkpoints()throws Exception{return jsonRows("SELECT record FROM checkpoints",null);}
    private JSONArray jsonRows(String sql,String[] args)throws Exception{
        JSONArray out=new JSONArray();try(Cursor c=getReadableDatabase().rawQuery(sql,args)){while(c.moveToNext())out.put(new JSONObject(c.getString(0)));}return out;
    }
    synchronized JSONArray messages(String address)throws Exception{
        JSONArray result=new JSONArray();try(Cursor c=getReadableDatabase().rawQuery("SELECT record,stamp,state,id FROM messages WHERE address=? ORDER BY stamp,rowid",new String[]{address})){
            while(c.moveToNext()){JSONObject r=new JSONObject(c.getString(0));r.put("stamp",c.getLong(1));r.put("state",c.getString(2));r.put("local_id",c.getString(3));result.put(r);}
        }return result;
    }
    static String id(JSONObject r)throws Exception{return r.getString("session_id")+":"+r.getLong("handle");}
    private JSONObject record(String id)throws Exception{
        try(Cursor c=getReadableDatabase().rawQuery("SELECT record FROM messages WHERE id=?",new String[]{id})){return c.moveToFirst()?new JSONObject(c.getString(0)):null;}
    }
    synchronized void composed(JSONObject batch)throws Exception{
        SQLiteDatabase db=getWritableDatabase();db.beginTransaction();try{
            JSONObject cp=batch.getJSONObject("checkpoint");ContentValues v=new ContentValues();v.put("address",cp.getString("conversation_address"));v.put("record",cp.toString());db.insertWithOnConflict("checkpoints",null,v,SQLiteDatabase.CONFLICT_REPLACE);
            JSONArray deletes=batch.getJSONArray("archive_deletes");for(int i=0;i<deletes.length();i++){JSONObject d=deletes.getJSONObject(i);db.delete("archives","address=? AND wire=?",new String[]{d.getString("conversation_address"),d.getString("message_id")});}
            JSONArray archives=batch.getJSONArray("archives");for(int i=0;i<archives.length();i++){JSONObject a=archives.getJSONObject(i);v=new ContentValues();v.put("address",a.getString("conversation_address"));v.put("wire",a.getInt("message_id"));v.put("fragment",a.isNull("fragment_index")?-1:a.getInt("fragment_index"));v.put("payload",a.getJSONArray("payload").toString());db.insertWithOnConflict("archives",null,v,SQLiteDatabase.CONFLICT_REPLACE);}
            mutations(batch.getJSONArray("mutations"));draft(cp.getString("conversation_address"),"");db.setTransactionSuccessful();
        }finally{db.endTransaction();}
    }
    synchronized void events(JSONObject update)throws Exception{
        SQLiteDatabase db=getWritableDatabase();db.beginTransaction();try{
            mutations(update.getJSONArray("chat_mutations"));
            JSONArray deliveries=update.getJSONArray("chat_deliveries");for(int i=0;i<deliveries.length();i++){
                JSONObject d=deliveries.getJSONObject(i);String id=id(d), state=d.getString("state");ContentValues v=new ContentValues();v.put("id",id);v.put("fragment",d.isNull("fragment_index")?-1:d.getInt("fragment_index"));v.put("state",state);
                // A later 'Sent' event cannot downgrade an acknowledged fragment.
                try(Cursor c=db.rawQuery("SELECT state FROM deliveries WHERE id=? AND fragment=?",new String[]{id,String.valueOf(v.getAsInteger("fragment"))})){if(c.moveToFirst()&&c.getString(0).equals("Acknowledged"))continue;}
                db.insertWithOnConflict("deliveries",null,v,SQLiteDatabase.CONFLICT_REPLACE);
                JSONObject message=record(id);if(message==null)continue;
                int sent=0,acked=0;boolean failed=false;
                try(Cursor c=db.rawQuery("SELECT state FROM deliveries WHERE id=?",new String[]{id})){while(c.moveToNext()){String s=c.getString(0);if(s.equals("Failed"))failed=true;else sent++;if(s.equals("Acknowledged"))acked++;}}
                int expected=message.optInt("fragment_count",1);expected=Math.max(1,expected);
                v=new ContentValues();v.put("state",failed?"Failed":acked>=expected?"Acknowledged":sent>=expected?"Sent":"Sending");db.update("messages",v,"id=?",new String[]{id});
            }
            JSONArray resolutions=update.getJSONArray("chat_sender_resolutions");for(int i=0;i<resolutions.length();i++){
                JSONObject resolution=resolutions.getJSONObject(i);JSONArray rows=messages(resolution.getString("conversation_address"));
                for(int j=0;j<rows.length();j++){JSONObject row=rows.getJSONObject(j);if(String.valueOf(row.opt("sender_hint")).equals(resolution.getJSONArray("sender_hint").toString())){row.put("sender_address",resolution.getString("sender_address"));ContentValues v=new ContentValues();v.put("record",row.toString());db.update("messages",v,"id=?",new String[]{row.getString("local_id")});}}
            }
            db.setTransactionSuccessful();
        }finally{db.endTransaction();}
    }
    private void mutations(JSONArray list)throws Exception{
        SQLiteDatabase db=getWritableDatabase();for(int i=0;i<list.length();i++){
            JSONObject m=list.getJSONObject(i);String key=id(m);JSONObject old=record(key);
            if(old!=null&&old.optLong("revision")>=m.getLong("revision"))continue;
            String kind=m.getString("kind");
            if(kind.equals("Edit")||kind.equals("Delete")){
                String target=m.isNull("original_handle")?null:m.getString("session_id")+":"+m.getLong("original_handle");
                JSONObject original=target==null?null:record(target);
                if(original==null&&!m.isNull("conversation_address")&&!m.isNull("original_wire_id")){
                    JSONArray rows=messages(m.getString("conversation_address"));for(int j=rows.length()-1;j>=0;j--){JSONObject r=rows.getJSONObject(j);
                        if(r.optInt("wire_id",-1)==m.getInt("original_wire_id")&&r.optString("direction").equals(m.optString("original_direction"))&&Objects.equals(String.valueOf(r.opt("sender_hint")),String.valueOf(m.opt("original_sender_hint")))){original=r;target=r.getString("local_id");break;}}
                }
                if(original!=null){original.put("body",kind.equals("Delete")?"Message deleted":m.optString("body"));original.put("edited",true);ContentValues v=new ContentValues();v.put("record",original.toString());db.update("messages",v,"id=?",new String[]{target});}
                continue;
            }
            JSONObject merged=old==null?new JSONObject():old;
            Iterator<String> fields=m.keys();while(fields.hasNext()){String f=fields.next();if(!m.isNull(f))merged.put(f,m.get(f));}
            if(!merged.has("conversation_address"))continue;
            String address=merged.getString("conversation_address");conversation(address,address,address.startsWith("ch:"),null);
            ContentValues v=new ContentValues();v.put("record",merged.toString());
            if(old==null){v.put("id",key);v.put("address",address);JSONObject rx=m.optJSONObject("rx");long age=rx==null?0:rx.optLong("buffered_age_seconds");v.put("stamp",System.currentTimeMillis()-age*1000);v.put("state",m.optString("direction").equals("Inbound")?"Received":"Pending");db.insertOrThrow("messages",null,v);}else db.update("messages",v,"id=?",new String[]{key});
        }
    }
    synchronized JSONArray archive(JSONObject lookup)throws Exception{
        try(Cursor c=getReadableDatabase().rawQuery("SELECT payload FROM archives WHERE address=? AND wire=? AND fragment=?",new String[]{lookup.getString("conversation_address"),lookup.getString("message_id"),lookup.isNull("fragment_index")?"-1":lookup.getString("fragment_index")})){return c.moveToFirst()?new JSONArray(c.getString(0)):null;}
    }
    synchronized void interrupted(){getWritableDatabase().execSQL("UPDATE messages SET state='Interrupted — not confirmed' WHERE state IN ('Pending','Sending')");}
}
