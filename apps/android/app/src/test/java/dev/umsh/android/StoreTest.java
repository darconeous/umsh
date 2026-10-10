package dev.umsh.android;
import android.app.Application;
import org.json.*;
import org.junit.*;
import org.junit.runner.RunWith;
import org.robolectric.*;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;
@RunWith(RobolectricTestRunner.class)
@Config(sdk=28,application=Application.class)
public class StoreTest {
    private Store store;
    @Before public void setup(){var context=RuntimeEnvironment.getApplication();context.deleteDatabase("umsh.db");store=new Store(context);}
    @After public void close(){store.close();}
    private JSONObject mutation(int handle,int revision,String body)throws Exception{
        return Core.obj("session_id","18446744073709551615","handle",handle,"revision",revision,"kind","Insert","conversation_address","peer","direction","Outbound","wire_id",3,"epoch",0,"body",body,"fragment_count",2);
    }
    private JSONObject event(JSONArray mutations,JSONArray deliveries)throws Exception{return Core.obj("chat_mutations",mutations,"chat_deliveries",deliveries,"chat_sender_resolutions",new JSONArray());}
    private JSONObject batch()throws Exception{return Core.obj("checkpoint",Core.obj("conversation_address","peer","next_id",4,"epoch",0),"archive_deletes",new JSONArray(),"archives",new JSONArray().put(Core.obj("conversation_address","peer","message_id",3,"fragment_index",JSONObject.NULL,"payload",new JSONArray().put(19))),"mutations",new JSONArray().put(mutation(1,1,"Hello")));}
    @Test public void compositionPersistsBeforeReleaseAndSurvivesReopen()throws Exception{
        store.conversation("peer","Alice",false,null);store.draft("peer","Hello");store.composed(batch());store.close();store=new Store(RuntimeEnvironment.getApplication());
        assertEquals(4,store.checkpoints().getJSONObject(0).getInt("next_id"));assertEquals("",store.conversations().getJSONObject(0).getString("draft"));
        assertEquals("Hello",store.messages("peer").getJSONObject(0).getString("body"));assertEquals(19,store.archive(Core.obj("conversation_address","peer","message_id",3,"fragment_index",JSONObject.NULL)).getInt(0));
    }
    @Test public void failedTransactionKeepsDraftAndCheckpointUnchanged()throws Exception{
        store.conversation("peer","Alice",false,null);store.draft("peer","Keep me");JSONObject b=batch();b.put("mutations",new JSONArray().put(Core.obj("invalid",true)));
        try{store.composed(b);fail("Expected malformed mutation to roll back");}catch(JSONException expected){}
        assertEquals(0,store.checkpoints().length());assertEquals("Keep me",store.conversations().getJSONObject(0).getString("draft"));assertNull(store.archive(Core.obj("conversation_address","peer","message_id",3,"fragment_index",JSONObject.NULL)));
    }
    @Test public void replayedEventsAreIdempotentAndOldRevisionsCannotOverwrite()throws Exception{
        JSONObject newer=mutation(1,2,"Newest"),older=mutation(1,1,"Old");store.events(event(new JSONArray().put(newer),new JSONArray()));store.events(event(new JSONArray().put(newer).put(older),new JSONArray()));
        assertEquals(1,store.messages("peer").length());assertEquals("Newest",store.messages("peer").getJSONObject(0).getString("body"));assertTrue(store.messages("peer").getJSONObject(0).getString("local_id").startsWith("18446744073709551615:"));
    }
    @Test public void fragmentedMessageRequiresEveryAcknowledgement()throws Exception{
        store.composed(batch());JSONObject d=Core.obj("session_id","18446744073709551615","handle",1,"fragment_index",0,"state","Acknowledged");
        store.events(event(new JSONArray(),new JSONArray().put(d)));assertEquals("Sending",store.messages("peer").getJSONObject(0).getString("state"));
        d.put("fragment_index",1);store.events(event(new JSONArray(),new JSONArray().put(d)));assertEquals("Acknowledged",store.messages("peer").getJSONObject(0).getString("state"));
        d.put("state","Sent");store.events(event(new JSONArray(),new JSONArray().put(d)));assertEquals("Acknowledged",store.messages("peer").getJSONObject(0).getString("state"));
    }
    @Test public void nativeBoundaryParsesProtocolInvitations()throws Exception{
        JSONObject a=Core.object("channel","input","PUBLIC"),b=Core.object("channel","input","public");assertEquals(a.getString("address"),b.getString("address"));
        try{Core.object("peer","input","invalid");fail("Invalid addresses must be rejected");}catch(Exception expected){assertNotNull(expected.getMessage());}
    }
}
