package dev.umsh.android;
import android.Manifest;
import android.app.*;
import android.bluetooth.*;
import android.content.*;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.*;
import android.text.*;
import android.view.*;
import android.widget.*;
import org.json.*;
import java.text.DateFormat;
import java.util.*;

public final class MainActivity extends Activity {
    private static final int BG=0xff101716,PANEL=0xff1c2724,TEXT=0xfff0f3ec,MUTED=0xffa4b5ad,ACCENT=0xffffb363;
    private UmshApp app;private LinearLayout root,content,nav,header;private TextView connection,title;private ScrollView scroll;
    private String tab="Chats",conversation=null,conversationName="",lastError="",messageFingerprint="";private EditText composer;private LinearLayout transcript;private boolean sending;
    @Override public void onCreate(Bundle state){super.onCreate(state);app=(UmshApp)getApplication();
        if(state!=null){tab=state.getString("tab","Chats");conversation=state.getString("conversation");conversationName=state.getString("name","");}
        build();handleIntent(getIntent());
    }
    @Override protected void onResume(){super.onResume();app.observer=this::refresh;refresh();}
    @Override protected void onPause(){app.observer=null;super.onPause();}
    @Override protected void onSaveInstanceState(Bundle state){super.onSaveInstanceState(state);state.putString("tab",tab);state.putString("conversation",conversation);state.putString("name",conversationName);}
    @Override protected void onNewIntent(Intent intent){super.onNewIntent(intent);setIntent(intent);handleIntent(intent);}
    private void handleIntent(Intent intent){if(intent.getData()!=null){String uri=intent.getData().toString();new AlertDialog.Builder(this).setTitle("Open UMSH invitation?").setMessage(uri).setPositiveButton("Add",(d,w)->app.work(()->{if(uri.startsWith("umsh:cs:")||uri.startsWith("umsh:ck:"))app.addChannel(uri);else app.addPeer(uri,"");})).setNegativeButton("Cancel",null).show();}}
    private int dp(int value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private LinearLayout vertical(){LinearLayout v=new LinearLayout(this);v.setOrientation(LinearLayout.VERTICAL);return v;}
    private GradientDrawable background(int color,int radius){GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;}
    private TextView text(String value,int size,int color){TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(color);t.setPadding(0,dp(5),0,dp(5));return t;}
    private TextView label(String value){TextView t=text(value,12,ACCENT);t.setLetterSpacing(.12f);return t;}
    private Button button(String value,Runnable action){Button b=new Button(this);b.setText(value);b.setAllCaps(false);b.setTextColor(ACCENT);b.setOnClickListener(v->action.run());return b;}
    private void build(){
        root=vertical();root.setBackgroundColor(BG);root.setPadding(dp(20),0,dp(20),0);root.setFitsSystemWindows(true);
        root.setOnApplyWindowInsetsListener((view,insets)->{view.setPadding(dp(20),insets.getSystemWindowInsetTop(),dp(20),insets.getSystemWindowInsetBottom());return insets.consumeSystemWindowInsets();});setContentView(root);
        header=vertical();header.addView(label("UMSH  /  OFF-GRID MESSAGING"));title=text(conversation==null?tab:conversationName,32,TEXT);title.setTypeface(null,Typeface.BOLD);header.addView(title);connection=text(app.status,13,MUTED);header.addView(connection);root.addView(header);
        if(conversation!=null)header.addView(button("‹ All conversations",()->{conversation=null;build();refresh();}));
        scroll=new ScrollView(this);scroll.setFillViewport(true);content=vertical();content.setPadding(0,dp(14),0,dp(16));scroll.addView(content);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        if(conversation==null){
            nav=new LinearLayout(this);for(String item:new String[]{"Chats","Channels","Nearby","Radio","Profile"}){TextView b=text(item,12,item.equals(tab)?ACCENT:MUTED);b.setGravity(Gravity.CENTER);b.setPadding(0,dp(18),0,dp(18));b.setOnClickListener(v->{tab=item;build();refresh();});nav.addView(b,new LinearLayout.LayoutParams(0,-2,1));}root.addView(nav);
        }else{
            transcript=content;composer=new EditText(this);composer.setTextColor(TEXT);composer.setHintTextColor(MUTED);composer.setHint("Message over the mesh…");composer.setMaxLines(5);composer.setInputType(android.text.InputType.TYPE_CLASS_TEXT|android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE|android.text.InputType.TYPE_TEXT_FLAG_CAP_SENTENCES);
            try{JSONArray rows=app.store.conversations();for(int i=0;i<rows.length();i++){JSONObject r=rows.getJSONObject(i);if(r.getString("address").equals(conversation))composer.setText(r.getString("draft"));}}catch(Exception e){app.problem(e.getMessage());}
            composer.addTextChangedListener(new TextWatcher(){public void beforeTextChanged(CharSequence s,int a,int c,int f){}public void onTextChanged(CharSequence s,int a,int b,int c){String dest=conversation,body=s.toString();app.work(()->app.store.draft(dest,body));}public void afterTextChanged(Editable e){}});
            LinearLayout send=new LinearLayout(this);send.setGravity(Gravity.BOTTOM);send.addView(composer,new LinearLayout.LayoutParams(0,-2,1));send.addView(button("Send",this::send));root.addView(send);messageFingerprint="";
        }
    }
    private void send(){if(sending||composer.getText().toString().trim().isEmpty())return;sending=true;String body=composer.getText().toString(),dest=conversation;
        app.work(()->{try{app.send(dest,body);app.main.post(()->{if(dest.equals(conversation)&&composer.getText().toString().equals(body))composer.setText("");});}finally{app.main.post(()->sending=false);}});
    }
    private void refresh(){if(isFinishing())return;connection.setText(app.status);
        if(!app.error.isEmpty()&&!app.error.equals(lastError)){lastError=app.error;new AlertDialog.Builder(this).setTitle("Couldn’t complete that").setMessage(app.error).setPositiveButton("OK",(d,w)->{app.error="";lastError="";}).show();}
        if(!app.initialized){content.removeAllViews();empty("Preparing your identity","Keys stay on this phone. The mesh needs no account or internet connection.");return;}
        try{if(conversation!=null){renderMessages();return;}content.removeAllViews();switch(tab){case "Chats":conversations(false);break;case "Channels":conversations(true);break;case "Nearby":nearby();break;case "Radio":radio();break;default:profile();}}
        catch(Exception e){app.problem(e.getMessage());}
    }
    private void empty(String heading,String body){LinearLayout box=card();box.addView(text(heading,23,TEXT));box.addView(text(body,15,MUTED));}
    private LinearLayout card(){LinearLayout box=vertical();box.setPadding(dp(18),dp(14),dp(18),dp(14));box.setBackground(background(PANEL,18));LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.bottomMargin=dp(12);content.addView(box,p);return box;}
    private void conversations(boolean channels)throws Exception{
        content.addView(button(channels?"+ Join a channel":"+ New conversation",()->{if(channels)joinChannel();else newPeer();}));
        if(channels)content.addView(button("Create a private channel",()->ask("Private channel","Channel name","",name->app.work(()->{String invite=app.privateChannel(name);app.main.post(()->share(invite));}))));
        JSONArray rows=app.store.conversations();int count=0;for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(row.getBoolean("channel")!=channels)continue;count++;
            String dest=row.getString("address"),name=row.getString("name");LinearLayout box=card();box.addView(label(channels?"CHANNEL":"DIRECT MESSAGE"));box.addView(text(name,22,TEXT));JSONArray messages=app.store.messages(dest);
            if(messages.length()>0)box.addView(text(messages.getJSONObject(messages.length()-1).optString("body","Message"),14,MUTED));else box.addView(text(channels?"A shared space on the mesh":"Ready when your radio is connected",14,MUTED));
            box.setOnClickListener(v->{conversation=dest;conversationName=name;build();refresh();});box.setContentDescription("Open "+name);
        }
        if(count==0)empty(channels?"Find your people":"A conversation starts here",channels?"Join a public channel by name, or paste a private invitation from another UMSH user.":"Add a friend’s UMSH address or invitation. Connect a companion radio to exchange encrypted messages.");
    }
    private void renderMessages()throws Exception{
        JSONArray messages=app.store.messages(conversation);String fingerprint=messages.toString();if(fingerprint.equals(messageFingerprint))return;messageFingerprint=fingerprint;transcript.removeAllViews();
        if(messages.length()==0){transcript.addView(text("You’re at the beginning of this conversation.",15,MUTED));return;}
        for(int i=0;i<messages.length();i++){JSONObject m=messages.getJSONObject(i);boolean outgoing="Outbound".equals(m.optString("direction"));LinearLayout bubble=vertical();bubble.setPadding(dp(16),dp(10),dp(16),dp(10));bubble.setBackground(background(outgoing?0xff344236:PANEL,16));
            LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.bottomMargin=dp(10);if(outgoing)p.leftMargin=dp(30);else p.rightMargin=dp(30);
            String sender=outgoing?"YOU":m.isNull("sender_handle")?"MESH PEER":m.optString("sender_handle");bubble.addView(label(sender));
            String presence=m.optString("presence"),body=m.optString("body","");if(presence.equals("GapPending"))body="Waiting for a missing message…";else if(presence.equals("Unavailable"))body="Message unavailable";
            TextView message=text(body,17,TEXT);message.setTextIsSelectable(true);bubble.addView(message);
            String stamp=DateFormat.getTimeInstance(DateFormat.SHORT).format(new Date(m.getLong("stamp")));bubble.addView(text(stamp+" · "+m.optString("state")+(m.optBoolean("edited")?" · edited":""),11,MUTED));transcript.addView(bubble,p);
        }scroll.post(()->scroll.fullScroll(View.FOCUS_DOWN));
    }
    private void newPeer(){ask("New conversation","UMSH address or invitation","",input->ask("Name this contact","Name (optional)","",name->app.work(()->app.addPeer(input.trim(),name.trim()))));}
    private void joinChannel(){ask("Join a channel","Public name or umsh: invitation","public",input->app.work(()->app.addChannel(input.trim())));}
    private void nearby()throws Exception{
        content.addView(button("Discover nearby nodes",()->{if(!app.attached){app.problem("Connect a radio first");return;}app.network(()->Core.invoke("discover"));}));
        JSONArray rows=app.store.conversations();int count=0;for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i),identity=row.optJSONObject("identity");if(identity==null)continue;count++;
            LinearLayout box=card();box.addView(text(row.getString("name"),22,TEXT));box.addView(text(identity.optString("role_label","Node"),14,MUTED));String address=row.getString("address");
            box.addView(button("Ping node",()->app.network(()->{if(!app.attached)throw new Exception("Connect a radio first");Core.invoke("ping","address",address);})));if(!identity.isNull("latitude")&&!identity.isNull("longitude")){
                double lat=identity.getDouble("latitude"),lon=identity.getDouble("longitude");box.addView(text(String.format(Locale.US,"%.5f, %.5f",lat,lon),14,MUTED));box.addView(button("Open location in Maps",()->{try{startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse("geo:"+lat+","+lon+"?q="+lat+","+lon)));}catch(ActivityNotFoundException e){app.problem("Install a maps app to view this location");}}));
            }
        }if(count==0)empty("Explore the mesh","Discovered nodes appear here after they reply to your radio. Verified locations can be opened in your maps app.");
    }
    private boolean permissions(){String[] required=Build.VERSION.SDK_INT>=31?new String[]{Manifest.permission.BLUETOOTH_SCAN,Manifest.permission.BLUETOOTH_CONNECT}:new String[]{Manifest.permission.ACCESS_FINE_LOCATION};for(String p:required)if(checkSelfPermission(p)!=PackageManager.PERMISSION_GRANTED){requestPermissions(required,10);return false;}return true;}
    @Override public void onRequestPermissionsResult(int code,String[] permissions,int[] results){super.onRequestPermissionsResult(code,permissions,results);if(code==10){boolean granted=results.length>0;for(int r:results)granted&=r==PackageManager.PERMISSION_GRANTED;if(granted)scan();else app.problem("Nearby devices permission is needed to find and connect a radio. You can enable it in Android app settings.");}}
    private void scan(){if(!permissions())return;synchronized(app.devices){app.devices.clear();}app.radioWork(()->app.radio.scan());}
    private void radio()throws Exception{
        LinearLayout info=card();info.addView(label("COMPANION RADIO"));info.addView(text(app.attached?"Connected to the mesh":"Take your messages off-grid",23,TEXT));info.addView(text("Use a UMSH-compatible LoRa radio. Open its pairing window, scan, then select it below.",15,MUTED));
        content.addView(button("Scan for radios",this::scan));content.addView(button("Disconnect",app::disconnect));
        if("AwaitingHost".equals(app.snapshot.optString("phase")))content.addView(button("Use this radio with my identity",()->new AlertDialog.Builder(this).setTitle("Use this companion radio?").setMessage("This assigns the radio’s host role to this phone. If it belongs to another phone, that host assignment will be replaced.").setPositiveButton("Use radio",(d,w)->app.radioWork(()->app.apply(Core.object("claim")))).setNegativeButton("Cancel",null).show()));
        if(app.attached){content.addView(button("Refresh radio details",()->app.radioWork(()->app.apply(Core.object("refresh")))));content.addView(button("Radio settings",this::radioSettings));}
        JSONObject battery=app.snapshot.optJSONObject("battery");if(battery!=null)content.addView(text("Battery: "+(battery.isNull("percentage")?"unavailable":battery.optInt("percentage")+"%"),15,MUTED));
        synchronized(app.devices){for(BluetoothDevice device:app.devices.values()){String name=checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)==PackageManager.PERMISSION_GRANTED||Build.VERSION.SDK_INT<31?device.getName():"UMSH radio";content.addView(button((name==null?"UMSH radio":name)+"  ·  "+device.getAddress(),()->{if(permissions()){if(Build.VERSION.SDK_INT>=33&&checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},11);app.connect(device);}}));}}
    }
    private void radioSettings(){JSONObject source=app.snapshot.optJSONObject("provisioning");if(source==null){app.problem("Radio settings have not been read yet");return;}
        LinearLayout fields=vertical();fields.setPadding(dp(20),0,dp(20),0);EditText frequency=new EditText(this);frequency.setHint("Frequency (kHz)");frequency.setInputType(2);frequency.setText(source.optString("frequency_khz"));fields.addView(text("Frequency in kHz",14,MUTED));fields.addView(frequency);
        EditText power=new EditText(this);power.setInputType(4098);power.setText(source.optString("transmit_power_dbm"));fields.addView(text("Transmit power in dBm",14,MUTED));fields.addView(power);Switch enabled=new Switch(this);enabled.setText("Enable radio PHY");enabled.setChecked(source.optBoolean("phy_enabled"));fields.addView(enabled);
        new AlertDialog.Builder(this).setTitle("Radio settings").setView(fields).setPositiveButton("Apply & save",(d,w)->app.radioWork(()->{JSONObject settings=new JSONObject();for(String key:new String[]{"device_name","bandwidth_hz","spreading_factor","coding_rate_denom","duty_cycle_limit"})settings.put(key,source.opt(key));settings.put("phy_enabled",enabled.isChecked());settings.put("frequency_khz",Integer.parseInt(frequency.getText().toString()));settings.put("transmit_power_dbm",Integer.parseInt(power.getText().toString()));app.apply(Core.object("configure","settings",settings));})).setNegativeButton("Cancel",null).show();
    }
    private void profile(){LinearLayout box=card();box.addView(label("YOUR MESH IDENTITY"));box.addView(text(app.name(),26,TEXT));TextView key=text(app.address,13,MUTED);key.setTextIsSelectable(true);box.addView(key);box.addView(text("Your identity and channel keys are protected by Android Keystore. Keep app data to keep this identity.",14,MUTED));content.addView(button("Edit display name",()->ask("Your display name","Name",app.name(),name->app.work(()->app.name(name.trim())))));content.addView(button("Share my address",()->share("umsh:n:"+app.address)));content.addView(button("Announce my identity",()->{if(!app.attached){app.problem("Connect a radio first");return;}app.network(()->Core.invoke("advertise","name",app.name()));}));content.addView(text("UMSH for Android · Java edition\nExperimental mesh protocol · No account required\nBuilt from the same protocol core as UMSH for iOS.",13,MUTED));}
    interface Input {void accept(String value);}
    private void ask(String title,String hint,String initial,Input callback){EditText edit=new EditText(this);edit.setHint(hint);edit.setText(initial);edit.setSingleLine(true);LinearLayout wrap=vertical();wrap.setPadding(dp(24),dp(8),dp(24),dp(8));wrap.addView(edit);new AlertDialog.Builder(this).setTitle(title).setView(wrap).setPositiveButton("Continue",(d,w)->callback.accept(edit.getText().toString())).setNegativeButton("Cancel",null).show();}
    private void share(String value){Intent intent=new Intent(Intent.ACTION_SEND);intent.setType("text/plain");intent.putExtra(Intent.EXTRA_TEXT,value);startActivity(Intent.createChooser(intent,"Share UMSH invitation"));}
    @Override public void onBackPressed(){if(conversation!=null){conversation=null;build();refresh();}else super.onBackPressed();}
}
