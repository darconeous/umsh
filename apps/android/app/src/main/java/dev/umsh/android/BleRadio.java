package dev.umsh.android;
import android.bluetooth.*;
import android.Manifest;
import android.content.pm.PackageManager;
import android.bluetooth.le.*;
import android.content.Context;
import android.os.*;
import java.util.*;

/** All GATT operations and callbacks are serialized on the application's worker. */
@SuppressWarnings("deprecation")
final class BleRadio {
    static final UUID SERVICE=UUID.fromString("21eb6b15-0001-4ccf-92e4-a079171bec97");
    static final UUID INPUT=UUID.fromString("21eb6b15-0002-4ccf-92e4-a079171bec97");
    static final UUID OUTPUT=UUID.fromString("21eb6b15-0003-4ccf-92e4-a079171bec97");
    static final UUID CCCD=UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");
    interface Listener {void status(String text);void device(BluetoothDevice d,int rssi);void ready();void data(byte[] data);void lost();}
    private final Context context;private final Handler worker;private final Listener listener;
    private BluetoothGatt gatt;private BluetoothGattCharacteristic input;private BluetoothLeScanner scanner;
    private final ArrayDeque<byte[]> writes=new ArrayDeque<>();private boolean writing,ready;private int mtu=23,generation;private long deadlineToken;
    BleRadio(Context context,Handler worker,Listener listener){this.context=context;this.worker=worker;this.listener=listener;}
    private BluetoothAdapter adapter(){BluetoothManager m=context.getSystemService(BluetoothManager.class);return m==null?null:m.getAdapter();}
    void scan(){
        stopScan();if(Build.VERSION.SDK_INT>=31&&context.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN)!=PackageManager.PERMISSION_GRANTED){listener.status("Nearby devices permission is required");return;}if(Build.VERSION.SDK_INT<31&&context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)!=PackageManager.PERMISSION_GRANTED){listener.status("Location permission is required on this Android version");return;}BluetoothAdapter a=adapter();if(a==null||!a.isEnabled()){listener.status("Turn on Bluetooth to find a radio");return;}
        scanner=a.getBluetoothLeScanner();if(scanner==null){listener.status("Bluetooth scanner unavailable");return;}
        listener.status("Scanning for UMSH radios…");
        scanner.startScan(Collections.singletonList(new ScanFilter.Builder().setServiceUuid(new ParcelUuid(SERVICE)).build()),new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),scanCallback);
        int gen=generation;worker.postDelayed(()->{if(gen==generation){stopScan();listener.status("Scan finished. Open the radio’s pairing window to find it.");}},12000);
    }
    private final ScanCallback scanCallback=new ScanCallback(){
        @Override public void onScanResult(int type,ScanResult r){worker.post(()->{if(scanner!=null)listener.device(r.getDevice(),r.getRssi());});}
        @Override public void onScanFailed(int code){worker.post(()->{stopScan();listener.status("Bluetooth scan failed ("+code+")");});}
    };
    void stopScan(){if(scanner!=null){try{scanner.stopScan(scanCallback);}catch(SecurityException ignored){listener.status("Scan permission was revoked");}finally{scanner=null;}}}
    void connect(BluetoothDevice device){
        if(Build.VERSION.SDK_INT>=31&&context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){fail("Nearby devices permission was revoked");return;}
        disconnect();listener.status("Connecting to "+device.getName()+"…");
        gatt=device.connectGatt(context,false,callback,BluetoothDevice.TRANSPORT_LE);arm(15000,"Connection timed out");
    }
    void disconnect(){generation++;deadlineToken++;stopScan();ready=false;writing=false;writes.clear();input=null;mtu=23;
        BluetoothGatt old=gatt;gatt=null;if(old!=null){try{old.disconnect();old.close();}catch(SecurityException ignored){listener.status("Bluetooth permission was revoked");}finally{listener.lost();}}}
    private void fail(String reason){disconnect();listener.status(reason);}
    private void arm(long ms,String reason){long token=++deadlineToken;int gen=generation;worker.postDelayed(()->{if(gen==generation&&token==deadlineToken)fail(reason);},ms);}
    private void dispatch(BluetoothGatt source,Runnable action){worker.post(()->{if(source==gatt)try{action.run();}catch(Exception e){fail("Bluetooth error: "+e.getMessage());}});}
    private void subscribe(){
        if(Build.VERSION.SDK_INT>=31&&context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){fail("Nearby devices permission was revoked");return;}
        BluetoothGattService service=gatt.getService(SERVICE);if(service==null){fail("This device has no UMSH service");return;}
        input=service.getCharacteristic(INPUT);BluetoothGattCharacteristic output=service.getCharacteristic(OUTPUT);
        if(input==null||output==null||!gatt.setCharacteristicNotification(output,true)){fail("UMSH characteristics unavailable");return;}
        BluetoothGattDescriptor descriptor=output.getDescriptor(CCCD);if(descriptor==null){fail("Notifications unavailable");return;}
        descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
        if(!gatt.writeDescriptor(descriptor)){fail("Could not enable notifications");return;}arm(60000,"Pairing or notification subscription timed out");
    }
    private final BluetoothGattCallback callback=new BluetoothGattCallback(){
        @Override public void onConnectionStateChange(BluetoothGatt g,int status,int state){dispatch(g,()->{
            if(status!=BluetoothGatt.GATT_SUCCESS||state==BluetoothProfile.STATE_DISCONNECTED){fail("Radio disconnected ("+status+"). Reconnect when it is nearby.");return;}
            if(state==BluetoothProfile.STATE_CONNECTED){if(Build.VERSION.SDK_INT>=31&&context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){fail("Nearby devices permission was revoked");return;}deadlineToken++;if(!g.discoverServices()){fail("Could not discover services");return;}arm(10000,"Service discovery timed out");}
        });}
        @Override public void onServicesDiscovered(BluetoothGatt g,int status){dispatch(g,()->{
            if(status!=BluetoothGatt.GATT_SUCCESS){fail("Service discovery failed");return;}deadlineToken++;
            if(Build.VERSION.SDK_INT>=31&&context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){fail("Nearby devices permission was revoked");return;}
            if(!g.requestMtu(247))subscribe();else arm(10000,"MTU negotiation timed out");
        });}
        @Override public void onMtuChanged(BluetoothGatt g,int value,int status){dispatch(g,()->{deadlineToken++;mtu=status==BluetoothGatt.GATT_SUCCESS?value:23;subscribe();});}
        @Override public void onDescriptorWrite(BluetoothGatt g,BluetoothGattDescriptor d,int status){dispatch(g,()->{
            deadlineToken++;if(status!=BluetoothGatt.GATT_SUCCESS){fail("Radio rejected notifications; pair using its pairing window");return;}
            ready=true;listener.ready();
        });}
        @Override public void onCharacteristicChanged(BluetoothGatt g,BluetoothGattCharacteristic c){if(Build.VERSION.SDK_INT<33){byte[] value=c.getValue().clone();dispatch(g,()->listener.data(value));}}
        @Override public void onCharacteristicChanged(BluetoothGatt g,BluetoothGattCharacteristic c,byte[] value){byte[] copy=value.clone();dispatch(g,()->listener.data(copy));}
        @Override public void onCharacteristicWrite(BluetoothGatt g,BluetoothGattCharacteristic c,int status){dispatch(g,()->{
            deadlineToken++;if(status!=BluetoothGatt.GATT_SUCCESS){fail("Radio write failed ("+status+")");return;}writing=false;if(!writes.isEmpty())writes.removeFirst();writeNext();
        });}
        @Override public void onServiceChanged(BluetoothGatt g){dispatch(g,()->fail("Radio services changed. Reconnect to refresh them."));}
    };
    void send(byte[] frame)throws Exception{
        if(!ready)throw new Exception("Radio is not connected");
        org.json.JSONArray segments=(org.json.JSONArray)Core.invoke("segments","frame",Core.array(frame),"mtu",mtu-3);
        if(writes.size()+segments.length()>1024)throw new Exception("Bluetooth output queue is full");
        for(int i=0;i<segments.length();i++)writes.add(Core.bytes(segments.getJSONObject(i).getJSONArray("value")));writeNext();
    }
    private void writeNext(){
        if(Build.VERSION.SDK_INT>=31&&context.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT)!=PackageManager.PERMISSION_GRANTED){fail("Nearby devices permission was revoked");return;}
        if(writing||writes.isEmpty()||!ready)return;input.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);input.setValue(writes.peek());
        if(!gatt.writeCharacteristic(input)){fail("Bluetooth write could not start");return;}writing=true;arm(8000,"Bluetooth write timed out");
    }
}
