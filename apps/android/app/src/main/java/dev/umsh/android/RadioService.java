package dev.umsh.android;
import android.app.*;
import android.content.*;
import android.os.IBinder;
public final class RadioService extends Service {
    @Override public void onCreate(){super.onCreate();NotificationManager manager=getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("radio","Radio connection",NotificationManager.IMPORTANCE_LOW));
        PendingIntent open=PendingIntent.getActivity(this,0,new Intent(this,MainActivity.class),PendingIntent.FLAG_IMMUTABLE|PendingIntent.FLAG_UPDATE_CURRENT);
        startForeground(1,new Notification.Builder(this,"radio").setSmallIcon(dev.umsh.android.R.drawable.ic_mesh).setContentTitle("UMSH radio session").setContentText("Mesh connection is active. Open UMSH to disconnect.").setContentIntent(open).setOngoing(true).build());
    }
    @Override public int onStartCommand(Intent intent,int flags,int id){return START_NOT_STICKY;}
    @Override public void onDestroy(){((UmshApp)getApplication()).disconnect();super.onDestroy();}
    @Override public IBinder onBind(Intent intent){return null;}
}
