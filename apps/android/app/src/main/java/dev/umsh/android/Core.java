package dev.umsh.android;
import org.json.*;
/** Narrow JNI boundary; Rust retains all cryptographic and protocol decisions. */
final class Core {
    static { System.loadLibrary("umsh_android"); }
    private static native String call(String input);
    static JSONObject obj(Object... pairs) throws JSONException {
        JSONObject v=new JSONObject();
        for(int i=0;i<pairs.length;i+=2) v.put((String)pairs[i],pairs[i+1]);
        return v;
    }
    static Object invoke(String op,Object... pairs) throws Exception {
        JSONObject request=obj(pairs); request.put("op",op);
        JSONObject result=new JSONObject(call(request.toString()));
        if(result.has("error")) throw new Exception(result.getString("error"));
        return result.opt("value");
    }
    static JSONObject object(String op,Object... pairs) throws Exception {return (JSONObject)invoke(op,pairs);}
    static JSONArray array(byte[] data) {JSONArray a=new JSONArray();for(byte b:data)a.put(b&255);return a;}
    static byte[] bytes(JSONArray data) throws JSONException {byte[] b=new byte[data.length()];for(int i=0;i<b.length;i++)b[i]=(byte)data.getInt(i);return b;}
}
