package dev.umsh.android;
import android.content.Context;
import android.security.keystore.*;
import android.util.Base64;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
/** Keys are encrypted at rest with a non-exportable Android Keystore key. */
final class Vault {
    private final Context context;
    Vault(Context c){context=c;}
    private Key key() throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        if(!store.containsAlias("umsh.v1")){
            KeyGenerator generator=KeyGenerator.getInstance("AES","AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder("umsh.v1",KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build());
            generator.generateKey();
        }
        return store.getKey("umsh.v1",null);
    }
    String seal(byte[] bytes) throws Exception {
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());
        return Base64.encodeToString(cipher.getIV(),Base64.NO_WRAP)+":"+Base64.encodeToString(cipher.doFinal(bytes),Base64.NO_WRAP);
    }
    byte[] unseal(String text) throws Exception {
        String[] parts=text.split(":"); if(parts.length!=2)throw new GeneralSecurityException("Invalid key record");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,Base64.decode(parts[0],Base64.NO_WRAP)));
        return cipher.doFinal(Base64.decode(parts[1],Base64.NO_WRAP));
    }
    byte[] identity() throws Exception {
        var preferences=context.getSharedPreferences("identity",0);
        String saved=preferences.getString("secret",null);
        if(saved!=null)return unseal(saved);
        byte[] secret=new byte[32];new SecureRandom().nextBytes(secret);
        if(!preferences.edit().putString("secret",seal(secret)).commit())throw new Exception("Could not save your identity");
        return secret;
    }
}
