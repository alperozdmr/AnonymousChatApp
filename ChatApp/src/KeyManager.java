package ChatApp.src;


import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Base64;

public class KeyManager {
    private static final String PRIVATE_KEY_FILE = "private.key";
    private static final String PUBLIC_KEY_FILE  = "public.key";
    private static final String KNOWN_KEYS_FILE  = "known_keys.properties";

    // Local key pair
    private KeyPair keyPair;

    // Diğer kullanıcıların public key'leri
    private Map<String, PublicKey> knownKeys = new HashMap<>();

    public KeyManager() throws Exception {

    }

    // 1) Eğer diskten yoksa new, varsa yükle
    public void loadOrGenerateLocalKeys() throws Exception {
        Path privPath = Paths.get(PRIVATE_KEY_FILE);
        Path pubPath  = Paths.get(PUBLIC_KEY_FILE);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        if (Files.exists(privPath) && Files.exists(pubPath)) {
            // Dosyalardan Base64 decode edip KeyPair oluştur
            byte[] privBytes = Base64.getDecoder().decode(Files.readAllBytes(privPath));
            byte[] pubBytes  = Base64.getDecoder().decode(Files.readAllBytes(pubPath));

            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
            X509EncodedKeySpec  pubSpec  = new X509EncodedKeySpec(pubBytes);

            PrivateKey priv = kf.generatePrivate(privSpec);
            PublicKey  pub  = kf.generatePublic(pubSpec);
            keyPair = new KeyPair(pub, priv);
        } else {
            // KeyPair üret
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            keyPair = kpg.generateKeyPair();

            // Dosyalara Base64 ile yaz
            Files.write(privPath, Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()));
            Files.write(pubPath,  Base64.getEncoder().encode(keyPair.getPublic().getEncoded()));

            // Private key dosyasını sadece okunabilir yap
            privPath.toFile().setReadable(true, true);
            privPath.toFile().setWritable(false, true);
        }
    }

    // 2) known_keys.properties dosyasını yükle
    private void loadKnownKeysFromDisk() throws Exception {
        File file = new File(KNOWN_KEYS_FILE);
        if (!file.exists()) return;

        Properties props = new Properties();
        try (FileInputStream in = new FileInputStream(file)) {
            props.load(in);
        }

        KeyFactory kf = KeyFactory.getInstance("RSA");
        Base64.Decoder dec = Base64.getDecoder();

        for (String nickname : props.stringPropertyNames()) {
            byte[] pubBytes = dec.decode(props.getProperty(nickname));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pubBytes);
            PublicKey pub = kf.generatePublic(spec);
            knownKeys.put(nickname, pub);
        }
    }

    // 3) Yeni bir kullanıcının public key'ini ekleyip diske yaz
    public void addKnownUser(String nickname, String base64PublicKey) throws Exception {
        // Belleğe ekle
        byte[] pubBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(pubBytes);
        PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(spec);
        knownKeys.put(nickname, pub);

        // Properties dosyasını güncelle
        Properties props = new Properties();
        File file = new File(KNOWN_KEYS_FILE);
        if (file.exists()) {
            try (FileInputStream in = new FileInputStream(file)) {
                props.load(in);
            }
        }
        props.setProperty(nickname, base64PublicKey);
        try (FileOutputStream out = new FileOutputStream(file)) {
            props.store(out, "Known users' public keys");
        }
    }
    public boolean hasPublicKey(String peerName) {
        return knownKeys.containsKey(peerName);
    }

    public PublicKey getKnownPublicKey(String nickname) {
        return knownKeys.get(nickname);
    }

    public KeyPair getLocalKeyPair() {
        return keyPair;
    }
    public PrivateKey getPrivateKey() {
  	  return keyPair.getPrivate();
  	}

  	public PublicKey getLocalPublicKey() {
  	  return keyPair.getPublic();
  	}
    
}

