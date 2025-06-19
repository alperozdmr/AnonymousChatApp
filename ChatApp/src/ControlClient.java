package ChatApp.src;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;

public class ControlClient {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private ChatClientGUI gui;
    private KeyManager key;
    private static final String CONTROL_HOST = "127.0.0.1";
    private static final int    CONTROL_PORT = 9001;

    public ControlClient(ChatClientGUI gui) throws IOException {
        this.gui = gui;
        socket = new Socket(CONTROL_HOST, CONTROL_PORT);
        in     = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out    = new PrintWriter(socket.getOutputStream(), true);
    }

    /** Gelen satırları GUI'ye ileten dinleyici */
    public void startListening() {
        new Thread(() -> {
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    gui.handleControlMessage(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }, "ControlClient-Listener").start();
    }

    /** Ham komutu ve Base64(payload) olarak yollayan temel method */
    public void sendCommand(String command, byte[] payload) {
        String b64 = Base64.getEncoder().encodeToString(payload);
        out.println(command + " " + b64);
    }

    /** NEW_USER TLV paketini oluşturup yollayan method */
    public void sendNewUser(String nickname) throws IOException {
        // 1) public.key dosyasını oku (Base64 formatta)
        String pubB64 = Files.readString(Paths.get("public.key"), StandardCharsets.UTF_8);

        // 2) TLV paket hazırla: [type=1][nickLen][nick][keyLen][keyBytes]
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos       = new DataOutputStream(baos);

        dos.writeInt(1);  // NEW_USER tipi
        byte[] nickBytes = nickname.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(nickBytes.length);
        dos.write(nickBytes);

        byte[] keyBytes = Base64.getDecoder().decode(pubB64);
        dos.writeInt(keyBytes.length);
        dos.write(keyBytes);
        dos.flush();

        // 3) Gönder
        sendCommand("NEW_USER", baos.toByteArray());
        gui.appendSystemMessage("NEW_USER broadcast sent.");
    }

    /** KEY_REQUEST TLV paketini oluşturup yollayan method */
    public void sendKeyRequest(String nickname) throws IOException {
        // TLV paket: [type=2][nickLen][nick]
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos       = new DataOutputStream(baos);

        dos.writeInt(2);  // KEY_REQUEST tipi
        byte[] nickBytes = nickname.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(nickBytes.length);
        dos.write(nickBytes);
        
        dos.flush();

        sendCommand("KEY_REQUEST", baos.toByteArray());
        gui.appendSystemMessage("KEY_REQUEST broadcast sent.");
    }

    public void sendChat(String nickname, String message) throws IOException {
        
    	try {
            // 1) Mesajı private key ile şifrele
            PrivateKey priv = gui.getKeyManager().getPrivateKey();
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, priv);
            byte[] cipherBytes = rsa.doFinal(message.getBytes(StandardCharsets.UTF_8));

            // 2) TLV: [4][nickLen][nick][cipherLen][cipherBytes]
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeInt(4);                              // CHAT
            byte[] nickBytes = nickname.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(nickBytes.length);  dos.write(nickBytes);

            dos.writeInt(cipherBytes.length); dos.write(cipherBytes);
            dos.flush();

            sendCommand("CHAT", baos.toByteArray());      // TCP→Python
            gui.appendSystemMessage("CHAT sent ("+cipherBytes.length+" bytes enc).");

        } catch (GeneralSecurityException gse) {
            gui.appendSystemMessage("RSA encrypt error: " + gse.getMessage());
        }
    }
    /** KEY_RESPONSE TLV paketini oluşturup yollayan method */
    public void sendKeyResponse(String requesterNick) throws IOException {
        // 1) public.key dosyasını oku (Base64 formatta)
        String pubB64 = Files.readString(Paths.get("public.key"), StandardCharsets.UTF_8);
        byte[] keyBytes = Base64.getDecoder().decode(pubB64);

        // 2) TLV paket hazırla: [type=5][nickLen][nick][keyLen][keyBytes]
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos       = new DataOutputStream(baos);

        dos.writeInt(5);  // KEY_RESPONSE tipi
        //byte[] nickBytes = requesterNick.getBytes(StandardCharsets.UTF_8);
        byte[] nickBytes = gui.getNickname().getBytes(StandardCharsets.UTF_8);
        dos.writeInt(nickBytes.length);
        dos.write(nickBytes);

        dos.writeInt(keyBytes.length);
        dos.write(keyBytes);
        int nonce = new SecureRandom().nextInt();  // 4-byte rastgele
        dos.writeInt(nonce);
        dos.flush();

        // 3) Gönder
        sendCommand("KEY_RESPONSE", baos.toByteArray());
        gui.appendSystemMessage("KEY_RESPONSE sent to " + requesterNick);
    }
    public void sendDirectKeyRequest(String fromNick, String toNick) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos       = new DataOutputStream(baos);

        dos.writeInt(6);        
        byte[] nickBytes = fromNick.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(nickBytes.length);
        dos.write(nickBytes);
        byte[] TonickBytes = toNick.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(TonickBytes.length);
        dos.write(TonickBytes);
        int nonce = new SecureRandom().nextInt();  // 4-byte rastgele
        dos.writeInt(nonce);
        dos.flush();
        sendCommand("DIR_KEY_REQ", baos.toByteArray());
        gui.appendSystemMessage("Direct KEY_REQUEST " + fromNick + " → " + toNick);
    }


    /** QUIT tipi = 3 */
    public void sendQuit(String nickname) throws IOException {
        byte[] nickBytes = nickname.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos       = new DataOutputStream(baos);

        dos.writeInt(3);                          // QUIT tipi
        dos.writeInt(nickBytes.length);
        dos.write(nickBytes);
        dos.flush();

        sendCommand("QUIT", baos.toByteArray());
        socket.close();
        gui.appendSystemMessage("QUIT sent.");
    }

   
    
}
