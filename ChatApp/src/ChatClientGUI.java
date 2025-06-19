package ChatApp.src;


import javax.crypto.Cipher;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.security.*;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;

public class ChatClientGUI extends JFrame {
    private JTextArea chatArea;
    private JTextField inputField;
    private JButton sendButton;
    private DefaultListModel<String> userListModel;
    private JList<String> userList;

    private KeyManager keyManager;
    private ControlClient controlClient;
    private String nickname;
    private KeyPair keyPair;
    private JMenuItem connectMenuItem;
    private JMenuItem disconnectMenuItem;

    public ChatClientGUI() {
        super("Anonymous Chat Application ClientA - 9001");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(600, 400);

        try {
            keyManager = new KeyManager();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                "KeyManager init error:\n" + ex.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }

        // Menü
        JMenuBar menuBar = new JMenuBar();
        JMenu fileMenu = new JMenu("File");
        fileMenu.add(new JMenuItem("Generate Keys") {{
            addActionListener(e -> generateKeys());
        }});
        connectMenuItem = new JMenuItem("Connect to Network");
        connectMenuItem.addActionListener(e -> connectToNetwork());
        fileMenu.add(connectMenuItem);

        disconnectMenuItem = new JMenuItem("Disconnect from Network");
        disconnectMenuItem.addActionListener(e -> disconnectFromNetwork());
        disconnectMenuItem.setEnabled(false);
        fileMenu.add(disconnectMenuItem);

        fileMenu.addSeparator();
        fileMenu.add(new JMenuItem("Exit") {{
            addActionListener(e -> System.exit(0));
        }});
        menuBar.add(fileMenu);

        JMenu helpMenu = new JMenu("Help");
        helpMenu.add(new JMenuItem("About") {{
            addActionListener(e -> showAboutDialog());
        }});
        menuBar.add(helpMenu);

        setJMenuBar(menuBar);

        // UI bileşenleri
        chatArea      = new JTextArea(); chatArea.setEditable(false);
        inputField    = new JTextField();
        sendButton    = new JButton("Send");
        sendButton.setEnabled(false);
        userListModel = new DefaultListModel<>();
        userList      = new JList<>(userListModel);

        sendButton.addActionListener(e -> sendMessage());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            new JScrollPane(chatArea),
            new JScrollPane(userList));
        split.setDividerLocation(400);

        JPanel inputPanel = new JPanel(new BorderLayout(5,5));
        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);

        add(split, BorderLayout.CENTER);
        add(inputPanel, BorderLayout.SOUTH);
    }

    private void connectToNetwork() {
        nickname = JOptionPane.showInputDialog(this, "Enter your nickname:");
        if (nickname == null || nickname.trim().isEmpty()) return;
        nickname = nickname.trim();
        appendSystemMessage("Connecting as: " + nickname);

        try {
            if (controlClient == null) {
                controlClient = new ControlClient(this);
                controlClient.startListening();
            }
            controlClient.sendNewUser(nickname);
            // 500 ms sonra key request
            new Timer(500, ev -> {
                try { controlClient.sendKeyRequest(nickname); }
                catch (IOException ex) { ex.printStackTrace(); }
                ((Timer)ev.getSource()).stop();
            }).start();

            sendButton.setEnabled(true);
            connectMenuItem .setEnabled(false);
            disconnectMenuItem.setEnabled(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this,
                "Connection error:\n" + ex.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private String readString(DataInputStream dis) throws IOException {
        int len = dis.readInt();
        byte[] buf = new byte[len];
        dis.readFully(buf);
        return new String(buf, StandardCharsets.UTF_8);
    }
    public void handleControlMessage(String msg) {
        SwingUtilities.invokeLater(() -> {
            try {
                // msg format: "RECV <base64_payload>"
                String[] parts = msg.split(" ", 2);
                if (!parts[0].equals("RECV")) return;

                byte[] payload = Base64.getDecoder().decode(parts[1]);
                DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload));
                int type = dis.readInt();
                
                String peerName = readString(dis);
                
                if(peerName.equalsIgnoreCase(nickname)) {
                	return ;
                }
                switch (type) {
                    case 1: // NEW_USER
                    	int keyLen = dis.readInt();
                        byte[] kb  = new byte[keyLen];
                        dis.readFully(kb);
                        String keyB64 = Base64.getEncoder().encodeToString(kb);
                        if (keyManager.hasPublicKey(peerName)) {
                            // ---> Artık kendi key’imi yollamayacağım.
                            // Sadece GUI’ye ekle, listede yoksa göster:
                            if (!userListModel.contains(peerName)) {
                                userListModel.addElement(peerName);
                            }
                            chatArea.append("[System] " + peerName + " yeniden katıldı (anahtar zaten kayıtlı)\n");
                            break;
                        }
                        keyManager.addKnownUser(peerName, keyB64);
                        userListModel.addElement(peerName);
                        chatArea.append("[System] " + peerName + " joined\n");
                        break;

                    case 2:// KEY_REQUEST
                        chatArea.append("[System] Key request from " + peerName + "\n");
                        controlClient.sendKeyResponse(peerName);
                        break;

                    case 3: // QUIT
                        userListModel.removeElement(peerName);
                        chatArea.append("[System] " + peerName + " left\n");
                        break;

                    case 4: // CHAT
//                        int ml = dis.readInt();
//                        byte[] mb = new byte[ml];
//                        dis.readFully(mb);
//                        String message = new String(mb, StandardCharsets.UTF_8);
////                        if (!userListModel.contains(peerName))
////                            userListModel.addElement(peerName);
//                        chatArea.append("[" + peerName + "] " + message + "\n");
//                        break;
                    	int msgLen = dis.readInt();
                        byte[] cipherBytes = new byte[msgLen];
                        dis.readFully(cipherBytes);

                        // 1) Gönderenin public-key’ini al
                        PublicKey senderPub = keyManager.getKnownPublicKey(peerName);
                        if (senderPub == null) {
                            chatArea.append("[Warn] unknown key for " + peerName + "\n");
                            try {
                            	controlClient.sendDirectKeyRequest(nickname, peerName);   // ► eksik anahtar için hemen iste
                            } catch (IOException io) {
                                chatArea.append("[Err] couldn't send KEY_REQUEST for " + peerName + "\n");
                            }
                            break;
                        }
                        try {
                            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            rsa.init(Cipher.DECRYPT_MODE, senderPub);
                            byte[] plain = rsa.doFinal(cipherBytes);
                            String message = new String(plain, StandardCharsets.UTF_8);

                            if (!userListModel.contains(peerName))
                                userListModel.addElement(peerName);

                            chatArea.append("[" + peerName + "] " + message + "\n");
                        } catch (GeneralSecurityException gse) {
                            chatArea.append("[Err] decrypt failed from " + peerName + "\n");
                        }
                        break;
                    case 5: // KEY_RESPONSE

                    	  int keyLen2 = dis.readInt();
                          byte[] kb2  = new byte[keyLen2];
                          dis.readFully(kb2);
                          String keyB642 = Base64.getEncoder().encodeToString(kb2);
                          if (keyManager.hasPublicKey(peerName)) {
                              // ---> Artık kendi key’imi yollamayacağım.
                              // Sadece GUI’ye ekle, listede yoksa göster:
                              if (!userListModel.contains(peerName)) {
                                  userListModel.addElement(peerName);
                              }
                              chatArea.append("[System] " + peerName + " (anahtar zaten kayıtlı)\n");
                              break;
                          }
                          // Anahtarı kaydet + UI’a yansıt
                          keyManager.addKnownUser(peerName, keyB642);
                        if (!userListModel.contains(peerName))
                            userListModel.addElement(peerName);

                        chatArea.append("[System] KEY_RESPONSE from " + peerName + "\n");
                        break;
                    case 6:      // 6
                        
                        String reqTo   = readString(dis);   // kimden istiyor

                        // Bu istek bana geldiyse (reqTo == benim nick)
                        if (reqTo.equalsIgnoreCase(nickname)) {
                            chatArea.append("[System] Direct key request from " + peerName + "\n");

                            // elimde anahtarı varsa hemen KEY_RESPONSE gönder
                            
                                controlClient.sendKeyResponse(peerName);
                            
                        }
                        break;

                    default:
                        chatArea.append("[Warn] Unknown type: " + type + "\n");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }
    private void generateKeys() {
        try {

        	keyManager.loadOrGenerateLocalKeys();

            // 4) Kullanıcıyı bilgilendir
            chatArea.append("[System] RSA anahtar çifti oluşturuldu ve kaydedildi.\n");
            JOptionPane.showMessageDialog(this,
                "RSA 2048-bit anahtar çifti başarıyla oluşturuldu.\n" +
                "public.key  → genel anahtar\n" +
                "private.key → özel anahtar",
                "Anahtarlar Oluşturuldu",
                JOptionPane.INFORMATION_MESSAGE);

        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this,
                "Anahtar oluşturma hatası:\n" + ex.getMessage(),
                "Hata",
                JOptionPane.ERROR_MESSAGE);
        }
    }
    public void appendSystemMessage(String msg) {
        chatArea.append("[System] " + msg + "\n");
    }

    private void disconnectFromNetwork() {
        // TODO: Quit mesajı yayınla
    	 int res = JOptionPane.showConfirmDialog(this,
    	            "Are you sure you want to disconnect?",
    	            "Disconnect",
    	            JOptionPane.YES_NO_OPTION);
    	        if (res != JOptionPane.YES_OPTION) return;

    	        try {
    	            controlClient.sendQuit(nickname);
    	           
    	        } catch (IOException ex) {
    	            ex.printStackTrace();
    	        }

    	        
    	        sendButton.setEnabled(false);
    	        connectMenuItem.setEnabled(true);
    	        disconnectMenuItem.setEnabled(false);
        chatArea.append("[System] You have disconnected.\n");
    }

    private void exitApplication() {
        System.exit(0);
    }

    private void showAboutDialog() {
        JOptionPane.showMessageDialog(this,
            "Anonymous Chat Application\n" +
            "Developer: [Adınız Soyadınız]\n" +
            "Course: CSE471 – Spring 2025",
            "About",
            JOptionPane.INFORMATION_MESSAGE);
    }

    private void sendMessage() {
    	  String message = inputField.getText().trim();
          if (message.isEmpty()) return;

          try {
              // 1) GUI’ye ekle
              chatArea.append("Me: " + message + "\n");
              inputField.setText("");

              // 2) ControlClient üzerinden gönder
              controlClient.sendChat(nickname, message);
          } catch (IOException ex) {
              ex.printStackTrace();
              JOptionPane.showMessageDialog(this,
                  "Mesaj gönderilemedi:\n" + ex.getMessage(),
                  "Error", JOptionPane.ERROR_MESSAGE);
          }
    }
    public KeyManager getKeyManager() {
        return keyManager;
    }
    public String getNickname() {
    	return nickname;
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            ChatClientGUI client = new ChatClientGUI();
            client.setResizable(false);
            client.setVisible(true);
        });
    }
}
