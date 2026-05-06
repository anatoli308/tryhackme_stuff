if (typeof forge === "undefined") {
    const script = document.createElement("script");
    script.src = "https://cdnjs.cloudflare.com/ajax/libs/forge/1.3.0/forge.min.js";
    document.head.appendChild(script);
}

const serverPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvwpg2aBRLT9RftlcE8Qn
cmYi2weLT0EnHwXDsAE4A/zvR1dT9X4pFIrNXVnTKlIq8RBMilyoTn3GHUgJoFHG
GdqZfnCCHxf0IVX2NhpYi1HqZeXNCgqY4FtMH9WvjYEH2/twhUnvymT8egG3c50a
pT8sTsJrhWi2M+lhQ2yYXGecZHgAM7EddavpyTEdMw1xhIeeNHo1QxPjii1+dJIU
8iIJ8F3NQtukTe/EQyTjJGx7qDxVobO+njnnreqdqHZ6PqYD/6jlm9myXtUuJQqg
xMWwbxJNuS5Ay9JQSRGEfwEugJHuKEuofJdTkW/PibG9G3zaws4Nhmco8rw59j1r
bQIDAQAB
-----END PUBLIC KEY-----`;

const clientPrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCHFhkwcfgZNVDe
KogLYzQSTTr8wgCi7WNepqeMuTTSXIX22SbzlK/gYlKtPPPxi2JzCkfa9VnTLsTd
3M4ZAL6d0rfo3L0KJ/SKMPq8VnGV9/y5YGyPmgbE1Dy8R2llP0m5GuO4giAoahZX
ePHsPbhNxtQuNW/EiGKcZaz5GQHILEQk2/0ZzqT0e/8jQMljpnbMUoGKe4yhT4JG
QGB7w7wPtQpFhDcASctUO8j3bcOL8tyrPfUcpNKFrkSNY0XT1gqnOuKe29YP0YnC
3bE/m5UPn7atBxP/4FrVRaQvM2S9ta+tZiDU5jP+xU3sBmMLlZByY5KiEeUGkvEz
FjfaMHihAgMBAAECggEAAMiqAvD721dW47Gh7EU+L/Of1afxZ5CeoaXQWcOoutZh
qn5tRHdAv6HJbJb6nESKkMvi0apoG+6g4r/PaDer63v1sEuw2v9jKta8uzlaD5B+
uGOG4LzQSI3J2A625dEImjLlxrAmXC6sqFN3zaboaAbg+/9IUabYEePRBYlhpEv7
jP9IquO6pO3q13gDhot0fS7MM4sTfYKdPfb8qEwYCpsz3Qi7lFdbBqZxz/O/tkPq
giNJNJnHBLmXNOIdSCocMldIhZaPMmcDODPXAehmrru7l/Kh5hnfdK7Njcoph5T4
EJqAPOU7XVSyBeJKiKj1x/S+2jzLn8s3hOKCiBbbwQKBgQC+IvSbRXVA16he1yBE
183VRAALdVRDDTZcFALaexuNfly2SMU9SL/AAFrbNMaQ83y79XtAbDqk8C6YRhyi
z2Il9puVu8G61UB2lWzD5DvDYbb4OS+AroluYZQzeR1+02sZUkR4R0QnfNRQUtMR
3awfBIgf9B6Kr90Dnn/OLmQrYQKBgQC14V2azqz4Nkg4bg1LLk612H2fhwz38Evj
mlMmxAxdIqGJUz+wGb3tSGmGz7fPxmIga9k8n22nMpfZOyyGF9D93LVa+/9NeFEV
DWH5yph+xBN7SSyQMb+Q1xD6gTigLmkIynUXzcucgZB8oUGtexR2IoFu3Li7R9F3
HYpUpsKVQQKBgQCFB3X20TEJbhm6SW+lWwwDY7FYUv3ib/MRl1qrvCh55eg+DUoa
57RpRJZM+m7XadRiuY1DdLXPQtCG778HVmvIPfN7XsNb0eppTYCsyhnaSJq4r2IB
+ZvkI9eJ7/poCsnLDJklQk94BUmS7XAJ9vt/NC99k9JunD7ZUmL/QcwJ4QKBgQCG
a812gJEt0VCHBC8nBU5+70XJBVL8W8h6qrAR0osguluQ1soXKK9KE16KmDJNiV00
gQDI4Tt1etrnXeiGIkv/k4Mlf2EsrGOgn4dtyeHyro+HaolY+KuQLKMLwT1MhYBz
Us4/jYWSYd+bfMLBqFlzBgWLHe4Z2/ZfhqGZ9rWRAQKBgGX7uHz9nUaldXxt4lBn
94FR8D6FJxyKGr0/35XrPE3gc1nDJIQGl62E9vk8eVuBsFgqhm2ISroRSxeRI6ml
djzuBNJ/gQ5hxhj7ifv1ZakiwvxR2D5uJBPU5gve19Fyrq5On6R+KvVR4b+vcZ5A
0HuYuUaGZhtLd9ouH49CvSXj
-----END PRIVATE KEY-----`;

// Convert PEM to RSA Key Object
function importPublicKey(pem) {
    return forge.pki.publicKeyFromPem(pem);
}

function importPrivateKey(pem) {
    return forge.pki.privateKeyFromPem(pem);
}

// Encrypt Data 
function encryptData(plainText) {
    const publicKey = importPublicKey(serverPublicKey);
    const encrypted = publicKey.encrypt(plainText); 
    return forge.util.encode64(encrypted); 
}

// Decrypt Data
function decryptData(encryptedData) {
    try {
        const privateKey = importPrivateKey(clientPrivateKey);
        const decrypted = privateKey.decrypt(forge.util.decode64(encryptedData)); 
        return decrypted;
    } catch (error) {
        console.error("Decryption error:", error);
        return "Decryption Failed";
    }
}

// Show Error in Alert Box (Stays Until Dismissed)
function showError(message) {
    const errorBox = document.getElementById("error-box");
    errorBox.innerText = message;
    errorBox.style.display = "block"; // Show error box

    // Add a close button
    if (!document.getElementById("close-error")) {
        const closeButton = document.createElement("span");
        closeButton.innerText = "";
        closeButton.id = "close-error";
        closeButton.style.cursor = "pointer";
        closeButton.style.float = "right";
        closeButton.style.fontSize = "1.2rem";
        closeButton.style.fontWeight = "bold";
        closeButton.style.marginLeft = "10px";

        closeButton.onclick = function () {
            errorBox.style.display = "none";
        };

        errorBox.appendChild(closeButton);
    }
}

function sanitizeInput(input) {
    return input
        .replace(/['"\\;#]/g, "") // Remove characters often used in SQL injection
        .replace(/\s{2,}/g, " ") // Collapse multiple spaces into one
        .trim(); // Remove leading/trailing spaces
}

// Login Function
async function login() {
    const username = sanitizeInput(document.getElementById("username").value.trim());
    const password = sanitizeInput(document.getElementById("password").value.trim());

    if (!username || !password) {
        showError("Username and password cannot be empty.");
        return;
    }

    const params = new URLSearchParams();
    params.append("action", "login");
    params.append("username", username);
    params.append("password", password);

    const requestData = params.toString();

    const encrypted = encryptData(requestData);

    const response = await fetch("server.php", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ data: encrypted })
    });

    const responseData = await response.json();

    if (responseData.data) {
        const decryptedResponse = decryptData(responseData.data);
        if (decryptedResponse.includes("Login successful")) {
            window.location.href = "dashboard.php";
        } else {
            showError(decryptedResponse);
        }
    } else {
        showError("Server Error: No response data received.");
    }
}