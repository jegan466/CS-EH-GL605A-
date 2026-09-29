// ======================================================
// DATA ENCRYPTION AND DECRYPTION TOOL
// AES-GCM + RSA-OAEP
// ======================================================

let rsaKeyPair = null;


// ======================================================
// STATUS MESSAGE
// ======================================================

function showStatus(message, type = "normal") {

    const status = document.getElementById("status");

    status.textContent = message;

    if (type === "success") {
        status.style.color = "#00ffb3";
    }

    else if (type === "error") {
        status.style.color = "#ff6b6b";
    }

    else {
        status.style.color = "#5ee7ff";
    }
}


// ======================================================
// AES KEY DERIVATION
// ======================================================

async function getAESKey(password, salt) {

    const encoder = new TextEncoder();

    const passwordData =
        encoder.encode(password);

    const baseKey =
        await crypto.subtle.importKey(
            "raw",
            passwordData,
            "PBKDF2",
            false,
            ["deriveKey"]
        );

    return crypto.subtle.deriveKey(

        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },

        baseKey,

        {
            name: "AES-GCM",
            length: 256
        },

        false,

        [
            "encrypt",
            "decrypt"
        ]
    );
}


// ======================================================
// AES ENCRYPTION
// ======================================================

async function encryptAES(message) {

    const password =
        prompt("Enter a secret password for AES encryption:");

    if (!password) {
        throw new Error("Secret password is required.");
    }

    const encoder = new TextEncoder();

    const data =
        encoder.encode(message);


    // Generate random salt
    const salt =
        crypto.getRandomValues(
            new Uint8Array(16)
        );


    // Generate random IV
    const iv =
        crypto.getRandomValues(
            new Uint8Array(12)
        );


    const key =
        await getAESKey(password, salt);


    const encrypted =
        await crypto.subtle.encrypt(

            {
                name: "AES-GCM",
                iv: iv
            },

            key,

            data
        );


    const result = {

        algorithm: "AES-GCM",

        salt:
            arrayBufferToBase64(salt),

        iv:
            arrayBufferToBase64(iv),

        data:
            arrayBufferToBase64(encrypted)

    };


    return JSON.stringify(result);
}


// ======================================================
// AES DECRYPTION
// ======================================================

async function decryptAES(encryptedText) {

    const password =
        prompt("Enter the AES secret password:");

    if (!password) {
        throw new Error("Secret password is required.");
    }


    const encryptedObject =
        JSON.parse(encryptedText);


    const salt =
        base64ToUint8Array(
            encryptedObject.salt
        );

    const iv =
        base64ToUint8Array(
            encryptedObject.iv
        );

    const encryptedData =
        base64ToUint8Array(
            encryptedObject.data
        );


    const key =
        await getAESKey(password, salt);


    const decrypted =
        await crypto.subtle.decrypt(

            {
                name: "AES-GCM",
                iv: iv
            },

            key,

            encryptedData
        );


    const decoder =
        new TextDecoder();


    return decoder.decode(decrypted);
}


// ======================================================
// GENERATE RSA KEY PAIR
// ======================================================

async function generateRSAKeys() {

    if (rsaKeyPair) {
        return;
    }


    showStatus("Generating RSA keys...");


    rsaKeyPair =
        await crypto.subtle.generateKey(

            {
                name: "RSA-OAEP",

                modulusLength: 2048,

                publicExponent:
                    new Uint8Array(
                        [1, 0, 1]
                    ),

                hash: "SHA-256"
            },

            true,

            [
                "encrypt",
                "decrypt"
            ]
        );


    showStatus(
        "RSA key pair generated.",
        "success"
    );
}


// ======================================================
// RSA ENCRYPTION
// ======================================================

async function encryptRSA(message) {

    await generateRSAKeys();


    const encoder =
        new TextEncoder();


    const data =
        encoder.encode(message);


    const encrypted =
        await crypto.subtle.encrypt(

            {
                name: "RSA-OAEP"
            },

            rsaKeyPair.publicKey,

            data
        );


    return arrayBufferToBase64(
        encrypted
    );
}


// ======================================================
// RSA DECRYPTION
// ======================================================

async function decryptRSA(encryptedText) {

    if (!rsaKeyPair) {

        throw new Error(
            "RSA key pair not available. Encrypt something first."
        );
    }


    const encrypted =
        base64ToUint8Array(
            encryptedText
        );


    const decrypted =
        await crypto.subtle.decrypt(

            {
                name: "RSA-OAEP"
            },

            rsaKeyPair.privateKey,

            encrypted
        );


    const decoder =
        new TextDecoder();


    return decoder.decode(decrypted);
}


// ======================================================
// MAIN ENCRYPT FUNCTION
// ======================================================

async function encryptData() {

    const algorithm =
        document.getElementById(
            "algorithm"
        ).value;


    const input =
        document.getElementById(
            "inputText"
        ).value.trim();


    if (!input) {

        showStatus(
            "Please enter a message.",
            "error"
        );

        return;
    }


    try {

        showStatus(
            "Encrypting..."
        );


        let result;


        if (algorithm === "AES") {

            result =
                await encryptAES(input);

        }

        else {

            result =
                await encryptRSA(input);

        }


        document.getElementById(
            "outputText"
        ).value = result;


        showStatus(
            algorithm +
            " encryption successful!",
            "success"
        );

    }

    catch (error) {

        console.error(error);

        showStatus(
            "Encryption failed: " +
            error.message,
            "error"
        );
    }
}


// ======================================================
// MAIN DECRYPT FUNCTION
// ======================================================

async function decryptData() {

    const algorithm =
        document.getElementById(
            "algorithm"
        ).value;


    const input =
        document.getElementById(
            "inputText"
        ).value.trim();


    if (!input) {

        showStatus(
            "Paste encrypted data into the input box.",
            "error"
        );

        return;
    }


    try {

        showStatus(
            "Decrypting..."
        );


        let result;


        if (algorithm === "AES") {

            result =
                await decryptAES(input);

        }

        else {

            result =
                await decryptRSA(input);

        }


        document.getElementById(
            "outputText"
        ).value = result;


        showStatus(
            algorithm +
            " decryption successful!",
            "success"
        );

    }

    catch (error) {

        console.error(error);

        showStatus(
            "Decryption failed. Check your data/key.",
            "error"
        );
    }
}


// ======================================================
// COPY OUTPUT
// ======================================================

async function copyOutput() {

    const output =
        document.getElementById(
            "outputText"
        );


    if (!output.value) {

        showStatus(
            "Nothing to copy.",
            "error"
        );

        return;
    }


    await navigator.clipboard.writeText(
        output.value
    );


    showStatus(
        "Output copied to clipboard!",
        "success"
    );
}


// ======================================================
// CLEAR
// ======================================================

function clearData() {

    document.getElementById(
        "inputText"
    ).value = "";


    document.getElementById(
        "outputText"
    ).value = "";


    showStatus(
        "Ready"
    );
}


// ======================================================
// CONVERSION FUNCTIONS
// ======================================================

function arrayBufferToBase64(buffer) {

    let binary = "";

    const bytes =
        new Uint8Array(buffer);


    bytes.forEach(
        byte => binary +=
            String.fromCharCode(byte)
    );


    return btoa(binary);
}


function base64ToUint8Array(base64) {

    const binary =
        atob(base64);


    const bytes =
        new Uint8Array(
            binary.length
        );


    for (
        let i = 0;
        i < binary.length;
        i++
    ) {

        bytes[i] =
            binary.charCodeAt(i);

    }


    return bytes;
}