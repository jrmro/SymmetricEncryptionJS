/**
* https://github.com/jrmro/SymmetricEncryptionJS
* 
* This JavaScript class provides methods for symmetric encryption and decryption using the Web Crypto API. 
* It encapsulates the necessary logic for encrypting and decrypting data with a secret key.
*
* (Note: For server-side PHP symmetric encryption, see https://github.com/jrmro/SymmetricEncryption).
*
* Example Usage:
*
* const originalData = "Hello, this is a secret message.";
*
* const encryptor = new SymmetricEncryption('AES-CBC'); // Initialize with optional encryption algorithm (default: 'AES-CBC')
*
* // Create a secretKey from a password (optional). You can bring your own key too (must be a CryptoKey object).
* const secretKey = await encryptor.deriveKey("YourPassword"); // Replace with your actual password
*
* const encryptedData = await encryptor.encrypt(originalData, secretKey);
* console.log("Encrypted Data:", encryptedData);
*
* const decryptedData = await encryptor.decrypt(encryptedData, secretKey);
* console.log("Decrypted Data:", decryptedData);
*
* @license    MIT License
* @author     Joseph Romero
* @version    1.0.0
* ...
*/

class SymmetricEncryption {

    constructor(algorithm = 'AES-CBC') {
        this.algorithm = algorithm;
    }

    async deriveKey(password) {

        const masterKey = await crypto.subtle.importKey(
            'raw',                                 
            new TextEncoder().encode(password),     
            { name: 'PBKDF2' },                 
            false,                                
            ['deriveKey']                          
        );

        const secretKey = await crypto.subtle.deriveKey(
            { 
                name: 'PBKDF2',
                hash: 'SHA-256', 
                salt: new TextEncoder().encode(crypto.getRandomValues(new Uint8Array(16))), 
                iterations: 100000 
            },                                     
            masterKey,                              
            { name: this.algorithm, length: 256 },  
            false,                                  
            ['encrypt', 'decrypt']                  
        );
        
        return secretKey;
        
    }

    async encrypt(data, secretKey) {

        if ( ! (secretKey instanceof CryptoKey)) {
            console.error('secretKey must be a CryptoKey object');
            return null;
        }

        const nonce = crypto.getRandomValues(new Uint8Array(16));

        const encrypted = await crypto.subtle.encrypt(
            { name: this.algorithm, iv: nonce }, 
            secretKey, 
            new TextEncoder().encode(data)
        );
        
        const combinedData = new Uint8Array(nonce.length + new Uint8Array(encrypted).length);
        combinedData.set(nonce, 0);
        combinedData.set(new Uint8Array(encrypted), nonce.length);
        const base64Data = btoa(String.fromCharCode.apply(null, new Uint8Array(combinedData)));
        
        return base64Data;

    }

    async decrypt(encrypted, secretKey) {

        if ( ! (secretKey instanceof CryptoKey)) {
            console.error('secretKey must be a CryptoKey object');
            return null;
        }
        
        const decoded = (base64 => {
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        })(encrypted);

        const iv = decoded.slice(0, 16);
        const encryptedData = decoded.slice(16);

        const decrypted = await crypto.subtle.decrypt(
            { name: this.algorithm, iv }, 
            secretKey, 
            encryptedData
        );

        return new TextDecoder().decode(new Uint8Array(decrypted));

    }

}
