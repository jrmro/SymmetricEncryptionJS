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
* async function example() {
*
*   const originalData = "Hello, this is a secret message.";
*
*   const encryptor = new SymmetricEncryption('AES-CBC'); // Initialize with optional encryption algorithm (default: 'AES-CBC')
*
*   // Create a secretKey from a password (optional). You can bring your own key too (must be a Base64-encoded string).
*   const secretKey = await encryptor.deriveKey("YourPassword"); // Replace with your actual password
*
*   const encryptedData = await encryptor.encrypt(originalData, secretKey);
*   console.log("Encrypted Data:", encryptedData);
*
*   const decryptedData = await encryptor.decrypt(encryptedData, secretKey);
*   console.log("Decrypted Data:", decryptedData);
* 
* }
*
* example();
*
* @license    MIT License
* @author     Joseph Romero
* @version    2.0.0
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
            true,                                  
            ['encrypt', 'decrypt']                  
        );
    
        // Convert the secret key to a base 64 string
        const secretKeyArray = new Uint8Array(await crypto.subtle.exportKey('raw', secretKey));
        const base64SecretKey = btoa(String.fromCharCode.apply(null, secretKeyArray));
        
        return base64SecretKey;
        
    }
    
    async encrypt(data, secretKey) {

        const isValidKey = typeof secretKey === 'string' && btoa(atob(secretKey)) === secretKey;
        if ( ! isValidKey) {
            console.error('secretKey must be a Base64-encoded string');
            return null;
        }
    
        const secretKeyArray = new Uint8Array(atob(secretKey).split('').map(char => char.charCodeAt(0)));
    
        // Import the secret key as a CryptoKey
        const importedSecretKey = await crypto.subtle.importKey(
            'raw',
            secretKeyArray,
            { name: this.algorithm },
            false,
            ['encrypt']
        );
    
        const nonce = crypto.getRandomValues(new Uint8Array(16));
    
        const encrypted = await crypto.subtle.encrypt(
            { name: this.algorithm, iv: nonce },
            importedSecretKey,
            new TextEncoder().encode(data)
        );
    
        const combinedData = new Uint8Array(nonce.length + new Uint8Array(encrypted).length);
        combinedData.set(nonce, 0);
        combinedData.set(new Uint8Array(encrypted), nonce.length);
        const base64Data = btoa(String.fromCharCode.apply(null, new Uint8Array(combinedData)));
    
        return base64Data;

    }
    
    async decrypt(encrypted, secretKey) {

        const isValidKey = typeof secretKey === 'string' && btoa(atob(secretKey)) === secretKey;
        if ( ! isValidKey) {
            console.error('secretKey must be a Base64-encoded string');
            return null;
        }
    
        const secretKeyArray = new Uint8Array(atob(secretKey).split('').map(char => char.charCodeAt(0)));
    
        // Import the secret key as a CryptoKey
        const importedSecretKey = await crypto.subtle.importKey(
            'raw',
            secretKeyArray,
            { name: this.algorithm },
            false,
            ['decrypt']
        );
    
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
            importedSecretKey,
            encryptedData
        );
    
        return new TextDecoder().decode(new Uint8Array(decrypted));

    }
       
}
