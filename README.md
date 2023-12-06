# Symmetric Encryption JS Class

This JavaScript class provides methods for symmetric encryption and decryption using the Web Crypto API. It encapsulates the necessary logic for encrypting and decrypting data with a secret key.

(Note: For server-side PHP symmetric encryption, see [https://github.com/jrmro/SymmetricEncryption](https://github.com/jrmro/SymmetricEncryption)).

## Sample Usage

```
const originalData = "Hello, this is a secret message.";

const encryptor = new SymmetricEncryption('AES-CBC'); // Initialize with optional encryption algorithm (default: 'AES-CBC')

// Create a secretKey from a password (optional). You can bring your own key too (must be a CryptoKey object).
const secretKey = await encryptor.deriveKey("YourPassword"); // Replace with your actual password

const encryptedData = await encryptor.encrypt(originalData, secretKey);
console.log("Encrypted Data:", encryptedData);

const decryptedData = await encryptor.decrypt(encryptedData, secretKey);
console.log("Decrypted Data:", decryptedData);
```

## Note
* If deriving a secret key from a password, ensure you replace 'YourPassword' with your actual password in the example.
* Alternatively, if bringing your own secret key, assign it to the `secretKey` constant instead of using `encryptor.deriveKey("YourPassword")`. 
* The class uses the Web Crypto API [https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
* Handle and store your secret key securely. Do not hardcode it in your project.

## License
This code is released under the MIT License.
