const CryptoJS = require('crypto-js');
const SECRET_KEY = process.env.REACT_APP_SECRETKEY;
const excludedTables = ['users', 'authentication','permissionServices'];

export function encryptData(data) {
    if (!SECRET_KEY) {
        console.error('Encryption Key is missing!');
        return context;
    }

    try {
        if (!data) throw new Error('No data provided for encryption');
        const ciphertext = CryptoJS.AES.encrypt(JSON.stringify(data), SECRET_KEY).toString();
        return ciphertext;
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

export function decryptData(ciphertext) {
    try {
        if (!ciphertext) throw new Error('No ciphertext provided for decryption');
        const bytes = CryptoJS.AES.decrypt(ciphertext, SECRET_KEY);
        const decryptedDataString = bytes.toString(CryptoJS.enc.Utf8);
        if (!decryptedDataString) {
            console.error('Decryption resulted in empty data. Ciphertext:', ciphertext);
            return null;
        }
        return JSON.parse(decryptedDataString);
    } catch (error) {
        console.error('Decryption failed:', error);
        return null;
    }
}

// Feathers Client Hook - Decrypt Response
export const decryptResponseClientHook = (context) => {
    const { result, path } = context;
    if (!result) return context;
    if (result && result.encrypted) {
        if (!excludedTables.includes(path)) context.result = decryptData(result.encrypted);
    }
    return context;
};

// Feathers Client Hook - Encrypt Request
export const encryptRequestClientHook = (context) => {
    const { path, data, params, method } = context;
    if (params && params.query) {
        if (params.query) {
            context.params.query = {
                encrypted: encryptData(params.query)
            };
        }
    }

    if (data && !data.encrypted) {
        if (!excludedTables.includes(path)) {
            context.data = {
                encrypted: encryptData(data)
            };
        }
    }
    return context;
};
