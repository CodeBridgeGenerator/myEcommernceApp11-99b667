const CryptoJS = require('crypto-js');

function encryptData(app, data) {
    const SECRET_KEY = app.get('authentication').secret;
    try {
        if (!data) throw new Error('No data provided for encryption');
        const ciphertext = CryptoJS.AES.encrypt(
            JSON.stringify(data),
            SECRET_KEY
        ).toString();
        return ciphertext;
    } catch (error) {
        console.error('Encryption error:', error);
        throw error;
    }
}

function decryptData(app, ciphertext) {
    const SECRET_KEY = app.get('authentication').secret;
    try {
        if (!ciphertext)
            throw new Error('No ciphertext provided for decryption');
        const bytes = CryptoJS.AES.decrypt(ciphertext, SECRET_KEY);
        const decryptedData = bytes.toString(CryptoJS.enc.Utf8);
        if (!decryptedData) throw new Error('Decryption failed - empty result');
        return JSON.parse(decryptedData);
    } catch (error) {
        console.error('Decryption error:', error);
        throw error;
    }
}

// FeathersJS Hook - Encrypt Response
const encryptResponse = (context) => {
    const { result, app, path } = context;
    if (!['users','authentication'].includes(path)) {
        context.result = { encrypted: encryptData(app, result) };
    }
    return context;
};

// FeathersJS Hook - Decrypt Request
const decryptRequest = (context) => {
    const { data, app, path, params } = context;
    if (params && params.query && params.query.encrypted) {
        context.params.query = decryptData(app, params.query.encrypted);
    }
    if (data && data.encrypted) {
        if (!['users','authentication'].includes(path)) {
            context.data = decryptData(app, data.encrypted);
        }
    }
    return context;
};

module.exports = {
    encryptData,
    decryptData,
    encryptResponse,
    decryptRequest
};
