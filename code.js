const encoder = new TextEncoder();
const decoder = new TextDecoder();
function b64OfArray(arr) {
    const carr = [];
    arr.forEach((u8) => {
        carr.push(String.fromCharCode(u8));
    });
    return btoa(carr.join(""));
}

function unb64(s) {
    const bs = atob(s);
    const uarr = new Uint8Array(bs.length);
    for (let i = 0; i < bs.length; i++) {
        uarr[i] = bs.charCodeAt(i);
    }
    return uarr;
}

function canonicalize(rawGuess) {
    rawGuess = rawGuess.toUpperCase();
    let canon = "";
    for (var i = 0; i < rawGuess.length; i++) {
        if (/[A-Z]/.test(rawGuess[i])) {
            canon += rawGuess[i];
        }
    }
    return canon;
}

// These security parameters are weaker than what most settings would need, to
// keep things reasonably fast, since our pure JavaScript library is slower
// than other options, and URLs reasonably compact. A brute-forcer who ran
// scrypt elsewhere with these parameters could go much faster, but this
// setting really isn't high-stakes.

// Don't copy my parameters into "actual crypto code" (why would you do that.
// just. why)
function generateLocalSalt() {
    let saltArr = new Uint8Array(12);
    if (window.crypto && window.crypto.getRandomValues) {
        window.crypto.getRandomValues(saltArr);
    } else {
        // Not secure, but like I said, I think cryptographic guarantees just
        // aren't worth breaking over.
        for (let i = 0; i < saltArr.length; i++) {
            saltArr[i] = Math.floor(Math.random()*256);
        }
    }
    return b64OfArray(saltArr);
}

function generateHash(label, answer, callback) {
    const version = '1';
    // The caller should canonicalize the answer!
    const salt = generateLocalSalt();
    // Note: add the label even if it's empty. Also assume the label is ASCII
    // (by being v0 URI-encoded or v1 base64ed) already.
    const fullSalt = encoder.encode("callingit.in/" + version + '/#' + salt + '#' + label);
    scrypt.scrypt(encoder.encode(answer), fullSalt, 4096, 8, 1, 24, function (progress) {
        callback({ 'progress': progress });
    }).then(function (key) {
        callback({
            'version': version,
            'salt': salt,
            'hash': b64OfArray(key),
        });
    });
}

function checkHash(version, label, salt, hash, answer, callback) {
    // Weirdly, the version doesn't yet affect this part of the code.
    if (version !== '1') {
        callback({
            'error': 'Unsupported version: ' + version,
        });
    }
    // The caller should canonicalize the answer!
    // Note: add the label even if it's empty. Also assume the label is ASCII
    // (by being URI-encoded) already.
    const fullSalt = encoder.encode("callingit.in/" + version + '/#' + salt + '#' + label);
    scrypt.scrypt(encoder.encode(answer), fullSalt, 4096, 8, 1, 24, function (progress) {
        callback({ 'progress': progress });
    }).then(function (key) {
        if (b64OfArray(key) === hash) {
            callback({ 'correct': true });
        } else {
            callback({ 'correct': false });
        }
    });
}

