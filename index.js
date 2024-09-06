import * as bigintBuffer from "bigint-buffer"
import * as crypto from "crypto"

/**
 * Throws an error if the condition is not met.
 * @param {boolean} val - The condition to check.
 * @param {string} [msg='assertion'] - The error message.
 */
function assert_ (val, msg = `assertion`) {
    if (!val) { throw new Error(msg) }
}

/**
 * Parameters for cryptographic operations.
 * @typedef {Object} Params
 * @property {number} N_length_bits - Length of N in bits.
 * @property {bigint} N - Large safe prime.
 * @property {bigint} g - Generator.
 * @property {string} hash - Hash function.
 * @property {number | null} identityMaxLength - identity max length
 * @property {number | null} passwordMaxLength - password max length
 */


/** @type {Params} */
const defaultParams = {
    N_length_bits: 256,
    N: BigInt(`0x894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7`),
    g: BigInt(`0x7`),
    hash: `sha1`,
    identityMaxLength: 16,
    passwordMaxLength: 16
}


/** @type {{[K in 'trinitycore' | 'azerothcore']: Params}} */
export const params = {
    trinitycore: {
        ...defaultParams
    },
    azerothcore: {
        ...defaultParams
    }
}

/**
 * Computes (base ** exponent) % modulus using BigInts, without intermediate overflows.
 * @param {bigint} base - The base number.
 * @param {bigint} exponent - The exponent.
 * @param {bigint} modulus - The modulus.
 * @returns {bigint} - The result of (base ** exponent) % modulus.
 */
const modPow = (base, exponent, modulus) => {
    let result = BigInt(1)
    base = base % modulus

    while (exponent > 0) {
        if (exponent % 2n === 1n) {  // If the exponent is odd
            result = (result * base) % modulus
        }
        exponent = exponent >> 1n  // Divide the exponent by 2
        base = (base * base) % modulus
    }
    return result
}

/**
 * Asserts that the argument is a buffer.
 * @param {Buffer} arg - The argument to check.
 * @param {string} [argname='arg'] - Name of the argument.
 */
const assertIsBuffer = (arg, argname = `arg`) => {
    assert_(Buffer.isBuffer(arg), `Type error: ${argname} must be a buffer`)
}

/**
 * Computes the intermediate value x.
 * @param {Params} params - Group parameters.
 * @param {Buffer} salt - Salt.
 * @param {string} identity - User identity.
 * @param {string} password - User password.
 * @returns {BigInt} - Computed user secret.
 */
const getX = (params, salt, identity, password) => {
    assertIsBuffer(salt, `salt`)
    const hashIP = crypto.createHash(params.hash)
        .update(`${identity}:${password}`)
        .digest()
    const hashX = crypto.createHash(params.hash)
        .update(salt)
        .update(hashIP)
        .digest()
    return bigintBuffer.toBigIntLE(hashX)
}

/**
 * Computes the verifier.
 * @param {Params} params - Group parameters.
 * @param {Buffer} salt - Salt.
 * @param {string} identity - User identity.
 * @param {string} password - User password.
 * @returns {Buffer} - Computed verifier.
 */
export const computeVerifier = (params, salt, identity, password) => {
    if(identity.length > params?.identityMaxLength) {
        throw new RangeError(`The identity should have maximum ${params.identityMaxLength} characters`)
    }
    if(password.length > params?.passwordMaxLength) {
        throw new RangeError(`The password should have maximum ${params.passwordMaxLength} characters`)
    }
    const x = getX(params, salt, identity.toUpperCase(), password.toUpperCase())
    const g = params.g
    const N = params.N
    const verifier = modPow(g, x, N)
    const lEVerifier = verifier.toString(16).match(/.{2}/g).reverse().join(``)
    return Buffer.from(lEVerifier, `hex`)
}

/**
 * Generates an ECC key pair.
 * @returns {Promise<crypto.KeyObject>} - Promise that resolves to an ECC key pair.
 */
export const generateECCKeyPair = () => {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('ec', {
            namedCurve: 'secp256k1',
        }, (err, publicKey, privateKey) => {
            if (err) {
                return reject(err)
            }
            resolve({ publicKey, privateKey })
        })
    })
}

/**
 * Signs a message using the provided ECC private key.
 * @param {crypto.KeyObject} privateKey - The ECC private key.
 * @param {string} message - The message to sign.
 * @returns {Buffer} - The signature.
 */
export const signMessage = (privateKey, message) => {
    const sign = crypto.createSign('SHA256')
    sign.update(message)
    sign.end()
    return sign.sign(privateKey)
}

/**
 * Verifies a signature against a message using the provided ECC public key.
 * @param {crypto.KeyObject} publicKey - The ECC public key.
 * @param {string} message - The original message.
 * @param {Buffer} signature - The signature to verify.
 * @returns {boolean} - True if the signature is valid, false otherwise.
 */
export const verifySignature = (publicKey, message, signature) => {
    const verify = crypto.createVerify('SHA256')
    verify.update(message)
    verify.end()
    return verify.verify(publicKey, signature)
}
