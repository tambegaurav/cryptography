const {
  createHash,
  scryptSync,
  randomBytes,
  createHmac,
  createCipheriv,
  randomBytes,
  createDecipheriv,
} = require("crypto");

//hash
const hash = (input) => {
  return createHash("sha256").update(input).digest("hex");
};

const pw = "Gaurav Tambe";

const hashed = hash(pw);

console.log(hash(pw));

console.log(hashed === hash(pw));

//only hashing can be predictable
//hashing is not enough for saving passwords, so we need salt

// Salt
function signup(email, password) {
  const salt = randomBytes(16).toString("hex");
  const hashedPassword = scryptSync(password, salt, 64).toString("hex");

  const user = { email, password: `${salt}:${hashedPassword}` };

  users.push(user);

  return user;
}

function login(email, password) {
  const user = users.find((v) => v.email === email);

  const [salt, key] = user.password.split(":");
  const hashedBuffer = scryptSync(password, salt, 64);

  const keyBuffer = Buffer.from(key, "hex");
  const match = timingSafeEqual(hashedBuffer, keyBuffer);

  if (match) {
    return "login success!";
  } else {
    return "login fail!";
  }
}

//hmac => hashing which also requires a secret key
const key = "super-secret!";
const message = "boo 👻";

const hmac = createHmac("sha256", key).update(message).digest("hex");

console.log(hmac);

const key2 = "other-password";
const hmac2 = createHmac("sha256", key2).update(message).digest("hex");

console.log(hmac2);

//symmetric encryption

// there is a shared key which receiver and sender both needs
//message ----sharedKey----> encrypt --> some garbage string ----sharedKey----> decrypt --> message

/// Cipher

const message = "i like turtles";
const key = randomBytes(32);
const iv = randomBytes(16);

const cipher = createCipheriv("aes256", key, iv);

/// Encrypt

const encryptedMessage =
  cipher.update(message, "utf8", "hex") + cipher.final("hex");
console.log(`Encrypted: ${encryptedMessage}`);

/// Decrypt

const decipher = createDecipheriv("aes256", key, iv);
const decryptedMessage =
  decipher.update(encryptedMessage, "hex", "utf-8") + decipher.final("utf8");

console.log(`Deciphered: ${decryptedMessage.toString("utf-8")}`);

//But sharing is awkward

//So keypairs ->> Private key - Public key

const { generateKeyPairSync } = require("crypto");

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048, // the length of your key in bits
  publicKeyEncoding: {
    type: "spki", // recommended to be 'spki' by the Node.js docs
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8", // recommended to be 'pkcs8' by the Node.js docs
    format: "pem",
    // cipher: 'aes-256-cbc',
    // passphrase: 'top secret'
  },
});

// console.log(publicKey);
// console.log(privateKey);

module.exports = {
  privateKey,
  publicKey,
};

//Assymetric encryption
const { publicEncrypt, privateDecrypt } = require("crypto");

const message = "the british are coming!";

const encryptedData = publicEncrypt(publicKey, Buffer.from(message));

console.log(encryptedData.toString("hex"));

const decryptedData = privateDecrypt(privateKey, encryptedData);

console.log(decryptedData.toString("utf-8"));

//Digital Signature --> consider as seal on letter
const { createSign, createVerify } = require("crypto");

const message = "this data must be signed";

/// SIGN

const signer = createSign("rsa-sha256");

signer.update(message);

const signature = signer.sign(privateKey, "hex");

/// VERIFY

const verifier = createVerify("rsa-sha256");

verifier.update(message);

const isVerified = verifier.verify(publicKey, signature, "hex");

console.log(`Verified: ${isVerified}`);
