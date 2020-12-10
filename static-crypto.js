const crypto = require('crypto');
const algorithm = 'aes-256-ctr';

function static_hash(x, outputLength) {
  var salt = crypto.createHash('md5').update(x).digest("hex");
  return crypto.pbkdf2Sync(x, salt, 100000, outputLength, 'sha512');
}

function generate_from(password) {
  const key_iv = static_hash(password, 32 + 16);
  return {
    key: key_iv.slice(0, 32),
    iv: key_iv.slice(32),
    salt: key_iv.slice(16)
  };
}

exports.one_way = function (plain_text){
    let encryption_key = generate_from(plain_text).salt
    let iv = generate_from(plain_text).iv
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(encryption_key, 'hex'), iv);
    let encrypted = cipher.update(plain_text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString('hex');
}

exports.encrypt = function (passwd, plain_text) {
    let encryption_key = generate_from(passwd).key
    let iv = generate_from(passwd).iv
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(encryption_key, 'hex'), iv);
    let encrypted = cipher.update(plain_text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    //return iv.toString('hex') + ':' + encrypted.toString('hex');
    return encrypted.toString('hex');
}

exports.decrypt = function (passwd, chipertext) {
    let encryption_key = generate_from(passwd).key
    let iv = generate_from(passwd).iv
    let encryptedText = Buffer.from(chipertext, 'hex')
    let decipher = crypto.createDecipheriv(algorithm, Buffer.from(encryption_key, 'hex'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

