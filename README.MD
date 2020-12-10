# static-crypto

Simplify encryption and decryption using CryptoJS with **static** result.
The key derived from the user password (or any string).

## Installation

Use the package manager [npm](https://docs.npmjs.com/about-npm) to install static-crypto.

```bash
npm install static-crypto
```

## Usage

```js
const static_crypto = require("static-crypto")

//encrypt
let encryption = static_crypto.encrypt("RawUserPasswd","hello world")

console.log(encryption)

//decrypt
let decryption = static_crypto.decrypt(
    "RawUserPasswd", 
    "ff47603fbb9278799dade5")
    
console.log(decryption)

//one way encryption
let save_password = static_crypto.one_way ("RawUserPasswd")

console.log(save_password)
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)