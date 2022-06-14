Usage:

```
const fos = require('./src/index');

const password = 'VerySecuredPassword';
const salt = 'Sb573aRXw2V0in3YpF.xeasGGqA2PeBL64GH9cHnCFs';

var encoded = fos.encodePassword(password, salt, 'sha512', 5000);
var isValid = fos.isPasswordValid(encoded, password, salt);

console.log(encoded, isValid);
```

Only works with sha512, im working on bcrypt.