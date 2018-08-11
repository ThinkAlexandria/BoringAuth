# BoringAuth

[![Build Status](https://api.travis-ci.org/ThinkAlexandria/boringauth.svg?branch=master)](https://travis-ci.org/breard-r/boringauth)
[![BoringAuth on crates.io](https://img.shields.io/crates/v/boringauth.svg)](https://crates.io/crates/boringauth)

BoringAuth is a collection of tools for user authentication. BoringAuth is a fork
of [LibreAuth](https://github.com/breard-r/libreauth) that chooses to use the
actively developed **ring** crypto crate over the dead **rust-crypto** crate for
its crypto primitives.


Ring compatibility chart.

| BoringAuth | Ring |
| ------ | ------ |
| v0.6.4 | 0.12 |
| v0.7.0 | 0.13 |

## Features

- Password / passphrase authentication
  - [x] no character-set limitation
  - [x] reasonable lenth limit ([security vs. DOS](http://arstechnica.com/security/2013/09/long-passwords-are-good-but-too-much-length-can-be-bad-for-security/))
  - [x] strong, evolutive and retro-compatible password derivation functions
  - [x] crypt() compatibility
- HOTP - HMAC-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 4226](https://tools.ietf.org/html/rfc4226))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable counter
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
- TOTP - Time-based One-time Password Algorithm ([OATH](http://www.openauthentication.org/) - [RFC 6238](https://tools.ietf.org/html/rfc6238))
  - [x] the key can be passed as bytes, an ASCII string, an hexadicimal string or a base32 string
  - [x] customizable timestamp
  - [x] customizable period
  - [x] customizable initial time (T0)
  - [x] customizable hash function (sha1, sha256, sha512)
  - [x] customizable output length
  - [x] customizable output alphabet
  - [x] customizable positive and negative period tolerance
- YubiKey OTP ([Yubico](https://developers.yubico.com/OTP/))
  - [ ] virtual device API
  - [ ] client API
  - [ ] server API
- U2F - Universal 2nd Factor ([FIDO Alliance](https://fidoalliance.org/specifications/download/))
  - [ ] virtual device API
  - [ ] client API
  - [ ] server API


## Using within a Rust project

You can find BoringAuth on [crates.io](https://crates.io/crates/boringauth) and include it in your `Cargo.toml`:

```toml
boringauth = "*"
```


## Using outside Rust

In order to build BoringAuth, you will need both the [rust compiler](https://github.com/rust-lang/rust) and [cargo](https://github.com/rust-lang/cargo).

```ShellSession
$ git clone https://github.com/ThinkAlexandria/boringauth.git
$ cd boringauth
$ make
$ make install prefix=/usr
```


## Quick examples


### Rust


```rust
extern crate boringauth;
use boringauth::oath::TOTPBuilder;

let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string();
let code = TOTPBuilder::new()
    .base32_key(&key)
    .finalize()
    .unwrap()
    .generate();
assert_eq!(code.len(), 6);
```

### C

```C
#include <stdio.h>
#include <boringauth.h>

int main(void) {
  struct boringauth_totp_cfg cfg;
  char   code[7], key[] = "12345678901234567890";

  if (boringauth_totp_init(&cfg) != LIBREAUTH_OTP_SUCCESS) {
    return 1;
  }
  cfg.key = key;
  cfg.key_len = sizeof(key);
  if (boringauth_totp_generate(&cfg, code) != LIBREAUTH_OTP_SUCCESS) {
    return 2;
  }

  printf("%s\n", code);

  return 0;
}
```

```ShellSession
$ cc -o totp totp.c -lboringauth
$ ./totp
848085
```

### Python

```Python
from ctypes.util import find_library
from struct import Struct
from ctypes import *

class TOTPcfg(Structure):
    _fields_ = [
        ('key', c_char_p),
        ('key_len', c_size_t),
        ('timestamp', c_longlong),
        ('period', c_uint),
        ('initial_time', c_ulonglong),
        ('output_len', c_size_t),
        ('output_base', c_char_p),
        ('output_base_len', c_size_t),
        ('hash_function', c_int),
    ]

def get_totp():
    key = b'12345678901234567890'
    lib_path = find_library('boringauth') or 'target/release/libboringauth.so'
    lib = cdll.LoadLibrary(lib_path)
    cfg = TOTPcfg()
    if lib.boringauth_totp_init(byref(cfg)) != 0:
        return
    cfg.key_len = len(key)
    cfg.key = c_char_p(key)
    code = create_string_buffer(b'\000' * cfg.output_len)
    if lib.boringauth_totp_generate(byref(cfg), code) != 0:
        return
    return str(code.value, encoding="utf-8")

if __name__ == '__main__':
    code = get_totp()
    print('{}'.format(code))
```
