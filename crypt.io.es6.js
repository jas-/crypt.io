/**
 * crypt.io - Encryption enabled browser storage
 *
 * https://www.github.com/jas-/crypt.io
 *
 * Author: Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT (see LICENSE)
 */

'use strict';

let cryptio = (function() {

  const defaults = {
    debug: false,
    passphrase: null,
    storage: 'local',
    crypto: {
      keysize:  256,
      hashing: 'SHA-512',
      keytype: 'AES-GCM',
      iterations: 25000
    }
  };


  class cryptio {

    constructor(opts) {
      this._libs = new libs(opts);
      this._opts = this._libs.merge(defaults, opts);

      this._storage = new storage(opts);
      this._storage.local = new local;
      this._storage.session = new session;

      this._crypto = new crypt(opts);
      this._opts.crypto.iv = this._crypto.iv();
      this._opts.crypto.salt = this._libs.encode(this._crypto.muid());
      
      if (this._opts.debug)
        console.log(this._opts);
    }

    get(key, cb) {
      let ct = this._storage.get(key, cb),
          pt = this._crypto.decrypt(this._opts, ct),
          valid = this._crypto.verify(this._opts.passphrase, ct['signature'],
            pt);

      if (!valid)
        cb('Original signed data has been tampered with!');
        
      cb(null, pt);
    }

    set(key, obj, cb) {
      let _obj = this;
      
      if (!_obj._opts.passphrase)
        _obj._opts.passphrase = _obj._crypto.muid();
      
      if (_obj._opts.debug) {
        console.log('User supplied key:')
        console.log(_obj._opts.passphrase);
      }
      
      _obj._crypto.hash(_obj._opts, _obj._opts.passphrase, function(err, hash) {
        if (err) return cb(err);

        _obj._opts.passphrase = hash;
        if (_obj._opts.debug) {
          console.log('Hashed value of initial key:')
          console.log(_obj._opts.passphrase);
        }

        _obj._crypto.derivekey(_obj._opts, function(derivedErr, dkey) {
          if (derivedErr) return cb(derivedErr);

          _obj._opts.passphrase = dkey;
          if (_obj._opts.debug) {
            console.log('Derived Key:')
            console.log(_obj._opts.passphrase);
          }

          _obj._crypto.hash(_obj._opts, _obj._libs.encode(obj),
                            function(sigErr, sig) {
            if (sigErr) return cb(sigErr);
            
            obj.signature = sig;

            if (_obj._opts.debug) {
              console.log('Plain Text:')
              console.log(obj);
            }

            _obj._crypto.encrypt(_obj._opts, obj, function encrypt(err, ct) {
              if (err) return cb(err);

              ct.iv = _obj._opts.crypto.iv;
              ct.salt = _obj._opts.crypto.salt;

              if (_obj._opts.debug) {
                console.log('Cipher Text:')
                console.log(ct);
              }

              _obj._storage.set(_obj, key, ct, function save(saveErr, res) {
                if (saveErr) return cb(saveErr);
                
                cb(null, res);
              });
            });
          });
        });
      });
    }
  }


  class storage {

    quota(storage) {
      const max = /local|session/.test(storage) ? 1024 * 1025 * 5 : 1024 * 4,
            cur = libs.total(storage),
            total = max - cur;

      return total > 0;
    }

    calculate(storage) {

      let current = '',
          engine = window.storage + 'Storage';

      for (const key in engine) {
        if (engine.hasOwnProperty(key)) {
          current += engine[key];
        }
      }

      return current ? 3 + ((current.length * 16) / (8 * 1024)) : 0;
    }

    getsize(obj) {

      let n = 0;

      if (/object/.test(typeof(obj))) {
        for (const i in obj) {
          if (obj.hasOwnProperty(obj[i])) n++;
        }
      } else if (/array/.test(typeof(obj))) {
        n = obj.length;
      }
      return n;
    }

    set(opts, key, data, cb) {
      console.log(data)
      data = opts._libs.decode(data);
      console.log(data)
      let ret = opts._storage[opts._opts.storage].set(key, data);
      
      if (!ret)
        cb(false);
        
      cb(null, true);
    }

    get() {

    }
  }


  class local {

    set(key, obj) {
      try {
        window.localStorage.setItem(key, obj);
        return true;
      } catch (e) {
        return false;
      }
    }

    get(key) {
      try {
        return window.localStorage.getItem(key);
      } catch (e) {
        return false;
      }
    }
  }


  class session {

    set(key, obj) {
      try {
        window.sessionStorage.setItem(key, obj);
        return true;
      } catch (e) {
        return false;
      }
    }

    get(key) {
      try {
        return window.sessionStorage.getItem(key);
      } catch (e) {
        return false;
      }
    }
  }


  class crypt {

    constructor(opts) {
/*
      opts.crypto.key_opts = {
        
      };
      opts.crypto.sig_opts = {
        
      };
      opts.crypto.derive_opts = {
        
      };
*/

      this._libs = new libs(opts);

      this.machine = window.navigator;
      this._engine = window.crypto || window.msCrypto;
    }

    muid() {
      return this.machine.appCodeName + this.machine.appName +
        this.machine.language + this.machine.product + this.machine.vendor;
    }

    iv() {
      return this._engine.getRandomValues(new Uint8Array(12));
    }

    hash(opts, str, cb) {
      const _libs = this._libs,
            _opts = {
              name: opts.crypto.hashing
            };
      
      let phash = this._engine.subtle.digest(_opts, _libs.encode(str));

      phash.then(function hashed(hash) {
        cb(null, _libs.encode(hash));
      });
      
      phash.catch(function hashedErr(err) {
        cb('Error occurred hashing string; ' + err);
      });
    }

    generate(opts, cb) {
      const _libs = this._libs,
            _opts = {
              name: opts.crypto.keytype,
              length: opts.crypto.keylength
            },
            _for = [
              "encrypt",
              "decrypt"
            ];

      let _pkey = null;

      _pkey = this._engine.subtle.generateKey(_opts, true, _for);
      
      _pkey.then(function generated(key) {
        cb(null, this._engine.subtle.exportKey("raw", key));
      });

      _pkey.catch(function generatedErr(err) {
        cb('Error generating key; ' + err);
      });
    }

    derivekey(opts, cb) {
      const _libs = this._libs,
            _engine = this._engine,
            _opts = {
              name: 'PBKDF2'
            },
            _for = [
              "deriveKey"
            ],
            _keyopts = {
              name: 'PBKDF2',
              iterations: opts.crypto.iterations,
              salt: _libs.encode(opts.crypto.salt),
              hash: opts.crypto.hashing
            },
            _keycrypto = {
              name: opts.crypto.keytype,
              length: opts.crypto.keysize
            },
            _keyfor = [
              "encrypt",
              "decrypt"
            ];

      let key = opts.passphrase;

      let pkey = _engine.subtle.importKey("raw", key, _opts, false, _for);

      pkey.then(function imported(key) {
        let pkey = _engine.subtle.deriveKey(_keyopts, key, _keycrypto, true,
          _keyfor);
      
        pkey.then(function derived(key) {

          let pexport = _engine.subtle.exportKey("raw", key);
          
          pexport.then(function exported(key) {
            cb(null, key);
          });
          
          pexport.catch(function exportedErr(err) {
            cb(err);
          });
        });
        
        pkey.catch(function derivedErr(err) {
          cb(err);
        });
      });
      
      pkey.catch(function importedErr(err) {
        cb('Error occurred importing key; ' + err);
      });
    }

    signature(opts, key, data, cb) {
      const _libs = this._libs,
            _engine = this._engine,
            _opts = {
              name: opts.crypto.keytype
            },
            _for = [
              "encrypt",
              "decrypt"
            ],
            _sigopts = {
              name: 'HMAC',
              hash: opts.crypto.hashing
            },
            _sigfor = [
              "sign",
              "verify"
            ];

      let pkey = _engine.subtle.importKey("raw", key, _sigopts, false, _sigfor);

      pkey.then(function imported(sigkey) {

        let psig = _engine.subtle.sign(_sigopts, sigkey, data);
        
        psig.then(function signed(signature) {
          cb(null, _libs.encode(signature));
        });
      
        psig.catch(function signedErr(err) {
          cb('Error occurred generating signature; ' + err);
        });
      });
      
      pkey.catch(function importedErr(err) {
        cb('Error occurred importing key; ' + err);
      });
    }
    
    verify(opts, key, data, cb) {
      const _libs = this._libs,
            _engine = this._engine,
            _opts = {
              name: opts.crypto.keytype
            },
            _for = [
              "encrypt",
              "decrypt"
            ],
            _sigopts = {
              name: 'HMAC'
            };

      let pkey = _engine.subtle.importKey("raw", key, _opts, false, _for);

      pkey.then(function imported(sigkey) {

        let psig = _engine.subtle.verify(_sigopts, sigkey, data);
        
        psig.then(function validate(signature) {
          cb(null, signature);
        });
      
        psig.catch(function validateErr(err) {
          cb('Error occurred validating signature; ' + err);
        });
      });
      
      pkey.catch(function importedErr(err) {
        cb('Error occurred importing key; ' + err);
      });
    }
    
    encrypt(opts, data, cb) {
      const _libs = this._libs,
            _engine = this._engine,
            _opts = {
              iv: opts.crypto.iv,
              name: opts.crypto.keytype,
              additionalData: opts.crypto.salt
            },
            _for = [
              "encrypt",
              "decrypt"
            ];

      let key = opts.passphrase;
      
      let pkey = _engine.subtle.importKey("raw", key, _opts, false, _for);

      pkey.then(function imported(ekey) {
        if (data instanceof ArrayBuffer == false)
          data = _libs.encode(data);

        _engine.subtle.encrypt(_opts, ekey, data);
        
        pkey.then(function(ct) {
          cb(null, ct);
        });
          
        pkey.catch(function(err) {
          cb('Error occurred encrypting data; ' + err);
        });
      });
    }

    decrypt(opts, data, cb) {
      const _libs = this._libs;

      this._engine.subtle.encrypt({
        name: opts.crypto.keytype,
        iv: data.iv,
        additionalData: data.salt,
        tagLength: opts.crypt.keylength
      },
      opts.passphrase,
      this._libs.encode(data)).then(function(pt) {
        cb(null, _libs.decode(pt));
      }).catch(function(err) {
        cb('Error occurred decrypting data; ' + err);
      });
    }
  }


  class libs {

    merge(obj, defaults) {

      obj = obj || {};

      for (let item in defaults) {
        if (defaults.hasOwnProperty(item)) {
          obj[item] = (typeof defaults[item] == 'object') ?
            this.merge(obj[item], defaults[item]) : defaults[item];
        }
        obj[item] = defaults[item];
      }

      return obj;
    }

    encode(data) {
      if (typeof data != 'string') {
        try {
          data = JSON.stringify(Array.from(data));
        } catch(err) {
          // discard
        }
      }

      return new TextEncoder('utf-8').encode(data);
    }
    
    decode(data) {
      return JSON.parse(new TextDecoder('utf-8').decode(data));
    }
  }

  return cryptio;
})();
