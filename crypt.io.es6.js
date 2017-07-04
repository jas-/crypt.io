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
    passphrase: null,
    storage: 'local',
    crypto: {
      length:  256,
      hashing: 'SHA-512',
      keytype: 'AES-GCM'
    }
  };


  class cryptio {

    constructor(opts) {
      let obj = this,
          iv = null,
          muid = null;

      obj._libs = new libs(opts);
      obj._opts = obj._libs.merge(defaults, opts);

      obj._storage = new storage(opts);

      obj._crypto = new crypt(opts);

      obj._opts.crypto.iv = obj._crypto.iv();
      muid = obj._crypto.muid(obj._opts)

      obj._crypto.hash(obj._opts, muid, function(err, salt) {
        if (err) throw err;
        obj._opts.crypto.salt = salt;
      });

      if (!obj._opts.passphrase) {
        obj._crypto.generate(obj._opts, function genkey(err, key) {
          if (err) throw err;
          obj._opts.passphrase = key;
        });
      } else {
        obj._crypto.importkey(obj._opts, obj._opts.passphrase, function impkey(err, key) {
          if(err) throw err;
          obj._opts.passphrase = key;
        });
      }

      return obj;
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
      let ct = {
        iv: this._opts.crypto.iv,
        salt: this._opts.crypto.salt,
        signature: null,
        ct: null
      };

      this._crypto.signature(this._opts, obj, function(err, sig) {
        if (err) throw err;
        
        ct.sig = sig;
      })

      this._crypto.encrypt(this._opts, ct.iv, ct.salt, obj, function(err, ct) {
        if (err) throw err;
        
        ct.ct = ct;
      });

      //this._storage.set(key, ct, cb);
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

    set() {

    }

    get() {

    }
  }


  class cookies extends storage {

    set() {

    }

    get() {

    }

    domain() {

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
      this._libs = new libs(opts);
      this.machine = window.navigator;
      this._engine = window.crypto || window.msCrypto;
    }

    muid(opts) {
      return this.machine.appCodeName + this.machine.appName +
        this.machine.language + this.machine.product + this.machine.vendor;
    }

    iv() {
      return this._engine.getRandomValues(new Uint8Array(12));
    }

    importkey(opts, cb) {
      const _libs = this._libs,
            _for = [
              "encrypt",
              "decrypt"
            ];
            
      let pass = null,
          pkey = null,
          key = null;

      this.hash(opts, opts.passphrase, function hash(err, hash) {
        if (err) throw err;
        pass = hash;
      });

      pkey = this._engine.subtle.importKey("raw", _libs.toarraybuffer(opts.passphrase),
        {name: opts.crypto.keytype}, false, _for);
      
      pkey.then(function importkey(value) {
        key = value;
      });
      
      pkey.catch(function (err) {
        cb('Error occurred importing key; ' + err);
      });
      
      cb(null, key);
    }
    
    generate(opts, cb) {
      const _libs = this._libs,
            _opts = {
              name: opts.crypto.keytype,
              length: opts.crypto.length
            },
            _for = [
              "encrypt",
              "decrypt"
            ];

      let _pkey = null,
          _key = null;

      _pkey = this._engine.subtle.generateKey(_opts, false, _for);
      
      _pkey.then(function(key) {
        _key = key;
      });

      _pkey.catch(function(err) {
        cb('Error generating key; ' + err);
      });
      
      cb(null, _libs.toarraybuffer(_key));
    }

    hash(opts, str, cb) {
      const _libs = this._libs;

      this._engine.subtle.digest({
        name: opts.crypto.hashing,
      },
      _libs.toarraybuffer(str)).then(function(hash) {
        cb(null, _libs.toarraybuffer(hash));
      }).catch(function(err) {
        cb('Error occurred hashing string; ' + err);
      });
    }
    
    signature(opts, data, cb) {
      const _libs = this._libs;

      this._engine.subtle.sign({
        name: "HMAC",
      },
      opts.passphrase,
      this._libs.toarraybuffer(data)).then(function(signature) {
        cb(null, _libs.toarraybuffer(signature));
      }).catch(function(err) {
        cb('Error occurred generating signature; ' + err);
      });
    }
    
    verify(opts, data, cb) {
      this._engine.subtle.verify({
        name: "HMAC",
      },
      opts.passphrase,
      this._libs.toarraybuffer(data)).then(function(isvalid) {
        cb(null, isvalid);
      }).catch(function(err) {
        cb('Error occurred validating signature ' + err);
      });
    }
    
    encrypt(opts, iv, salt, data, cb) {
      const _libs = this._libs;

      this._engine.subtle.encrypt({
        name: opts.crypto.keytype,
        iv: iv,
        additionalData: salt,
        tagLength: opts.length
      },
      opts.passphrase,
      this._libs.toarraybuffer(data)).then(function(ct) {
        cb(null, _libs.toarraybuffer(ct));
      }).catch(function(err) {
        cb('Error occurred encrypting data; ' + err);
      });
    }

    decrypt(opts, data, cb) {
      const _libs = this._libs;

      this._engine.subtle.encrypt({
        name: opts.crypto.keytype,
        iv: data.iv,
        additionalData: data.salt,
        tagLength: opts.length
      },
      opts.passphrase,
      this._libs.toarraybuffer(data)).then(function(pt) {
        cb(null, _libs.fromarraybuffer(pt));
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

    toarraybuffer(str) {
      if (typeof str != 'string')
        return str;
      
      let buf = new ArrayBuffer(str.length * 2),
          bufView = new Uint16Array(buf);
          
      for (let i=0, strLen=str.length; i<strLen; i++) {
        bufView[i] = str.charCodeAt(i);
      }
      return buf;
    }
    
    fromarraybuffer(buf) {
      return String.fromCharCode.apply(null, new Uint16Array(buf));
    }
  }

  return cryptio;
})();
