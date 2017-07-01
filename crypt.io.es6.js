/**
 * crypt.io - Encryption enabled browser storage
 *
 * https://www.github.com/jas-/crypt.io
 *
 * Author: Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT (see LICENSE)
 */

'use strict';

let cryptio = (function(){

  const defaults = {
    passphrase: '',
    storage: 'local',
    crypto: {
      hashing: 'SHA-512',
      keytype: 'AES-GCM',
      length: 256,
      output: 'base64'
    }
  };

  class cryptio {
    constrctor(opts, key, obj, func) {
      let storage = new storage()
        , crypto = new crypto()
        , libs = new libs();
        
      opts = libs.merge(defaults, opts);
      
      if (!opts.passphrase)
        opts.passphrase = crypto.key(opts);
    }
  }
  
  class storage {
    constrctor(opts) {
      let cookies = new cookies()
        , local = new local()
        , session = new session();
      
    }

    quota() {
    
    }
  
    calculate() {
    
    }
  
    getsize() {
    
    }
  
    set() {
    
    }
  
    get() {
    
    }
  }

  class cookies {
    constrctor() {
      let storage = new storage();
    }

    set() {
    
    }
  
    get() {
    
    }
  
    domain() {
    
    }
  }

  class local {
    constrctor() {
      
    }

    set() {
    
    }
  
    get() {
    
    }
  }

  class session {
    constrctor() {
      
    }

    set() {
    
    }
  
    get() {
    
    }
  }

  class crypto {
    constructor() {
      const crypto = window.crypto || window.msCrypto
          , libs = new libs();
      
      
    }
  
    derive() {
    
    }
  
    guid() {
    
    }
  
    salt() {
    
    }
    
    hash(str) {
      this.crypto.subtle.digest(this.libs.encodeUTF8(str))
    }
  }

  class libs {

    merge(defaults, obj) {
      defaults = defaults || {};

      for (const item in defaults) {
        if (defaults.hasOwnProperty(item)) {
          obj[item] = (/object/.test(typeof(defaults[item]))) ?
            this.merge(obj[item], defaults[item]) : defaults[item];
        }
        obj[item] = defaults[item];
      }

      return obj;
    }
    
    encodeUTF8(str) {
      let i = 0
        , bytes = new Uint8Array(str.length * 4);

    	for (const ci = 0; ci != str.length; ci++) {
    		let c = str.charCodeAt(ci);
		    
		    if (c < 128) {
			    bytes[i++] = c;
			    continue;
		    }
		
		    if (c < 2048) {
			    bytes[i++] = c >> 6 | 192;
		    } else {
			    if (c > 0xd7ff && c < 0xdc00) {
				    
				    if (++ci == str.length)
				      throw 'UTF-8 encode: incomplete surrogate pair';
				
				    let c2 = str.charCodeAt(ci);
				
				    if (c2 < 0xdc00 || c2 > 0xdfff)
				      throw 'UTF-8 encode: second char code 0x' + c2.toString(16) + ' at index ' + ci + ' in surrogate pair out of range';

				    c = 0x10000 + ((c & 0x03ff) << 10) + (c2 & 0x03ff);
				    bytes[i++] = c >> 18 | 240;
				    bytes[i++] = c>> 12 & 63 | 128;
			    } else { // c <= 0xffff
				    bytes[i++] = c >> 12 | 224;
			    }
			    bytes[i++] = c >> 6 & 63 | 128;
		    }
		    bytes[i++] = c & 63 | 128;
    	}
	  
      return bytes.subarray(0, i);
    }
    
    decodeUTF8(bytes) {
    	let s = ''
    	  , i = 0;
    	  
    	  
	    while (i < bytes.length) {
		    let c = bytes[i++];
		
		    if (c > 127) {
			    if (c > 191 && c < 224) {
				    
				    if (i >= bytes.length)
				      throw 'UTF-8 decode: incomplete 2-byte sequence';
				
				    c = (c & 31) << 6 | bytes[i] & 63;
			    } else if (c > 223 && c < 240) {
				    
				    if (i + 1 >= bytes.length)
				      throw 'UTF-8 decode: incomplete 3-byte sequence';
				
				    c = (c & 15) << 12 | (bytes[i] & 63) << 6 | bytes[++i] & 63;
			    } else if (c > 239 && c < 248) {
				
				    if (i+2 >= bytes.length)
				      throw 'UTF-8 decode: incomplete 4-byte sequence';
				
				    c = (c & 7) << 18 | (bytes[i] & 63) << 12 | (bytes[++i] & 63) << 6 | bytes[++i] & 63;
			    } else {
			      throw 'UTF-8 decode: unknown multibyte start 0x' + c.toString(16) + ' at index ' + (i - 1);
			    }			
			    ++i;
		    }

    		if (c <= 0xffff) {
    		  s += String.fromCharCode(c);
		
		    } else if (c <= 0x10ffff) {
    			c -= 0x10000;
		    	s += String.fromCharCode(c >> 10 | 0xd800)
			    s += String.fromCharCode(c & 0x3FF | 0xdc00)
		    } else {
		      throw 'UTF-8 decode: code point 0x' + c.toString(16) + ' exceeds UTF-16 reach';
      	}
      }
      return s;
    }
  }

  return cryptio;
})();
