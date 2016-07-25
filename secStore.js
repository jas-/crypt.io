/**
 * secStore.js - Encryption enabled browser storage
 *
 * https://www.github.com/jas-/secStore.js
 *
 * Author: Jason Gerfen <jason.gerfen@gmail.com>
 * License: GPL (see LICENSE)
 */


(function(window, undefined) {

  'use strict';

  /**
   * @function secStore
   * @abstract Namespace for saving/retrieving encrypted HTML5 storage engine
   * data
   */
  var secStore = secStore || function() {

    /**
     * @var {Object} defaults
     * @abstract Default set of options for plug-in
     *
     * @param {String} key Encryption passphrase
     * @param {String} storage Storage engine [local|session|cookies]
     * @param {String} index Default storage index key
     */
    var defaults = {
      key:          '',
      storage:      'local',
      index:        'secStore.js',
    };

    /**
     * @method setup
     * @scope private
     * @abstract Initial setup routines
     */
    var setup = setup || {

      /**
       * @function set
       * @abstract Initialization
       *
       * @param {Object} opts Plug-in option object
       */
      init: function(opts) {

        var engine = window.crypto || sjcl;

        if (opts.encrypt && !/function/.test(engine))
          throw new Error("Could not load required cryptographic libraries");

        opts.passphrase = opts.encrypt ?
          (opts.passphrase || crypto.key(opts)) : false;
      }
    };


    /**
     * @method crypt
     * @abstract Handles crypto operations
     */
    var crypt = crypt || {

      /**
       * @function init
       * @abstract Determines crypto API to use (SJCL or W3C Crypto API)
       *
       */
      init: function() {

      },


      /**
       * @function genkey
       * @abstract Derives internal key based on supplied key or transparently
       *           aquired browser fingerprint
       *
       */
      genkey: function() {

      }
    }

    /**
     * @method storage
     * @abstract Interface to handle storage options
     */
    var storage = storage || {

      /**
       * @function quota
       * @abstract Tests specified storage option for current amount of space
       *           available.
       *
       *  - Cookies: 4K
       *  - localStorage: 5MB
       *  - sessionStorage: 5MB
       *  - default: 5MB
       *
       * @param {String} t Type of storage specified
       *
       * @returns {Boolean}
       */
      quota: function(storage) {
        var max = /local|session/.test(storage) ? 1024 * 1025 * 5 : 1024 * 4
          , cur = libs.total(storage)
          , total = max - cur;

        return total > 0;
      },

      /**
       * @function set
       * @abstract Interface for saving to available storage mechanisms
       *
       * @param {Object} opts Default options
       * @param {Function} cb Callback function
       *
       * @returns {Boolean}
       */
      set: function(opts, key, cb) {
        if (!storage.quota(opts.storage))
          cb('Browser storage quota has been exceeded.');

        if (opts.encrypt) {
          try {
            opts.data = sjcl.encrypt(opts.passphrase,
                                     storage.fromJSON(key));
          } catch(err) {
            cb('An error occured encrypting data');
          }
        }

        opts.data = storage.fromJSON(key);

        try {
          this[opts.storage] ?
            this[opts.storage].set(opts) : this.local.set(opts);
        } catch(err) {
          cb('An error occured saving data');
        }

        cb(null, 'Successfully set data');
      },

      /**
       * @function get
       * @abstract Interface for retrieving from available storage mechanisms
       *
       * @param {Object} opts Default options
       * @param {Function} cb Callback function
       *
       * @returns {Object}
       */
      get: function(opts, cb) {
        var ret = false;

        try {
          ret = this[opts.storage] ?
            this[opts.storage].get(opts) : this.local.get(opts);
        } catch(err) {
          cb('An error retrieving saved data');
        }

        try {
          ret = sjcl.decrypt(opts.passphrase, ret);
        } catch(err) {
          cb('An error occured decrypting saved data');
        }

        ret = storage.toJSON(ret);

        cb(null, ret);
      },

      /**
       * @function fromJSON
       * @abstract Convert to JSON object to string
       *
       * @param {Object|Array|String} obj Object, Array or String
       *
       * @returns {String}
       */
      fromJSON: function(obj) {
        var ret;
        try {
          ret = JSON.stringify(obj);
        } catch (e) {
          ret = obj;
        }
        return ret;
      },

      /**
       * @function toJSON
       * @abstract Creates JSON object from formatted string
       *
       * @param {String} obj Object to convert to JSON object
       *
       * @returns {Object}
       */
      toJSON: function(obj) {
        var ret;
        try {
          ret = JSON.parse(obj);
        } catch (e) {
          ret = obj;
        }
        return ret;
      },

      /**
       * @method cookie
       * @abstract Method for handling setting & retrieving of cookie objects
       */
      cookie: {

        /**
         * @function set
         * @abstract Handle setting of cookie objects
         *
         * @param {String} key Key to use for cookies
         * @param {String|Object} value String or object to place in cookie
         *
         * @returns {Boolean}
         */
        set: function(key, value) {
          var date = new Date();

          date.setTime(date.getTime() + (30 * 24 * 60 * 60 * 1000));

          document.cookie = key + '=' + value + ';expires=' +
            date.toGMTString() + ';path=/;domain=' + this.domain();

          return true;
        },

        /**
         * @function get
         * @abstract Handle retrieval of cookie objects
         *
         * @param {String} key cookie key
         *
         * @returns {String|False}
         */
        get: function(key) {
          var i, index, value, content = document.cookie.split(";");

          for (i = 0; i < content.length; i++) {
            index = content[i].substr(0, content[i].indexOf('='));
            value = content[i].substr(content[i].indexOf('=') + 1);
            index = index.replace(/^\s+|\s+$/g, '');
            if (index == key) {
              return unescape(value);
            }
          }
          return false;
        },

        /**
         * @function domain
         * @abstract Provides current domain of client for cookie realm
         *
         * @returns {String}
         */
        domain: function() {
          return location.hostname;
        }
      },

      /**
       * @method local
       * @abstract Method for handling setting & retrieving of localStorage objects
       */
      local: {

        /**
         * @function set
         * @abstract Handle setting & retrieving of localStorage objects
         *
         * @param {Object} opts Application defaults
         *
         * @returns {Boolean}
         */
        set: function(opts) {
          try {
            window.localStorage.setItem(opts.key, opts.data);
            return true;
          } catch (e) {
            return false;
          }
        },

        /**
         * @function get
         * @abstract Handle retrieval of localStorage objects
         *
         * @param {Object} o Application defaults
         *
         * @returns {Object|String|Boolean}
         */
        get: function(opts) {
          return window.localStorage.getItem(opts.key);
        }
      },

      /**
       * @method session
       * @abstract Method for handling setting & retrieving of sessionStorage objects
       */
      session: {

        /**
         * @function set
         * @scope private
         * @abstract Set session storage objects
         *
         * @param {Object} o Application defaults
         *
         * @returns {Boolean}
         */
        set: function(opts) {
          try {
            window.sessionStorage.setItem(opts.key, opts.data);
            return true;
          } catch (e) {
            return false;
          }
        },

        /**
         * @function get
         * @abstract Retrieves sessionStorage objects
         *
         * @param {Object} opts Application defaults
         *
         * @returns {Object|String|Boolean}
         */
        get: function(opts) {
          return window.sessionStorage.getItem(opts.key);
        }
      }
    };

    /**
     * @method crypto
     * @abstract Interface to handle encryption option
     */
    var crypto = crypto || {

      /**
       * @function key
       * @abstract Prepares key for encryption/decryption routines
       *
       * @returns {String}
       */
      key: function() {
        var pass = crypto.muid(),
          salt = crypto.salt(pass);

        return sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(pass, salt,
          10000, 256));
      },

      /**
       * @function muid
       * @abstract Generates a machine identifier
       *
       * @returns {String}
       */
      muid: function() {
        var ret = window.navigator.appName + '|'
          window.navigator.product + '|'
          window.navigator.language + '|'
          window.navigator.platform + '|'
          window.navigator.product;
        return encodeURI(ret.replace(/\s/, ' '));
      },

      /**
       * @function salt
       * @abstract Creates salt from string & iv
       *
       * @param {String} str Machine identification used as salt
       *
       * @returns {String}
       */
      salt: function(str) {
        var rec, ret, hash = [],
          slt = crypto.iv(str);

        hash[0] = sjcl.hash.sha256.hash(str), rec = [], rec = hash[0],
          ret;

        for (var i = 1; i < 3; i++) {
          hash[i] = sjcl.hash.sha256.hash(hash[i - 1].concat(slt));
          ret = rec.concat(hash[i]);
        }
        return JSON.stringify(sjcl.codec.hex.fromBits(ret));
      },

      /**
       * @function iv
       * @abstract Creates IV based on UID
       *
       * @param {String} str Supplied string
       *
       * @returns {String}
       */
      iv: function(str) {
        return encodeURI(str.replace(/-/gi, '').substring(16, Math.ceil(
          16 * str.length) % str.length));
      }
    };

    /**
     * @method libs
     * @abstract Miscellaneous helper libraries
     */
    var libs = libs || {

      /**
       * @function total
       * @abstract Returns size of specified storage
       *
       * @param {String} engine Storage mechanism
       *
       * @returns {Insteger}
       */
      total: function(storage) {
        var current = ''
          , engine = window.storage + 'Storage';

        for (var key in engine) {
          if (engine.hasOwnProperty(key)) {
            current += engine[key];
          }
        }

        return current ? 3 + ((current.length * 16) / (8 * 1024)) : 0;
      },

      /**
       * @function size
       * @abstract Perform calculation on objects
       *
       * @param {Object|Array} obj The object/array to calculate
       *
       * @returns {Integer}
       */
      size: function(obj) {
        var n = 0;

        if (/object/.test(typeof(obj))) {
          for (var i in obj) {
            if (obj.hasOwnProperty(obj[i])) n++;
          }
        } else if (/array/.test(typeof(obj))) {
          n = obj.length;
        }
        return n;
      },

      /**
       * @function merge
       * @abstract Perform preliminary option/default object merge
       *
       * @param {Object} defaults Application defaults
       * @param {Object} obj User supplied object
       *
       * @returns {Object}
       */
      merge: function(defaults, obj) {
        defaults = defaults || {};

        for (var item in defaults) {
          if (defaults.hasOwnProperty(item)) {
            obj[item] = (/object/.test(typeof(defaults[item]))) ?
              this.merge(obj[item], defaults[item]) : defaults[item];
          }
          obj[item] = defaults[item];
        }

        return obj;
      }
    };

    /**
     * @function get
     * @abstract Retrieves storage engine data
     *
     * @param {Object} opts User supplied options
     * @param {String} key Index of data to retrieve
     * @param {Function} cb User supplied callback function
     */
    secStore.prototype.get = function(opts, key, cb) {
      opts = opts || key;

      opts = libs.merge(obj, defaults);

      setup.init(opts);

      storage.get(opts, key, cb);
    };

    /**
     * @function set
     * @abstract Saves data to specified storage engine
     *
     * @param {Object} opts User supplied options
     * @param {Mixed} obj Object/String/Array of data to save
     * @param {Function} cb User supplied callback function
     */
    secStore.prototype.set = function(opts, obj, cb) {
      opts = opts || obj;

      opts = libs.merge(opts, defaults);

      setup.init(opts);

      storage.set(opts, obj, cb);
    };

  };

  /* secStore.js, do work */
  window.secStore = new secStore;

})(window);
