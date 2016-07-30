/**
 * secstore.js - Encryption enabled browser storage
 *
 * https://www.github.com/jas-/secstore.js
 *
 * Author: Jason Gerfen <jason.gerfen@gmail.com>
 * License: GPL (see LICENSE)
 */


(((window, undefined) => {

  /**
   * @function secstore
   * @abstract Namespace for saving/retrieving encrypted HTML5 storage engine
   * data
   */
  const secstore = secstore || (() => {


    /**
     * @var {Object} defaults
     * @abstract Default set of options for plug-in
     *
     * @param {String} key Encryption passphrase
     * @param {String} storage Storage engine [local|session]
     * @param {String} index Default storage index key
     */
    const defaults = {
      key:          '',
      storage:      'local',
      index:        'secstore.js',
      engine:       false
    };


    /**
     * @method setup
     * @scope private
     * @abstract Initial setup routines
     */
    const setup = setup || {


      /**
       * @function set
       * @abstract Initialization
       *
       * @param {Object} opts Plug-in option object
       */
      init(opts) {

        opts.storage = opts.storage + 'Storage';

        if (!opts.storage || !/function/.test(opts.storage))
          throw new Error("Storage engine specified does not exist in DOM");

        if (opts.encrypt && !/function/.test(opts.engine))
          throw new Error("Could not load required cryptographic libraries");

        opts.passphrase = opts.encrypt ?
          (opts.passphrase || crypto.key(opts)) : false;
      }
    };


    /**
     * @method storage
     * @abstract Interface to handle storage options
     */
    const storage = storage || {


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
       * @param {String} storage Type of storage specified
       *
       * @returns {Boolean}
       */
      quota(storage) {
        const max = 1024 * 1025 * 5,
              cur = libs.total(storage),
              total = max - cur;

        return total >= 0;
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
      set(opts, key, cb) {
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
          opts.storage.set(opts);
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
      get(opts, cb) {
        let ret = false;

        try {
          ret = opts.storage.get(opts);
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
      fromJSON(obj) {
        let ret;
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
      toJSON(obj) {
        let ret;
        try {
          ret = JSON.parse(obj);
        } catch (e) {
          ret = obj;
        }
        return ret;
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
      key() {
        const pass = crypto.muid(), salt = crypto.salt(pass);

        return sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(pass, salt,
          10000, 256));
      },


      /**
       * @function muid
       * @abstract Generates a machine identifier
       *
       * @returns {String}
       */
      muid() {
        const ret = `${window.navigator.appName}|`;
          `${window.navigator.product}|`
          `${window.navigator.language}|`
          `${window.navigator.platform}|`
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
      salt(str) {
        let rec;
        let ret;
        const hash = [];
        const slt = crypto.iv(str);

        hash[0] = sjcl.hash.sha256.hash(str), rec = [], rec = hash[0],
          ret;

        for (let i = 1; i < 3; i++) {
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
      iv(str) {
        return encodeURI(str.replace(/-/gi, '').substring(16, Math.ceil(
          16 * str.length) % str.length));
      },


      /**
       * @function fingerprint
       * @abstract Fingerprints the browser (minimalist)
       *
       * @returns {String}
       */
      fingerprint() {
        const nav = window.navigator,
              ret = nav.appName +
                    nav.product +
                    nav.language +
                    nav.platform +
                    nav.product;

        return this.hash(ret);
      },


      /**
       * @method native
       * @abstract Handles crypto operations using the browsers crypto api
       */
      native: {


        /**
         * @function genkey
         * @abstract Derives internal key based on supplied key or transparently
         *           aquired browser fingerprint
         *
         */
        genkey() {

        },


        /**
         * @function hash
         * @abstract Generates hash
         *
         * @param {Object} opts Global options object
         * @param {String} algo Hashing algorithm to use
         * @param {String} pt Supplied plain text to hash
         * @param {Function} cb Callback function
         *
         * @returns {String}
         */
        hash(opts, algo, pt, cb) {
          const algo = algo || 'SHA-512',
                binpt = new Uint8Array(pt);

          opts.engine.digest(
            {
              name: algo
            },
            binpt
          ).then(hash => {
            cb(null, new Uint8Array(hash));
          }).catch(err => {
            cb(err);
          });
        }
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
      total(storage) {
        let current = '';
        const engine = `${window.storage}Storage`;

        for (const key in engine) {
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
      size(obj) {
        let n = 0;

        if (/object/.test(typeof(obj))) {
          for (const i in obj) {
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
      merge(defaults={}, obj) {
        for (const item in defaults) {
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
    secstore.prototype.get = (opts, key, cb) => {
      opts = opts || key;

      opts = libs.merge(opts, defaults);

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
    secstore.prototype.set = (opts, obj, cb) => {
      opts = libs.merge(opts || obj, defaults);

      setup.init(opts);

      storage.set(opts, obj, cb);
    };

  });


  /* secstore.js, do work */
  window.secstore = new secstore;
}))(window);
