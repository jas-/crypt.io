/**
 * secStore.js - Encryption enabled browser storage
 *
 * Fork me @ https://www.github.com/jas-/secStore.js
 *
 * Author: Jason Gerfen <jason.gerfen@gmail.com>
 * License: GPL (see LICENSE)
 */
(function (window, undefined) {

  'use strict';

  /**
   * @function secStore
   * @abstract
   * @param obj {Object} User defined options
   * @param cb {Function} User defined function
   */
  var secStore = secStore || function (obj, cb) {

    /**
     * @var {Object} defaults
     * @abstract Default set of options for plug-in
     *
     * @param {Boolean} encrypt Optionally encrypt stored data
     * @param {Object} data Data to be setd (JSON objects)
     * @param {String} passphrase Passphrase to use (optional)
     * @param {String} storage Storage mechanism (local, session or cookies)
     */
    var defaults = {
      encrypt: false,
      data: {},
      key: 'secStore.js',
      passphrase: '',
      storage: 'local'
    };

    /**
     * @method setup
     * @scope private
     * @abstract Initial setup routines
     */
    var setup = setup || {

      /**
       * @function set
       * @scope private
       * @abstract Initialization
       *
       * @param {Object} opts Plug-in option object
       * @param {Function} cb Callback function
       *
       * @returns {Boolean}
       */
      init: function (opts, cb) {
        opts.passphrase = (opts.encrypt && opts.passphrase) ?
          opts.passphrase : (opts.encrypt && !opts.passphrase) ?
          crypto.key(opts) : false;

        var ret = (libs.size(storage.toJSON(opts.data)) > 0) ?
          storage.set(opts, cb) : storage.set(opts, cb);

        return ret;
      }
    };

    /**
     * @method storage
     * @scope private
     * @abstract Interface to handle storage options
     */
    var storage = storage || {

      /**
       * @function quota
       * @scope private
       * @abstract Tests specified storage option for current amount of space available.
       *  - Cookies: 4K
       *  - localStorage: 5MB
       *  - sessionStorage: 5MB
       *  - default: 5MB
       *
       * @param {String} t Type of storage specified
       *
       * @returns {Boolean}
       */
      quota: function (storage) {
        var max = /local|session/.test(storage) ? 1024 * 1025 * 5 : 1024 * 4
					,	cur = libs.total(storage)
					,	total = max - cur;

        if (total <= 0) {
          return false;
        }

        return true;
      },

      /**
       * @function set
       * @scope private
       * @abstract Interface for saving to available storage mechanisms
       *
       * @param {Object} opts Default options
       * @param {Function} cb Callback function
       *
       * @returns {Boolean}
       */
      set: function (opts, cb) {
        var ret = false;

        if (!storage.quota(opts.storage))
          cb('Browser storage quota has been exceeded.');

        var existing = storage.get(opts, cb);

        if (libs.size(opts) > 0) {
          libs.merge(opts.data, existing);
        }

        opts.data = (opts.encrypt) ?
          sjcl.encrypt(opts.passphrase, storage.fromJSON(opts.data)) :
          storage.fromJSON(opts.data);

        switch (opts.storage) {
	        case 'cookie':
	          ret = this.cookie.set(opts);
	          break;
	        case 'local':
	          ret = this.local.set(opts);
	          break;
	        case 'session':
	          ret = this.session.set(opts);
	          break;
	        default:
	          ret = this.local.set(opts);
	          break;
        }
        if (!ret) {
          cb('Error occured saving data');
        } else {
          cb(null, 'Successfully set data');
        }
      },

      /**
       * @function get
       * @scope private
       * @abstract Interface for retrieving from available storage mechanisms
       *
       * @param {Object} opts Default options
       *
       * @returns {Object}
       */
      get: function (opts) {
        var ret = {};

        switch (opts.storage) {
        case 'cookie':
          ret = this.cookie.set(opts);
          break;
        case 'local':
          ret = this.local.set(opts);
          break;
        case 'session':
          ret = this.session.set(opts);
          break;
        default:
          ret = this.local.set(opts);
          break;
        }

        if (libs.size(storage.toJSON(ret)) > 0) {
          ret = (opts.encrypt) ? sjcl.decrypt(opts.passphrase, ret) : ret;

          cb(null, /string/.test(typeof (ret)) ? storage.toJSON(ret) : ret);
        }

				return false;
      },

      /**
       * @function fromJSON
       * @scope private
       * @abstract Convert to JSON object to string
       *
       * @param {Object|Array|String} obj Object, Array or String to convert to JSON object
       *
       * @returns {String}
       */
      fromJSON: function (obj) {
        return (/object/.test(typeof (obj))) ? JSON.stringify(obj) : obj;
      },

      /**
       * @function toJSON
       * @scope private
       * @abstract Creates JSON object from formatted string
       *
       * @param {String} obj Object to convert to JSON object
       *
       * @returns {Object}
       */
      toJSON: function (obj) {
        return (/string/.test(typeof (obj))) ? JSON.parse(obj) : obj;
      },

      /**
       * @method cookie
       * @scope private
       * @abstract Method for handling setting & retrieving of cookie objects
       */
      cookie: {

        /**
         * @function set
         * @scope private
         * @abstract Handle setting of cookie objects
         *
         * @param {Object} o Application defaults
         * @param {String} k Key to use for cookies
         * @param {String|Object} v String or object to place in cookie
         *
         * @returns {Boolean}
         */
        set: function (o, k, v) {
          var d = new Date();
          d.setTime(d.getTime() + (30 * 24 * 60 * 60 * 1000));
          document.cookie = k + '=' + v + ';expires=' + d.toGMTString() +
            ';path=/;domain=' + this.domain();
          return true;
        },

        /**
         * @function get
         * @scope private
         * @abstract Handle retrieval of cookie objects
         *
         * @param {Object} o Application defaults
         * @param {String} k cookie key
         *
         * @returns {String|False}
         */
        get: function (o, k) {
          var i, x, y, z = document.cookie.split(";");
          for (i = 0; i < z.length; i++) {
            x = z[i].substr(0, z[i].indexOf('='));
            y = z[i].substr(z[i].indexOf('=') + 1);
            x = x.replace(/^\s+|\s+$/g, '');
            if (x == k) {
              return unescape(y);
            }
          }
          return false;
        },

        /**
         * @function domain
         * @scope private
         * @abstract Provides current domain of client for cookie realm
         *
         * @returns {String}
         */
        domain: function () {
          return location.hostname;
        }
      },

      /**
       * @method local
       * @scope private
       * @abstract Method for handling setting & retrieving of localStorage objects
       */
      local: {

        /**
         * @function set
         * @scope private
         * @abstract Handle setting & retrieving of localStorage objects
         *
         * @param {Object} opts Application defaults
         *
         * @returns {Boolean}
         */
        set: function (opts) {
					try {
	          window.localStorage.setItem(opts.key, opts.data);
						return true;
					} catch(e) {
						return false;
					}
        },

        /**
         * @function get
         * @scope private
         * @abstract Handle retrieval of localStorage objects
         *
         * @param {Object} o Application defaults
         *
         * @returns {Object|String|Boolean}
         */
        get: function (opts) {
          return window.localStorage.getItem(opts.key);
        }
      },

      /**
       * @method session
       * @scope private
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
        set: function (opts) {
					try {
						window.sessionStorage.setItem(opts.key, opts.data);
						return true;
					} catch(e) {
						return false;
					}
        },

        /**
         * @function get
         * @scope private
         * @abstract Retrieves sessionStorage objects
         *
         * @param {Object} o Application defaults
         *
         * @returns {Object|String|Boolean}
         */
        get: function (o) {
          return window.sessionStorage.getItem(opts.key);
        }
			}
    };

    /**
     * @method crypto
     * @scope private
     * @abstract Interface to handle encryption option
     */
    var crypto = crypto || {

      /**
       * @function key
       * @scope private
       * @abstract Prepares key for encryption/decryption routines
       *
       * @param {Object} opts Global options object
       *
       * @returns {String}
       */
      key: function (opts) {
        var pass = crypto.uid()
					,	salt = crypto.salt(pass);

        return sjcl.codec.hex.fromBits(sjcl.misc.pbkdf2(pass, salt, 10000, 256));
      },

      /**
       * @function uid
       * @scope private
       * @abstract Generates a machine identifier
       *
       * @returns {String}
       */
      uid: function () {
        var ret = window.navigator.appName +
          window.navigator.appCodeName +
          window.navigator.product +
          window.navigator.productSub +
          window.navigator.appVersion +
          window.navigator.buildID +
          window.navigator.userAgent +
          window.navigator.language +
          window.navigator.platform +
          window.navigator.oscpu;
        return ret.replace(/\s/, '');
      },

      /**
       * @function salt
       * @scope private
       * @abstract Creates salt from string & iv
       *
       * @param {String} str Machine identification used as salt
       *
       * @returns {String}
       */
      salt: function (str) {
        var rec
					,	ret
					,	hash = []
					, slt = crypto.iv(str);

        hash[0] = sjcl.hash.sha256.hash(str), rec = [], rec = hash[0], ret;

        for (var i = 1; i < 3; i++) {
          hash[i] = sjcl.hash.sha256.hash(hash[i - 1].concat(slt));
          ret = rec.concat(hash[i]);
        }
        return JSON.stringify(sjcl.codec.hex.fromBits(ret));
      },

      /**
       * @function iv
       * @scope private
       * @abstract Creates IV based on UID
       *
       * @param {String} str Supplied string
       *
       * @returns {String}
       */
      iv: function (str) {
        return encodeURI(str.replace(/-/gi, '').substring(16, Math.ceil(16 * str.length) % str.length));
      }
    };

    /**
     * @method libs
     * @scope private
     * @abstract Miscellaneous helper libraries
     */
    var libs = libs || {

			/**
			 * @function total
			 * @scope private
			 * @abstract Returns size of specified storage
			 *
			 * @param {String} storage Storage mechanism
			 *
			 * @returns {Insteger}
			 */
			total: function(storage) {
				var current = ''
					,	engine = window.storage+'Storage';

				for(var key in engine){
					if(engine.hasOwnProperty(key)){
						current += engine[key];
					}
        }

        return current ? 3 + ((current.length * 16) / (8 * 1024)) : 0;
			},

      /**
       * @function size
       * @scope private
       * @abstract Perform calculation on objects
       *
       * @param {Object|Array} obj The object/array to calculate
       *
       * @returns {Integer}
       */
      size: function (obj) {
				var n = 0;

			  if (/object/.test(typeof(obj))) {
			    for(var i in obj){
			      if (obj.hasOwnProperty(obj[i])) n++;
			    }
			  } else if (/array/.test(typeof(obj))) {
			    n = obj.length;
			  }
			  return n;
			},

      /**
       * @function merge
       * @scope private
       * @abstract Perform preliminary option/default object merge
       *
       * @param {Object} defaults Application defaults
       * @param {Object} obj User supplied object
       *
       * @returns {Object}
       */
      merge: function (defaults, obj) {
        defaults = defaults || {};

        for (var item in defaults) {
          if (defaults.hasOwnProperty(item)) {
            obj[item] = (/object/.test(typeof (defaults[item]))) ?
              this.merge(obj[item], defaults[item]) : defaults[item];
          }
          obj[item] = defaults[item];
        }

        return obj;
      }
    };

    /**
     * @function init
     * @scope public
     * @abstract Handles options and begins communications
     */
    var init = function () {
      cb = cb || obj;

      var opts = libs.merge(obj, defaults);

      setup.init(opts, cb);
    }();
  };

  /* secStore.js, do work */
  window.secStore = secStore;

})(window);
