#secStore.js

  Fork me @ https://www.github.com/jas-/secStore.js

##Description:
secStore is simple wrapper to handle client storage mechanisms
within the browser.

It is named secStore.js because not only will this plug-in assist
you in transparent storage & retrieval of client data, but it
will optionally provide a layer of security for said data with
the use of the [SJCL (Stanford Javascript Crypto Libraries)](http://bitwiseshiftleft.github.io/sjcl/).

##Installation:
Three methods are available for setup and use; using bower, cloning & manual

###Bower
To setup using bower

```sh
%> bower install secstore.js
```

###Clone
To setup using git

```sh
%> git clone --recursive https://github.com/jas-/secStore.js.git
```

###Manual
Copy the [secStore.min.js](https://github.com/jas-/secStore.js/blob/master/secStore.min.js)
and the [sjcl](https://github.com/bitwiseshiftleft/sjcl) libraries to your web project
and include them like so.

```html
<script src="/path/to/sjcl.js"></script>
<script src="/path/to/secStore.min.js"></script>
```

##Requirements:
* SJCL libraries (optional - https://github.com/bitwiseshiftleft/sjcl)

##Features:
* HTML5 localStorage support
* HTML5 sessionStorage support
* Cookie support
* AES encryption support
* Quota support (4K for cookies and 5MB for HTML5 mechanisms)

##Options:
* _encrypt_: `{Boolean}` Provide transparent symmetric encryption of saved data
* _data_: `{Mixed}` Object, string, array or booleans of data to be saved
* _key_: `{String}` Unique identifier used as storage key
* _passphrase_: `{String}` User supplied passphrase
* _storage_: `{String}` Storage engine to use; local, session or cookies

##Support:
Found a bug? Want a feature added? General feedback or kudos? Please open
an issue so I can address it. Thanks!

##Examples:
Here are a few examples of use to get you started.

###Default use
Saving data...

```javascript
var storage = new secStore
  , options = {
    encrypt: true,
    data: {
      key: 'some data that is somewhat private'
    }
  };


storage.set(options, function(err, results){
  if (err) throw err;
  console.log(results);
});
```

Retrieving data...

```javascript
var storage = new secStore
  , options = {
    encrypt: true
  };


storage.get(options, function(error, results){
  if err throw err;
  console.log(results);
});
```

###Storage option
Want to use a different storage engine like the HTML5 sessionStorage feature?

```javascript
var options = {
  encrypt: true,
  storage: 'session',
  data: {
    key: 'some data that is somewhat private'
  }
};
```

Or some depreciated cookies? This is the least tested option

```javascript
var options = {
  encrypt: true,
  storage: 'cookies',
  data: {
    key: 'some data that is somewhat private'
  }
};
```

###Extra security
While providing a transparent method of encryption for objects within
the client prevents the need for user interaction, in terms of security
in the event of a same-origin, dom rebinding attack coupled with a man-
in-the-middle scenario it would be more secure to prompt the user
for his/her passphrase. Here is an example of user input for the passphrase.

```javascript
var pass = window.prompt("Please enter password...", "a custom password");

var options = {
  encrypt: true,
  passphrase: pass,
  data: {
    key: 'some data that is somewhat private'
  }
};
```

###For the paranoid
Here is a robust example of saving & retrieving data implementing a user
defined password based on their input while also using key stretching
techniques to further enhance the security of the key used as well as using
a tempoary storage option such as sessionStorage for the current authenticated
session. Of course wrapping this around a TLS/SSL connection is recommended.


Saving data (please keep in mind that a static value for the salt is not recommended)

```javascript
var pass = window.prompt("Enter password to protect saved data", "");

var options = {
  encrypt: true,
  passphrase: sjcl.misc.pbkdf2(pass, "salt", 1000000, 256),
  data: {
    key: 'some data that is somewhat private'
  }
};
```

##Warning:
I feel it is worth noting that while this plugin makes every
attempt at providing a secure transparent method of saving &
retieving encrypted data based on unique identifiers retrieved
from the client browser, it is by no means a replacement for
a user specifying their own passphrase. See the 'Extra security'
example for this.

For the reasons behind this notice please research MITM ARP
poisoning techniques coupled with use of the BeEF injection
framework. This attack vector as well as browser plug-ins &
JavaScript scriplets can expose the parameters used to create
a unique transparent key used by the browser.

While this technique is possible, it is typically a low threat
vector due to the technologies & knowledge necessary to exploit.

