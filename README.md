#crypt.io
crypt.io implements secures browser storage with the
[SJCL (Stanford Javascript Crypto Libraries)](http://bitwiseshiftleft.github.io/sjcl/)
crypto library.

##Features:
* HTML5 localStorage support
* HTML5 sessionStorage support
* Cookie support
* AES encryption support
* Quota support (4K for cookies and 5MB for HTML5 mechanisms)

##Options:
* _passphrase_: `{String}` User supplied passphrase
* _storage_: `{String}` Storage engine to use; local, session or cookies

##Examples:
Here are a few examples of use to get you started.

###Default use
Saving data...

```javascript
var storage = cryptio
  , inventory = [{
  	  "SKU": "39-48949",
	    "Price": 618,
	    "Item": "Snowboard"
    }, {
	    "SKU": "99-28128",
    	"Price": 78.99,
	    "Item": "Cleats"
    }, {
	    "SKU": "83-38285",
	    "Price": 3.99,
	    "Item": "Hockey Puck"
    }];

storage.set(options, 'inventory', inventory, function(err, results){
  if (err) throw err;
  console.log(results);
});
```

Retrieving data...

```javascript
var storage = cryptio;

storage.get(options, 'inventory', function(err, results){
  if (err) throw err;
  console.log(results);
});
```

###Storage option
Want to use a different storage engine like the HTML5 sessionStorage feature?

```javascript
var options = {
  storage: 'session',
};
```

Or some depreciated cookies? This is the least tested option

```javascript
var options = {
  storage: 'cookies',
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

##Requirements:
* SJCL libraries (optional - https://github.com/bitwiseshiftleft/sjcl)

##Installation:
Three methods are available for setup and use; using bower, cloning & manual

###Bower
To setup using bower

```sh
%> bower install crypt.io
```

###Clone
To setup using git

```sh
%> git clone --recursive https://github.com/jas-/crypt.io.git
```

###Manual
Copy the [crypt.io.min.js](https://github.com/jas-/crypt.io/blob/master/dist/crypt.io.min.js)
and the [sjcl](https://github.com/bitwiseshiftleft/sjcl) libraries to your web project
and include them like so.

```html
<script src="/path/to/sjcl.js"></script>
<script src="/path/to/crypt.io.min.js"></script>
```

##Support:
Found a bug? Want a feature added? General feedback or kudos? Please open
an issue so I can address it. Thanks!
