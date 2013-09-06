#secStore.js

   Fork me @ https://www.github.com/jas-/secStore.js

##Description:
secStore is simple wrapper to handle client storage mechanisms
within the browser.

It is named secStore.js because not only will this plug-in assist
you in transparent storage & retrieval of client data, but it
will optionally provide a layer of security for said data with
the use of the SJCL (Stanford Javascript Crypto Libraries).

##Requirements:
* jQuery libraries (required - http://www.jquery.com)
* SJCL libraries (optional - https://github.com/bitwiseshiftleft/sjcl)

##Features:
* HTML5 localStorage support
* HTML5 sessionStorage support
* Cookie support
* AES encryption support
* Quota support (4K for cookies and 5MB for HTML5 mechanisms)

##Options:
* appID:       Unique application identifier
* storage:     HTML5 localStorage, sessionStorage and cookies supported
* aes:         Use AES encryption for client storage objects
* callback:    Executes a callback function on success saves
* errCallback: Executes a callback function when any save was unsuccessful


##Notes:
I feel it is worth noting that while this plugin makes every
attempt at providing a secure transparent method of saving &
retieving encrypted data based on unique identifiers retrieved
from the client browser, it is by no means a replacement for
a user specifying their own passphrase. See the 'Extra security'
example for this.

##Support:
Found a bug? Want a feature added? General feedback or kudos? Please open
an issue so I can address it. Thanks!

##Examples:
Here are a few examples of use to get you started.

###Default use
Saving data...

```
$(window).secStore({
  appID: 'stuff',
  data: {key: 'value'}
});
```

Retrieving data...

```
$(window).secStore({
  appID: 'stuff',
  callback: function(obj){
    /* process obj */
  }
});
```

###Debugging example
Need to see some details of what is transpiring? This will not be available
if you are using the minified version.

```
$(window).secStore({
  debug: true
});
```

###Storage option
Want to use a different storage engine?

```
$(window).secStore({
  storage: 'session'
});
```

Or some depreciated cookies?

```
$(window).secStore({
  storage: 'cookies'
});
```

###Need some encryption?
When you need to protect a bit of data in the event of browser flaw
that leads to bypassing same-origin restrictions.

```
$(window).secStore({
  aes: true,
  data: {key: 'value'}
});
```

###Extra security
While providing a transparent method of encryption for objects within
the client prevents the need for user interaction, in terms of security
in the event of a same-origin, dom rebinding attack coupled with a man-
in-the-middle scenario it would be more secure to prompt the user
for his/her passphrase. Here is an example of user input for the passphrase.

```
var pass = window.prompt("Please enter password...", "a custom password");
$(window).secStore({
  uuid: pass,
  aes: true,
});
```

###For the paranoid
Here is a robust example of saving & retrieving data implementing a user
defined password based on their input while also using key stretching
techniques to further enhance the security of the key used as well as using
a tempoary storage option such as sessionStorage for the current authenticated
session. Of course wrapping this around a TLS/SSL connection is recommended.


Saving data (please keep in mind that a static value for the salt is not recommended)
```
var pass = window.prompt("Enter password to protect saved data", "");
$(window).secStore({
  storage: 'session',
  aes: true,
  uuid: sjcl.misc.pbkdf2(pass, "salt", 1000, 256),
  data: {key: "value"},
  callback: function(results){
    document.write("Results of encrypted save: <br/>"+results);
    document.write("<br/>");
  }
});
```

Retrieving data
var pw = window.prompt("Enter password to retrieve protected data", "");
$(window).secStore({
  storage: 'session',
  aes: true,
  uuid: sjcl.misc.pbkdf2(pw, "salt", 1000, 256),
  callback: function(results){
    document.write("Results of decrypted retrieval: <br/>"+JSON.stringify(results));
    document.write("<br/>");
  }
});
```