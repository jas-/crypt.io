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
