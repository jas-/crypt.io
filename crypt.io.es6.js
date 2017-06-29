/**
 * crypt.io - Encryption enabled browser storage
 *
 * https://www.github.com/jas-/crypt.io
 *
 * Author: Jason Gerfen <jason.gerfen@gmail.com>
 * License: MIT (see LICENSE)
 */
'use strict';

export class cryptio {
  
  constructor() {
    this.get = storage.get();
    this.set = storage.set();
  }
  
}

class setup extends cryptio {
  
}

class storage extends cryptio {
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

class cookies extends storage() {
  set() {
    
  }
  
  get() {
    
  }
  
  domain() {
    
  }
}

class local extends storage() {
  set() {
    
  }
  
  get() {
    
  }
}

class session extends storage() {
  set() {
    
  }
  
  get() {
    
  }
}

class crypto extends cryptio() {
  constructor() {
    
  }
  
  derive() {
    
  }
  
  guid() {
    
  }
  
  salt() {
    
  }
}

class libs extends cryptio() {
  merge() {
    
  }
}
