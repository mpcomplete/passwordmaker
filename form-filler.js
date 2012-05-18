// Copyright (c) 2009 Matt Perry. All rights reserved.
// Use of this source code is governed by the LGPL that can be found in the
// LICENSE file.

var hasPasswordField = false;

chrome.extension.onMessage.addListener(function(msg, sender, sendResponse) {
  fillPasswords(msg.password);
});

function getPassword() {
  chrome.extension.sendMessage({showDialog: true,
                                hasPasswordField: hasPasswordField});
}

function fillPasswords(password) {
  forEachPasswordField(function(form) {
    form.value = password;
  });
}

function forEachPasswordField(callback) {
  for (var i = 0; i < document.forms.length; ++i) {
    var form = document.forms[i];
    for (var j = 0; j < form.length; ++j) {
      if (form[j].type && form[j].type.toLowerCase() == 'password') {
        callback(form[j]);
      }
    }
  }
}

function findPasswordFields() {
  forEachPasswordField(function(form) {hasPasswordField = true;});

  if (hasPasswordField) {
    chrome.extension.sendMessage({showPageAction: true});
  }
}

function registerKeybind() {
  // looking for alt+` which is 18, 192
  var lastKeyDown = 0;
  document.addEventListener(
    'keydown',
    function(e) {
      if (lastKeyDown == 18 && e.keyCode == 192) {
        e.stopPropagation();
        e.preventDefault();
        getPassword();
      }
      lastKeyDown = e.keyCode;
      return false;
    },
    false
  );
  document.addEventListener(
    'keyup',
    function(e) { lastKeyDown = 0; },
    false
  );
}

if (window == top) {
  registerKeybind();
  findPasswordFields();
}
