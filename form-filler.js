// Copyright (c) 2009 Matt Perry. All rights reserved.
// Use of this source code is governed by the LGPL that can be found in the
// LICENSE file.

chrome.extension.onMessage.addListener(function(msg, sender, sendResponse) {
  fillPasswords(msg.password);
});

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
