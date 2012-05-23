// Copyright (c) 2012 Matt Perry. All rights reserved.
// Use of this source code is governed by the LGPL that can be found in the
// LICENSE file.

var changedSettings = {};

// A hackish way to detect when our popup has closed, so we can sync any
// changed settings.
chrome.extension.onConnect.addListener(function(port) {
  port.onMessage.addListener(function(settings) {
    changedSettings = settings;
  });
  port.onDisconnect.addListener(function() {
    changedSettings.cookie = document.cookie;
    chrome.storage.sync.set(changedSettings);
  });
});
