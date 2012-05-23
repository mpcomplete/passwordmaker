var changedSettings = {};

chrome.extension.onConnect.addListener(function(port) {
  port.onMessage.addListener(function(settings) {
    changedSettings = settings;
  });
  port.onDisconnect.addListener(function() {
    changedSettings.cookie = document.cookie;
    chrome.storage.sync.set(changedSettings);
  });
});
