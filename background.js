chrome.extension.onMessage.addListener(function(msg, sender, sendResponse) {
  if (msg.showDialog) {
    // A page is msging a site password.
    if (msg.hasPasswordField) {
      openDialog(sender.tab);
    } else {
      openSettings(sender.tab);
    }
  } else if (msg.showPageAction) {
    chrome.pageAction.show(sender.tab.id);
  }
  sendResponse();
});

function openSettings(tab) {
  height = Math.min(900, screen.availHeight);
  var dialog = window.open('passwordmaker.html', 'PasswordMaker',
                           'width=800, height=' + height);
  dialog.contentTab = tab;
  dialog.passwordMode = false;
}

function openDialog(tab) {
  height = Math.min(450, screen.availHeight);
  var dialog = window.open('passwordmaker.html', 'PasswordMaker',
                           'width=800, height=' + height);
  dialog.contentTab = tab;
  dialog.passwordMode = true;
}

chrome.browserAction.onClicked.addListener(function(tab) {
  openDialog(tab);
});

chrome.storage.sync.get("settings", function(value) {
  document.cookie = value;
});

function saveSettings() {
  chrome.storage.sync.set({"settings": document.cookie});
}
