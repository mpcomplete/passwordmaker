chrome.extension.onRequest.addListener(function(request, sender, sendResponse) {
  if (request.showDialog) {
    // A page is requesting a site password.
    if (request.hasPasswordField) {
      openDialog(sender.tab);
    } else {
      openSettings(sender.tab);
    }
  } else if (request.showPageAction) {
    chrome.pageAction.show(sender.tab.id);
  }
  sendResponse();
});

function openSettings(tab) {
  height = Math.min(900, screen.availHeight);
  var dialog = window.open('passwordmaker.html', 'PasswordMaker',
                           'width=800, height=' + height);
  dialog.contentTab = tab;
  dialog.showSettings = true;
}

function openDialog(tab) {
  height = Math.min(400, screen.availHeight);
  var dialog = window.open('passwordmaker.html', 'PasswordMaker',
                           'width=800, height=' + height);
  dialog.contentTab = tab;
  dialog.showSettings = false;
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
