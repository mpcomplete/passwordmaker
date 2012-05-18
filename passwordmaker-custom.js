// Copyright (c) 2009 Matt Perry. All rights reserved.
// Use of this source code is governed by the LGPL that can be found in the
// LICENSE file.

// Custom hacks to tweak the javascript edition of PasswordMaker to work as a
// Chrome extension.

window.onload = function() {
  if (typeof(preUrl) == "undefined")
    init();

  // Get the site's URL from the query param, and fill in the input field.
  preUrl.value = window.contentTab ? window.contentTab.url : '';
  populateURL();

  function pwchanged(e) {
    preGeneratePassword();
    updatePasswordVerify();
    if (e && e.charCode == 13) {
      sendPassword();
    }
  }
  passwdMaster.onkeypress = pwchanged;
  passwdMaster.oninput = pwchanged;

  var elemTable = document.getElementsByTagName('table')[0];
  elemTable = elemTable.getElementsByTagName('tbody')[0];

  // Add a button to actually send the password to the page.
  var accept = document.createElement('tr');
  accept.innerHTML =
     '<td>Fill in Password</td>' +
     '<td><button onclick="sendPassword()">Accept</button></td>';
  elemTable.insertBefore(accept, elemTable.firstChild);

  // Add a toggle settings and help link at the top right.
  var links = document.createElement('div');
  links.innerHTML =
     '<a id="toggleSettings" href="javascript:toggleSettings()">' +
     'hide settings</a> ' +
     '<a href="help.html" target="pwmakerhelp">help</a> ';
  links.style.float = 'right';
  links.style.width = '20em';
  document.body.insertBefore(links, document.body.firstChild);

  // Add a Password Verifier.
  var pwVerify = document.createElement('tr');
  pwVerify.innerHTML =
     '<td><input type="checkbox" id="passwordVerifyToggle"' +
     ' onchange="onPasswordVerifyToggle();" />Manual Password Verifier</input></td>' +
     '<td><div id="passwordVerify"></div></td>';
  pwVerify.title = 'A 3 letter code that will always be the same for a given master' +
     ' password. Use this to quickly check that you typed your password correctly.';
  var saveMaster = document.getElementById('saveMasterLB');
  saveMaster = saveMaster.parentNode.parentNode;
  elemTable.insertBefore(pwVerify, saveMaster);
  var toggle = document.getElementById('passwordVerifyToggle');
  toggle.checked = localStorage['enablePasswordVerify'] == "true";

  if (window.showSettings) {
    // Settings mode: hide password fill stuff.
    accept.style.display = 'none';
    elemTable.childNodes[3].style.display = 'none';  // input URL
  } else {
    // Password fill mode: Hide settings options.
    updateSettings();
  }

  document.body.style.visibility = 'visible';
  passwdMaster.focus();
}

window.onunload = function() {
  chrome.extension.getBackgroundPage().saveSettings();
}

function addHandler(id, eventName, handler) {
  document.getElementById(id)[eventName] = handler;
}

function foo() {
  addHandler("profileLB", "onchange", loadProfile);
  addHandler("preURL", "onchange", populateURL);
  addHandler("passwdMaster", "onchange", preGeneratePassword);
  addHandler("saveMasterBtn", "onchange", saveMaster);
  addHandler("whereLeetLB", "onchange",
      function() { onWhereLeetLBChanged(); preGeneratePassword(); });
  addHandler("leetLevelLB", "onchange", preGeneratePassword);
  addHandler("hashAlgorithmLB", "onchange", preGeneratePassword);
  addHandler("protocolCB", "onchange", populateURL);
  addHandler("subdomainCB", "onchange", populateURL);
  addHandler("domainCB", "onchange", populateURL);
  addHandler("pathCB", "onchange", populateURL);
  addHandler("passwdUrl", "onchange", preGeneratePassword);
  addHandler("passwdLength", "onchange", function() {
      if (/\D/.test(this.value)) this.value = "8";
      preGeneratePassword();
  });
  addHandler("usernameTB", "onchange", preGeneratePassword);
  addHandler("counter", "onchange", preGeneratePassword);
  addHandler("charset", "onchange", preGeneratePassword);
  addHandler("tipsBtn", "onchange", onClickTips);
  addHandler("passwordPrefix", "onchange", preGeneratePassword);
  addHandler("passwordSuffix", "onchange", preGeneratePassword);
  addHandler("ifHidePasswd", "onchange", function() {
      if (ifHidePasswd.checked) {
	passwdGenerated.style.color = "#fff";
      } else {
        passwdGenerated.style.color = "#00f";
      }
      saveGlobalPrefs();
  });
  addHandler("saveProfileBtn", "onchange", saveProfile);
  addHandler("loadProfileBtn", "onchange", loadProfile);
  addHandler("deleteProfileBtn", "onchange", deleteProfile);
}

// Sends our generated password up to the extension, who routes it to the
// page.
function sendPassword() {
  chrome.tabs.sendRequest(contentTab.id, {password: passwdGenerated.value});
  window.close();
}

function toggleSettings() {
  showSettings = !showSettings;
  updateSettings();

  // Fit the window to the contents, plus padding.
  window.resizeBy(0, document.body.clientHeight - window.innerHeight + 20);
}

// Shows or hides the "settings" rows based on showSettings.
function updateSettings() {
  var elemTable = document.getElementsByTagName('table')[0];
  elemTable = elemTable.getElementsByTagName('tbody')[0];

  // Hardcoded silliness to pick out the rows pertaining to settings.
  var numRows = 0;
  for (var i in elemTable.childNodes) {
    var tr = elemTable.childNodes[i];
    if (tr.nodeName != 'TR' || ++numRows < 7 || numRows == 18)
      continue;

    tr.style.display = showSettings ? 'table-row' : 'none';
  }

  // Change link text.
  var str = showSettings ? "hide" : "show";
  document.getElementById('toggleSettings').innerText = str + " settings";
}

// Updates the Password Verifier code based on the master password.
function updatePasswordVerify() {
  var toggle = document.getElementById('passwordVerifyToggle');
  var pwVerify = document.getElementById('passwordVerify');
  if (!toggle.checked) {
    pwVerify.innerText = "";
    return;
  }
  var hashAlgorithm = "sha256";
  var whereToUseL33t = "none";
  var l33tLevel = "off";
  var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  var length = 3;
  var result = generatepassword(
       hashAlgorithm, passwdMaster.value, "",
       whereToUseL33t, l33tLevel, length, charset, "", "");
  pwVerify.innerText = result.substr(0, length);
}

// Turns the Password Verifier on or off based on the checkbox status.
function onPasswordVerifyToggle() {
  updatePasswordVerify();
  var toggle = document.getElementById('passwordVerifyToggle');
  localStorage['enablePasswordVerify'] = toggle.checked;
}
