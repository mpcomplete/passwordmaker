// Copyright (c) 2009 Matt Perry. All rights reserved.
// Use of this source code is governed by the LGPL that can be found in the
// LICENSE file.

// Custom hacks to tweak the javascript edition of PasswordMaker to work as a
// Chrome extension.

// Load saved settings before anything else.
chrome.storage.sync.get(null, function(storage) {
  console.log("got cookie: " + storage.cookie);
  if (storage.cookie)
    document.cookie = storage.cookie;
  enablePasswordVerify = storage.enablePasswordVerify;
  initCustom();
});

function initCustom() {
  init();

  // Get the site's URL and fill in the input field.
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs && tabs[0]) {
      window.contentTab = tabs[0];
      preUrl.value = window.contentTab ? window.contentTab.url : '';
      populateURL();
    }
  });

  var elemTable = document.getElementsByTagName('table')[0];
  elemTable = elemTable.getElementsByTagName('tbody')[0];

  // Add a button to actually send the password to the page.
  var accept = document.createElement('tr');
  accept.innerHTML =
      '<td>Fill in Password</td>' +
      '<td><button onclick="sendPassword()">Accept</button></td>';
  elemTable.insertBefore(accept, elemTable.firstChild);

  // Add a Password Verifier.
  var pwVerify = document.createElement('tr');
  pwVerify.innerHTML =
      '<td><input type="checkbox" id="passwordVerifyToggle"/><label' +
      ' for="passwordVerifyToggle">Manual Password Verifier</label></td>' +
      '<td><div id="passwordVerify"></div></td>';
  pwVerify.title =
      'A 3 letter code that will always be the same for a given master' +
      ' password. Use this to quickly check that you typed your password' +
      ' correctly.';
  var saveMaster = document.getElementById('saveMasterLB');
  saveMaster = saveMaster.parentNode.parentNode;
  elemTable.insertBefore(pwVerify, saveMaster);
  var toggle = document.getElementById('passwordVerifyToggle');
  toggle.checked = !!enablePasswordVerify;
  toggle.onchange = function() {
    updatePasswordVerify();
    enablePasswordVerify = toggle.checked;
  };

  var isOptions = location.search.indexOf("options=true") >= 0;
  if (isOptions) {
    // Options mode: hide password fill stuff.
    accept.style.display = 'none';
    elemTable.childNodes[3].style.display = 'none';  // input URL
    showOptions();
  }

  updatePasswordVerify();
  initChangeHandlers();

  document.body.style.visibility = 'visible';
  passwdMaster.focus();
}

window.onload = function() {
  // For some reason the popup won't focus the master password immediately.
  // Wait 100ms instead.
  setTimeout(function() { passwdMaster.focus(); }, 100);
}

window.onunload = function() {
  chrome.storage.sync.set({
    "cookie": document.cookie,
    "enablePasswordVerify": enablePasswordVerify
  });
  console.log("saving cookie: " + document.cookie);
}

function addHandler(id, handler) {
  var elem = document.getElementById(id);
  if (elem.type == "button") {
    elem.onclick = handler;
  } else {
    elem.onchange = handler;
    elem.onkeypress = handler;
    elem.oninput = handler;
  }
}

function initChangeHandlers() {
  addHandler("profileLB", loadProfile);
  addHandler("preURL", populateURL);
  addHandler("passwdMaster", function(e) {
    updatePassword();
    if (e && e.charCode == 13)
      sendPassword();
  });
  addHandler("saveMasterLB", onSaveMasterLBChanged);
  addHandler("whereLeetLB", "onchange",
      function() { onWhereLeetLBChanged(); updatePassword(); });
  addHandler("leetLevelLB", updatePassword);
  addHandler("hashAlgorithmLB", updatePassword);
  addHandler("protocolCB", populateURL);
  addHandler("subdomainCB", populateURL);
  addHandler("domainCB", populateURL);
  addHandler("pathCB", populateURL);
  addHandler("passwdUrl", updatePassword);
  addHandler("passwdLength", function() {
    if (/\D/.test(this.value)) this.value = "8";
    updatePassword();
  });
  addHandler("usernameTB", updatePassword);
  addHandler("counter", updatePassword);
  addHandler("charset", updatePassword);
  addHandler("passwordPrefix", updatePassword);
  addHandler("passwordSuffix", updatePassword);
  addHandler("ifHidePasswd", function() {
    if (ifHidePasswd.checked) {
      passwdGenerated.style.color = "#fff";
    } else {
      passwdGenerated.style.color = "#00f";
    }
    saveGlobalPrefs();
  });
  addHandler("saveProfileBtn", saveProfile);
  addHandler("loadProfileBtn", loadProfile);
  addHandler("deleteProfileBtn", deleteProfile);
}

// Sends our generated password up to the extension, who routes it to the
// page.
function sendPassword() {
  chrome.tabs.sendMessage(contentTab.id, {password: passwdGenerated.value});
  window.close();
}

// Shows the options rows.
function showOptions() {
  var options = document.getElementsByClassName("options");
  for (var i = 0; i < options.length; ++i) {
    options[i].style.display = 'table-row';
  }
}

// Regenerates the password and verifier code.
function updatePassword() {
  preGeneratePassword();
  updatePasswordVerify();
}

// Updates the Password Verifier code based on the master password.
function updatePasswordVerify() {
  var toggle = document.getElementById('passwordVerifyToggle');
  var pwVerify = document.getElementById('passwordVerify');
  if (!toggle.checked) {
    pwVerify.innerText = "";
    return;
  }

  // Generate the master password with an empty URL first, then feed the
  // result through the hash function again. This way, we take all the
  // settings into account, while still generating a usable 3-letter code.
  var passwdUrlSaved = passwdUrl.value;
  var passwdLengthSaved = passwdLength.value;
  var passwdGeneratedSaved = passwdGenerated.value;

  passwdUrl.value = "";
  preGeneratePassword();
  var result = passwdGenerated.value;
  passwdUrl.value = passwdUrlSaved;
  passwdLength.value = passwdLengthSaved;
  passwdGenerated.value = passwdGeneratedSaved;

  var hashAlgorithm = "sha256";
  var whereToUseL33t = "none";
  var l33tLevel = "off";
  var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  var length = 3;
  var result = generatepassword(
       hashAlgorithm, result, "",
       whereToUseL33t, l33tLevel, length, charset, "", "");
  pwVerify.innerText = result.substr(0, length);
}
