// Copyright (c) 2009 Matt Perry. All rights reserved.
//               2013 Chris Juelg: minor user experience changes
// Use of this source code is governed by the LGPL that can be found in the
// LICENSE file.

// Custom hacks to tweak the javascript edition of PasswordMaker to work as a
// Chrome extension.

// Load saved settings before anything else.
chrome.storage.sync.get({enablePasswordVerify: true, cookies: []},
    function(storage) {
  for (var i in storage.cookies) {
    document.cookie = storage.cookies[i];
  }
  enablePasswordVerify = storage.enablePasswordVerify;
  initCustom();
});

function saveSettings() {
  // Save the profile data (stored in document.cookie). We skip global and
  // session prefs because those may contain the master password, and we don't
  // want to sync that.
  var cookies = document.cookie.split("; ");
  var storage = {enablePasswordVerify: enablePasswordVerify, cookies: []};
  for (var i in cookies) {
    if (cookies[i].indexOf("globalPrefs=") != 0 &&
        cookies[i].indexOf("sessionPrefs=") != 0) {
      storage.cookies.push(cookies[i]);
    }
  }
  chrome.storage.sync.set(storage);
}

function insertTabURL() {
  // Get the site's URL and fill in the input field.
  preUrl.value = window.contentTab ? window.contentTab.url : '';
  populateURL();
}

// wrap loadProfile() and insertTabURL if none given in profile
var alias_loadProfile = loadProfile;

var loadProfile = function loadProfile() {  
  alias_loadProfile();
  
// don't insert if isOptions or defined in profile
  var isOptions = location.search.indexOf("options=true") >= 0;
  if (!isOptions && (preUrl.value == undefined || preUrl.value == "")) insertTabURL();
}

function initCustom() {
  init();
  
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs && tabs[0]) {
      window.contentTab = tabs[0];
    }
  });
  
  var isOptions = location.search.indexOf("options=true") >= 0;
  if (!isOptions) insertTabURL();

  var elemTable = document.getElementsByTagName('table')[0];
  elemTable = elemTable.getElementsByTagName('tbody')[0];

  // Add a Password Verifier, if it's enabled.
  if (isOptions || enablePasswordVerify) {
    var pwVerify = document.createElement('tr');
    pwVerify.innerHTML =
        '<td>' +
        (isOptions ?
            '<input type="checkbox" id="passwordVerifyToggle"/>' : '') +
        '<label for="passwordVerifyToggle">Manual Password Verifier</label>' +
        '</td><td><div id="passwordVerify"></div></td>';
    pwVerify.title =
        'A 3 letter code that will always be the same for a given master' +
        ' password and settings. Use this to quickly check that you typed' +
        ' your password correctly.';
    var saveMaster = document.getElementById('saveMasterLB');
    saveMaster = saveMaster.parentNode.parentNode;
    elemTable.insertBefore(pwVerify, saveMaster);
    var toggle = document.getElementById('passwordVerifyToggle');
    if (toggle) {
      toggle.checked = !!enablePasswordVerify;
      toggle.onchange = function() {
        enablePasswordVerify = toggle.checked;
        updatePasswordVerify();
      };
    }
  }

  if (isOptions) {
    showOptions();
  } else {
    // Add a button to actually send the password to the page.
    var accept = document.createElement('tr');
    accept.innerHTML =
        '<td>Fill in Password</td>' +
        '<td><button id="sendPassword">Accept</button></td>';
    elemTable.insertBefore(accept, elemTable.firstChild);
    document.getElementById('sendPassword').onclick = sendPassword;

    // Add a link to the options page at the top right.
    var options = document.createElement('tr');
    options.innerHTML =
       '<td colspan="2" style="text-align: right;">' +
       '<button id="editOptions">Edit Settings</button></td>';
    elemTable.appendChild(options);
    document.getElementById('editOptions').onclick = function() {
      window.open('passwordmaker.html?options=true', 'passwordmaker.options');
    };
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
  setTimeout(function() { passwdMaster.focus(); }, 500);
}

window.onunload = function() {
  saveSettings();
}

// Sets up all the onchange event handlers for the form elements. This
// is needed because CSP has us on lockdown.
function initChangeHandlers() {
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
  addHandler("saveProfileBtn", function() {
    saveProfile();
    saveSettings();
  });
  addHandler("loadProfileBtn", loadProfile);
  addHandler("deleteProfileBtn", deleteProfile);
}

// Sends our generated password down to the current page.
function sendPassword() {
  chrome.tabs.executeScript(contentTab.id,
      {file: "form-filler.js", allFrames: true},
      function() {
    chrome.tabs.sendMessage(contentTab.id, {password: passwdGenerated.value});
    window.close();
  });
}

// Shows the options rows.
function showOptions() {
  var options = document.getElementsByClassName("options");
  for (var i = 0; i < options.length; ++i) {
    options[i].style.display = 'table-row';
  }

  var activateEdits = document.getElementsByClassName("activateEdit");
  for (var i = 0; i < activateEdits.length; ++i) {
    activateEdits[i].style.display = 'inline';
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
  if (!enablePasswordVerify) {
    if (pwVerify)
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
