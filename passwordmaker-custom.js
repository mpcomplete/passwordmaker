// Copyright (c) 2009 Matt Perry. All rights reserved.
// Use of this source code is governed by the LGPL that can be found in the
// LICENSE file.

// Custom hacks to tweak the javascript edition of PasswordMaker to work as a
// Chrome extension.

// Open a port to the event page. When the page dies, the port will die,
// letting the event page clean things up for us.
var port = chrome.extension.connect();

// Load saved settings before anything else.
chrome.storage.sync.get({enablePasswordVerify: true}, function(storage) {
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

  var isOptions = location.search.indexOf("options=true") >= 0;

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
        port.postMessage({enablePasswordVerify: enablePasswordVerify});
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
  addHandler("saveProfileBtn", saveProfile);
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
