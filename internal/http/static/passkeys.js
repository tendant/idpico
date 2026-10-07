// Passkeys (WebAuthn) for IDPico: the one piece of the UI that needs
// JavaScript, because only the browser can talk to an authenticator.
// No inline script: pages mark elements with data-passkey-* attributes.
//
// The server speaks the WebAuthn JSON form (binary fields as base64url);
// navigator.credentials wants ArrayBuffers, so this file converts both ways.
(function () {
  "use strict";

  function b64urlToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function descriptors(list) {
    return (list || []).map(function (c) {
      return Object.assign({}, c, { id: b64urlToBuf(c.id) });
    });
  }

  function creationOptions(json) {
    var pk = json.publicKey;
    return Object.assign({}, pk, {
      challenge: b64urlToBuf(pk.challenge),
      user: Object.assign({}, pk.user, { id: b64urlToBuf(pk.user.id) }),
      excludeCredentials: descriptors(pk.excludeCredentials),
    });
  }

  function requestOptions(json) {
    var pk = json.publicKey;
    return Object.assign({}, pk, {
      challenge: b64urlToBuf(pk.challenge),
      allowCredentials: descriptors(pk.allowCredentials),
    });
  }

  function credentialJSON(cred) {
    var r = cred.response, out = {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: { clientDataJSON: bufToB64url(r.clientDataJSON) },
    };
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64url(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = bufToB64url(r.authenticatorData);
      out.response.signature = bufToB64url(r.signature);
      if (r.userHandle) out.response.userHandle = bufToB64url(r.userHandle);
    }
    return JSON.stringify(out);
  }

  function post(url, fields) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString(),
    }).then(function (resp) {
      return resp.json().then(function (body) {
        if (!resp.ok) {
          if (body.redirect) window.location.assign(body.redirect);
          throw new Error(body.error || "Request failed.");
        }
        return body;
      });
    });
  }

  function showError(root, err) {
    var el = root.querySelector("[data-passkey-error]");
    var msg = err && err.name === "NotAllowedError"
      ? "The passkey request was cancelled or timed out."
      : (err && err.message) || "Something went wrong.";
    if (el) { el.textContent = msg; el.hidden = false; }
  }

  function supported() {
    return window.PublicKeyCredential && navigator.credentials && navigator.credentials.create;
  }

  // Account page: <form data-passkey-register data-begin=… data-finish=…>
  // with csrf_token, current_password and name fields.
  function register(form) {
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var csrf = form.elements.csrf_token.value;
      var button = form.querySelector("button");
      if (button) button.disabled = true;
      post(form.dataset.begin, { csrf_token: csrf, current_password: form.elements.current_password.value })
        .then(function (options) { return navigator.credentials.create({ publicKey: creationOptions(options) }); })
        .then(function (cred) {
          return post(form.dataset.finish, { csrf_token: csrf, name: form.elements.name.value, credential: credentialJSON(cred) });
        })
        .then(function (body) {
          if (body.recovery_codes) {
            var box = document.querySelector("[data-passkey-recovery]");
            box.querySelector("pre").textContent = body.recovery_codes.join("\n");
            box.hidden = false;
            form.hidden = true;
            return;
          }
          window.location.assign(body.redirect || "/account");
        })
        .catch(function (err) { showError(form, err); if (button) button.disabled = false; });
    });
  }

  // Code page: <div data-passkey-login data-begin=… data-finish=…
  // data-csrf=… data-return-url=…> with a button inside.
  function login(root) {
    var button = root.querySelector("button");
    button.addEventListener("click", function () {
      var d = root.dataset;
      button.disabled = true;
      post(d.begin, { csrf_token: d.csrf })
        .then(function (options) { return navigator.credentials.get({ publicKey: requestOptions(options) }); })
        .then(function (cred) {
          return post(d.finish, { csrf_token: d.csrf, return_url: d.returnUrl || "", credential: credentialJSON(cred) });
        })
        .then(function (body) { window.location.assign(body.redirect || "/"); })
        .catch(function (err) { showError(root, err); button.disabled = false; });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var nodes = document.querySelectorAll("[data-passkey-register], [data-passkey-login]");
    if (!supported()) {
      nodes.forEach(function (n) {
        var el = n.querySelector("[data-passkey-error]");
        if (el) { el.textContent = "This browser does not support passkeys."; el.hidden = false; }
        var b = n.querySelector("button"); if (b) b.disabled = true;
      });
      return;
    }
    document.querySelectorAll("[data-passkey-register]").forEach(register);
    document.querySelectorAll("[data-passkey-login]").forEach(login);
  });
})();
