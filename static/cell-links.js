(function (global) {
  "use strict";

  var IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;

  function isIpv4(host) {
    if (!IPV4_RE.test(host)) return false;
    var parts = host.split(".");
    for (var i = 0; i < parts.length; i++) {
      var n = parseInt(parts[i], 10);
      if (n < 0 || n > 255) return false;
    }
    return true;
  }

  function browseUrlForCell(text) {
    if (!text || !String(text).trim()) return "";
    var t = String(text).trim().split(/\r?\n/)[0].trim();
    var low = t.toLowerCase();
    if (low.indexOf("http://") === 0 || low.indexOf("https://") === 0) return t;
    var first = t.split(/\s+/)[0] || t;
    var hostPart = first.split("/")[0];
    var hostOnly = hostPart.indexOf(":") >= 0 ? hostPart.split(":")[0] : hostPart;
    if (isIpv4(hostOnly)) return "http://" + hostPart;
    return "https://" + hostOnly;
  }

  /** Cột có thể Ctrl+click mở link */
  var LINK_COLUMN_KEYS = ["Domain"];

  function isLinkColumn(key) {
    return LINK_COLUMN_KEYS.indexOf(key) >= 0;
  }

  function appendCellLink(td, text) {
    var s = text != null && text !== undefined ? String(text).trim() : "";
    if (!s) return false;
    var href = browseUrlForCell(s);
    if (!href) {
      td.textContent = s;
      return false;
    }
    var a = document.createElement("a");
    a.className = "link-cell";
    a.href = href;
    a.textContent = s;
    a.title = "Ctrl+click để mở trong tab mới";
    td.appendChild(a);
    return true;
  }

  global.CellLinks = {
    browseUrlForCell: browseUrlForCell,
    appendCellLink: appendCellLink,
    isLinkColumn: isLinkColumn,
    LINK_COLUMN_KEYS: LINK_COLUMN_KEYS,
  };
})(typeof window !== "undefined" ? window : globalThis);
