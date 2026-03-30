(function () {
  function parseCell(table, row, colIndex, type) {
    var cell = row.cells[colIndex];
    var t = (cell && cell.textContent) ? cell.textContent.trim() : "";
    if (type === "num") {
      var n = parseInt(t.replace(/[^\d-]/g, ""), 10);
      return isNaN(n) ? 0 : n;
    }
    return t.toLowerCase();
  }

  function sortTable(table, colIndex, type, ascending) {
    var tbody = table.tBodies[0];
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.sort(function (a, b) {
      var va = parseCell(table, a, colIndex, type);
      var vb = parseCell(table, b, colIndex, type);
      var cmp = 0;
      if (type === "num") {
        cmp = va - vb;
      } else {
        cmp = va < vb ? -1 : va > vb ? 1 : 0;
      }
      return ascending ? cmp : -cmp;
    });
    rows.forEach(function (r) {
      tbody.appendChild(r);
    });
  }

  document.querySelectorAll("table.sortable-table").forEach(function (table) {
    var headers = table.querySelectorAll("thead th.sortable");
    var state = {};
    headers.forEach(function (th) {
      th.style.cursor = "pointer";
      th.title = "Click để sắp xếp";
      th.addEventListener("click", function () {
        var col = parseInt(th.getAttribute("data-col"), 10);
        var type = th.getAttribute("data-type") || "str";
        var key = String(col);
        var asc = state[key] !== true;
        state[key] = asc;
        sortTable(table, col, type, asc);
      });
    });
  });
})();
