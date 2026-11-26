(function () {
  'use strict';
  var doc = document;
  var root = doc.documentElement;
  root.classList.add('js');

  function all(selector, scope) {
    return Array.prototype.slice.call((scope || doc).querySelectorAll(selector));
  }

  // Theme: the system setting applies until the reader chooses.
  var themeKey = 'iptables-analyzer-theme';
  function applyTheme(theme) {
    if (theme === 'light' || theme === 'dark') {
      root.setAttribute('data-theme', theme);
    } else {
      root.removeAttribute('data-theme');
    }
  }
  try {
    applyTheme(localStorage.getItem(themeKey));
  } catch (e) { /* storage is not available: the system setting stays */ }
  var themeButton = doc.getElementById('theme');
  if (themeButton) {
    themeButton.addEventListener('click', function () {
      var current = root.getAttribute('data-theme');
      var dark = current ? current === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches;
      var next = dark ? 'light' : 'dark';
      applyTheme(next);
      try {
        localStorage.setItem(themeKey, next);
      } catch (e) { /* the choice lasts until the page is closed */ }
    });
  }

  // Findings: filter by severity and by text.
  var findings = all('details.finding');
  var search = doc.getElementById('search');
  var shown = doc.getElementById('shown');
  var filters = all('button[data-filter]');
  var off = {};
  function refreshFindings() {
    var query = search ? search.value.trim().toLowerCase() : '';
    var count = 0;
    findings.forEach(function (finding) {
      var hide = !!off[finding.getAttribute('data-sev')] ||
        (query !== '' && finding.textContent.toLowerCase().indexOf(query) < 0);
      finding.hidden = hide;
      if (!hide) {
        count++;
      }
    });
    if (shown) {
      shown.textContent = count === findings.length ? '' : count + ' of ' + findings.length + ' shown';
    }
  }
  filters.forEach(function (button) {
    button.addEventListener('click', function () {
      var severity = button.getAttribute('data-filter');
      off[severity] = !off[severity];
      button.setAttribute('aria-pressed', off[severity] ? 'false' : 'true');
      refreshFindings();
    });
  });
  if (search) {
    search.addEventListener('input', refreshFindings);
  }
  function showAllFindings() {
    off = {};
    filters.forEach(function (button) {
      button.setAttribute('aria-pressed', 'true');
    });
    if (search) {
      search.value = '';
    }
    refreshFindings();
  }

  // Rules: filter by text. A chain without a matching rule is hidden.
  var chains = all('details.chain');
  var ruleSearch = doc.getElementById('rule-search');
  var rulesShown = doc.getElementById('rules-shown');
  var chainState = null;
  function refreshRules() {
    var query = ruleSearch.value.trim().toLowerCase();
    if (query === '') {
      chains.forEach(function (chain, i) {
        chain.hidden = false;
        if (chainState) {
          chain.open = chainState[i];
        }
        all('li', chain).forEach(function (rule) {
          rule.hidden = false;
        });
      });
      chainState = null;
      rulesShown.textContent = '';
      return;
    }
    if (!chainState) {
      chainState = chains.map(function (chain) {
        return chain.open;
      });
    }
    var count = 0;
    chains.forEach(function (chain) {
      var matches = 0;
      all('li', chain).forEach(function (rule) {
        var hit = rule.textContent.toLowerCase().indexOf(query) >= 0;
        rule.hidden = !hit;
        if (hit) {
          matches++;
        }
      });
      chain.hidden = matches === 0;
      chain.open = matches > 0;
      count += matches;
    });
    rulesShown.textContent = count + (count === 1 ? ' rule matches' : ' rules match');
  }
  if (ruleSearch && rulesShown) {
    ruleSearch.addEventListener('input', refreshRules);
  }

  // Buttons that open or close a group of blocks.
  all('button[data-toggle]').forEach(function (button) {
    button.addEventListener('click', function () {
      var open = button.getAttribute('data-state') === 'open';
      all(button.getAttribute('data-toggle')).forEach(function (block) {
        block.open = open;
      });
    });
  });

  // Copy the text of a block.
  function copyText(text, button) {
    var label = button.textContent;
    function done(ok) {
      button.textContent = ok ? 'Copied' : 'Select and copy';
      window.setTimeout(function () {
        button.textContent = label;
      }, 1600);
    }
    function fallback() {
      var area = doc.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.className = 'offscreen';
      doc.body.appendChild(area);
      area.select();
      var ok = false;
      try {
        ok = doc.execCommand('copy');
      } catch (e) { /* the reader copies by hand */ }
      doc.body.removeChild(area);
      done(ok);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () {
        done(true);
      }, fallback);
    } else {
      fallback();
    }
  }
  all('button[data-copy]').forEach(function (button) {
    button.addEventListener('click', function () {
      var source = doc.getElementById(button.getAttribute('data-copy'));
      if (source) {
        copyText(source.textContent, button);
      }
    });
  });

  // Sort a table by the column of the header that is activated.
  function sortKey(cell) {
    var value = cell.getAttribute('data-sort');
    if (value !== null && value !== '' && !isNaN(value)) {
      return Number(value);
    }
    return (value !== null ? value : cell.textContent).trim().toLowerCase();
  }
  function sortBy(header) {
    var table = header.closest('table');
    var body = table.tBodies[0];
    var index = Array.prototype.indexOf.call(header.parentNode.children, header);
    var ascending = header.getAttribute('aria-sort') !== 'ascending';
    var rows = Array.prototype.slice.call(body.rows);
    rows.sort(function (a, b) {
      var x = sortKey(a.cells[index]);
      var y = sortKey(b.cells[index]);
      var order = typeof x === 'number' && typeof y === 'number' ?
        x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
      return ascending ? order : -order;
    });
    rows.forEach(function (row) {
      body.appendChild(row);
    });
    all('th', header.parentNode).forEach(function (other) {
      other.removeAttribute('aria-sort');
    });
    header.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
  }
  all('th.sortable').forEach(function (header) {
    header.setAttribute('tabindex', '0');
    header.addEventListener('click', function () {
      sortBy(header);
    });
    header.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        sortBy(header);
      }
    });
  });

  // A link to a rule or to a finding opens the blocks that hold it.
  function reveal() {
    var id = window.location.hash.slice(1);
    if (!/^[A-Za-z0-9_-]+$/.test(id)) {
      return;
    }
    var target = doc.getElementById(id);
    if (!target) {
      return;
    }
    if (target.closest('[hidden]')) {
      if (target.closest('#findings')) {
        showAllFindings();
      } else if (ruleSearch && rulesShown) {
        ruleSearch.value = '';
        refreshRules();
      }
    }
    for (var node = target; node; node = node.parentElement) {
      if (node.tagName === 'DETAILS') {
        node.open = true;
      }
    }
    target.scrollIntoView();
  }
  window.addEventListener('hashchange', reveal);
  reveal();

  // Print everything, also what is folded.
  var folded = [];
  window.addEventListener('beforeprint', function () {
    folded = all('details:not([open])');
    folded.forEach(function (block) {
      block.open = true;
    });
  });
  window.addEventListener('afterprint', function () {
    folded.forEach(function (block) {
      block.open = false;
    });
    folded = [];
  });
})();
