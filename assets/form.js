// Pide un sello firmado al cargar la página; sin él, el servidor rechaza el envío.
(function () {
  var forms = document.querySelectorAll('form[data-request]');
  if (!forms.length) return;
  function stamp() {
    return fetch('/token.php', { cache: 'no-store' }).then(function (r) { return r.json(); }).then(function (d) {
      forms.forEach(function (f) { f.elements.t.value = d.t; f.elements.s.value = d.s; });
    });
  }
  var ready = stamp().catch(function () {});
  forms.forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (f.elements.s.value) return;
      e.preventDefault();
      ready.then(stamp).then(function () { f.submit(); });
    });
  });
})();
