/**
 * IP multi-source purity check widget
 * Sources: IPPure / ipapi.is / IP2Location / Scamalytics / DB-IP / ipregistry / ipinfo
 * Env: POLICY, MARK_IP
 */
export default async function(ctx) {
  var BG_COLOR  = { light: '#FFFFFF', dark: '#1C1C1E' };
  var C_TITLE   = { light: '#1A1A1A', dark: '#FFD700' };
  var C_SUB     = { light: '#666666', dark: '#B0B0B0' };
  var C_MAIN    = { light: '#1A1A1A', dark: '#FFFFFF' };
  var C_GREEN   = { light: '#32D74B', dark: '#32D74B' };
  var C_YELLOW  = { light: '#FFD60A', dark: '#FFD60A' };
  var C_ORANGE  = { light: '#FF9500', dark: '#FF9500' };
  var C_RED     = { light: '#FF3B30', dark: '#FF3B30' };
  var C_ICON_IP = { light: '#007AFF', dark: '#0A84FF' };
  var C_ICON_LO = { light: '#5856D6', dark: '#5E5CE6' };
  var C_ICON_SC = { light: '#AF52DE', dark: '#BF5AF2' };

  var policy = ctx.env.POLICY || "";
  var markIP = (ctx.env.MARK_IP || "").toLowerCase() === "true";

  async function safe(fn) { try { return await fn(); } catch(e) { return null; } }

  async function get(url, headers) {
    var opts = { timeout: 10000 };
    if (headers) opts.headers = headers;
    if (policy && policy !== "DIRECT") opts.policy = policy;
    var res = await ctx.http.get(url, opts);
    return await res.text();
  }

  function jp(s) { try { return JSON.parse(s); } catch(e) { return null; } }
  function ti(v) { var n = Number(v); return Number.isFinite(n) ? Math.round(n) : null; }

  function maskIP(ip) {
    if (!ip) return '';
    if (ip.includes('.')) { var p = ip.split('.'); return p[0] + '.' + p[1] + '.*.*'; }
    var p6 = ip.split(':'); return p6[0] + ':' + p6[1] + ':*:*:*:*:*:*';
  }

  function toFlag(code) {
    if (!code) return '\uD83C\uDF10';
    var c = code.toUpperCase();
    if (c === 'TW') c = 'CN';
    if (c.length !== 2) return '\uD83C\uDF10';
    return String.fromCodePoint(c.charCodeAt(0) + 127397, c.charCodeAt(1) + 127397);
  }

  function gradeIppure(score) {
    var s = ti(score); if (s === null) return null;
    if (s >= 80) return { sev: 4, t: 'IPPure: \u6781\u9AD8 (' + s + ')' };
    if (s >= 70) return { sev: 3, t: 'IPPure: \u9AD8\u5371 (' + s + ')' };
    if (s >= 40) return { sev: 1, t: 'IPPure: \u4E2D\u7B49 (' + s + ')' };
    return { sev: 0, t: 'IPPure: \u4F4E\u5371 (' + s + ')' };
  }

  function gradeIpapi(j) {
    if (!j || !j.company || !j.company.abuser_score) return null;
    var m = String(j.company.abuser_score).match(/([0-9.]+)\s*\(([^)]+)\)/);
    if (!m) return null;
    var pct = Math.round(Number(m[1]) * 10000) / 100 + '%';
    var lv = String(m[2]).trim();
    var map = { 'Very Low': 0, 'Low': 0, 'Elevated': 2, 'High': 3, 'Very High': 4 };
    var sev = map[lv] !== undefined ? map[lv] : 2;
    return { sev: sev, t: 'ipapi: ' + lv + ' (' + pct + ')' };
  }

  function gradeIp2loc(score) {
    var s = ti(score); if (s === null) return null;
    if (s >= 66) return { sev: 3, t: 'IP2Loc: \u9AD8\u5371 (' + s + ')' };
    if (s >= 33) return { sev: 1, t: 'IP2Loc: \u4E2D\u5371 (' + s + ')' };
    return { sev: 0, t: 'IP2Loc: \u4F4E\u5371 (' + s + ')' };
  }

  function gradeScam(html) {
    if (!html) return null;
    var m = html.match(/Fraud\s*Score[:\s]*(\d+)/i) || html.match(/class="score"[^>]*>(\d+)/i);
    var s = m ? ti(m[1]) : null; if (s === null) return null;
    if (s >= 90) return { sev: 4, t: 'Scam: \u6781\u9AD8 (' + s + ')' };
    if (s >= 60) return { sev: 3, t: 'Scam: \u9AD8\u5371 (' + s + ')' };
    if (s >= 20) return { sev: 1, t: 'Scam: \u4E2D\u5371 (' + s + ')' };
    return { sev: 0, t: 'Scam: \u4F4E\u5371 (' + s + ')' };
  }

  function gradeDbip(html) {
    if (!html) return null;
    var m = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
    var lv = (m ? m[1] : '').toLowerCase();
    if (lv === 'high') return { sev: 3, t: 'DB-IP: \u9AD8\u5371' };
    if (lv === 'medium') return { sev: 1, t: 'DB-IP: \u4E2D\u5371' };
    if (lv === 'low') return { sev: 0, t: 'DB-IP: \u4F4E\u5371' };
    return null;
  }

  function gradeIpreg(j) {
    if (!j || j.code) return null;
    var sec = j.security || {};
    var tags = [];
    if (sec.is_proxy) tags.push('Proxy');
    if (sec.is_tor || sec.is_tor_exit) tags.push('Tor');
    if (sec.is_vpn) tags.push('VPN');
    if (sec.is_cloud_provider) tags.push('Hosting');
    if (sec.is_abuser) tags.push('Abuser');
    if (!tags.length) return { sev: 0, t: 'ipreg: \u4F4E\u5371' };
    var sev = tags.includes('Tor') || tags.includes('Abuser') ? 3 : tags.length >= 2 ? 2 : 1;
    return { sev: sev, t: 'ipreg: ' + tags.join('/') };
  }

  function sevColor(sev) {
    if (sev >= 4) return C_RED;
    if (sev >= 3) return C_ORANGE;
    if (sev >= 1) return C_YELLOW;
    return C_GREEN;
  }
  function sevIcon(sev) {
    if (sev >= 3) return 'xmark.shield.fill';
    if (sev >= 1) return 'exclamationmark.shield.fill';
    return 'checkmark.shield.fill';
  }
  function sevText(sev) {
    if (sev >= 4) return '\u6781\u9AD8\u98CE\u9669';
    if (sev >= 3) return '\u9AD8\u98CE\u9669';
    if (sev >= 2) return '\u4E2D\u7B49\u98CE\u9669';
    if (sev >= 1) return '\u4E2D\u4F4E\u98CE\u9669';
    return '\u7EAF\u51C0\u4F4E\u5371';
  }

  async function fetchIpapi(ip) { return jp(await get('https://api.ipapi.is/?q=' + encodeURIComponent(ip))); }
  async function fetchDbip(ip)  { return await get('https://db-ip.com/' + encodeURIComponent(ip)); }
  async function fetchScam(ip)  { return await get('https://scamalytics.com/ip/' + encodeURIComponent(ip)); }

  async function fetchIpreg(ip) {
    var html = await get('https://ipregistry.co', { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' });
    var m = String(html).match(/apiKey="([a-zA-Z0-9]+)"/);
    if (!m) return null;
    return jp(await get('https://api.ipregistry.co/' + encodeURIComponent(ip) + '?hostname=true&key=' + m[1], {
      'Origin': 'https://ipregistry.co', 'Referer': 'https://ipregistry.co/', 'User-Agent': 'Mozilla/5.0'
    }));
  }

  async function fetchIp2loc(ip) {
    var html = await get('https://www.ip2location.io/' + encodeURIComponent(ip));
    var um = html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*\(([A-Z]+)\)/i)
          || html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*([A-Z]+(?:\/[A-Z]+)?)\s*</i);
    var fm = html.match(/Fraud\s*Score<\/label>\s*<p[^>]*>\s*(\d+)/i);
    return { usageType: um ? um[1] : null, fraudScore: fm ? ti(fm[1]) : null };
  }

  async function fetchIpinfo(ip) {
    var html = await get('https://ipinfo.io/' + encodeURIComponent(ip), { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html' });
    var det = [];
    var types = ['VPN','Proxy','Tor','Relay','Hosting'];
    for (var i = 0; i < types.length; i++) {
      if (new RegExp('aria-label="' + types[i] + '\\s+Detected"', 'i').test(html)) det.push(types[i]);
    }
    return det;
  }

  function usageText(code) {
    if (!code) return '\u672A\u77E5';
    var map = { 'DCH':'\u6570\u636E\u4E2D\u5FC3', 'WEB':'\u6570\u636E\u4E2D\u5FC3', 'SES':'\u6570\u636E\u4E2D\u5FC3', 'CDN':'CDN', 'MOB':'\u79FB\u52A8\u7F51\u7EDC', 'ISP':'\u5BB6\u5EAD\u5BBD\u5E26', 'COM':'\u5546\u4E1A\u5BBD\u5E26', 'EDU':'\u6559\u80B2\u7F51\u7EDC', 'RES':'\u4F4F\u5B85\u7F51\u7EDC' };
    var parts = code.toUpperCase().split('/');
    var r = [];
    for (var i = 0; i < parts.length; i++) {
      var d = map[parts[i]];
      if (d && r.indexOf(d) === -1) r.push(d);
    }
    return r.length ? r.join('/') + ' (' + code + ')' : code;
  }

  function errWidget(msg) {
    return {
      type: 'widget', padding: 12, gap: 6, backgroundColor: BG_COLOR,
      children: [
        { type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
          { type: 'image', src: 'sf-symbol:exclamationmark.triangle.fill', color: C_RED, width: 14, height: 14 },
          { type: 'text', text: 'IP \u7EAF\u51C0\u5EA6', font: { size: 14, weight: 'heavy' }, textColor: C_TITLE },
        ]},
        { type: 'text', text: msg, font: { size: 11 }, textColor: C_RED },
      ]
    };
  }

  function Row(iconName, iconColor, label, value, valueColor) {
    return {
      type: 'stack', direction: 'row', alignItems: 'center', gap: 6,
      children: [
        { type: 'image', src: 'sf-symbol:' + iconName, color: iconColor, width: 13, height: 13 },
        { type: 'text', text: label, font: { size: 11 }, textColor: C_SUB },
        { type: 'spacer' },
        { type: 'text', text: value, font: { size: 11, weight: 'bold', family: 'Menlo' }, textColor: valueColor, maxLines: 1, minScale: 0.5 },
      ]
    };
  }

  function ScoreRow(grade) {
    var col = sevColor(grade.sev);
    return {
      type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
      children: [
        { type: 'image', src: 'sf-symbol:' + sevIcon(grade.sev), color: col, width: 10, height: 10 },
        { type: 'text', text: grade.t, font: { size: 10, family: 'Menlo' }, textColor: col, maxLines: 1, minScale: 0.5 },
      ]
    };
  }

  try {
    var ip = null, cachedIpapi = null;
    try {
      var d = jp(await get('http://ip-api.com/json?lang=zh-CN'));
      ip = d && (d.query || d.ip);
    } catch(e) {}
    if (!ip) {
      try { cachedIpapi = jp(await get('https://api.ipapi.is/')); ip = cachedIpapi && cachedIpapi.ip; } catch(e) {}
    }
    if (!ip) return errWidget('\u83B7\u53D6 IP \u5931\u8D25');

    var ippureScore = null;
    try { var d2 = jp(await get('https://my.ippure.com/v1/info')); ippureScore = d2 && d2.fraudScore; } catch(e) {}

    var results = await Promise.all([
      cachedIpapi ? Promise.resolve(cachedIpapi) : safe(function() { return fetchIpapi(ip); }),
      safe(function() { return fetchIp2loc(ip); }),
      safe(function() { return fetchIpinfo(ip); }),
      safe(function() { return fetchDbip(ip); }),
      safe(function() { return fetchScam(ip); }),
      safe(function() { return fetchIpreg(ip); }),
    ]);
    var rIpapi = results[0], rIp2loc = results[1], rIpinfo = results[2];
    var rDbip = results[3], rScam = results[4], rIpreg = results[5];

    var ipapiD = rIpapi || {};
    var asnText = (ipapiD.asn && ipapiD.asn.asn) ? ('AS' + ipapiD.asn.asn + ' ' + (ipapiD.asn.org || '')).trim() : '\u672A\u77E5';
    var cc = (ipapiD.location && ipapiD.location.country_code) || '';
    var country = (ipapiD.location && ipapiD.location.country) || '';
    var city = (ipapiD.location && ipapiD.location.city) || '';
    var loc = (toFlag(cc) + ' ' + country + ' ' + city).trim() || '\u672A\u77E5\u4F4D\u7F6E';
    var hosting = usageText(rIp2loc && rIp2loc.usageType);

    var grades = [
      gradeIppure(ippureScore),
      gradeIpapi(rIpapi),
      gradeIp2loc(rIp2loc && rIp2loc.fraudScore),
      gradeScam(rScam),
      gradeDbip(rDbip),
      gradeIpreg(rIpreg),
    ].filter(Boolean);

    var maxSev = 0;
    for (var i = 0; i < grades.length; i++) {
      if (grades[i].sev > maxSev) maxSev = grades[i].sev;
    }
    var showIP = markIP ? maskIP(ip) : ip;
    var ipLabel = ip.includes(':') ? 'IPv6' : 'IPv4';

    var tags = [];
    if (rIp2loc && rIp2loc.usageType && ['DCH','WEB','SES'].indexOf(rIp2loc.usageType.toUpperCase()) !== -1) tags.push('DC');
    if (ipapiD.is_vpn) tags.push('VPN');
    if (ipapiD.is_proxy) tags.push('Proxy');
    if (ipapiD.is_tor) tags.push('Tor');
    if (ipapiD.is_datacenter) tags.push('DC');
    if (rIpinfo && rIpinfo.length) {
      for (var i = 0; i < rIpinfo.length; i++) tags.push(rIpinfo[i]);
    }
    var seen = {};
    var uniqueTags = [];
    for (var i = 0; i < tags.length; i++) {
      if (!seen[tags[i]]) { seen[tags[i]] = true; uniqueTags.push(tags[i]); }
    }

    var family = ctx.widgetFamily || 'systemMedium';

    // Lock screen
    if (family === 'accessoryRectangular') {
      return {
        type: 'widget', padding: [4, 8], gap: 2,
        children: [
          { type: 'stack', direction: 'row', alignItems: 'center', gap: 4, children: [
            { type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), width: 12, height: 12 },
            { type: 'text', text: 'IP\u98CE\u9669: ' + sevText(maxSev), font: { size: 'caption1', weight: 'bold' } },
          ]},
          { type: 'text', text: showIP, font: { size: 'caption2', family: 'Menlo' } },
          { type: 'text', text: loc, font: { size: 'caption2' }, maxLines: 1 },
        ]
      };
    }
    if (family === 'accessoryCircular') {
      return {
        type: 'widget', padding: 4, gap: 2,
        children: [
          { type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), width: 20, height: 20 },
          { type: 'text', text: sevText(maxSev), font: { size: 'caption2', weight: 'bold' }, maxLines: 1, minScale: 0.5 },
        ]
      };
    }
    if (family === 'accessoryInline') {
      return { type: 'widget', children: [
        { type: 'text', text: 'IP\u98CE\u9669: ' + sevText(maxSev) + ' | ' + showIP, font: { size: 'caption1' } },
      ]};
    }

    // systemSmall
    if (family === 'systemSmall') {
      return {
        type: 'widget', padding: 12, gap: 6, backgroundColor: BG_COLOR,
        children: [
          { type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
            { type: 'image', src: 'sf-symbol:shield.lefthalf.filled', color: C_TITLE, width: 14, height: 14 },
            { type: 'text', text: 'IP \u7EAF\u51C0\u5EA6', font: { size: 13, weight: 'heavy' }, textColor: C_TITLE },
          ]},
          Row(sevIcon(maxSev), sevColor(maxSev), '\u98CE\u9669', sevText(maxSev), sevColor(maxSev)),
          Row('globe', C_ICON_IP, ipLabel, showIP, C_GREEN),
          Row('mappin.and.ellipse', C_ICON_LO, '\u4F4D\u7F6E', loc, C_MAIN),
        ]
      };
    }

    // systemMedium - compact: left info + right scores
    if (family === 'systemMedium') {
      var infoRows = [
        Row('globe', C_ICON_IP, ipLabel, showIP, C_GREEN),
        Row('number.square.fill', C_ICON_IP, '\u5F52\u5C5E', asnText, C_GREEN),
        Row('mappin.and.ellipse', C_ICON_LO, '\u4F4D\u7F6E', loc, C_MAIN),
        Row('building.2.fill', C_ICON_LO, '\u7C7B\u578B', hosting, C_SUB),
      ];
      if (uniqueTags.length) {
        infoRows.push(Row('tag.fill', C_ORANGE, '\u6807\u8BB0', uniqueTags.join('/'), C_ORANGE));
      }
      var scoreRows = [];
      for (var i = 0; i < grades.length; i++) {
        scoreRows.push(ScoreRow(grades[i]));
      }
      return {
        type: 'widget', padding: [10, 12], gap: 6, backgroundColor: BG_COLOR,
        children: [
          { type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
            { type: 'image', src: 'sf-symbol:shield.lefthalf.filled', color: C_TITLE, width: 14, height: 14 },
            { type: 'text', text: 'IP \u7EAF\u51C0\u5EA6', font: { size: 13, weight: 'heavy' }, textColor: C_TITLE },
            { type: 'spacer' },
            { type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), color: sevColor(maxSev), width: 12, height: 12 },
            { type: 'text', text: sevText(maxSev), font: { size: 11, weight: 'bold' }, textColor: sevColor(maxSev) },
          ]},
          { type: 'stack', direction: 'row', gap: 8, flex: 1, children: [
            { type: 'stack', direction: 'column', gap: 3, flex: 1, children: infoRows },
            { type: 'stack', direction: 'column', gap: 3, flex: 1, children: scoreRows },
          ]},
        ]
      };
    }

    // systemLarge / systemExtraLarge
    var lgInfoRows = [
      Row('globe', C_ICON_IP, ipLabel, showIP, C_GREEN),
      Row('number.square.fill', C_ICON_IP, '\u5F52\u5C5E', asnText, C_GREEN),
      Row('mappin.and.ellipse', C_ICON_LO, '\u4F4D\u7F6E', loc, C_MAIN),
      Row('building.2.fill', C_ICON_LO, '\u7C7B\u578B', hosting, C_SUB),
    ];
    if (uniqueTags.length) {
      lgInfoRows.push(Row('tag.fill', C_ORANGE, '\u6807\u8BB0', uniqueTags.join(' / '), C_ORANGE));
    }
    var lgScoreRows = [];
    for (var i = 0; i < grades.length; i++) {
      lgScoreRows.push(ScoreRow(grades[i]));
    }
    return {
      type: 'widget', padding: 14, gap: 8, backgroundColor: BG_COLOR,
      children: [
        { type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
          { type: 'image', src: 'sf-symbol:shield.lefthalf.filled', color: C_TITLE, width: 18, height: 18 },
          { type: 'text', text: 'IP \u591A\u6E90\u7EAF\u51C0\u5EA6', font: { size: 15, weight: 'heavy' }, textColor: C_TITLE },
          { type: 'spacer' },
          { type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), color: sevColor(maxSev), width: 14, height: 14 },
          { type: 'text', text: sevText(maxSev), font: { size: 13, weight: 'bold' }, textColor: sevColor(maxSev) },
        ]},
        { type: 'stack', direction: 'column', gap: 6, children: lgInfoRows },
        { type: 'stack', direction: 'row', backgroundColor: { light: '#E5E5EA', dark: '#38383A' }, height: 1 },
        { type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
          { type: 'image', src: 'sf-symbol:chart.bar.fill', color: C_ICON_SC, width: 13, height: 13 },
          { type: 'text', text: '\u591A\u6E90\u8BC4\u5206', font: { size: 13, weight: 'bold' }, textColor: C_MAIN },
        ]},
        { type: 'stack', direction: 'column', gap: 4, children: lgScoreRows },
        { type: 'spacer' },
        { type: 'date', date: new Date().toISOString(), format: 'relative', font: { size: 'caption2' }, textColor: C_SUB },
      ]
    };
  } catch (e) {
    return errWidget('\u8BF7\u6C42\u5931\u8D25: ' + String(e && e.message || e));
  }
}
