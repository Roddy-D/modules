/**
 * IP multi-source purity check widget + Streaming/AI unlock detection
 * Sources: IPPure / ipapi.is / IP2Location / Scamalytics / DB-IP / ipregistry / ipinfo
 * Unlock: ChatGPT / Gemini / Netflix / TikTok / YouTube Premium
 * Env: POLICY, MARK_IP
 */
export default async function (ctx) {
    var BG_COLOR = { light: '#FFFFFF', dark: '#1C1C1E' };
    var C_TITLE = { light: '#1A1A1A', dark: '#FFD700' };
    var C_SUB = { light: '#666666', dark: '#B0B0B0' };
    var C_MAIN = { light: '#1A1A1A', dark: '#FFFFFF' };
    var C_GREEN = { light: '#32D74B', dark: '#32D74B' };
    var C_YELLOW = { light: '#FFD60A', dark: '#FFD60A' };
    var C_ORANGE = { light: '#FF9500', dark: '#FF9500' };
    var C_RED = { light: '#FF3B30', dark: '#FF3B30' };
    var C_ICON_IP = { light: '#007AFF', dark: '#0A84FF' };
    var C_ICON_LO = { light: '#5856D6', dark: '#5E5CE6' };
    var C_ICON_SC = { light: '#AF52DE', dark: '#BF5AF2' };
    var C_BLUE = { light: '#007AFF', dark: '#0A84FF' };

    var policy = ctx.env.POLICY || "";
    var markIP = (ctx.env.MARK_IP || "").toLowerCase() === "true";

    var BASE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1";

    async function safe(fn) { try { return await fn(); } catch (e) { return null; } }

    async function get(url, headers) {
        var opts = { timeout: 10000 };
        if (headers) opts.headers = headers;
        if (policy && policy !== "DIRECT") opts.policy = policy;
        var res = await ctx.http.get(url, opts);
        return await res.text();
    }

    async function post(url, body, headers) {
        var opts = { timeout: 10000, body: body };
        if (headers) opts.headers = headers;
        if (policy && policy !== "DIRECT") opts.policy = policy;
        var res = await ctx.http.post(url, opts);
        return await res.text();
    }

    async function getRaw(url, headers, extraOpts) {
        var opts = { timeout: 10000 };
        if (headers) opts.headers = headers;
        if (policy && policy !== "DIRECT") opts.policy = policy;
        if (extraOpts) { for (var k in extraOpts) opts[k] = extraOpts[k]; }
        return await ctx.http.get(url, opts);
    }

    function jp(s) { try { return JSON.parse(s); } catch (e) { return null; } }
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

    // ===================== 评分函数（含标记信息）=====================

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
        // 收集标记
        var tags = [];
        if (j.is_vpn) tags.push('VPN');
        if (j.is_proxy) tags.push('Proxy');
        if (j.is_tor) tags.push('Tor');
        // DC/Hosting 已在标题行类型中显示，不重复
        if (j.is_abuser) tags.push('Abuser');
        var tagStr = tags.length ? ' ' + tags.join('/') : '';
        return { sev: sev, t: 'ipapi: ' + lv + ' (' + pct + ')' + tagStr };
    }

    function gradeIp2loc(score) {
        var s = ti(score); if (s === null) return null;
        if (s >= 66) return { sev: 3, t: 'IP2Location: \u9AD8\u5371 (' + s + ')' };
        if (s >= 33) return { sev: 1, t: 'IP2Location: \u4E2D\u5371 (' + s + ')' };
        return { sev: 0, t: 'IP2Location: \u4F4E\u5371 (' + s + ')' };
    }

    function gradeScam(html) {
        if (!html) return null;
        var m = html.match(/Fraud\s*Score[:\s]*(\d+)/i) || html.match(/class="score"[^>]*>(\d+)/i);
        var s = m ? ti(m[1]) : null; if (s === null) return null;
        if (s >= 90) return { sev: 4, t: 'Scamalytics: \u6781\u9AD8 (' + s + ')' };
        if (s >= 60) return { sev: 3, t: 'Scamalytics: \u9AD8\u5371 (' + s + ')' };
        if (s >= 20) return { sev: 1, t: 'Scamalytics: \u4E2D\u5371 (' + s + ')' };
        return { sev: 0, t: 'Scamalytics: \u4F4E\u5371 (' + s + ')' };
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

    function gradeIpreg(j, ipinfoDetected) {
        if (!j || j.code) return null;
        var sec = j.security || {};
        var tags = [];
        if (sec.is_proxy) tags.push('Proxy');
        if (sec.is_tor || sec.is_tor_exit) tags.push('Tor');
        if (sec.is_vpn) tags.push('VPN');
        // Hosting 已在标题行类型中显示，不重复
        if (sec.is_abuser) tags.push('Abuser');
        // 合并 ipinfo 检测结果
        if (ipinfoDetected && ipinfoDetected.length) {
            for (var i = 0; i < ipinfoDetected.length; i++) {
                if (ipinfoDetected[i] === 'Hosting') continue; // 已在标题行显示
                if (tags.indexOf(ipinfoDetected[i]) === -1) tags.push(ipinfoDetected[i]);
            }
        }
        var tagStr = tags.length ? ' ' + tags.join('/') : '';
        if (!tags.length) return { sev: 0, t: 'ipregistry: \u4F4E\u5371' };
        var sev = tags.indexOf('Tor') !== -1 || tags.indexOf('Abuser') !== -1 ? 3 : tags.length >= 2 ? 2 : 1;
        return { sev: sev, t: 'ipregistry: ' + tags.join('/') };
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

    function usageText(code) {
        if (!code) return '\u672A\u77E5';
        var map = { 'DCH': '\u6570\u636E\u4E2D\u5FC3', 'WEB': '\u6570\u636E\u4E2D\u5FC3', 'SES': '\u6570\u636E\u4E2D\u5FC3', 'CDN': 'CDN', 'MOB': '\u79FB\u52A8\u7F51\u7EDC', 'ISP': '\u5BB6\u5EAD\u5BBD\u5E26', 'COM': '\u5546\u4E1A\u5BBD\u5E26', 'EDU': '\u6559\u80B2\u7F51\u7EDC', 'RES': '\u4F4F\u5B85\u7F51\u7EDC' };
        var parts = code.toUpperCase().split('/');
        var r = [];
        for (var i = 0; i < parts.length; i++) {
            var d = map[parts[i]];
            if (d && r.indexOf(d) === -1) r.push(d);
        }
        return r.length ? r.join('/') + ' (' + code + ')' : code;
    }

    // ===================== 数据获取函数 =====================

    async function fetchIpapi(ip) { return jp(await get('https://api.ipapi.is/?q=' + encodeURIComponent(ip))); }
    async function fetchDbip(ip) { return await get('https://db-ip.com/' + encodeURIComponent(ip)); }
    async function fetchScam(ip) { return await get('https://scamalytics.com/ip/' + encodeURIComponent(ip)); }

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
        var types = ['VPN', 'Proxy', 'Tor', 'Relay', 'Hosting'];
        for (var i = 0; i < types.length; i++) {
            if (new RegExp('aria-label="' + types[i] + '\\s+Detected"', 'i').test(html)) det.push(types[i]);
        }
        return det;
    }

    // ===================== 解锁检测函数 =====================

    async function checkChatGPT() {
        try {
            var headRes = await getRaw("https://chatgpt.com", { "User-Agent": BASE_UA }, { redirect: 'manual' });
            var headOk = !!headRes;
            var locationHeader = "";
            if (headRes && headRes.headers) {
                locationHeader = headRes.headers.get ? headRes.headers.get('location') || '' : (headRes.headers.location || headRes.headers.Location || '');
            }
            var webAccessible = headOk && !!locationHeader;

            var iosRes = await getRaw("https://ios.chat.openai.com", { "User-Agent": BASE_UA });
            var iosBody = iosRes ? await iosRes.text() : "";
            var cfDetails = "";
            try {
                var asJson = iosBody ? JSON.parse(iosBody) : null;
                if (asJson && asJson.cf_details) cfDetails = String(asJson.cf_details);
            } catch (e2) {
                var cm = iosBody ? iosBody.match(/"cf_details"\s*:\s*"([^"]*)"/) : null;
                if (cm && cm[1]) cfDetails = cm[1];
            }

            var appBlocked = !iosBody
                || iosBody.indexOf("blocked_why_headline") !== -1
                || iosBody.indexOf("unsupported_country_region_territory") !== -1
                || cfDetails.indexOf("(1)") !== -1
                || cfDetails.indexOf("(2)") !== -1;
            var appAccessible = !!iosBody && !appBlocked;

            if (!webAccessible && !appAccessible) return "\u274C";
            if (appAccessible && !webAccessible) return "APP";
            if (webAccessible && appAccessible) {
                var traceTxt = await get("https://chatgpt.com/cdn-cgi/trace");
                if (traceTxt) {
                    var tm = traceTxt.match(/loc=([A-Z]{2})/);
                    if (tm && tm[1]) return tm[1];
                }
                return "OK";
            }
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    async function checkGemini() {
        try {
            var bodyRaw = 'f.req=[["K4WWud","[[0],[\\"en-US\\"]]",null,"generic"]]';
            var txt = await post('https://gemini.google.com/_/BardChatUi/data/batchexecute', bodyRaw, {
                "User-Agent": BASE_UA, "Accept-Language": "en-US", "Content-Type": "application/x-www-form-urlencoded"
            });
            if (!txt) return "\u274C";

            var m = txt.match(/"countryCode"\s*:\s*"([A-Z]{2})"/i);
            if (m && m[1]) return m[1].toUpperCase();
            m = txt.match(/"requestCountry"\s*:\s*\{[^}]*"id"\s*:\s*"([A-Z]{2})"/i);
            if (m && m[1]) return m[1].toUpperCase();
            m = txt.match(/\[\[\\?"([A-Z]{2})\\?",\\?"S/);
            if (m && m[1]) return m[1].toUpperCase();
            var idx = txt.indexOf('K4WWud');
            if (idx >= 0) {
                var slice = txt.slice(idx, idx + 200);
                var m2 = slice.match(/([A-Z]{2})/);
                if (m2 && m2[1]) return m2[1].toUpperCase();
            }
            return "OK";
        } catch (e) { return "\u274C"; }
    }

    // 移除 Disney+ 检测

    async function checkNetflix() {
        try {
            var titles = [
                "https://www.netflix.com/title/81280792",
                "https://www.netflix.com/title/70143836"
            ];
            var fetchTitle = async function (url) {
                try {
                    var body = await get(url, { "User-Agent": BASE_UA });
                    return body || "";
                } catch (e) { return ""; }
            };
            var bodies = await Promise.all([fetchTitle(titles[0]), fetchTitle(titles[1])]);
            var t1 = bodies[0], t2 = bodies[1];
            if (!t1 && !t2) return "\u274C";

            // 检查 "Oh no!"
            var oh1 = t1 && /oh no!/i.test(t1);
            var oh2 = t2 && /oh no!/i.test(t2);
            if (oh1 && oh2) return "\uD83C\uDF7F"; // 🍿

            // 提取地区码
            var allBodies = [t1, t2];
            for (var i = 0; i < allBodies.length; i++) {
                var b = allBodies[i];
                if (!b) continue;
                var rm = b.match(/"countryCode"\s*:\s*"?([A-Z]{2})"?/);
                if (rm && rm[1]) return rm[1];
            }
            return "OK";
        } catch (e) { return "\u274C"; }
    }

    async function checkTikTok() {
        try {
            var body1 = await get("https://www.tiktok.com/", { "User-Agent": BASE_UA });
            if (body1 && body1.indexOf("Please wait...") !== -1) {
                try { body1 = await get("https://www.tiktok.com/explore", { "User-Agent": BASE_UA }); } catch (e2) { }
            }
            var m1 = body1 ? body1.match(/"region"\s*:\s*"([A-Z]{2})"/) : null;
            if (m1 && m1[1]) return m1[1];

            var body2 = await get("https://www.tiktok.com/", {
                "User-Agent": BASE_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en"
            });
            var m2 = body2 ? body2.match(/"region"\s*:\s*"([A-Z]{2})"/) : null;
            if (m2 && m2[1]) return m2[1];
            if (body1 || body2) return "OK";
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    async function checkYouTube() {
        try {
            var body = await get('https://www.youtube.com/premium', { "User-Agent": BASE_UA, "Accept-Language": "en" });
            if (!body) return "\u274C";
            if (body.indexOf('www.google.cn') !== -1) return "CN";

            var isNotAvailable = body.indexOf('Premium is not available in your country') !== -1 || body.indexOf('YouTube Premium is not available') !== -1;
            var m = body.match(/"contentRegion"\s*:\s*"?([A-Z]{2})"?/);
            var region = (m && m[1]) ? m[1].toUpperCase() : null;
            var isAvailable = body.indexOf('ad-free') !== -1 || body.indexOf('Ad-free') !== -1;

            if (isNotAvailable) return "\u274C";
            if (isAvailable && region) return region;
            if (isAvailable && !region) return "OK";
            if (region) return region;
            return "\u274C";
        } catch (e) { return "\u274C"; }
    }

    // ===================== UI 组件 =====================

    function errWidget(msg) {
        return {
            type: 'widget', padding: 12, gap: 6, backgroundColor: BG_COLOR,
            children: [
                {
                    type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
                        { type: 'image', src: 'sf-symbol:exclamationmark.triangle.fill', color: C_RED, width: 14, height: 14 },
                        { type: 'text', text: 'IP \u7EAF\u51C0\u5EA6', font: { size: 14, weight: 'heavy' }, textColor: C_TITLE },
                    ]
                },
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
        var parts = grade.t.split(': ');
        var src = parts[0] || grade.t;
        var val = parts[1] || '';
        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
            children: [
                { type: 'image', src: 'sf-symbol:' + sevIcon(grade.sev), color: col, width: 10, height: 10 },
                { type: 'text', text: src, font: { size: 10 }, textColor: C_SUB },
                { type: 'spacer' },
                { type: 'text', text: val, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: col, maxLines: 1, minScale: 0.5 },
            ]
        };
    }

    function UnlockRow(name, result) {
        var isOk = result !== "\u274C" && result !== "\uD83C\uDF7F" && result !== "\u23F3" && result !== "CN";
        var color = isOk ? C_GREEN : (result === "\uD83C\uDF7F" || result === "\u23F3" || result === "APP") ? C_YELLOW : C_RED;
        var icon = isOk ? 'checkmark.circle.fill' : (result === "\uD83C\uDF7F" || result === "\u23F3" || result === "APP") ? 'exclamationmark.circle.fill' : 'xmark.circle.fill';
        return {
            type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
            children: [
                { type: 'image', src: 'sf-symbol:' + icon, color: color, width: 10, height: 10 },
                { type: 'text', text: name, font: { size: 10 }, textColor: C_SUB },
                { type: 'spacer' },
                { type: 'text', text: result, font: { size: 10, weight: 'bold' }, textColor: color, maxLines: 1 },
            ]
        };
    }

    // ===================== 主逻辑 =====================

    try {
        var ip = null, cachedIpapi = null;
        try {
            var d = jp(await get('http://ip-api.com/json?lang=zh-CN'));
            ip = d && (d.query || d.ip);
        } catch (e) { }
        if (!ip) {
            try { cachedIpapi = jp(await get('https://api.ipapi.is/')); ip = cachedIpapi && cachedIpapi.ip; } catch (e) { }
        }
        if (!ip) return errWidget('\u83B7\u53D6 IP \u5931\u8D25');

        var ippureScore = null;
        try { var d2 = jp(await get('https://my.ippure.com/v1/info')); ippureScore = d2 && d2.fraudScore; } catch (e) { }

        // 并行：数据库查询 + 解锁检测
        var results = await Promise.all([
            cachedIpapi ? Promise.resolve(cachedIpapi) : safe(function () { return fetchIpapi(ip); }),
            safe(function () { return fetchIp2loc(ip); }),
            safe(function () { return fetchIpinfo(ip); }),
            safe(function () { return fetchDbip(ip); }),
            safe(function () { return fetchScam(ip); }),
            safe(function () { return fetchIpreg(ip); }),
            safe(checkChatGPT),
            safe(checkGemini),
            safe(checkNetflix),
            safe(checkTikTok),
            safe(checkYouTube)
        ]);
        var rIpapi = results[0], rIp2loc = results[1], rIpinfo = results[2];
        var rDbip = results[3], rScam = results[4], rIpreg = results[5];
        var uGPT = results[6] || "\u274C", uGemini = results[7] || "\u274C";
        var uNetflix = results[8] || "\u274C", uTikTok = results[9] || "\u274C";
        var uYouTube = results[10] || "\u274C";

        var ipapiD = rIpapi || {};
        var asnText = (ipapiD.asn && ipapiD.asn.asn) ? ('AS' + ipapiD.asn.asn + ' ' + (ipapiD.asn.org || '')).trim() : '\u672A\u77E5';
        var cc = (ipapiD.location && ipapiD.location.country_code) || '';
        var country = (ipapiD.location && ipapiD.location.country) || '';
        var city = (ipapiD.location && ipapiD.location.city) || '';
        var loc = (toFlag(cc) + ' ' + country + ' ' + city).trim() || '\u672A\u77E5\u4F4D\u7F6E';
        var hosting = usageText(rIp2loc && rIp2loc.usageType);
        var hostingShort = rIp2loc && rIp2loc.usageType ? rIp2loc.usageType : '';

        // 评分（含标记）
        var grades = [
            gradeIppure(ippureScore),
            gradeIpapi(rIpapi),
            gradeIp2loc(rIp2loc && rIp2loc.fraudScore),
            gradeScam(rScam),
            gradeDbip(rDbip),
            gradeIpreg(rIpreg, rIpinfo),
        ].filter(Boolean);

        var maxSev = 0;
        for (var i = 0; i < grades.length; i++) {
            if (grades[i].sev > maxSev) maxSev = grades[i].sev;
        }
        var showIP = markIP ? maskIP(ip) : ip;
        var ipLabel = ip.includes(':') ? 'IPv6' : 'IPv4';

        var family = ctx.widgetFamily || 'systemMedium';

        // Lock screen
        if (family === 'accessoryRectangular') {
            return {
                type: 'widget', padding: [4, 8], gap: 2,
                children: [
                    {
                        type: 'stack', direction: 'row', alignItems: 'center', gap: 4, children: [
                            { type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), width: 12, height: 12 },
                            { type: 'text', text: 'IP\u98CE\u9669: ' + sevText(maxSev), font: { size: 'caption1', weight: 'bold' } },
                        ]
                    },
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
            return {
                type: 'widget', children: [
                    { type: 'text', text: 'IP\u98CE\u9669: ' + sevText(maxSev) + ' | ' + showIP, font: { size: 'caption1' } },
                ]
            };
        }

        // systemSmall
        if (family === 'systemSmall') {
            return {
                type: 'widget', padding: 12, gap: 6, backgroundColor: BG_COLOR,
                children: [
                    {
                        type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
                            { type: 'image', src: 'sf-symbol:shield.lefthalf.filled', color: C_TITLE, width: 14, height: 14 },
                            { type: 'text', text: 'IP \u7EAF\u51C0\u5EA6', font: { size: 13, weight: 'heavy' }, textColor: C_TITLE },
                        ]
                    },
                    Row(sevIcon(maxSev), sevColor(maxSev), '\u98CE\u9669', sevText(maxSev), sevColor(maxSev)),
                    Row('globe', C_ICON_IP, ipLabel, showIP, C_GREEN),
                    Row('mappin.and.ellipse', C_ICON_LO, '\u4F4D\u7F6E', loc, C_MAIN),
                ]
            };
        }

        // ===================== systemMedium — 新布局 =====================
        if (family === 'systemMedium') {
            // 标题行：IP纯净度 + IPv4 | 类型 | 风险
            var headerRow = {
                type: 'stack', direction: 'row', alignItems: 'center', gap: 4,
                children: [
                    { type: 'image', src: 'sf-symbol:shield.lefthalf.filled', color: C_TITLE, width: 14, height: 14 },
                    { type: 'text', text: 'IP\u7EAF\u51C0\u5EA6', font: { size: 13, weight: 'heavy' }, textColor: C_TITLE },
                    { type: 'text', text: ipLabel + ': ' + showIP, font: { size: 10, weight: 'bold', family: 'Menlo' }, textColor: C_GREEN, maxLines: 1 },
                    { type: 'spacer' },
                ]
            };
            // 类型完整文本（如 类型:数据中心(DCH)）
            if (hostingShort) {
                headerRow.children.push({ type: 'text', text: '类型:' + hosting, font: { size: 11, weight: 'bold' }, textColor: C_SUB });
            }
            headerRow.children.push({ type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), color: sevColor(maxSev), width: 12, height: 12 });
            headerRow.children.push({ type: 'text', text: sevText(maxSev), font: { size: 11, weight: 'bold' }, textColor: sevColor(maxSev) });

            var unlockRows = [
                {
                    type: 'stack', direction: 'column', gap: 2,
                    children: [
                        UnlockRow('GPT', uGPT),
                        UnlockRow('Gemini', uGemini),
                        UnlockRow('YouTube', uYouTube),
                    ]
                },
                {
                    type: 'stack', direction: 'column', gap: 2,
                    children: [
                        UnlockRow('\u5948\u98DE', uNetflix),
                        UnlockRow('TikTok', uTikTok),
                    ]
                }
            ];

            // 右半：数据库评分（含内联标记）
            var scoreRows = [];
            for (var i = 0; i < grades.length; i++) {
                scoreRows.push(ScoreRow(grades[i]));
            }

            return {
                type: 'widget', padding: [10, 12], gap: 5, backgroundColor: BG_COLOR,
                children: [
                    headerRow,
                    Row('number.square.fill', C_ICON_IP, '\u5F52\u5C5E', asnText, C_GREEN),
                    Row('mappin.and.ellipse', C_ICON_LO, '\u4F4D\u7F6E', loc, C_MAIN),
                    {
                        type: 'stack', direction: 'row', gap: 8, flex: 1, children: [
                            { type: 'stack', direction: 'column', gap: 3, flex: 1, children: unlockRows },
                            { type: 'stack', direction: 'column', gap: 3, flex: 1, children: scoreRows },
                        ]
                    },
                ]
            };
        }

        // ===================== systemLarge / systemExtraLarge =====================
        var lgInfoRows = [
            Row('globe', C_ICON_IP, ipLabel, showIP, C_GREEN),
            Row('number.square.fill', C_ICON_IP, '\u5F52\u5C5E', asnText, C_GREEN),
            Row('mappin.and.ellipse', C_ICON_LO, '\u4F4D\u7F6E', loc, C_MAIN),
            Row('building.2.fill', C_ICON_LO, '\u7C7B\u578B', hosting, C_SUB),
        ];
        var lgScoreRows = [];
        for (var i = 0; i < grades.length; i++) {
            lgScoreRows.push(ScoreRow(grades[i]));
        }
        var lgUnlockRows = [
            UnlockRow('ChatGPT', uGPT),
            UnlockRow('Gemini', uGemini),
            UnlockRow('Netflix', uNetflix),
            UnlockRow('TikTok', uTikTok),
            UnlockRow('YouTube', uYouTube),
        ];
        return {
            type: 'widget', padding: 14, gap: 8, backgroundColor: BG_COLOR,
            children: [
                {
                    type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
                        { type: 'image', src: 'sf-symbol:shield.lefthalf.filled', color: C_TITLE, width: 18, height: 18 },
                        { type: 'text', text: 'IP \u591A\u6E90\u7EAF\u51C0\u5EA6', font: { size: 15, weight: 'heavy' }, textColor: C_TITLE },
                        { type: 'spacer' },
                        { type: 'image', src: 'sf-symbol:' + sevIcon(maxSev), color: sevColor(maxSev), width: 14, height: 14 },
                        { type: 'text', text: sevText(maxSev), font: { size: 13, weight: 'bold' }, textColor: sevColor(maxSev) },
                    ]
                },
                { type: 'stack', direction: 'column', gap: 6, children: lgInfoRows },
                { type: 'stack', direction: 'row', backgroundColor: { light: '#E5E5EA', dark: '#38383A' }, height: 1 },
                {
                    type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
                        { type: 'image', src: 'sf-symbol:chart.bar.fill', color: C_ICON_SC, width: 13, height: 13 },
                        { type: 'text', text: '\u591A\u6E90\u8BC4\u5206', font: { size: 13, weight: 'bold' }, textColor: C_MAIN },
                    ]
                },
                { type: 'stack', direction: 'column', gap: 4, children: lgScoreRows },
                { type: 'stack', direction: 'row', backgroundColor: { light: '#E5E5EA', dark: '#38383A' }, height: 1 },
                {
                    type: 'stack', direction: 'row', alignItems: 'center', gap: 6, children: [
                        { type: 'image', src: 'sf-symbol:play.tv.fill', color: C_BLUE, width: 13, height: 13 },
                        { type: 'text', text: '\u89E3\u9501\u68C0\u6D4B', font: { size: 13, weight: 'bold' }, textColor: C_MAIN },
                    ]
                },
                { type: 'stack', direction: 'column', gap: 4, children: lgUnlockRows },
                { type: 'spacer' },
                { type: 'date', date: new Date().toISOString(), format: 'relative', font: { size: 'caption2' }, textColor: C_SUB },
            ]
        };
    } catch (e) {
        return errWidget('\u8BF7\u6C42\u5931\u8D25: ' + String(e && e.message || e));
    }
}
