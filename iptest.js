const IPPURE_URL = "https://my.ippure.com/v1/info";
const IPV4_API = "http://ip-api.com/json?lang=zh-CN";
const IPAPI_IS_URL = "https://api.ipapi.is/";

let policyName = "";
let MarkIP = false;

if (typeof $argument !== 'undefined' && $argument) {
    try {
        const argObj = JSON.parse($argument);
        MarkIP = String(argObj.markip).toLowerCase() === 'true' || argObj.markip === true;
        policyName = argObj.policy || argObj.Proxy || "";
    } catch (e) {
        MarkIP = String($argument).toLowerCase() === 'true';
    }
}

function maskIP(ip) {
    if (!ip) return '';
    if (ip.includes('.')) {
        const p = ip.split('.');
        return `${p[0]}.${p[1]}.*.*`;
    }
    const p6 = ip.split(':');
    return `${p6[0]}:${p6[1]}:*:*:*:*:*:*`;
}

function httpGet(url, headers = {}) {
    return new Promise((resolve, reject) => {
        const options = { url, headers };
        if (policyName && policyName !== "DIRECT") {
            options.policy = policyName;
        }

        $httpClient.get(options, (err, resp, data) => {
            if (err) return reject(err);
            if (!data) return reject(new Error("empty response"));
            resolve({ resp, data });
        });
    });
}

function safeJsonParse(s) {
    try {
        return JSON.parse(s);
    } catch (_) {
        return null;
    }
}

function toInt(v) {
    const n = Number(v);
    return Number.isFinite(n) ? Math.round(n) : null;
}

function severityMeta(sev) {
    if (sev >= 4) return { icon: "xmark.octagon.fill", color: "#8E0000" };
    if (sev >= 3) return { icon: "exclamationmark.triangle.fill", color: "#FF3B30" };
    if (sev >= 2) return { icon: "exclamationmark.circle.fill", color: "#FF9500" };
    if (sev >= 1) return { icon: "exclamationmark.circle", color: "#FFCC00" };
    return { icon: "checkmark.seal.fill", color: "#34C759" };
}

function gradeIppure(score) {
    const s = toInt(score);
    if (s === null) return { sev: 2, text: "IPPure：获取失败" };
    if (s >= 80) return { sev: 4, text: `IPPure：🛑 极高风险 (${s})` };
    if (s >= 70) return { sev: 3, text: `IPPure：⚠️ 高风险 (${s})` };
    if (s >= 40) return { sev: 1, text: `IPPure：🔶 中等风险 (${s})` };
    return { sev: 0, text: `IPPure：✅ 低风险 (${s})` };
}

function gradeIpapi(j) {
    if (!j || !j.company) return { sev: 2, text: "ipapi：获取失败" };
    const abuserScoreText = j.company.abuser_score;
    if (!abuserScoreText || typeof abuserScoreText !== "string") {
        return { sev: 2, text: "ipapi：无评分" };
    }
    const m = abuserScoreText.match(/([0-9.]+)\s*\(([^)]+)\)/);
    if (!m) return { sev: 2, text: `ipapi：${abuserScoreText}` };
    const ratio = Number(m[1]);
    const level = String(m[2] || "").trim();
    const pct = Number.isFinite(ratio) ? `${Math.round(ratio * 10000) / 100}%` : "?";
    const sevByLevel = { "Very Low": 0, Low: 0, Elevated: 2, High: 3, "Very High": 4 };
    const sev = sevByLevel[level] ?? 2;
    const label = sev >= 4 ? "🛑 极高风险" : sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "✅ 低风险";
    return { sev, text: `ipapi：${label} (${pct}, ${level})` };
}

function parseIp2locationIo(data) {
    if (!data) return {
        usageType: null, fraudScore: null, isProxy: false, proxyType: "-", threat: "-",
        country: null, countryCode: null, city: null, asn: null, asOrg: null
    };
    return {
        usageType: data.as_usage_type || null,
        fraudScore: data.fraud_score ?? null,
        isProxy: data.is_proxy || false,
        proxyType: data.proxy_type || "-",
        threat: data.threat || "-",
        country: data.country || null,
        countryCode: data.country_code || null,
        city: data.city || null,
        asn: data.asn || null,
        asOrg: data.as_org || null
    };
}

function gradeIp2locationIo(fraudScore) {
    const s = toInt(fraudScore);
    if (s === null) return { sev: -1, text: null };
    if (s >= 66) return { sev: 3, text: `IP2Location：⚠️ 高风险 (${s})` };
    if (s >= 33) return { sev: 1, text: `IP2Location：🔶 中风险 (${s})` };
    return { sev: 0, text: `IP2Location：✅ 低风险 (${s})` };
}

function ip2locationHostingText(usageType) {
    if (!usageType) return "未知";
    const typeMap = {
        "DCH": "🏢 数据中心", "WEB": "🏢 数据中心", "SES": "🏢 数据中心",
        "CDN": "🌐 CDN", "MOB": "📱 移动网络", "ISP": "🏠 家庭宽带",
        "COM": "🏬 商业宽带", "EDU": "🎓 教育网络", "GOV": "🏛️ 政府网络",
        "MIL": "🎖️ 军用网络", "ORG": "🏢 组织机构", "RES": "🏠 住宅网络"
    };
    const parts = String(usageType).toUpperCase().split("/");
    const descriptions = [];
    for (const part of parts) {
        const desc = typeMap[part];
        if (desc && !descriptions.includes(desc)) descriptions.push(desc);
    }
    return descriptions.length ? `${descriptions.join("/")} (${usageType})` : usageType;
}

function gradeDbip(html) {
    if (!html) return { sev: 2, text: "DB-IP：获取失败" };
    const riskTextMatch = html.match(/Estimated threat level for this IP address is\s*<span[^>]*>\s*([^<\s]+)\s*</i);
    const riskText = (riskTextMatch ? riskTextMatch[1] : "").toLowerCase();
    if (!riskText) return { sev: 2, text: "DB-IP：获取失败" };
    if (riskText === "high") return { sev: 3, text: "DB-IP：⚠️ 高风险" };
    if (riskText === "medium") return { sev: 1, text: "DB-IP：🔶 中风险" };
    if (riskText === "low") return { sev: 0, text: "DB-IP：✅ 低风险" };
    return { sev: 2, text: `DB-IP：${riskText}` };
}

function gradeScamalytics(html) {
    if (!html) return { sev: 2, text: "Scamalytics：获取失败" };
    const scoreMatch = html.match(/Fraud\s*Score[:\s]*(\d+)/i)
        || html.match(/class="score"[^>]*>(\d+)/i)
        || html.match(/"score"\s*:\s*(\d+)/i);
    if (!scoreMatch) return { sev: 2, text: "Scamalytics：获取失败" };
    const s = toInt(scoreMatch[1]);
    if (s === null) return { sev: 2, text: "Scamalytics：获取失败" };
    if (s >= 90) return { sev: 4, text: `Scamalytics：🛑 极高风险 (${s})` };
    if (s >= 60) return { sev: 3, text: `Scamalytics：⚠️ 高风险 (${s})` };
    if (s >= 20) return { sev: 1, text: `Scamalytics：🔶 中风险 (${s})` };
    return { sev: 0, text: `Scamalytics：✅ 低风险 (${s})` };
}

// 直接接收扁平的 security 标记对象（由 fetchIpregistry 解析详情页得到）
function gradeIpregistry(sec) {
    if (!sec) return { sev: 2, text: "ipregistry：获取失败" };
    const items = [];
    if (sec.is_proxy === true) items.push("Proxy");
    if (sec.is_tor === true) items.push("Tor");
    if (sec.is_vpn === true) items.push("VPN");
    if (sec.is_cloud_provider === true) items.push("Hosting");
    if (sec.is_abuser === true) items.push("Abuser");
    if (items.length === 0) return { sev: 0, text: "ipregistry：✅ 低风险（无标记）" };
    const sev = items.includes("Tor") ? 3 : items.includes("Abuser") ? 3 : items.length >= 2 ? 2 : 1;
    const label = sev >= 3 ? "⚠️ 高风险" : sev >= 2 ? "🔶 较高风险" : "🔶 有标记";
    return { sev, text: `ipregistry：${label} (${items.join("/")})` };
}

function flagEmoji(code) {
    if (!code) return "";
    let c = String(code).toUpperCase();
    if (c === "TW") c = "CN";
    if (c.length !== 2) return "";
    return String.fromCodePoint(...c.split("").map((x) => 127397 + x.charCodeAt(0)));
}

async function fetchIpapi(ip) {
    const { data } = await httpGet(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}`);
    return safeJsonParse(data);
}

async function fetchDbipHtml(ip) {
    const { data } = await httpGet(`https://db-ip.com/${encodeURIComponent(ip)}`);
    return String(data);
}

async function fetchScamalyticsHtml(ip) {
    const { data } = await httpGet(`https://scamalytics.com/ip/${encodeURIComponent(ip)}`);
    return String(data);
}

// 从 ipregistry.co/{ip} 详情页里，按字段名提取 Yes/No 布尔值
function extractIpregistrySecurityFlag(html, fieldName) {
    const re = new RegExp(
        `${fieldName}</span>[\\s\\S]{0,300}?<div class="(?:positive|negative)">[\\s\\S]{0,800}?(Yes|No)</div>`,
        "i"
    );
    const m = html.match(re);
    if (!m) return null;
    return m[1].trim().toLowerCase() === "yes";
}

// 直接抓取 ipregistry.co/{IP} 详情页解析 Security 板块（不再依赖抓取 API Key）
async function fetchIpregistry(ip) {
    const { data } = await httpGet(`https://ipregistry.co/${encodeURIComponent(ip)}`, {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    });
    const html = String(data);

    const isAbuser = extractIpregistrySecurityFlag(html, "Abuser");
    const isAttacker = extractIpregistrySecurityFlag(html, "Attacker");
    const isBogon = extractIpregistrySecurityFlag(html, "Bogon");
    const isCloudProvider = extractIpregistrySecurityFlag(html, "Cloud Provider");
    const isProxy = extractIpregistrySecurityFlag(html, "Proxy");
    const isRelay = extractIpregistrySecurityFlag(html, "Relay");
    const isTor = extractIpregistrySecurityFlag(html, "Tor");
    const isVpn = extractIpregistrySecurityFlag(html, "VPN");
    const isAnonymous = extractIpregistrySecurityFlag(html, "Anonymous");
    const isThreat = extractIpregistrySecurityFlag(html, "Threat");

    // 一个字段都没解析到，说明页面结构变了或请求失败，视为获取失败
    const allNull = [isAbuser, isAttacker, isBogon, isCloudProvider, isProxy, isRelay, isTor, isVpn, isAnonymous, isThreat]
        .every(v => v === null);
    if (allNull) return null;

    return {
        is_abuser: isAbuser,
        is_attacker: isAttacker,
        is_bogon: isBogon,
        is_cloud_provider: isCloudProvider,
        is_proxy: isProxy,
        is_relay: isRelay,
        is_tor: isTor,
        is_vpn: isVpn,
        is_anonymous: isAnonymous,
        is_threat: isThreat,
    };
}

async function fetchIp2locationIo(ip) {
    const { data } = await httpGet(`https://www.ip2location.io/${encodeURIComponent(ip)}`);
    const html = String(data);
    let usageMatch = html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*\(([A-Z]+)\)/i);
    if (!usageMatch) usageMatch = html.match(/Usage\s*Type<\/label>\s*<p[^>]*>\s*([A-Z]+(?:\/[A-Z]+)?)\s*</i);
    const fraudMatch = html.match(/Fraud\s*Score<\/label>\s*<p[^>]*>\s*(\d+)/i);
    const proxyMatch = html.match(/>Proxy<\/label>\s*<p[^>]*>[^<]*<i[^>]*><\/i>\s*(Yes|No)/i);
    const proxyTypeMatch = html.match(/Proxy\s*Type<\/label>\s*<p[^>]*>\s*([^<]+)/i);
    const threatMatch = html.match(/>Threat<\/label>\s*<p[^>]*>\s*([^<]+)/i);

    // 归属地 / ASN（用于 ipapi 失败时回落）
    // Country: >Country</label> ... <a ...>United States of America (US)</a>
    const countryMatch = html.match(/>Country<\/label>[\s\S]{0,300}?<a[^>]*>([^(<]+)\(([A-Z]{2})\)<\/a>/i);
    // City: >City</label> <p class="ip-result">Los Angeles</p>
    const cityMatch = html.match(/>City<\/label>\s*<p[^>]*>([^<]+)<\/p>/i);
    // ASN: >ASN</label> ... <a ...>25820</a>
    const asnMatch = html.match(/>ASN<\/label>[\s\S]{0,300}?<a[^>]*>(\d+)<\/a>/i);
    // AS（组织名）: >AS</label> ... <a ...>IT7 Networks Inc</a>
    const asOrgMatch = html.match(/>AS<\/label>[\s\S]{0,300}?<a[^>]*>([^<]+)<\/a>/i);

    return {
        as_usage_type: usageMatch ? usageMatch[1] : null,
        fraud_score: fraudMatch ? toInt(fraudMatch[1]) : null,
        is_proxy: proxyMatch ? proxyMatch[1].toLowerCase() === "yes" : false,
        proxy_type: proxyTypeMatch ? proxyTypeMatch[1].trim() : "-",
        threat: threatMatch ? threatMatch[1].trim() : "-",
        country: countryMatch ? countryMatch[1].trim() : null,
        country_code: countryMatch ? countryMatch[2].trim() : null,
        city: cityMatch ? cityMatch[1].trim() : null,
        asn: asnMatch ? asnMatch[1].trim() : null,
        as_org: asOrgMatch ? asOrgMatch[1].trim() : null
    };
}

async function fetchIpinfoIo(ip) {
    const { data } = await httpGet(`https://ipinfo.io/${encodeURIComponent(ip)}`, {
        "User-Agent": "Mozilla/5.0", "Accept": "text/html"
    });
    const html = String(data);
    const detected = [];
    const privacyTypes = ["VPN", "Proxy", "Tor", "Relay", "Hosting", "Residential Proxy"];
    for (const type of privacyTypes) {
        if (new RegExp(`aria-label="${type}\\s+Detected"`, "i").test(html)) detected.push(type);
    }
    return { detected };
}

(async () => {
    let ip = null;
    let cachedIpapiResponse = null;

    try {
        const { data: ipv4Data } = await httpGet(IPV4_API);
        const ipv4Json = safeJsonParse(ipv4Data);
        ip = ipv4Json?.query || ipv4Json?.ip || String(ipv4Data || "").trim();
    } catch (_) { }

    if (!ip) {
        try {
            const { data } = await httpGet(IPAPI_IS_URL);
            cachedIpapiResponse = safeJsonParse(data);
            if (cachedIpapiResponse && cachedIpapiResponse.ip) {
                ip = cachedIpapiResponse.ip;
            }
        } catch (_) { }
    }

    if (!ip) {
        $done({ title: "IP 纯净度", content: "获取 IPv4 失败", icon: "exclamationmark.triangle.fill" });
        return;
    }

    let ippureFraudScore = null;
    try {
        const { data } = await httpGet(IPPURE_URL);
        const base = safeJsonParse(data);
        if (base) ippureFraudScore = base.fraudScore;
    } catch (_) { }

    const tasks = {
        ipapi: cachedIpapiResponse ? Promise.resolve(cachedIpapiResponse) : fetchIpapi(ip),
        ip2locIo: fetchIp2locationIo(ip),
        ipinfoIo: fetchIpinfoIo(ip),
        dbipHtml: fetchDbipHtml(ip),
        scamHtml: fetchScamalyticsHtml(ip),
        ipregistry: fetchIpregistry(ip),
    };

    const results = await Promise.allSettled(Object.keys(tasks).map((k) => tasks[k].then((v) => [k, v])));
    const ok = {};
    for (const r of results) {
        if (r.status === "fulfilled") {
            const [k, v] = r.value;
            ok[k] = v;
        }
    }

    const ipapiData = ok.ipapi || {};
    const ip2loc = parseIp2locationIo(ok.ip2locIo);
    const hostingLine = ip2locationHostingText(ip2loc.usageType);

    // ipapi 是否有效返回了地理信息 / ASN，没有则回落到 IP2Location
    const ipapiHasLocation = !!(ipapiData.location?.country_code || ipapiData.location?.country);
    const ipapiHasAsn = !!ipapiData.asn?.asn;

    let countryCode, country, city;
    if (ipapiHasLocation) {
        countryCode = ipapiData.location?.country_code || "";
        country = ipapiData.location?.country || "";
        city = ipapiData.location?.city || "";
    } else if (ip2loc.country || ip2loc.city) {
        countryCode = ip2loc.countryCode || "";
        country = ip2loc.country || "";
        city = ip2loc.city || "";
    } else {
        countryCode = "";
        country = "";
        city = "";
    }
    const flag = flagEmoji(countryCode);

    let asnText;
    if (ipapiHasAsn) {
        asnText = `AS${ipapiData.asn.asn} ${ipapiData.asn.org || ""}`.trim();
    } else if (ip2loc.asn) {
        asnText = `AS${ip2loc.asn} ${ip2loc.asOrg || ""}`.trim();
    } else {
        asnText = "-";
    }

    const grades = [];
    grades.push(gradeIppure(ippureFraudScore));
    grades.push(gradeIpapi(ok.ipapi));
    const ip2locGrade = gradeIp2locationIo(ip2loc.fraudScore);
    if (ip2locGrade.text) grades.push(ip2locGrade);
    grades.push(gradeScamalytics(ok.scamHtml));
    grades.push(gradeDbip(ok.dbipHtml));
    grades.push(gradeIpregistry(ok.ipregistry));

    const maxSev = grades.reduce((m, g) => Math.max(m, g.sev ?? 2), 0);
    const meta = severityMeta(maxSev);
    const riskLines = grades.map((g) => g.text).filter(Boolean);

    // 纯文本输出
    const showIP = MarkIP ? maskIP(ip) : ip;

    let content = `IP：${showIP}
ASN：${asnText}
位置：${flag} ${country} ${city}
类型：${hostingLine} （来源：IP2Location）

—— 多源评分 ——
${riskLines.join('\n')}`;

    // IP类型风险
    const factorParts = [];
    if (ip2loc.isProxy) factorParts.push("Proxy");
    if (ip2loc.proxyType && ip2loc.proxyType !== "-") factorParts.push(ip2loc.proxyType);
    if (ip2loc.threat && ip2loc.threat !== "-") factorParts.push(`威胁:${ip2loc.threat}`);
    if (ok.ipapi) {
        const items = [];
        if (ok.ipapi.is_proxy === true) items.push("Proxy");
        if (ok.ipapi.is_tor === true) items.push("Tor");
        if (ok.ipapi.is_vpn === true) items.push("VPN");
        if (ok.ipapi.is_datacenter === true) items.push("Datacenter");
        if (ok.ipapi.is_abuser === true) items.push("Abuser");
        if (items.length) factorParts.push(`ipapi: ${items.join("/")}`);
    }
    if (ok.ipinfoIo?.detected?.length) {
        factorParts.push(`ipinfo: ${ok.ipinfoIo.detected.join("/")}`);
    }
    if (ok.ipregistry) {
        const sec = ok.ipregistry;
        const items = [];
        if (sec.is_proxy === true) items.push("Proxy");
        if (sec.is_tor === true) items.push("Tor");
        if (sec.is_relay === true) items.push("Relay");
        if (sec.is_vpn === true) items.push("VPN");
        if (sec.is_anonymous === true) items.push("Anonymous");
        if (sec.is_cloud_provider === true) items.push("Hosting");
        if (sec.is_abuser === true) items.push("Abuser");
        if (sec.is_attacker === true) items.push("Attacker");
        if (sec.is_bogon === true) items.push("Bogon");
        if (sec.is_threat === true) items.push("Threat");
        if (items.length) factorParts.push(`ipregistry: ${items.join("/")}`);
    }

    if (factorParts.length) {
        content += `\n\n—— IP类型风险 ——\n${factorParts.join('\n')}`;
    }

    $done({
        title: "节点 IP 风险汇总",
        content: content,
        icon: meta.icon,
        "icon-color": meta.color
    });
})().catch((e) => {
    $done({
        title: "IP 纯净度",
        content: `请求失败：${String(e?.message || e)}`,
        icon: "network.slash"
    });
});
