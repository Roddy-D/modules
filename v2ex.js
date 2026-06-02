// ================= 全局参数解析区 =================
let v2exCookie = "";
let tgToken = "";
let tgUserId = "";
let notifyOnlyFail = false;
let enableCapture = true; // 默认开启抓取
const COOKIE_CACHE_KEY = "V2EX_COOKIE"; // 持久化存储的Key（与插件版 V2EX_LOON_COOKIE 区分）

// 解析 $argument (支持传入 JSON 字符串)
if (typeof $argument !== "undefined" && $argument) {
    try {
        let arg = typeof $argument === "string" ? JSON.parse($argument) : $argument;

        // 过滤掉用户可能填写的占位符，如 "xxx"、"无"、"none" 等
        const isValid = (val) => val && val.trim() !== "xxx" && val.trim() !== "无" && val.trim().toLowerCase() !== "none";

        v2exCookie = isValid(arg.V2EX_COOKIE) ? String(arg.V2EX_COOKIE) : "";
        tgToken = isValid(arg.TG_BOT_TOKEN) ? String(arg.TG_BOT_TOKEN) : "";
        tgUserId = isValid(arg.TG_USER_ID) ? String(arg.TG_USER_ID) : "";

        notifyOnlyFail = (arg.TG_NOTIFY_ONLY_FAIL === "true" || arg.TG_NOTIFY_ONLY_FAIL === "1" || arg.TG_NOTIFY_ONLY_FAIL === true);

        if (arg.ENABLE_CAPTURE !== undefined) {
            enableCapture = (arg.ENABLE_CAPTURE === "true" || arg.ENABLE_CAPTURE === "1" || arg.ENABLE_CAPTURE === true);
        }
    } catch (e) {
        console.log("[V2EX签到] 解析参数错误: " + e + ", argument: " + $argument);
    }
}
// ===============================================

const isGetHeader = typeof $request !== "undefined";

const COMMON_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "en,zh-CN;q=0.9,zh;q=0.8",
    "cache-control": "max-age=0",
    "pragma": "no-cache",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Referer": "https://www.v2ex.com/"
};

// 核心执行入口 (异步闭包)
(async () => {
    if (isGetHeader) {
        handleCaptureCookie();
    } else {
        await handleCheckin();
    }
})().finally(() => {
    $done({});
});

/**
 * ============================================
 * 1. 抓取与持久化请求头模块
 * ============================================
 */
function handleCaptureCookie() {
    // 检查抓取开关
    if (!enableCapture) {
        console.log("[V2EX签到] 抓取开关已关闭，跳过抓取流程。");
        return;
    }

    const allHeaders = $request.headers || {};
    // 忽略大小写取 Header
    const getHeader = (name) => allHeaders[name] ?? allHeaders[name.toLowerCase()] ?? allHeaders[name.toUpperCase()];

    const cookie = getHeader("Cookie") || getHeader("cookie");

    if (!cookie) {
        console.log("[V2EX签到] ⚠️ 提取 Cookie 为空，原始全量Header为: " + JSON.stringify(allHeaders));
        $notification.post("V2EX Cookie 获取失败", "", "未能从请求中找到 Cookie，请重新访问 V2EX 个人主页尝试。");
    } else {
        // 利用 $persistentStore 持久化保存
        const success = $persistentStore.write(cookie, COOKIE_CACHE_KEY);

        if (success) {
            console.log("[V2EX签到] ✨ 成功保存 Cookie: " + cookie.substring(0, 30) + "...");
            $notification.post("V2EX Cookie 获取成功", "", "Cookie 已保存。\n请前往配置关闭【抓取开关】。");
        } else {
            console.log("[V2EX签到] ❌ 保存 Cookie 失败");
            $notification.post("V2EX Cookie 保存失败", "", "写入存储失败，请检查存储权限。");
        }
    }
}

/**
 * ============================================
 * 2. 核心签到逻辑
 * ============================================
 */
async function handleCheckin() {
    // 优先级: 插件传参 > PersistentStore 持久化存储
    let finalCookie = v2exCookie || $persistentStore.read(COOKIE_CACHE_KEY);

    if (!finalCookie) {
        const msg = "📉 未检测到脚本的 Cookie 参数 或 持久化Cookie，请打开 Cookie 抓取开关后前往 V2EX 个人主页登录一次。";
        console.log("[V2EX签到] " + msg);
        $notification.post("V2EX签到结果", "❌ 无法签到", msg);
        await sendTgNotify("<b>❌ V2EX 签到失败</b>\n\n原因: <code>未检测到传入的 V2EX Cookie，请检查配置！</code>");
        return;
    }

    const headers = buildHeaders(finalCookie);

    try {
        await doCheckin(0, 3, headers);
    } catch (error) {
        const errStr = error?.error || error?.message || String(error);
        console.log(`[V2EX签到] 网络请求出现异常: ${errStr}`);
        $notification.post("V2EX签到结果", "⚠️ 网络请求异常", errStr);
        await sendTgNotify(`<b>⚠️ V2EX 签到系统/网络异常</b>\n\n详细信息: \n<code>${escapeHtml(errStr)}</code>`);
    }
}

/**
 * 签到主流程，支持失败重试
 */
async function doCheckin(attempt, maxRetry, headers) {
    console.log(`[V2EX签到] 尝试 ${attempt + 1}/${maxRetry}`);
    try {
        const info = await getOnce(headers);

        // ---- Cookie 失效 ----
        if (!info.logged_in) {
            console.log("[V2EX签到] Cookie 已失效");
            $notification.post("V2EX签到结果", "❌ Cookie 已失效", "请重新访问 V2EX 个人主页更新 Cookie");
            await sendTgNotify("<b>❌ V2EX 签到失败</b>\n\n原因: <code>Cookie 已失效，请重新登录抓取。</code>");
            return;
        }

        // ---- 今日已签到 ----
        if (info.already) {
            const q = await queryBalance(headers);
            let logMsg = `[V2EX签到] ✅ 已签到 | 连续 ${info.days} 天`;
            if (q.balance) logMsg += " | " + q.balance;
            console.log(logMsg);

            let n = `连续签到 ${info.days} 天`;
            if (q.balance) n += "\n" + q.balance;
            $notification.post("V2EX 今日已签到", "", n);

            if (!notifyOnlyFail) {
                let tg = `<b>📅 V2EX 今日已签到</b>\n\n连续签到: <code>${info.days} 天</code>`;
                if (q.balance) tg += `\n当前余额: <code>${escapeHtml(q.balance)}</code>`;
                await sendTgNotify(tg);
            }
            return;
        }

        // ---- 未找到 once 码，重试 ----
        if (!info.once) {
            console.log("[V2EX签到] 未找到 once 码");
            if (attempt + 1 < maxRetry) {
                console.log("[V2EX签到] 3秒后重试...");
                await sleep(3000);
                return doCheckin(attempt + 1, maxRetry, headers);
            }
            $notification.post("V2EX 签到失败", "未找到 once 码", "已达最大重试次数");
            await sendTgNotify("<b>❌ V2EX 签到失败</b>\n\n原因: <code>未找到 once 码，已达最大重试次数。</code>");
            return;
        }

        // ---- 执行签到 ----
        console.log(`[V2EX签到] once=${info.once} | 连续 ${info.days} 天`);
        await checkIn(info.once, headers);
        const q = await queryBalance(headers);

        let logMsg = `[V2EX签到] ✅ 签到成功 | 连续 ${info.days} 天`;
        if (q.bonus) logMsg += ` | 奖励 +${q.bonus} 铜币`;
        if (q.balance) logMsg += " | " + q.balance;
        console.log(logMsg);

        let n = `连续签到 ${info.days} 天`;
        if (q.reward) n += "\n" + q.reward;
        if (q.balance) n += "\n余额 " + q.balance;
        $notification.post("V2EX 签到成功", "", n);

        if (!notifyOnlyFail) {
            let tg = `<b>🎉 V2EX 自动签到成功</b>\n\n连续签到: <code>${info.days} 天</code>`;
            if (q.bonus) tg += `\n本次奖励: <code>+${q.bonus} 铜币</code>`;
            if (q.balance) tg += `\n当前余额: <code>${escapeHtml(q.balance)}</code>`;
            await sendTgNotify(tg);
        }
    } catch (e) {
        // 网络层错误，重试或抛出由上层处理
        if (attempt + 1 < maxRetry) {
            console.log(`[V2EX签到] 出错，3秒后重试: ${e?.message || e}`);
            await sleep(3000);
            return doCheckin(attempt + 1, maxRetry, headers);
        }
        throw e;
    }
}

/**
 * ============================================
 * 3. V2EX 接口解析模块
 * ============================================
 */
// 访问 mission/daily 页面，解析登录状态、是否已签、连续天数与 once 码
function getOnce(headers) {
    return fetchUrl("https://www.v2ex.com/mission/daily", headers).then((html) => {
        if (!html) return { once: "", logged_in: false, already: false, days: "?" };
        if (html.includes("你要查看的页面需要先登录") || html.includes("需要先登录")) {
            return { once: "", logged_in: false, already: false, days: "?" };
        }
        const daysMatch = html.match(/已连续登录\s*(\d+)\s*天/);
        const days = daysMatch ? daysMatch[1] : "?";
        if (html.includes("每日登录奖励已领取")) {
            return { once: "", logged_in: true, already: true, days };
        }
        const onceMatch = html.match(/once=(\d+)/);
        const once = onceMatch ? onceMatch[1] : "";
        return { once, logged_in: true, already: false, days };
    });
}

// 领取每日奖励
function checkIn(once, headers) {
    return fetchUrl("https://www.v2ex.com/mission/daily/redeem?once=" + once, headers);
}

// 查询余额与本次奖励
function queryBalance(headers) {
    return fetchUrl("https://www.v2ex.com/balance", headers).then((html) => {
        const rewardMatch = html.match(/\d+ 的每日登录奖励 \d+ 铜币/);
        const reward = rewardMatch ? rewardMatch[0] : "";
        const bonusMatch = html.match(/每日登录奖励\s*([+-]?\d+)\s*铜币/);
        const bonus = bonusMatch ? bonusMatch[1] : "";
        const balance = formatBalance(html);
        return { reward, bonus, balance };
    });
}

// 解析金/银/铜币余额
function formatBalance(html) {
    try {
        if (!html) return "";
        const block = html.match(/balance_area bigger[\s\S]*?<\/div>/);
        if (!block) return "";
        const gold = (block[0].match(/(\d+)\s*<img[^>]*?alt="G"/) || [])[1] || "0";
        const silver = (block[0].match(/(\d+)\s*<img[^>]*?alt="S"/) || [])[1] || "0";
        const bronze = (block[0].match(/(\d+)\s*<img[^>]*?alt="B"/) || [])[1] || "0";
        return `${gold} 金币, ${silver} 银币, ${bronze} 铜币`;
    } catch (e) {
        console.log("[V2EX签到] 解析余额出错: " + e);
        return "";
    }
}

/**
 * ============================================
 * 4. 辅助函数区
 * ============================================
 */
function buildHeaders(cookie) {
    const h = {};
    for (const k in COMMON_HEADERS) h[k] = COMMON_HEADERS[k];
    h["Cookie"] = cookie;
    return h;
}

function fetchUrl(url, headers) {
    return fetchPromise({ url, headers, method: "GET" }).then((resp) => {
        const status = resp.status || "?";
        const body = resp.body || "";
        console.log(`[V2EX签到] ${url} -> ${status} (${body.length} bytes)`);
        return body;
    });
}

function fetchPromise(request) {
    return new Promise((resolve, reject) => {
        const method = (request.method || "GET").toUpperCase();

        const options = {
            url: request.url,
            headers: request.headers || {}
        };

        if (request.body !== undefined && request.body !== null) {
            options.body = request.body;
        }

        const callback = (error, response, data) => {
            if (error) {
                // 如果包含网络层断联或超时
                reject(error);
            } else {
                resolve({
                    status: response.status || response.statusCode,
                    body: data,
                    headers: response.headers
                });
            }
        };

        if (method === "POST") {
            $httpClient.post(options, callback);
        } else {
            $httpClient.get(options, callback);
        }
    });
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe.replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * ============================================
 * 5. Telegram 推送通知模块
 * ============================================
 */
async function sendTgNotify(text) {
    if (!tgToken || !tgUserId) {
        return;
    }

    const tgUrl = `https://api.telegram.org/bot${tgToken}/sendMessage`;
    const requestOpts = {
        url: tgUrl,
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            chat_id: tgUserId,
            text: text,
            parse_mode: "HTML",
            disable_web_page_preview: true
        })
    };

    try {
        const resp = await fetchPromise(requestOpts);
        if (resp.status !== 200) {
            console.log(`[TG_Notify] ❌ TG 推送失败, HTTP 状态码: ${resp.status}, 响应: ${resp.body}`);
        }
    } catch (error) {
        const errStr = error?.error || error?.message || String(error);
        console.log(`[TG_Notify] ❌ TG 推送环节发生网络异常: ${errStr}`);
    }
}
