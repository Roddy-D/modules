// ================= 全局参数解析区 =================
let checkinCookie = "";
let tgToken = "";
let tgUserId = "";
let notifyOnlyFail = false;
let enableCapture = true; // 默认开启抓取
let useRandomReward = false; // 默认关闭随机鸡腿，走固定保底
const COOKIE_CACHE_KEY = "NS_COOKIE"; // 持久化存储的Key

// 解析 $argument (支持传入 JSON 字符串)
if (typeof $argument !== "undefined" && $argument) {
    try {
        let arg = typeof $argument === "string" ? JSON.parse($argument) : $argument;

        // 过滤掉用户可能填写的占位符，如 "xxx"、"无"、"none" 等
        const isValid = (val) => val && val.trim() !== "xxx" && val.trim() !== "无" && val.trim().toLowerCase() !== "none";

        checkinCookie = isValid(arg.NS_COOKIE) ? arg.NS_COOKIE : "";
        tgToken = isValid(arg.TG_BOT_TOKEN) ? arg.TG_BOT_TOKEN : "";
        tgUserId = isValid(arg.TG_USER_ID) ? String(arg.TG_USER_ID) : "";

        notifyOnlyFail = (arg.TG_NOTIFY_ONLY_FAIL === "true" || arg.TG_NOTIFY_ONLY_FAIL === "1" || arg.TG_NOTIFY_ONLY_FAIL === true);

        if (arg.ENABLE_CAPTURE !== undefined) {
            enableCapture = (arg.ENABLE_CAPTURE === "true" || arg.ENABLE_CAPTURE === "1" || arg.ENABLE_CAPTURE === true);
        }

        if (arg.RANDOM_REWARD !== undefined) {
            useRandomReward = (arg.RANDOM_REWARD === "true" || arg.RANDOM_REWARD === "1" || arg.RANDOM_REWARD === true);
        }
    } catch (e) {
        console.log("[NS签到] 解析参数错误: " + e + ", argument: " + $argument);
    }
}
// ===============================================

const isGetHeader = typeof $request !== "undefined";

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
        console.log("[NS签到] 抓取开关已关闭，跳过抓取流程。");
        return;
    }

    const allHeaders = $request.headers || {};
    // 忽略大小写取 Header
    const getHeader = (name) => allHeaders[name] ?? allHeaders[name.toLowerCase()] ?? allHeaders[name.toUpperCase()];

    const cookie = getHeader("Cookie") || getHeader("cookie");

    if (!cookie) {
        console.log("[NS签到] ⚠️ 提取 Cookie 为空，原始全量Header为: " + JSON.stringify(allHeaders));
        $notification.post("NS Cookie 获取失败", "", "未能从请求中找到 Cookie，请检查抓包逻辑重新访问个人页面尝试。");
    } else {
        // 利用 $persistentStore 持久化保存
        const success = $persistentStore.write(cookie, COOKIE_CACHE_KEY);
        if (success) {
            console.log("[NS签到] ✨ 成功保存 Cookie: " + cookie.substring(0, 30) + "...");
            $notification.post("NS Cookie 获取成功", "", "Cookie 已安全持久化保存，请前往配置将其它的选项配好，并关闭【抓取开关】。");
        } else {
            console.log("[NS签到] ❌ 保存 Cookie 失败");
            $notification.post("NS Cookie 保存失败", "", "写入存储失败，请检查存储权限。");
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
    let finalCookie = checkinCookie || $persistentStore.read(COOKIE_CACHE_KEY);

    if (!finalCookie) {
        const msg = "📉 未检测到脚本的 Cookie 参数 或 持久化Cookie，请打开 Cookie 抓取开关前往 NodeSeek 登录一次。";
        console.log("[NS签到] " + msg);
        $notification.post("NS签到结果", "❌ 无法签到", msg);
        await sendTgNotify("<b>❌ NodeSeek 签到失败</b>\n\n原因: <code>未检测到参数中传入的 NodeSeek Cookie，请检查配置！</code>");
        return;
    }

    const url = `https://www.nodeseek.com/api/attendance?random=${useRandomReward}`;

    const headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
        "Origin": "https://www.nodeseek.com",
        "Referer": "https://www.nodeseek.com/board",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Content-Length": "0",
        "Content-Type": "application/json",
        "Cookie": finalCookie
    };

    const requestOpts = {
        url: url,
        method: "POST",
        headers: headers,
        body: ""
    };

    try {
        const resp = await fetchPromise(requestOpts);
        await processResponse(resp);
    } catch (error) {
        const errStr = error?.error || error?.message || String(error);
        console.log(`[NS签到] 网络请求出现异常: ${errStr}`);
        $notification.post("NS签到结果", "⚠️ 网络请求异常", errStr);
        await sendTgNotify(`<b>⚠️ NodeSeek 签到系统/网络异常</b>\n\n详细信息: \n<code>${escapeHtml(errStr)}</code>`);
    }
}

/**
 * ============================================
 * 3. 响应解析模型
 * ============================================
 */
async function processResponse(resp) {
    const status = resp.status;
    const body = resp.body || "";
    let msg = "";

    try {
        const obj = JSON.parse(body);
        msg = obj?.message ? String(obj.message) : "";
        console.log(`[NS签到] JSON返回报文解析 message: ${msg || "无"}`);
    } catch (e) {
        console.log(`[NS签到] 响应体非JSON格式或无法解析: ${body.substring(0, 150)}...`);
    }

    const content = msg || body.substring(0, 150) || "服务端未返回任何有效内容";

    if (status >= 200 && status < 300) {
        const notifyStr = msg || "您已签到成功或已经签过到了";
        console.log(`[NS签到] ✅ 签到响应成功: ${notifyStr}`);
        $notification.post("NS活动签到", "✅ 签到成功", notifyStr);

        if (!notifyOnlyFail) {
            await sendTgNotify(`<b>🎉 NodeSeek 自动签到成功</b>\n\n状态码: ${status}\n返回信息：\n<code>${escapeHtml(notifyStr)}</code>`);
        }
    } else if (status === 403) {
        const notifyStr = `遭受 Cloudflare 或 系统风控，请稍后重试\n拦截详情：${content}`;
        console.log(`[NS签到] ⚠️ 403风控拦截: ${notifyStr}`);
        $notification.post("NS活动签到", "⚠️ 403 风控拦截", notifyStr);
        await sendTgNotify(`<b>⚠️ NodeSeek 签到被风控拦截(403)</b>\n\n拦截信息详情：\n<code>${escapeHtml(content)}</code>`);

    } else if (status === 500) {
        const notifyStr = `服务器发生内部报错(500)\n内容：${content}`;
        console.log(`[NS签到] ❌ 500错误: ${notifyStr}`);
        $notification.post("NS活动签到", "❌ 服务器内部错误", notifyStr);
        await sendTgNotify(`<b>❌ NodeSeek 签到服务器错误(500)</b>\n\n错误信息详情：\n<code>${escapeHtml(content)}</code>`);

    } else {
        const notifyStr = `请求返回了异常状态码: ${status}\n内容：${content}`;
        console.log(`[NS签到] ❓ 未知异常: ${notifyStr}`);
        $notification.post("NS活动签到", `❓ 未知请求异常 (${status})`, notifyStr);
        await sendTgNotify(`<b>❓ NodeSeek 签到未知异常状态 (${status})</b>\n\n异常信息详情：\n<code>${escapeHtml(content)}</code>`);
    }
}

/**
 * ============================================
 * 4. 辅助函数区
 * ============================================
 */
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
