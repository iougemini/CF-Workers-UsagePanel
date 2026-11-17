

export default {
    async fetch(request, env, ctx) {
        try {
            const 响应 = await (async () => {
                const 面板管理员账号 = env.USER || env.user || env.USERNAME || env.username || 'admin';
                const 面板管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd;
                const 演示样板 = 解析布尔变量(env.DEMO);
                if (!面板管理员密码) {
                    return new Response('请先在变量中设置 PASSWORD 变量', { status: 500 });
                }

                if (env.KV && typeof env.KV.get === 'function') {
                    const url = new URL(request.url);
                    if (url.pathname === '/admin/') {
                        return new Response(null, { status: 302, headers: { 'Location': '/admin' } });
                    }
                    const 访问路径 = url.pathname.slice(1).toLowerCase();
                    const 区分大小写访问路径 = url.pathname.slice(1);

                    // 验证会话：Cookie 中保存随机会话令牌，服务端在 KV 中校验，登出可真正吊销。
                    // 会话值兼容两种格式：JSON（含 username/role）或旧的纯时间戳（视为管理员）。
                    let 当前会话缓存 = null;
                    const 获取会话 = async () => {
                        if (当前会话缓存) return 当前会话缓存;
                        const cookies = request.headers.get('Cookie') || '';
                        const 会话匹配 = cookies.match(/admin_token=([a-f0-9]{64})/);
                        if (!会话匹配) {
                            // Cloudflare Access 自动登录：仅在 Worker 已被 Access 保护时启用（Access 会注入该请求头）
                            const accessEmail = String(request.headers.get('Cf-Access-Authenticated-User-Email') || '').trim();
                            if (accessEmail && 解析布尔变量(env.ACCESS_AUTO_LOGIN)) {
                                const 允许邮箱 = String(env.ACCESS_ADMIN_EMAILS || '').split(',').map(item => item.trim().toLowerCase()).filter(Boolean);
                                if (允许邮箱.length === 0 || 允许邮箱.includes(accessEmail.toLowerCase())) {
                                    当前会话缓存 = { username: accessEmail, role: 'admin', userId: 'access', accounts: null, source: 'access' };
                                    return 当前会话缓存;
                                }
                            }
                            return null;
                        }
                        try {
                            const 原始 = await env.KV.get('admin_session:' + 会话匹配[1]);
                            if (!原始) return null;
                            let 会话 = { username: 'admin', role: 'admin', userId: null, accounts: null };
                            try {
                                const 解析 = JSON.parse(原始);
                                if (解析 && typeof 解析 === 'object') {
                                    会话 = {
                                        username: String(解析.username || 'admin'),
                                        role: 解析.role === 'viewer' ? 'viewer' : 'admin',
                                        userId: 解析.userId ? String(解析.userId) : null,
                                        accounts: Array.isArray(解析.accounts) ? 解析.accounts.map(String) : null
                                    };
                                }
                            } catch (解析错误) {
                                // 旧格式时间戳，按管理员处理
                            }
                            当前会话缓存 = 会话;
                            return 会话;
                        } catch (error) {
                            console.error('校验管理员会话失败:', error.message);
                            return null;
                        }
                    };
                    const 验证管理员Cookie = async () => !!(await 获取会话());

            if (访问路径 == 'usage.json') {// 请求数使用数据接口 Usage.json（公开只读，不需要 token）
                const 跨域头 = { 'Content-Type': 'application/json;charset=UTF-8', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
                if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: 跨域头 });
                const 用量限流 = 内存限流检查(request, 'usage.json');
                if (用量限流 > 0) return 限流响应(用量限流, 跨域头);
                const 只读Token = await 验证只读Token(env, request);
                if (只读Token && Array.isArray(只读Token.accounts) && 只读Token.accounts.length > 0) {
                    return new Response(JSON.stringify({ success: false, msg: '按账号授权的只读 Token 不能读取汇总接口' }), { status: 403, headers: 跨域头 });
                }
                const 已保存Usage = await env.KV.get('usage.json', { type: 'json' });
                const 已保存更新时间 = Number(已保存Usage?.UpdateTime || 0) || 0;
                const 已过期 = !已保存Usage || (Date.now() - 已保存更新时间) > 获取单账号查询间隔毫秒(env);
                let usage_json;
                if (已过期) {
                    // 过期时允许触发一次带锁的刷新：并发请求由刷新锁收敛，只有抢到锁的请求会真正查询外部 API；
                    // writeUsage 保证刷新后 UpdateTime 更新，避免持续过期导致每个请求都重复抢锁。
                    usage_json = await 更新请求数(env, { writeUsage: true });
                } else {
                    usage_json = 补全Usage结构(已保存Usage);
                    usage_json.success = true;
                    usage_json.total = (usage_json.pages || 0) + (usage_json.workers || 0);
                    usage_json.msg = '✅ 成功加载免费额度使用数据';
                }
                return new Response(JSON.stringify(usage_json, null, 2), { headers: 跨域头 });
            } else if (访问路径 === 'health') {// 健康检查（供 Uptime Kuma 等探活）
                return 处理健康检查(env);
            } else if (访问路径 === 'metrics') {// Prometheus 指标（METRICS_TOKEN 或管理员会话）
                const 指标已授权 = (await 校验Metrics访问(env, request)) || (await 验证管理员Cookie()) || !!(await 验证只读Token(env, request));
                if (!指标已授权) return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });
                return 处理Metrics(env);
            } else if (访问路径 === 'badge.svg') {// 动态用量徽章
                return 处理Badge(env);
            } else if (访问路径 === 'status') {// 公开聚合状态页
                const 状态用量 = await env.KV.get('usage.json', { type: 'json' });
                const 状态配置 = await 读取账号配置(env);
                return new Response(渲染状态页(状态用量, Array.isArray(状态配置) ? 状态配置.length : 0), {
                    status: 200,
                    headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'public, max-age=30' }
                });
            } else if (访问路径 === 'history') {// 历史趋势（汇总公开，单账号需管理员会话或只读 Token）
                const 历史账户 = String(url.searchParams.get('account') || 'all');
                const 历史Token = await 验证只读Token(env, request);
                const 历史会话 = await 获取会话();
                if (历史账户 !== 'all' && !历史会话 && !历史Token) {
                    return new Response(JSON.stringify({ success: false, msg: '未登录或会话已过期' }), { status: 401, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                }
                if (历史Token) {
                    if (历史账户 === 'all' && Array.isArray(历史Token.accounts) && 历史Token.accounts.length > 0) {
                        return new Response(JSON.stringify({ success: false, msg: '按账号授权的只读 Token 请指定 account 参数' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    }
                    if (历史账户 !== 'all' && Array.isArray(历史Token.accounts) && 历史Token.accounts.length > 0 && !历史Token.accounts.includes(历史账户)) {
                        return new Response(JSON.stringify({ success: false, msg: '该 Token 无权查看此账号历史' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    }
                } else if (历史账户 !== 'all' && 历史会话?.accounts && !历史会话.accounts.includes(历史账户)) {
                    return new Response(JSON.stringify({ success: false, msg: '无权查看该账号历史' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                }
                return 处理历史查询(env, url);
            } else if (访问路径 == 'admin' || 访问路径.startsWith('admin/')) {// 管理员面板
                const 管理限流 = 内存限流检查(request, 'admin');
                if (管理限流 > 0) return 限流响应(管理限流);
                // 管理面板 - 验证会话
                const 管理会话 = await 获取会话();
                if (管理会话) {
                    const 只读管理 = 管理会话.role !== 'admin';
                    if (只读管理 && request.method !== 'GET') {
                        return new Response(JSON.stringify({ success: false, msg: '只读账号无权执行此操作' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    }
                    if (只读管理 && url.searchParams.get('force') === '1') {
                        return new Response(JSON.stringify({ success: false, msg: '只读账号无权强制刷新' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    }
                    if (区分大小写访问路径 === 'admin/config.json') {
                        const 原始配置 = await 读取账号配置(env);
                        const 全部配置 = Array.isArray(原始配置) ? 原始配置 : [];
                        const usage_config_json = 管理会话.accounts
                            ? 全部配置.filter(item => 管理会话.accounts.includes(String(item.ID)))
                            : 全部配置;
                        const masked_config_json = usage_config_json.map(item => {
                            const updateTime = 获取账号最后更新时间(item);
                            return {
                                ...item,
                                UpdateTime: updateTime || item.UpdateTime,
                                Usage: 应用账号限额(补全账号Usage结构(item), item),
                                GlobalAPIKey: item.GlobalAPIKey ? 掩码敏感信息(item.GlobalAPIKey) : null,
                                APIToken: item.APIToken ? 掩码敏感信息(item.APIToken) : null
                            };
                        });
                        return new Response(JSON.stringify(masked_config_json, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/usage.json') {
                        const 强制执行 = url.searchParams.get('force') === '1';
                        const 告警配置 = 强制执行 ? await 读取告警配置(env) : null;
                        const 预留子请求 = 强制执行 && 告警配置?.enabled ? Math.min(6, 告警渠道数量(告警配置) * 3) : 0;
                        const usage_json = await 更新请求数(env, { force: 强制执行, reserveSubrequests: 预留子请求 });
                        if (强制执行 && 告警配置) {
                            try {
                                const 告警结果 = await 评估并发送告警(env, usage_json, 告警配置);
                                if (告警结果.sent > 0) usage_json.msg += `（已发送 ${告警结果.sent} 条告警）`;
                            } catch (告警错误) {
                                console.error('刷新后评估告警失败:', 告警错误.message);
                            }
                        }
                        return new Response(JSON.stringify(usage_json, null, 2), { headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/alerts.json') {// 告警配置
                        if (request.method === 'GET') {
                            return new Response(JSON.stringify(脱敏告警配置(await 读取告警配置(env)), null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        if (!body || typeof body !== 'object' || Array.isArray(body)) {
                            return new Response(JSON.stringify({ success: false, msg: '请求体必须是 JSON 对象' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 现有配置 = await 读取告警配置(env);
                        const 新配置 = 规范化告警配置({
                            enabled: body.enabled === undefined ? 现有配置.enabled : body.enabled === true,
                            cooldownMinutes: body.cooldownMinutes === undefined ? 现有配置.cooldownMinutes : body.cooldownMinutes,
                            thresholds: { ...现有配置.thresholds, ...(body.thresholds && typeof body.thresholds === 'object' && !Array.isArray(body.thresholds) ? body.thresholds : {}) },
                            telegram: {
                                enabled: body.telegram?.enabled === undefined ? 现有配置.telegram.enabled : body.telegram.enabled === true,
                                botToken: typeof body.telegram?.botToken === 'string' && body.telegram.botToken.trim() ? body.telegram.botToken.trim() : 现有配置.telegram.botToken,
                                chatId: typeof body.telegram?.chatId === 'string' ? body.telegram.chatId.trim() : 现有配置.telegram.chatId
                            },
                            webhook: {
                                enabled: body.webhook?.enabled === undefined ? 现有配置.webhook.enabled : body.webhook.enabled === true,
                                url: typeof body.webhook?.url === 'string' && body.webhook.url.trim() ? body.webhook.url.trim() : 现有配置.webhook.url,
                                platform: 支持的Webhook平台.includes(body.webhook?.platform) ? body.webhook.platform : 现有配置.webhook.platform
                            },
                            webhooks: Array.isArray(body.webhooks) ? body.webhooks : 现有配置.webhooks,
                            quietHours: body.quietHours && typeof body.quietHours === 'object' ? { ...现有配置.quietHours, ...body.quietHours } : 现有配置.quietHours,
                            rules: Array.isArray(body.rules) ? body.rules : 现有配置.rules,
                            forecast: {
                                enabled: body.forecast?.enabled === undefined ? 现有配置.forecast.enabled : body.forecast.enabled === true,
                                hours: body.forecast?.hours === undefined ? 现有配置.forecast.hours : body.forecast.hours,
                                checkMinutes: body.forecast?.checkMinutes === undefined ? 现有配置.forecast.checkMinutes : body.forecast.checkMinutes
                            },
                            dailyReport: {
                                enabled: body.dailyReport?.enabled === undefined ? 现有配置.dailyReport.enabled : body.dailyReport.enabled === true,
                                hourUtc: body.dailyReport?.hourUtc === undefined ? 现有配置.dailyReport.hourUtc : body.dailyReport.hourUtc
                            }
                        });
                        await 保存告警配置(env, 新配置);
                        await 记录审计(env, 管理会话, 'alerts.save', '更新告警配置');
                        return new Response(JSON.stringify({ success: true, msg: '告警设置已保存', config: 脱敏告警配置(新配置) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/alerts/test') {// 发送测试告警
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 结果 = await 发送测试告警(env);
                        const 成功 = 结果.telegram || 结果.webhook;
                        await 记录审计(env, 管理会话, 'alerts.test', 成功 ? '测试消息发送成功' : '测试消息发送失败');
                        return new Response(JSON.stringify({ success: 成功, msg: 成功 ? '测试消息已发送' : '没有成功发送的渠道，请检查告警配置', result: 结果 }), { status: 成功 ? 200 : 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/alerts/history.json') {// 告警历史
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 历史 = await env.KV.get('alert_history.json', { type: 'json' });
                        return new Response(JSON.stringify(Array.isArray(历史) ? 历史 : []), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/alerts/history/clear') {// 清空告警历史
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可清空告警历史' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        await env.KV.delete('alert_history.json');
                        await 记录审计(env, 管理会话, 'alerts.history.clear', '清空告警历史');
                        return new Response(JSON.stringify({ success: true, msg: '告警历史已清空' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/report/test') {// 发送当前用量日报（测试）
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 日报结果 = await 发送当前日报(env);
                        await 记录审计(env, 管理会话, 'report.test', 日报结果.msg || '');
                        return new Response(JSON.stringify({ success: 日报结果.sent > 0, msg: 日报结果.msg, sent: 日报结果.sent }), { status: 日报结果.sent > 0 ? 200 : 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/report/export') {// 导出用量报告
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.accounts) {
                            return new Response(JSON.stringify({ success: false, msg: '按账号授权的只读用户暂不支持导出历史报告' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        return 处理导出报告(env, url);
                    } else if (区分大小写访问路径 === 'admin/audit.json') {// 审计日志
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可查看审计日志' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 审计日志 = await env.KV.get('audit_log.json', { type: 'json' });
                        return new Response(JSON.stringify(Array.isArray(审计日志) ? 审计日志 : []), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/anomaly.json') {// 异常检测
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        return 检测用量异常(env, url);
                    } else if (区分大小写访问路径 === 'admin/cost.json') {// 费用估算
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        return new Response(JSON.stringify(await 计算费用估算(env), null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/backup/export') {// 加密导出配置
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可导出配置' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const passphrase = String(body?.passphrase || '');
                        if (passphrase.length < 8) {
                            return new Response(JSON.stringify({ success: false, msg: '备份口令至少 8 位' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        try {
                            const backup = await 导出加密备份(env, passphrase);
                            await 记录审计(env, 管理会话, 'backup.export', '导出加密配置备份');
                            return new Response(JSON.stringify({ success: true, backup }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        } catch (error) {
                            console.error('导出备份失败:', error.message);
                            return new Response(JSON.stringify({ success: false, msg: '导出失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                    } else if (区分大小写访问路径 === 'admin/backup/import') {// 导入加密配置
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可导入配置' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const passphrase = String(body?.passphrase || '');
                        const backup = body?.backup;
                        if (!passphrase || !backup) {
                            return new Response(JSON.stringify({ success: false, msg: '需要备份口令与备份内容' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        try {
                            const 结果 = await 导入加密备份(env, passphrase, backup);
                            await 记录审计(env, 管理会话, 'backup.import', '导入配置备份（账号 ' + 结果.accounts + ' 个）');
                            return new Response(JSON.stringify({ success: true, msg: '备份已导入，账号配置已覆盖', ...结果 }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        } catch (error) {
                            console.error('导入备份失败:', error.message);
                            return new Response(JSON.stringify({ success: false, msg: '导入失败（口令错误或备份损坏）' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                    } else if (区分大小写访问路径 === 'admin/tokens.json') {// 只读 Token 列表
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可管理只读 Token' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 列表 = await 读取只读Token列表(env);
                        return new Response(JSON.stringify({ success: true, tokens: 列表.map(脱敏只读Token) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/tokens/add') {// 新增只读 Token
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可管理只读 Token' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const name = String(body?.name || '只读 Token').trim().slice(0, 50) || '只读 Token';
                        const accounts = Array.isArray(body?.accounts) ? body.accounts.map(String).slice(0, 100) : null;
                        const 有效期天数 = Math.min(3650, Math.max(0, Math.floor(Number(body?.expiresDays) || 0)));
                        const 明文 = 生成只读Token明文();
                        const 记录 = {
                            id: (crypto.randomUUID ? crypto.randomUUID() : 生成随机十六进制(16)),
                            name,
                            tokenHash: await SHA256十六进制(明文),
                            prefix: 明文.slice(0, 12) + '…',
                            accounts,
                            createdAt: new Date().toISOString(),
                            expiresAt: 有效期天数 > 0 ? Date.now() + 有效期天数 * 86400000 : null,
                            createdBy: 管理会话.username || 'admin'
                        };
                        const 列表 = await 读取只读Token列表(env);
                        列表.push(记录);
                        await 保存只读Token列表(env, 列表);
                        await 记录审计(env, 管理会话, 'token.add', '新增只读 Token ' + name);
                        return new Response(JSON.stringify({ success: true, token: 明文, record: 脱敏只读Token(记录) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/tokens/revoke') {// 吊销只读 Token
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可管理只读 Token' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const 列表 = await 读取只读Token列表(env);
                        const 目标 = 列表.find(item => String(item.id) === String(body?.id));
                        if (!目标) {
                            return new Response(JSON.stringify({ success: false, msg: 'Token 不存在' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        await 保存只读Token列表(env, 列表.filter(item => String(item.id) !== String(body?.id)));
                        await 记录审计(env, 管理会话, 'token.revoke', '吊销只读 Token ' + 目标.name);
                        return new Response(JSON.stringify({ success: true, msg: 'Token 已吊销' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/users.json') {// 面板用户列表
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可管理用户' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 面板用户 = await 读取面板用户(env);
                        return new Response(JSON.stringify({
                            success: true,
                            admin: { username: 面板管理员账号, role: 'admin', userId: 'env-admin', passwordChanged: !!(await 读取管理员密码记录(env)) },
                            users: 面板用户.map(脱敏面板用户),
                            envViewers: 解析只读用户(env).map(item => ({ username: item.username, role: 'viewer', accounts: item.accounts, source: 'env' }))
                        }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/users/add') {// 新增面板用户
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可管理用户' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const username = String(body?.username || '').trim();
                        const password = String(body?.password || '');
                        const role = body?.role === 'admin' ? 'admin' : 'viewer';
                        const accounts = Array.isArray(body?.accounts) ? body.accounts.map(String) : null;
                        if (!/^[A-Za-z0-9_.-]{2,32}$/.test(username)) {
                            return new Response(JSON.stringify({ success: false, msg: '用户名需为 2-32 位字母、数字、下划线、点或短横线' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (password.length < 8 || password.length > 200) {
                            return new Response(JSON.stringify({ success: false, msg: '密码长度需为 8-200 位' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 面板用户 = await 读取面板用户(env);
                        if (username === 面板管理员账号 || 面板用户.some(item => item.username === username) || 解析只读用户(env).some(item => item.username === username)) {
                            return new Response(JSON.stringify({ success: false, msg: '用户名已存在' }), { status: 409, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 密码记录 = await 创建密码记录(password);
                        const 新用户 = {
                            id: (crypto.randomUUID ? crypto.randomUUID() : 生成随机十六进制(16)),
                            username,
                            role,
                            accounts,
                            disabled: false,
                            createdAt: new Date().toISOString(),
                            updatedAt: new Date().toISOString(),
                            ...密码记录
                        };
                        面板用户.push(新用户);
                        await 保存面板用户(env, 面板用户);
                        await 记录审计(env, 管理会话, 'user.add', '新增用户 ' + username + '（' + role + '）');
                        return new Response(JSON.stringify({ success: true, msg: '用户已创建', user: 脱敏面板用户(新用户) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/users/update') {// 编辑面板用户
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可管理用户' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const 面板用户 = await 读取面板用户(env);
                        const 索引 = 面板用户.findIndex(item => String(item.id) === String(body?.id));
                        if (索引 === -1) {
                            return new Response(JSON.stringify({ success: false, msg: '用户不存在' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 用户 = 面板用户[索引];
                        if (body?.password !== undefined) {
                            const password = String(body.password);
                            if (password.length < 8 || password.length > 200) {
                                return new Response(JSON.stringify({ success: false, msg: '密码长度需为 8-200 位' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                            }
                            Object.assign(用户, await 创建密码记录(password));
                        }
                        if (body?.role !== undefined) 用户.role = body.role === 'admin' ? 'admin' : 'viewer';
                        if (body?.accounts !== undefined) 用户.accounts = Array.isArray(body.accounts) ? body.accounts.map(String) : null;
                        if (body?.disabled !== undefined) 用户.disabled = body.disabled === true;
                        if (body?.username !== undefined) {
                            const 新用户名 = String(body.username || '').trim();
                            if (!/^[A-Za-z0-9_.-]{2,32}$/.test(新用户名)) {
                                return new Response(JSON.stringify({ success: false, msg: '用户名格式不正确' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                            }
                            if (新用户名 === 面板管理员账号 || 面板用户.some((item, i) => i !== 索引 && item.username === 新用户名)) {
                                return new Response(JSON.stringify({ success: false, msg: '用户名已存在' }), { status: 409, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                            }
                            用户.username = 新用户名;
                        }
                        用户.updatedAt = new Date().toISOString();
                        面板用户[索引] = 用户;
                        await 保存面板用户(env, 面板用户);
                        await 记录审计(env, 管理会话, 'user.update', '更新用户 ' + 用户.username);
                        return new Response(JSON.stringify({ success: true, msg: '用户已更新', user: 脱敏面板用户(用户) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/users/delete') {// 删除面板用户
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可管理用户' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const 面板用户 = await 读取面板用户(env);
                        const 目标 = 面板用户.find(item => String(item.id) === String(body?.id));
                        if (!目标) {
                            return new Response(JSON.stringify({ success: false, msg: '用户不存在' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        await 保存面板用户(env, 面板用户.filter(item => String(item.id) !== String(body?.id)));
                        await 记录审计(env, 管理会话, 'user.delete', '删除用户 ' + 目标.username);
                        return new Response(JSON.stringify({ success: true, msg: '用户已删除' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/password') {// 修改管理员密码
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可修改密码' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const 当前密码 = String(body?.currentPassword || '');
                        const 新密码 = String(body?.newPassword || '');
                        if (新密码.length < 8 || 新密码.length > 200) {
                            return new Response(JSON.stringify({ success: false, msg: '新密码长度需为 8-200 位' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 旧记录 = await 读取管理员密码记录(env);
                        const 当前正确 = 旧记录
                            ? await 验证密码记录(当前密码, 旧记录)
                            : await 恒定时间比较(当前密码, 面板管理员密码);
                        if (!当前正确) {
                            return new Response(JSON.stringify({ success: false, msg: '当前密码错误' }), { status: 401, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 新记录 = await 创建密码记录(新密码);
                        await env.KV.put('admin_credentials.json', JSON.stringify({ ...新记录, updatedAt: Date.now() }));
                        // 修改密码后吊销其它会话（保留当前会话）
                        try {
                            const 当前令牌匹配 = (request.headers.get('Cookie') || '').match(/admin_token=([a-f0-9]{64})/);
                            const 会话键列表 = await env.KV.list({ prefix: 'admin_session:' });
                            for (const key of (会话键列表.keys || [])) {
                                if (!当前令牌匹配 || key.name !== 'admin_session:' + 当前令牌匹配[1]) await env.KV.delete(key.name);
                            }
                        } catch (删除会话错误) {
                            console.error('修改密码后清理会话失败:', 删除会话错误.message);
                        }
                        await 记录审计(env, 管理会话, 'password.change', '修改管理员密码');
                        return new Response(JSON.stringify({ success: true, msg: '管理员密码已修改，其它会话已失效' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/sessions.json') {// 会话列表
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可查看会话' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 当前令牌匹配 = (request.headers.get('Cookie') || '').match(/admin_token=([a-f0-9]{64})/);
                        const 会话列表 = [];
                        try {
                            const 键列表 = await env.KV.list({ prefix: 'admin_session:' });
                            for (const key of (键列表.keys || []).slice(0, 100)) {
                                const 原始 = await env.KV.get(key.name);
                                if (!原始) continue;
                                let 信息 = {};
                                try { 信息 = JSON.parse(原始); } catch (解析错误) { 信息 = {}; }
                                会话列表.push({
                                    suffix: key.name.slice(-8),
                                    username: 信息.username || 'admin',
                                    role: 信息.role === 'viewer' ? 'viewer' : 'admin',
                                    createdAt: 信息.ts ? new Date(信息.ts).toISOString() : null,
                                    ip: 信息.ip || '',
                                    ua: 信息.ua || '',
                                    current: !!当前令牌匹配 && key.name === 'admin_session:' + 当前令牌匹配[1]
                                });
                            }
                        } catch (列出会话错误) {
                            console.error('读取会话列表失败:', 列出会话错误.message);
                        }
                        会话列表.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
                        return new Response(JSON.stringify({ success: true, sessions: 会话列表 }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/sessions/revoke') {// 吊销会话
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.role !== 'admin') {
                            return new Response(JSON.stringify({ success: false, msg: '仅管理员可吊销会话' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const suffix = String(body?.suffix || '').trim();
                        if (!/^[a-f0-9]{8}$/.test(suffix)) {
                            return new Response(JSON.stringify({ success: false, msg: '会话标识不正确' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        let 已吊销 = false;
                        try {
                            const 键列表 = await env.KV.list({ prefix: 'admin_session:' });
                            for (const key of (键列表.keys || [])) {
                                if (key.name.endsWith(suffix)) {
                                    await env.KV.delete(key.name);
                                    已吊销 = true;
                                    break;
                                }
                            }
                        } catch (吊销错误) {
                            console.error('吊销会话失败:', 吊销错误.message);
                        }
                        await 记录审计(env, 管理会话, 'session.revoke', '吊销会话 ' + suffix);
                        return new Response(JSON.stringify({ success: 已吊销, msg: 已吊销 ? '会话已吊销' : '未找到该会话' }), { status: 已吊销 ? 200 : 404, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/2fa.json') {// 两步验证状态
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 二步配置 = await 读取2FA配置(env);
                        return new Response(JSON.stringify({ success: true, enabled: 二步配置.enabled, enabledAt: 二步配置.enabledAt || null, backupRemaining: 二步配置.backupHashes.length }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/2fa/setup') {// 生成两步验证密钥
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 现有配置 = await 读取2FA配置(env);
                        if (现有配置.enabled) {
                            return new Response(JSON.stringify({ success: false, msg: '两步验证已启用，请先关闭' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const secret = 生成TOTP密钥();
                        await env.KV.put('admin_2fa_pending.json', JSON.stringify({ secret, createdAt: Date.now() }), { expirationTtl: 600 });
                        return new Response(JSON.stringify({
                            success: true,
                            secret,
                            otpauth: 生成OTPAuthURL(secret, 面板管理员账号),
                            msg: '请在验证器中添加密钥，然后输入 6 位验证码完成启用'
                        }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/2fa/enable') {// 启用两步验证
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const 待启用配置 = await env.KV.get('admin_2fa_pending.json', { type: 'json' });
                        if (!待启用配置 || !待启用配置.secret) {
                            return new Response(JSON.stringify({ success: false, msg: '设置已过期，请重新生成密钥' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 步 = await TOTP验证(待启用配置.secret, body?.code);
                        if (!步) {
                            return new Response(JSON.stringify({ success: false, msg: '验证码错误' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 恢复码列表 = Array.from({ length: 8 }, () => 生成恢复码());
                        const 恢复码哈希 = await Promise.all(恢复码列表.map(code => SHA256十六进制(code)));
                        await 保存2FA配置(env, { enabled: true, secret: 待启用配置.secret, lastStep: 步, enabledAt: Date.now(), backupHashes: 恢复码哈希 });
                        await env.KV.delete('admin_2fa_pending.json');
                        await 记录审计(env, 管理会话, '2fa.enable', '启用两步验证');
                        return new Response(JSON.stringify({ success: true, msg: '两步验证已启用', backupCodes: 恢复码列表 }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/2fa/disable') {// 关闭两步验证
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 现有配置 = await 读取2FA配置(env);
                        if (!现有配置.enabled) {
                            return new Response(JSON.stringify({ success: false, msg: '两步验证未启用' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        const 步 = await TOTP验证(现有配置.secret, body?.code, 2);
                        if (!步 || 步 <= Number(现有配置.lastStep || 0)) {
                            return new Response(JSON.stringify({ success: false, msg: '验证码错误或已使用' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        await env.KV.delete('admin_2fa.json');
                        await 记录审计(env, 管理会话, '2fa.disable', '关闭两步验证');
                        return new Response(JSON.stringify({ success: true, msg: '两步验证已关闭' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    } else if (区分大小写访问路径 === 'admin/top-scripts') {// Top N 脚本与错误率
                        if (request.method !== 'GET') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const Top账号 = String(url.searchParams.get('account') || '');
                        if (管理会话.accounts && (!Top账号 || !管理会话.accounts.includes(Top账号))) {
                            return new Response(JSON.stringify({ success: false, msg: '无权查看该账号' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        return 查询Top脚本(env, url);
                    } else if (区分大小写访问路径 === 'admin/optimize/analyze') {// 用量优化建议分析
                        if (request.method !== 'GET' && request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 优化账号 = String(url.searchParams.get('account') || '');
                        if (管理会话.accounts && (!优化账号 || !管理会话.accounts.includes(优化账号))) {
                            return new Response(JSON.stringify({ success: false, msg: '无权查看该账号' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        return 分析用量优化建议(env, url);
                    } else if (区分大小写访问路径 === 'admin/account-limits') {// 账号自定义配额
                        if (request.method !== 'POST') {
                            return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const body = await request.json().catch(() => null);
                        if (!body || typeof body !== 'object' || Array.isArray(body) || body.ID === undefined) {
                            return new Response(JSON.stringify({ success: false, msg: '请求体必须包含账号 ID' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        if (管理会话.accounts && !管理会话.accounts.includes(String(body.ID))) {
                            return new Response(JSON.stringify({ success: false, msg: '无权修改该账号' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        const 配置锁令牌 = await 尝试获取刷新锁(env);
                    const 配置锁获取时间 = 配置锁令牌 ? Date.now() : 0;
                        if (!配置锁令牌) {
                            return new Response(JSON.stringify({ success: false, msg: '系统正在刷新数据，请稍后重试' }), { status: 503, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        }
                        try {
                            const 原始配置 = await 读取账号配置(env);
                            const 配置列表 = Array.isArray(原始配置) ? 原始配置 : [];
                            const 索引 = 配置列表.findIndex(item => String(item.ID) === String(body.ID));
                            if (索引 === -1) {
                                return new Response(JSON.stringify({ success: false, msg: '未找到该账号' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                            }
                            const 限额 = 规范化账号限额输入(body.Limits);
                            if (Object.keys(限额).length > 0) 配置列表[索引].Limits = 限额;
                            else delete 配置列表[索引].Limits;
                            await 保存账号配置(env, 配置列表);
                            try {
                                await 更新请求数(env, { skipRefresh: true, skipLock: true, writeUsage: true });
                            } catch (重算错误) {
                                console.error('重算用量汇总失败:', 重算错误.message);
                            }
                            await 记录审计(env, 管理会话, 'account.limits', '账号 ' + String(body.ID) + ' 配额更新');
                            return new Response(JSON.stringify({ success: true, msg: '配额已更新', Limits: 限额 }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                        } finally {
                            await 释放刷新锁(env, 配置锁令牌, 配置锁获取时间);
                        }
                    }

                    return UsagePanel管理面板();
                } else return new Response(null, { status: 302, headers: { 'Location': '/' } });

            } else if (区分大小写访问路径.startsWith('api/')) {// API接口
                const 接口限流 = 内存限流检查(request, 'api');
                if (接口限流 > 0) return 限流响应(接口限流);
                if (区分大小写访问路径 === 'api/login') { // 管理员登录接口
                    if (request.method !== 'POST') {
                        return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                    }
                    const 登录标识 = String(request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown').slice(0, 64);
                    const 剩余锁定毫秒 = await 检查登录限速(env, 登录标识);
                    if (剩余锁定毫秒 > 0) {
                        const 等待秒数 = Math.ceil(剩余锁定毫秒 / 1000);
                        return new Response(JSON.stringify({ success: false, msg: `尝试次数过多，请 ${等待秒数} 秒后再试` }), {
                            status: 429,
                            headers: { 'Content-Type': 'application/json;charset=UTF-8', 'Retry-After': String(等待秒数) }
                        });
                    }
                    try {
                        const body = await request.json();
                        const 输入账号 = String(body?.username ?? '');
                        const 输入密码 = String(body?.password ?? '');
                        // 管理员优先，其次面板用户（PBKDF2），最后兼容环境变量只读用户
                        const 管理员密码记录 = await 读取管理员密码记录(env);
                        const 管理员账号正确 = await 恒定时间比较(输入账号, 面板管理员账号);
                        const 管理员密码正确 = 管理员密码记录
                            ? await 验证密码记录(输入密码, 管理员密码记录)
                            : await 恒定时间比较(输入密码, 面板管理员密码);
                        let 登录身份 = null;
                        if (管理员账号正确 && 管理员密码正确) {
                            登录身份 = { username: 面板管理员账号, role: 'admin', userId: 'env-admin', accounts: null };
                        }
                        if (!登录身份) {
                            for (const 面板用户 of await 读取面板用户(env)) {
                                if (面板用户.disabled === true) continue;
                                const 用户正确 = await 恒定时间比较(输入账号, String(面板用户.username || ''));
                                if (!用户正确) continue;
                                const 密码正确 = await 验证密码记录(输入密码, 面板用户);
                                if (密码正确) {
                                    登录身份 = {
                                        username: 面板用户.username,
                                        role: 面板用户.role === 'admin' ? 'admin' : 'viewer',
                                        userId: 面板用户.id || null,
                                        accounts: Array.isArray(面板用户.accounts) ? 面板用户.accounts.map(String) : null
                                    };
                                    break;
                                }
                            }
                        }
                        if (!登录身份) {
                            for (const 只读用户 of 解析只读用户(env)) {
                                const 用户正确 = await 恒定时间比较(输入账号, 只读用户.username);
                                if (!用户正确) continue;
                                const 密码正确 = await 恒定时间比较(输入密码, 只读用户.password);
                                if (密码正确) {
                                    登录身份 = {
                                        username: 只读用户.username,
                                        role: 'viewer',
                                        userId: null,
                                        accounts: Array.isArray(只读用户.accounts) ? 只读用户.accounts.map(String) : null
                                    };
                                    break;
                                }
                            }
                        }

                        if (!登录身份) {
                            await 记录登录失败(env, 登录标识);
                            return new Response(JSON.stringify({ success: false, msg: '账号或密码错误' }), {
                                status: 401,
                                headers: { 'Content-Type': 'application/json;charset=UTF-8' }
                            });
                        }

                        // 两步验证只对管理员生效，只读用户沿用密码登录
                        if (登录身份.role === 'admin') {
                            const 二步配置 = await 读取2FA配置(env);
                            if (二步配置.enabled) {
                                const 输入验证码 = String(body?.totp ?? '').replace(/\s/g, '');
                                let 验证步 = await TOTP验证(二步配置.secret, 输入验证码);
                                let 使用恢复码 = false;
                                if (!验证步) {
                                    const 恢复码 = 输入验证码.toUpperCase();
                                    if (/^[A-Z2-9]{4}-?[A-Z2-9]{4}$/.test(恢复码) && 二步配置.backupHashes.length > 0) {
                                        const 规范化恢复码 = 恢复码.includes('-') ? 恢复码 : 恢复码.slice(0, 4) + '-' + 恢复码.slice(4);
                                        const 恢复码哈希 = await SHA256十六进制(规范化恢复码);
                                        const 索引 = 二步配置.backupHashes.indexOf(恢复码哈希);
                                        if (索引 >= 0) {
                                            const 剩余恢复码 = 二步配置.backupHashes.slice();
                                            剩余恢复码.splice(索引, 1);
                                            await 保存2FA配置(env, { ...二步配置, backupHashes: 剩余恢复码 });
                                            使用恢复码 = true;
                                            登录身份.usedBackupCode = true;
                                        }
                                    }
                                }
                                if (!验证步 && !使用恢复码) {
                                    await 记录登录失败(env, 登录标识);
                                    return new Response(JSON.stringify({ success: false, need2fa: true, msg: '请输入正确的两步验证码或恢复码' }), { status: 401, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                                }
                                if (验证步) {
                                    if (验证步 <= Number(二步配置.lastStep || 0)) {
                                        await 记录登录失败(env, 登录标识);
                                        return new Response(JSON.stringify({ success: false, need2fa: true, msg: '验证码已使用，请等待下一个周期' }), { status: 401, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                                    }
                                    await 保存2FA配置(env, { ...二步配置, lastStep: 验证步 });
                                }
                            }
                        }

                        await 清除登录失败记录(env, 登录标识);
                        const 会话令牌 = 生成随机十六进制(32);
                        await env.KV.put('admin_session:' + 会话令牌, JSON.stringify({
                            username: 登录身份.username,
                            role: 登录身份.role,
                            userId: 登录身份.userId || null,
                            accounts: 登录身份.accounts || null,
                            ts: Date.now(),
                            ip: request.headers.get('CF-Connecting-IP') || '',
                            ua: String(request.headers.get('User-Agent') || '').slice(0, 160)
                        }), { expirationTtl: 86400 });
                        await 记录审计(env, 登录身份, 'login', 登录身份.usedBackupCode ? '登录成功（使用恢复码）' : '登录成功');
                        const 安全属性 = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
                        return new Response(JSON.stringify({ success: true, msg: '登录成功', role: 登录身份.role, username: 登录身份.username }), {
                            status: 200,
                            headers: {
                                'Content-Type': 'application/json;charset=UTF-8',
                                'Set-Cookie': `admin_token=${会话令牌}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400${安全属性}`
                            }
                        });
                    } catch (e) {
                        console.error('登录处理失败:', e.message);
                        return new Response(JSON.stringify({ success: false, msg: '登录处理失败，请稍后重试' }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json;charset=UTF-8' }
                        });
                    }
                }

                if (request.method !== 'POST' && 区分大小写访问路径 !== 'api/status') {
                    return new Response(JSON.stringify({ success: false, msg: 'Method Not Allowed' }), { status: 405, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                }
                if (!(await 验证管理员Cookie())) {
                    return new Response(JSON.stringify({ success: false, msg: '未登录或会话已过期，请重新登录' }), { status: 401, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                }

                const 接口会话 = 当前会话缓存 || await 获取会话();
                const 只读接口 = 接口会话?.role === 'viewer';
                if (只读接口 && request.method !== 'GET' && 区分大小写访问路径 !== 'api/logout' && 区分大小写访问路径 !== 'api/status') {
                    return new Response(JSON.stringify({ success: false, msg: '只读账号无权执行此操作' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                }

                if (区分大小写访问路径 === 'api/status') {// 当前登录状态（供前端判断会话）
                    return new Response(JSON.stringify({
                        success: true,
                        authenticated: true,
                        username: 接口会话?.username || 'admin',
                        role: 接口会话?.role === 'viewer' ? 'viewer' : 'admin'
                    }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
                }

                if (区分大小写访问路径 === 'api/logout') {// 登出接口
                    await 记录审计(env, 接口会话, 'logout', '退出登录');
                    const cookies = request.headers.get('Cookie') || '';
                    const 会话匹配 = cookies.match(/admin_token=([a-f0-9]{64})/);
                    if (会话匹配) {
                        try {
                            await env.KV.delete('admin_session:' + 会话匹配[1]);
                        } catch (error) {
                            console.error('删除管理员会话失败:', error.message);
                        }
                    }
                    const 安全属性 = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
                    return new Response(JSON.stringify({ success: true, msg: '登出成功' }), {
                        status: 200,
                        headers: {
                            'Content-Type': 'application/json;charset=UTF-8',
                            'Set-Cookie': `admin_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${安全属性}`
                        }
                    });
                } else if (区分大小写访问路径 === 'api/add' && !演示样板) {// 增加CF账号
                    const 配置锁令牌 = await 尝试获取刷新锁(env);
                    const 配置锁获取时间 = 配置锁令牌 ? Date.now() : 0;
                    if (!配置锁令牌) {
                        return new Response(JSON.stringify({ success: false, msg: '系统正在刷新数据，请稍后重试' }), { status: 503, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                    try {
                        const newConfig = await request.json().catch(() => null);
                        if (!newConfig || typeof newConfig !== 'object' || Array.isArray(newConfig)) {
                            return new Response(JSON.stringify({ success: false, msg: '请求体必须是 JSON 对象' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                        const 名称 = typeof newConfig.Name === 'string' ? newConfig.Name.trim() : '';
                        const 邮箱 = typeof newConfig.Email === 'string' ? newConfig.Email.trim() : '';
                        const 全局密钥 = typeof newConfig.GlobalAPIKey === 'string' ? newConfig.GlobalAPIKey.trim() : '';
                        const 账户ID = typeof newConfig.AccountID === 'string' ? newConfig.AccountID.trim() : '';
                        const 接口令牌 = typeof newConfig.APIToken === 'string' ? newConfig.APIToken.trim() : '';
                        const 限额 = 规范化账号限额输入(newConfig.Limits);

                        // 验证配置完整性：需要 (Email + GlobalAPIKey) 或 (AccountID + APIToken)
                        const hasEmailAuth = !!(邮箱 && 全局密钥);
                        const hasTokenAuth = !!(账户ID && 接口令牌);

                        if (!hasEmailAuth && !hasTokenAuth) {
                            return new Response(JSON.stringify({ success: false, msg: '配置不完整，需要提供 Email+GlobalAPIKey 或 AccountID+APIToken' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }

                        const now = Date.now();
                        const CF_JSON = {
                            ID: 0,
                            Name: 名称 || '未命名账号',
                            Email: hasEmailAuth ? 邮箱 : null,
                            GlobalAPIKey: hasEmailAuth ? 全局密钥 : null,
                            AccountID: 账户ID || null,
                            APIToken: hasTokenAuth ? 接口令牌 : null,
                            Limits: Object.keys(限额).length > 0 ? 限额 : undefined,
                            UpdateTime: now,
                            LastCheckTime: now,
                            Usage: 创建默认Usage(false)
                        };

                        // 验证 API 信息是否有效
                        const usage_result = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
                        if (!usage_result.success) {
                            return new Response(JSON.stringify({ success: false, msg: '无法验证该CF账号的API信息' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }

                        // Email 认证方式下把自动解析出的 AccountID 写回配置，减少后续查询并避免匹配到错误账号
                        if (!CF_JSON.AccountID && usage_result.resolvedAccountID) {
                            CF_JSON.AccountID = usage_result.resolvedAccountID;
                        }

                        应用账号限额(usage_result, CF_JSON);
                        CF_JSON.UpdateTime = Date.now();
                        CF_JSON.LastCheckTime = CF_JSON.UpdateTime;
                        CF_JSON.Usage = 补全账号Usage结构({ ...CF_JSON, Usage: usage_result });

                        // 读取现有配置
                        let usage_config_json = await 读取账号配置(env);
                        if (!Array.isArray(usage_config_json)) {
                            usage_config_json = [];
                        }

                        // 验证账号是否已存在 (通过 Email 或 AccountID 判断)
                        const existingIndex = usage_config_json.findIndex(item =>
                            (CF_JSON.Email && item.Email && String(item.Email).toLowerCase() === CF_JSON.Email.toLowerCase()) ||
                            (CF_JSON.AccountID && item.AccountID && String(item.AccountID) === CF_JSON.AccountID)
                        );

                        let 响应消息;
                        if (existingIndex !== -1) {
                            // 账号已存在，更新现有账号信息
                            const existingAccount = usage_config_json[existingIndex];
                            CF_JSON.ID = existingAccount.ID; // 保留原有 ID
                            usage_config_json[existingIndex] = CF_JSON;
                            await 保存账号配置(env, usage_config_json);
                            响应消息 = '账号已存在，已更新账号信息';
                        } else {
                            // 生成新 ID：现有最大 ID + 1，如果为空则从 1 开始
                            CF_JSON.ID = usage_config_json.length > 0
                                ? Math.max(...usage_config_json.map(item => Number(item.ID) || 0)) + 1
                                : 1;
                            usage_config_json.push(CF_JSON);
                            await 保存账号配置(env, usage_config_json);
                            响应消息 = '账号添加成功';
                        }

                        // 配置变化后立即重算汇总缓存，避免首页/公开接口继续展示旧数据
                        try {
                            await 更新请求数(env, { skipRefresh: true, skipLock: true, writeUsage: true });
                        } catch (重算错误) {
                            console.error('重算用量汇总失败:', 重算错误.message);
                        }

                        await 记录审计(env, 接口会话, 'account.add', 响应消息 + ': ' + String(CF_JSON.Name || CF_JSON.ID));
                        return new Response(JSON.stringify({ success: true, msg: 响应消息, data: { ID: CF_JSON.ID, Name: CF_JSON.Name } }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } catch (error) {
                        console.error('保存配置失败:', error);
                        return new Response(JSON.stringify({ success: false, msg: '保存配置失败，请查看 Worker 日志' }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } finally {
                        await 释放刷新锁(env, 配置锁令牌, 配置锁获取时间);
                    }

                } else if (区分大小写访问路径 === 'api/del' && !演示样板) {// 删除CF账号
                    const 配置锁令牌 = await 尝试获取刷新锁(env);
                    const 配置锁获取时间 = 配置锁令牌 ? Date.now() : 0;
                    if (!配置锁令牌) {
                        return new Response(JSON.stringify({ success: false, msg: '系统正在刷新数据，请稍后重试' }), { status: 503, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                    try {
                        const body = await request.json().catch(() => null);
                        const deleteId = body?.ID;

                        // 验证 ID 参数
                        if (deleteId === undefined || deleteId === null) {
                            return new Response(JSON.stringify({ success: false, msg: '请提供要删除的账号ID' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }

                        // 读取现有配置
                        let usage_config_json = await 读取账号配置(env);
                        if (!Array.isArray(usage_config_json) || usage_config_json.length === 0) {
                            return new Response(JSON.stringify({ success: false, msg: '配置列表为空，无法删除' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }

                        // 查找要删除的账号（兼容字符串/数字 ID）
                        const targetIndex = usage_config_json.findIndex(item => String(item.ID) === String(deleteId));
                        if (targetIndex === -1) {
                            return new Response(JSON.stringify({ success: false, msg: `未找到ID为 ${deleteId} 的账号` }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }

                        // 获取被删除账号的名称用于返回信息
                        const deletedName = usage_config_json[targetIndex].Name || '未命名账号';

                        // 删除该账号
                        usage_config_json.splice(targetIndex, 1);

                        // 保存回 KV
                        await 保存账号配置(env, usage_config_json);

                        // 配置变化后立即重算汇总缓存
                        try {
                            await 更新请求数(env, { skipRefresh: true, skipLock: true, writeUsage: true });
                        } catch (重算错误) {
                            console.error('重算用量汇总失败:', 重算错误.message);
                        }

                        await 记录审计(env, 接口会话, 'account.del', '删除账号 ' + String(deletedName));
                        return new Response(JSON.stringify({ success: true, msg: `账号 "${deletedName}" 已删除`, data: { ID: deleteId, Name: deletedName } }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } catch (error) {
                        console.error('删除账号失败:', error);
                        return new Response(JSON.stringify({ success: false, msg: '删除账号失败，请查看 Worker 日志' }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } finally {
                        await 释放刷新锁(env, 配置锁令牌, 配置锁获取时间);
                    }

                } else if (区分大小写访问路径 === 'api/check' && !演示样板) {// 检查单个CF账号请求量接口
                    try {
                        // 密钥不再通过 URL query 传递，避免进入浏览器历史/边缘日志
                        const body = await request.json().catch(() => ({}));
                        const Usage_JSON = await getCloudflareUsage(body?.Email, body?.GlobalAPIKey, body?.AccountID, body?.APIToken);
                        return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                    } catch (err) {
                        console.error('查询账号用量失败:', err.message);
                        return new Response(JSON.stringify({ msg: '查询请求量失败，请查看 Worker 日志' }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                } else if (演示样板) {
                    return new Response(JSON.stringify({ success: false, msg: '预览模式下，无法进行此操作' }), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                }
            } else if (访问路径 === 'robots.txt') {
                return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
            } else if (url.pathname === '/') {
                return UsagePanel主页();
            }

            return new Response('404 Not Found', { status: 404 });
        } else {
            return new Response('请先绑定一个KV命名空间到变量KV', { status: 500 });
        }
            })();
            return 应用安全头(响应, request);
        } catch (error) {
            console.error('请求处理失败:', error);
            let 是接口请求 = false;
            try {
                const 出错路径 = new URL(request.url).pathname;
                是接口请求 = 出错路径 === '/usage.json' || 出错路径.startsWith('/api/') || 出错路径.endsWith('.json');
            } catch (解析错误) {
                // 忽略 URL 解析异常
            }
            const 错误响应 = 是接口请求
                ? new Response(JSON.stringify({ success: false, msg: '服务器内部错误' }), { status: 500, headers: { 'Content-Type': 'application/json;charset=UTF-8' } })
                : new Response('服务器内部错误', { status: 500, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
            return 应用安全头(错误响应, request);
        }
    },
    async scheduled(event, env, ctx) {
        // 定时刷新 → 普通告警 → D1 预测告警 → 每日报告
        ctx.waitUntil((async () => {
            try {
                const 告警配置 = await 读取告警配置(env);
                const 渠道数 = 告警渠道数量(告警配置);
                const 普通告警预留 = 告警配置.enabled ? Math.min(6, 渠道数 * 3) : 0;

                // 只为“本轮可能真正发送”的预测/日报预留子请求，避免平时压缩刷新能力
                const 计划时间 = Number(event?.scheduledTime) || Date.now();
                const 当前UTC小时 = new Date(计划时间).getUTCHours();
                const 今天UTC = new Date(计划时间).toISOString().slice(0, 10);
                let 预测将触发 = false;
                if (告警配置.enabled && 告警配置.forecast?.enabled && 历史功能已启用(env)) {
                    try {
                        const 上次检查 = Number(await env.KV.get('forecast_last_check')) || 0;
                        预测将触发 = Date.now() - 上次检查 >= Math.max(15, Number(告警配置.forecast.checkMinutes) || 60) * 60000;
                    } catch (错误) {
                        console.error('读取预测检查状态失败:', 错误.message);
                    }
                }
                let 日报将触发 = false;
                if (告警配置.dailyReport?.enabled) {
                    try {
                        const 上次日报 = await env.KV.get('daily_report_day');
                        日报将触发 = 当前UTC小时 === Number(告警配置.dailyReport.hourUtc) && 上次日报 !== 今天UTC;
                    } catch (错误) {
                        console.error('读取日报状态失败:', 错误.message);
                    }
                }
                const 预测预留 = 预测将触发 ? Math.min(6, 渠道数 * 3) : 0;
                const 日报预留 = 日报将触发 ? Math.min(2, 渠道数) : 0;
                const 预留子请求 = Math.min(14, 普通告警预留 + 预测预留 + 日报预留);
                const usage_json = await 更新请求数(env, { reserveSubrequests: 预留子请求 });
                await 评估并发送告警(env, usage_json, 告警配置);
                await 评估预测告警(env, usage_json, 告警配置);
                await 评估每日报告(env, usage_json, 告警配置, event?.scheduledTime);
            } catch (error) {
                console.error('定时刷新/告警失败:', error.message);
            }
        })());
    }
};

/////////////////////////////////通用辅助函数//////////////////////////////////

const 登录失败内存表 = new Map();
const 登录失败上限 = 5;
const 登录失败窗口毫秒 = 15 * 60 * 1000;

function 解析布尔变量(value) {
    if (typeof value === 'boolean') return value;
    const 文本 = String(value ?? '').trim().toLowerCase();
    return ['1', 'true', 'yes', 'on'].includes(文本);
}

function 生成随机十六进制(字节数 = 16) {
    const 缓冲区 = new Uint8Array(Math.max(1, 字节数));
    crypto.getRandomValues(缓冲区);
    return Array.from(缓冲区).map(字节 => 字节.toString(16).padStart(2, '0')).join('');
}

async function 恒定时间比较(输入, 期望) {
    const 编码器 = new TextEncoder();
    const 输入字节 = 编码器.encode(String(输入 ?? ''));
    const 期望字节 = 编码器.encode(String(期望 ?? ''));
    if (输入字节.byteLength !== 期望字节.byteLength) return false;
    if (crypto.subtle.timingSafeEqual) {
        try {
            return crypto.subtle.timingSafeEqual(输入字节, 期望字节);
        } catch (error) {
            console.error('恒定时间比较失败:', error.message);
        }
    }
    let 差异 = 0;
    for (let i = 0; i < 输入字节.length; i++) 差异 |= 输入字节[i] ^ 期望字节[i];
    return 差异 === 0;
}

async function 检查登录限速(env, 标识) {
    const 现在 = Date.now();
    const 内存记录 = 登录失败内存表.get(标识);
    if (内存记录) {
        if (现在 - 内存记录.首次 >= 登录失败窗口毫秒) {
            登录失败内存表.delete(标识);
        } else if (内存记录.次数 >= 登录失败上限) {
            return 内存记录.首次 + 登录失败窗口毫秒 - 现在;
        }
    }
    try {
        const 存储记录 = await env.KV.get('login_fail:' + 标识, { type: 'json' });
        if (存储记录 && Number(存储记录.count) >= 登录失败上限 && 现在 < Number(存储记录.resetAt)) {
            return Number(存储记录.resetAt) - 现在;
        }
    } catch (error) {
        console.error('读取登录限速记录失败:', error.message);
    }
    return 0;
}

async function 记录登录失败(env, 标识) {
    const 现在 = Date.now();
    const 内存记录 = 登录失败内存表.get(标识);
    const 仍在上次窗口内 = 内存记录 && 现在 - 内存记录.首次 < 登录失败窗口毫秒;
    const 首次时间 = 仍在上次窗口内 ? 内存记录.首次 : 现在;
    const 次数 = 仍在上次窗口内 ? 内存记录.次数 + 1 : 1;
    登录失败内存表.set(标识, { 首次: 首次时间, 次数 });
    try {
        await env.KV.put('login_fail:' + 标识, JSON.stringify({ count: 次数, resetAt: 首次时间 + 登录失败窗口毫秒 }), { expirationTtl: 86400 });
    } catch (error) {
        console.error('写入登录限速记录失败:', error.message);
    }
}

async function 清除登录失败记录(env, 标识) {
    登录失败内存表.delete(标识);
    try {
        await env.KV.delete('login_fail:' + 标识);
    } catch (error) {
        console.error('清除登录限速记录失败:', error.message);
    }
}

// KV 没有原子 CAS，这里是"尽力而为"的互斥：用于收敛并发刷新，降低同一 key 的写入冲突。
async function 尝试获取刷新锁(env, ttl = 120) {
    const 键 = 'lock:refresh';
    try {
        if (await env.KV.get(键)) return null;
        const 令牌 = 生成随机十六进制(16);
        await env.KV.put(键, 令牌, { expirationTtl: ttl });
        return 令牌;
    } catch (error) {
        console.error('获取刷新锁失败:', error.message);
        return null;
    }
}

async function 释放刷新锁(env, 令牌, 获取时间 = 0) {
    if (!令牌) return;
    try {
        const 当前令牌 = await env.KV.get('lock:refresh');
        if (当前令牌 === 令牌) {
            // KV 对同一 key 限 1 次写/秒，put 后立刻 delete 可能触发 429；不足 1 秒时等待补齐
            const 已用毫秒 = 获取时间 ? Date.now() - 获取时间 : 0;
            if (获取时间 && 已用毫秒 < 1050) {
                await new Promise(resolve => setTimeout(resolve, 1050 - 已用毫秒));
            }
            await env.KV.delete('lock:refresh');
        }
    } catch (error) {
        console.error('释放刷新锁失败:', error.message);
    }
}

function 应用安全头(响应, request) {
    const 头 = new Headers(响应.headers);
    头.set('X-Content-Type-Options', 'nosniff');
    头.set('X-Frame-Options', 'DENY');
    头.set('Referrer-Policy', 'no-referrer');
    头.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (!头.has('Cache-Control')) 头.set('Cache-Control', 'no-store');
    try {
        if (request && new URL(request.url).protocol === 'https:') {
            头.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        }
    } catch (error) {
        // 忽略 URL 解析异常
    }
    return new Response(响应.body, { status: 响应.status, statusText: 响应.statusText, headers: 头 });
}

/////////////////////////////////账号密钥加密（AES-GCM）//////////////////////////////////

const 加密前缀 = 'enc:v1:';
let 加密密钥缓存 = { 原始: null, 密钥: null };

function 字节数组转Base64(bytes) {
    let binary = '';
    const view = new Uint8Array(bytes);
    for (let i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i]);
    return btoa(binary);
}

function Base64转字节数组(text) {
    const binary = atob(String(text || ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

async function 获取加密密钥(env) {
    const 原始 = env?.SECRET_KEY || env?.ENCRYPTION_KEY;
    if (!原始) return null;
    if (加密密钥缓存.原始 === 原始 && 加密密钥缓存.密钥) return 加密密钥缓存.密钥;
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(原始)));
    const key = await crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    加密密钥缓存 = { 原始, 密钥: key };
    return key;
}

async function 加密敏感值(env, 明文) {
    const 文本 = String(明文 == null ? '' : 明文);
    if (!文本 || 文本.startsWith(加密前缀)) return 文本;
    const key = await 获取加密密钥(env);
    if (!key) return 文本;
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(文本)));
    return 加密前缀 + 字节数组转Base64(iv) + ':' + 字节数组转Base64(ciphertext);
}

async function 解密敏感值(env, 密文) {
    const 文本 = String(密文 == null ? '' : 密文);
    if (!文本.startsWith(加密前缀)) return 文本;
    const key = await 获取加密密钥(env);
    if (!key) return '';
    try {
        const 部分 = 文本.slice(加密前缀.length).split(':');
        if (部分.length !== 2) return '';
        const iv = Base64转字节数组(部分[0]);
        const ciphertext = Base64转字节数组(部分[1]);
        const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
        return new TextDecoder().decode(plaintext);
    } catch (error) {
        console.error('解密账号密钥失败:', error.message);
        return '';
    }
}

async function 加密账号配置(env, account) {
    if (!account || typeof account !== 'object') return account;
    const 副本 = { ...account };
    if (typeof 副本.APIToken === 'string') 副本.APIToken = await 加密敏感值(env, 副本.APIToken);
    if (typeof 副本.GlobalAPIKey === 'string') 副本.GlobalAPIKey = await 加密敏感值(env, 副本.GlobalAPIKey);
    return 副本;
}

async function 解密账号配置(env, account) {
    if (!account || typeof account !== 'object') return account;
    const 副本 = { ...account };
    if (typeof 副本.APIToken === 'string') 副本.APIToken = await 解密敏感值(env, 副本.APIToken);
    if (typeof 副本.GlobalAPIKey === 'string') 副本.GlobalAPIKey = await 解密敏感值(env, 副本.GlobalAPIKey);
    return 副本;
}

async function 读取账号配置(env) {
    const 原始 = await env.KV.get('usage_config.json', { type: 'json' });
    if (!Array.isArray(原始)) return 原始;
    return Promise.all(原始.map(account => 解密账号配置(env, account)));
}

async function 保存账号配置(env, 配置列表) {
    const 原始 = Array.isArray(配置列表) ? 配置列表 : [];
    const 加密后 = await Promise.all(原始.map(account => 加密账号配置(env, account)));
    await env.KV.put('usage_config.json', JSON.stringify(加密后));
}

/////////////////////////////////加密配置备份/恢复//////////////////////////////////

async function 派生备份密钥(passphrase, saltBytes, iterations = 12000) {
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(passphrase)), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function 导出加密备份(env, passphrase) {
    const [账号配置, 告警配置] = await Promise.all([
        读取账号配置(env),
        读取告警配置(env)
    ]);
    const 数据 = {
        format: 'cf-usage-panel-backup',
        version: 1,
        exportedAt: new Date().toISOString(),
        accounts: Array.isArray(账号配置) ? 账号配置 : [],
        alertConfig: 告警配置
    };
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const iterations = 12000;
    const key = await 派生备份密钥(passphrase, salt, iterations);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(数据))));
    return {
        format: 'cf-usage-panel-backup',
        version: 1,
        kdf: 'PBKDF2-SHA256',
        iterations,
        salt: 字节数组转Base64(salt),
        iv: 字节数组转Base64(iv),
        data: 字节数组转Base64(ciphertext),
        exportedAt: 数据.exportedAt
    };
}

async function 导入加密备份(env, passphrase, backup) {
    if (!backup || backup.format !== 'cf-usage-panel-backup' || typeof backup.data !== 'string') {
        throw new Error('备份格式不正确');
    }
    const iterations = Math.min(200000, Math.max(1000, Number(backup.iterations) || 12000));
    const salt = Base64转字节数组(backup.salt);
    const iv = Base64转字节数组(backup.iv);
    const key = await 派生备份密钥(passphrase, salt, iterations);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, Base64转字节数组(backup.data));
    const 数据 = JSON.parse(new TextDecoder().decode(plaintext));
    if (!Array.isArray(数据.accounts)) throw new Error('备份中没有账号数据');
    await 保存账号配置(env, 数据.accounts);
    if (数据.alertConfig && typeof 数据.alertConfig === 'object') await 保存告警配置(env, 数据.alertConfig);
    return { accounts: 数据.accounts.length, hasAlertConfig: !!数据.alertConfig, exportedAt: 数据.exportedAt || null };
}

/////////////////////////////////只读用户 / 审计日志//////////////////////////////////

function 解析只读用户(env) {
    const 原始 = env?.VIEWER_USERS_JSON;
    if (!原始) return [];
    try {
        const 列表 = JSON.parse(原始);
        if (!Array.isArray(列表)) return [];
        return 列表
            .filter(item => item && typeof item.username === 'string' && typeof item.password === 'string')
            .map(item => ({
                username: item.username.trim(),
                password: item.password,
                accounts: Array.isArray(item.accounts) ? item.accounts.map(String) : null
            }))
            .filter(item => item.username && item.password);
    } catch (error) {
        console.error('VIEWER_USERS_JSON 解析失败:', error.message);
        return [];
    }
}

const 用户密码迭代次数 = 12000;

function 字节转十六进制(bytes) {
    return Array.from(new Uint8Array(bytes)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

function 十六进制转字节(十六进制) {
    const clean = String(十六进制 || '').replace(/[^0-9a-f]/gi, '');
    const out = new Uint8Array(Math.floor(clean.length / 2));
    for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function 生成盐() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return 字节转十六进制(bytes);
}

async function PBKDF2哈希(password, saltHex, iterations = 用户密码迭代次数) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: 十六进制转字节(saltHex), iterations, hash: 'SHA-256' }, key, 256);
    return 字节转十六进制(bits);
}

async function 创建密码记录(password) {
    const salt = 生成盐();
    return { passwordHash: await PBKDF2哈希(password, salt), salt, iterations: 用户密码迭代次数 };
}

async function 验证密码记录(password, record) {
    if (!record || typeof record.passwordHash !== 'string' || typeof record.salt !== 'string') return false;
    const iterations = Number(record.iterations) || 用户密码迭代次数;
    const hash = await PBKDF2哈希(password, record.salt, iterations);
    return 恒定时间比较(hash, record.passwordHash);
}

async function SHA256十六进制(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(text)));
    return 字节转十六进制(digest);
}

function 生成恢复码() {
    const 字母 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    let code = '';
    for (let i = 0; i < 8; i += 1) code += 字母[bytes[i] % 字母.length];
    return code.slice(0, 4) + '-' + code.slice(4);
}

async function 读取面板用户(env) {
    try {
        const 列表 = await env.KV.get('users.json', { type: 'json' });
        if (!Array.isArray(列表)) return [];
        return 列表.filter(user => user && typeof user === 'object' && typeof user.username === 'string');
    } catch (error) {
        console.error('读取面板用户失败:', error.message);
        return [];
    }
}

async function 保存面板用户(env, 列表) {
    await env.KV.put('users.json', JSON.stringify(Array.isArray(列表) ? 列表 : []));
}

function 脱敏面板用户(user) {
    return {
        id: user.id,
        username: user.username,
        role: user.role === 'admin' ? 'admin' : 'viewer',
        accounts: Array.isArray(user.accounts) ? user.accounts.map(String) : null,
        disabled: user.disabled === true,
        createdAt: user.createdAt || null,
        updatedAt: user.updatedAt || null
    };
}

async function 读取管理员密码记录(env) {
    try {
        const 记录 = await env.KV.get('admin_credentials.json', { type: 'json' });
        return 记录 && typeof 记录.passwordHash === 'string' ? 记录 : null;
    } catch (error) {
        return null;
    }
}

async function 记录审计(env, 会话, 动作, 详情 = '') {
    try {
        let 日志 = await env.KV.get('audit_log.json', { type: 'json' });
        if (!Array.isArray(日志)) 日志 = [];
        日志.unshift({
            time: new Date().toISOString(),
            user: String(会话?.username || 'unknown'),
            role: 会话?.role === 'viewer' ? 'viewer' : 'admin',
            action: String(动作 || ''),
            detail: String(详情 || '').slice(0, 300)
        });
        await env.KV.put('audit_log.json', JSON.stringify(日志.slice(0, 200)));
    } catch (error) {
        console.error('写入审计日志失败:', error.message);
    }
}

/////////////////////////////////只读 Token//////////////////////////////////

function 生成只读Token明文() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return 'cfp_' + 字节转十六进制(bytes);
}

async function 读取只读Token列表(env) {
    try {
        const 列表 = await env.KV.get('readonly_tokens.json', { type: 'json' });
        return Array.isArray(列表) ? 列表.filter(item => item && typeof item.tokenHash === 'string') : [];
    } catch (error) {
        console.error('读取只读 Token 失败:', error.message);
        return [];
    }
}

async function 保存只读Token列表(env, 列表) {
    await env.KV.put('readonly_tokens.json', JSON.stringify(Array.isArray(列表) ? 列表 : []));
}

function 脱敏只读Token(记录) {
    return {
        id: 记录.id,
        name: 记录.name,
        prefix: 记录.prefix,
        accounts: Array.isArray(记录.accounts) ? 记录.accounts.map(String) : null,
        createdAt: 记录.createdAt || null,
        expiresAt: 记录.expiresAt || null,
        createdBy: 记录.createdBy || null
    };
}

async function 验证只读Token(env, request) {
    let 明文 = '';
    const auth = request.headers.get('Authorization') || '';
    if (auth.startsWith('Bearer ')) 明文 = auth.slice(7).trim();
    if (!明文) {
        try {
            const url = new URL(request.url);
            明文 = String(url.searchParams.get('token') || '').trim();
        } catch (解析错误) {
            // ignore
        }
    }
    if (!明文 || !明文.startsWith('cfp_')) return null;
    const 哈希 = await SHA256十六进制(明文);
    const 列表 = await 读取只读Token列表(env);
    const 记录 = 列表.find(item => item.tokenHash === 哈希);
    if (!记录) return null;
    if (记录.expiresAt && Date.now() > Number(记录.expiresAt)) return null;
    return 记录;
}

function HTML转义(值) {
    return String(值 == null ? '' : 值).replace(/[&<>"']/g, 字符 => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[字符]);
}

function 渲染状态页(usage, 配置数量) {
    const 资源 = usage?.resources || {};
    const d1 = 资源.d1 || {};
    const kv = 资源.kv || {};
    const r2 = 资源.r2 || {};
    const 总数 = Number(usage?.total) || 0;
    const 上限 = Number(usage?.max) || 0;
    const 百分比 = 上限 > 0 ? Math.min(999, 总数 / 上限 * 100) : 0;
    const 行 = [
        ['Workers+Pages 请求', `${总数.toLocaleString()} / ${上限.toLocaleString()}`, 百分比],
        ['D1 读取', `${(Number(d1.rowsRead) || 0).toLocaleString()} / ${(Number(d1.rowsReadLimit) || 0).toLocaleString()}`, 配额百分比(d1.rowsRead, d1.rowsReadLimit)],
        ['D1 写入', `${(Number(d1.rowsWritten) || 0).toLocaleString()} / ${(Number(d1.rowsWrittenLimit) || 0).toLocaleString()}`, 配额百分比(d1.rowsWritten, d1.rowsWrittenLimit)],
        ['KV 读取', `${(Number(kv.reads) || 0).toLocaleString()} / ${(Number(kv.readsLimit) || 0).toLocaleString()}`, 配额百分比(kv.reads, kv.readsLimit)],
        ['KV 写入', `${(Number(kv.writes) || 0).toLocaleString()} / ${(Number(kv.writesLimit) || 0).toLocaleString()}`, 配额百分比(kv.writes, kv.writesLimit)],
        ['R2 Class A', `${(Number(r2.classA) || 0).toLocaleString()} / ${(Number(r2.classALimit) || 0).toLocaleString()}`, 配额百分比(r2.classA, r2.classALimit)],
        ['R2 Class B', `${(Number(r2.classB) || 0).toLocaleString()} / ${(Number(r2.classBLimit) || 0).toLocaleString()}`, 配额百分比(r2.classB, r2.classBLimit)]
    ];
    const 卡片 = 行.map(([名称, 文本, 百分比值]) => {
        const 颜色 = 百分比值 >= 100 ? '#ef4444' : 百分比值 >= 80 ? '#f59e0b' : '#22c55e';
        return `<div class="card"><div class="name">${HTML转义(名称)}</div><div class="value">${HTML转义(文本)}</div><div class="bar"><i style="width:${Math.min(100, 百分比值).toFixed(1)}%;background:${颜色}"></i></div><div class="pct">${百分比值.toFixed(1)}%</div></div>`;
    }).join('');
    const 更新时间 = usage?.UpdateTime ? new Date(usage.UpdateTime).toLocaleString() : '未知';
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="refresh" content="60"><title>Cloudflare 额度状态</title>
    <style>body{margin:0;padding:1.5rem;background:#0f172a;color:#e2e8f0;font-family:system-ui,-apple-system,sans-serif}.wrap{max-width:760px;margin:0 auto}.head{display:flex;justify-content:space-between;align-items:baseline;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}h1{font-size:1.25rem;margin:0}.meta{font-size:.75rem;color:#94a3b8}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem}.card{background:#1e293b;border:1px solid #334155;border-radius:14px;padding:.9rem}.name{font-size:.8rem;color:#94a3b8}.value{font-size:1rem;font-weight:600;margin:.3rem 0}.bar{height:6px;border-radius:999px;background:#334155;overflow:hidden}.bar i{display:block;height:100%}.pct{font-size:.7rem;color:#94a3b8;margin-top:.3rem;text-align:right}.foot{margin-top:1rem;font-size:.7rem;color:#64748b}</style></head><body><div class="wrap"><div class="head"><h1>Cloudflare 额度状态</h1><div class="meta">${配置数量} 个账号 · 更新于 ${HTML转义(更新时间)}</div></div><div class="grid">${卡片}</div><div class="foot">公开聚合状态页 · 每 60 秒自动刷新 · 不展示账号名、密钥或历史明细</div></div></body></html>`;
}

function 配额百分比(已用, 上限) {
    const 上限值 = Number(上限) || 0;
    if (上限值 <= 0) return 0;
    return Math.max(0, (Number(已用) || 0) / 上限值 * 100);
}

/////////////////////////////////TOTP 两步验证//////////////////////////////////

const Base32字母表 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function Base32编码(bytes) {
    let bits = 0;
    let value = 0;
    let out = '';
    for (const byte of bytes) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += Base32字母表[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += Base32字母表[(value << (5 - bits)) & 31];
    return out;
}

function Base32解码(text) {
    const clean = String(text || '').toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
    let bits = 0;
    let value = 0;
    const out = [];
    for (const ch of clean) {
        const index = Base32字母表.indexOf(ch);
        if (index < 0) continue;
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
            out.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return new Uint8Array(out);
}

function 生成TOTP密钥() {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    return Base32编码(bytes);
}

async function TOTP生成(secret, 时间步 = Math.floor(Date.now() / 30000)) {
    const keyBytes = Base32解码(secret);
    if (keyBytes.length === 0) return '';
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const counter = new ArrayBuffer(8);
    const view = new DataView(counter);
    view.setUint32(4, Number(时间步) >>> 0);
    const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter));
    const offset = signature[signature.length - 1] & 0x0f;
    const binary = ((signature[offset] & 0x7f) << 24) | (signature[offset + 1] << 16) | (signature[offset + 2] << 8) | signature[offset + 3];
    return String(binary % 1000000).padStart(6, '0');
}

async function TOTP验证(secret, code, 窗口 = 1) {
    const clean = String(code || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(clean)) return 0;
    const nowStep = Math.floor(Date.now() / 30000);
    for (let offset = -窗口; offset <= 窗口; offset += 1) {
        const step = nowStep + offset;
        if (step > 0 && await TOTP生成(secret, step) === clean) return step;
    }
    return 0;
}

function 生成OTPAuthURL(secret, accountName, issuer = 'CF Usage Panel') {
    const 标签 = encodeURIComponent(`${issuer}:${accountName || 'admin'}`);
    return `otpauth://totp/${标签}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&period=30&digits=6`;
}

async function 读取2FA配置(env) {
    try {
        const 原始 = await env.KV.get('admin_2fa.json', { type: 'json' });
        return {
            enabled: 原始?.enabled === true,
            secret: typeof 原始?.secret === 'string' ? 原始.secret : '',
            lastStep: Number(原始?.lastStep) || 0,
            enabledAt: Number(原始?.enabledAt) || 0,
            backupHashes: Array.isArray(原始?.backupHashes) ? 原始.backupHashes.filter(item => typeof item === 'string') : []
        };
    } catch (error) {
        console.error('读取 2FA 配置失败:', error.message);
        return { enabled: false, secret: '', lastStep: 0, enabledAt: 0, backupHashes: [] };
    }
}

async function 保存2FA配置(env, config) {
    await env.KV.put('admin_2fa.json', JSON.stringify(config));
}

/////////////////////////////////轻量限流（内存，零 KV 写）//////////////////////////////////

const 内存限流表 = new Map();
const 接口限流规则 = {
    'usage.json': { max: 60, windowMs: 60000 },
    'api': { max: 30, windowMs: 60000 },
    'admin': { max: 60, windowMs: 60000 }
};

function 内存限流检查(request, endpoint) {
    const 规则 = 接口限流规则[endpoint];
    if (!规则) return 0;
    const 标识 = String(request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown').slice(0, 64);
    const 键 = endpoint + ':' + 标识;
    const 现在 = Date.now();
    let 记录 = 内存限流表.get(键);
    if (!记录 || 现在 - 记录.开始 >= 规则.windowMs) {
        记录 = { 开始: 现在, 次数: 1 };
        内存限流表.set(键, 记录);
    } else {
        记录.次数 += 1;
    }
    if (内存限流表.size > 5000) {
        for (const [表键, 表记录] of 内存限流表) {
            if (现在 - 表记录.开始 >= 规则.windowMs * 2) 内存限流表.delete(表键);
        }
    }
    if (记录.次数 > 规则.max) {
        return Math.max(1, Math.ceil((记录.开始 + 规则.windowMs - 现在) / 1000));
    }
    return 0;
}

function 限流响应(等待秒数, 额外头 = null) {
    const 头 = { 'Content-Type': 'application/json;charset=UTF-8', 'Retry-After': String(等待秒数), ...(额外头 || {}) };
    return new Response(JSON.stringify({ success: false, msg: `请求过于频繁，请 ${等待秒数} 秒后再试` }), { status: 429, headers: 头 });
}

/////////////////////////////////多语言（中/英）//////////////////////////////////

// 由构建脚本写入完整词典；键为界面中文原文，值为英文
const 多语言字典 = {"，按当前速率预计仍有余量":", expected to stay within quota at the current rate","，按当前速率约":", about","，部分失败":", partially failed","，失败":", failed","，已超过额度":", quota already exceeded","，阈值":", threshold","；留空恢复默认免费额度。":"; leave blank to restore the default free quotas.","· 合计":"· Total","（":" (","）":")","（成功":" (successful:","（已发送":" (sent","（已截断）":"(truncated)","），绑定后刷新页面即可开始记录。":"), then refresh the page to start recording.","[CF Usage Panel] ⚠️ 用量告警":"[CF Usage Panel] ⚠️ Usage alert","[CF Usage Panel] 📈 用量预测告警":"[CF Usage Panel] 📈 Usage forecast alert","[CF Usage Panel] 📊 每日用量报告":"[CF Usage Panel] 📊 Daily usage report","[CF Usage Panel] 测试消息 ✅":"[CF Usage Panel] Test message ✅","告警渠道配置正常":"Alert channels are configured correctly","/月":"/mo","+ 超额":"+ overage","| 存储":"| storage","| 写入":"| written","⏳ 正在刷新数据...":"⏳ Refreshing data...","☁️ Cloudflare 额度统计":"☁️ Cloudflare usage stats","☁️ Cloudflare 账号管理":"☁️ Cloudflare account management","⚙️ 添加 Cloudflare 账号":"⚙️ Add Cloudflare account","⚙️ 账号配额设置":"⚙️ Account quota settings","⚠️ 部分账号查询异常（成功":"⚠️ Some accounts failed to refresh (successful:","⚠️ 部分账号的资源统计失败，显示用量可能偏低":"⚠️ Resource stats failed for some accounts; displayed usage may be lower than actual","⚠️ 部分资源统计失败，用量可能偏低":"⚠️ Some resource stats failed; usage may be lower than actual","⚠️ 读取用量缓存失败":"⚠️ Failed to load usage cache","⚠️ 请填写完整信息":"⚠️ Please fill in all fields","⚠️ 尚未添加任何Cloudflare账号":"⚠️ No Cloudflare account added yet","⚠️ 数据已超过 2 个刷新周期未更新":"⚠️ Data has not updated for more than 2 refresh cycles","⚠️ 数据已超过 2 个刷新周期未更新，请检查 cron 或手动刷新":"⚠️ Data has not updated for more than 2 refresh cycles; check cron or refresh manually","⚠️ 数据正在初始化，请稍后刷新":"⚠️ Data is initializing; refresh shortly","✅ 报告已开始下载":"✅ Report download started","✅ 测试消息已发送":"✅ Test message sent","✅ 成功更新免费额度使用数据":"✅ Free quota usage data updated","✅ 成功更新免费额度使用数据（本次刷新":"✅ Free quota usage data updated (this refresh:","✅ 成功加载免费额度使用数据":"✅ Free quota usage data loaded","✅ 告警设置已保存":"✅ Alert settings saved","✅ 日报已发送":"✅ Daily report sent","✅ 删除成功，正在更新数据...":"✅ Deleted; updating data...","✅ 数据已是最新（未到刷新间隔）":"✅ Data is up to date (refresh interval not reached)","✅ 数据已刷新":"✅ Data refreshed","✅ 添加成功，正在更新数据...":"✅ Added; updating data...","✅ 账号配额已更新":"✅ Account quota updated","✅ UsageAPI 已复制到粘贴板":"✅ UsageAPI copied to clipboard","❌ 导出失败，请刷新页面或重新登录":"❌ Export failed; refresh the page or sign in again","❌ 发送测试消息失败":"❌ Failed to send test message","❌ 发送日报失败":"❌ Failed to send daily report","❌ 复制失败，请手动复制":"❌ Copy failed; please copy manually","❌ 获取使用量失败:":"❌ Failed to fetch usage:","❌ 刷新失败":"❌ Refresh failed","❌ 网络错误":"❌ Network error","❌ 暂无用量数据":"❌ No usage data","❌ JSON 格式错误":"❌ Invalid JSON format","💰 费用估算":"💰 Cost estimate","📈 查看用量趋势（7 / 14 / 30 天）":"📈 View usage trend (7 / 14 / 30 days)","📈 历史趋势":"📈 History trend","📈 用量趋势":"📈 Usage trend","📊 用量排行榜":"📊 Usage leaderboard","📤 导出用量报告":"📤 Export usage report","🔐 管理员登录":"🔐 Admin login","🔔 用量告警":"🔔 Usage alerts","🕒 更新时间:":"🕒 Updated:","🧠 用量优化建议":"🧠 Usage optimization tips","14 天":"14 days","24 小时":"24 hours","30 天":"30 days","7 天":"7 days","按当前日用量 × 30 天线性外推（R2 操作按本月累计值）；实际账单以 Cloudflare 为准。":"Linear projection from current daily usage × 30 days (R2 operations use month-to-date totals); actual billing is determined by Cloudflare.","按当前速率约":"about","按每个账号独立 Workers Paid 估算":"Estimated with Workers Paid for each account separately","按最近趋势预计约":"Based on the recent trend, expected in about","绑定 D1（变量名 DB）后自动写入历史快照；未绑定时仅展示实时数据，可按需设置 HISTORY_ENABLED=false 关闭":"History snapshots are written automatically once D1 is bound (variable name DB); without D1 only live data is shown. Set HISTORY_ENABLED=false to disable.","包含\"阅读分析数据和日志\"权限的 API令牌":"API token with \"Read analytics data and logs\" permission","保存":"Save","保存设置":"Save settings","保存失败":"Save failed","保存配置失败，请查看 Worker 日志":"Failed to save configuration; check Worker logs","查询请求量失败，请查看 Worker 日志":"Failed to query request usage; check Worker logs","读取 Workers 脚本列表失败（HTTP":"Failed to read Workers script list (HTTP","优化分析失败:":"Optimization analysis failed:","本次刷新":"this refresh","本月":"this month","本月累计":"month-to-date","避免在请求路径中 List 全桶，必要时缓存列表结果或使用对象 key 直读。":"Avoid listing whole buckets in request paths; cache list results or read objects directly by key when needed.","部分失败":"partially failed","部分资源统计失败":"Some resource stats failed","测试消息已发送":"Test message sent","查询历史数据失败":"Failed to query history data","查询失败":"Query failed","查询失败:":"Query failed:","尝试次数过多，请":"Too many attempts; try again in","超额：":"Overage: ","成功":"successful","从未更新":"Never updated","存储":"Storage","大量 console 日志会占用日志额度并增加 CPU 开销。":"Heavy console logging consumes log quota and adds CPU overhead.","大体积脚本会增加部署、冷启动和内存压力，免费 Worker 还有体积上限。":"Large bundles increase deployment, cold-start and memory pressure, and free Workers have a size limit.","单脚本内容超过 2 MB，已跳过逐行分析以避免占用过多资源。":"Script content exceeds 2 MB; line-by-line analysis was skipped to avoid excessive resource use.","当前":"Current","当前 API Token 缺少 Workers Scripts:Read 权限，无法读取脚本内容；可继续参考通用建议。":"The current API token lacks the Workers Scripts:Read permission, so script contents cannot be read; general tips still apply.","当前:":"Current:","导出报告":"Export report","导出格式":"Export format","导出内容不包含 API Key / Bot Token / Webhook URL 等敏感信息；历史数据来自 D1，未绑定 D1 时使用 KV 每日快照。":"Exports exclude sensitive data such as API keys, bot tokens and webhook URLs. History comes from D1; without D1, daily KV snapshots are used.","的账号":"","登 录":"Sign in","登出成功":"Signed out","登录成功":"Signed in","登录处理失败，请稍后重试":"Login failed; try again later","登录失败":"Sign-in failed","登录中...":"Signing in...","钉钉机器人":"DingTalk bot","定期清理 D1/KV/R2 存储":"Clean up D1/KV/R2 storage regularly","动态执行代码会带来安全风险和额外 CPU 开销，也不利于缓存。":"Dynamic code execution adds security risk and CPU overhead, and hurts caching.","读取（今日）":"Reads (today)","对非关键后台写入使用 ctx.waitUntil(...) 包裹。":"Wrap non-critical background writes with ctx.waitUntil(...).","对可缓存的 GET 响应使用 Cache API：match → 未命中再 fetch → waitUntil(put)。":"Use the Cache API for cacheable GET responses: match → fetch on miss → waitUntil(put).","对可缓存的 GET 响应使用 caches.default.match/put，并在响应上设置合理 Cache-Control。":"Use caches.default.match/put for cacheable GET responses and set a sensible Cache-Control header.","发送测试消息":"Send test message","发送日报测试":"Send daily report test","发送失败":"Send failed","范围:":"Scope:","飞书机器人":"Feishu bot","费用为每个账号升级 Workers Paid（$5/月/账号）后的估算，含基础订阅费；不含 CPU 时间、日志、队列、Durable Objects 等其他计费项。":"Costs assume each account upgrades to Workers Paid ($5/mo/account) and include the base subscription; CPU time, logs, queues, Durable Objects and other charges are excluded.","分析失败":"Analysis failed","分析失败，请刷新页面或重新登录":"Analysis failed; refresh the page or sign in again","分析中，可能需要几秒...":"Analyzing, this may take a few seconds...","峰值":"Peak","服务器内部错误":"Internal server error","复制 UsageAPI":"Copy UsageAPI","复制失败":"Copy failed","改用 Cron Triggers、Durable Objects Alarms 或 Queues 做定时/后台任务。":"Use Cron Triggers, Durable Objects Alarms or Queues for scheduled/background work.","改用 Promise.all 控制并发（注意免费计划 6 个并发连接限制）。":"Use Promise.all to bound concurrency (note the free plan's 6 concurrent connection limit).","告警设置已保存":"Alert settings saved","个":"","个 Worker，分析":"Workers, analyzed","个，":", ","个，部分失败":", partially failed","个，失败":", failed","个（本次刷新":"(this refresh:","个存储桶":"buckets","个命名空间":"namespaces","个使用历史数据":"using cached data","个使用历史数据）":"using cached data)","个数据点 ·":"data points ·","个数据库":"databases","个账号":"accounts","个账号，":"accounts, ","个账号的部分资源统计失败，显示用量可能偏低":"accounts had partial resource stats failures; displayed usage may be lower than actual","各账号用量明细":"Usage details by account","更新时间:":"Updated:","估算月费":"Est. monthly cost","关闭":"Close","管理员登录":"Admin login","合并 API 调用、使用 Promise.all 限制并发，并做超时与失败降级。":"Combine API calls, bound concurrency with Promise.all, and add timeouts and failure fallbacks.","合计":"Total","缓存 list 结果、改为按已知 key 直读，或用 D1 维护索引。":"Cache list results, read directly by known keys instead, or maintain an index in D1.","汇总":"Summary","会话已过期，请重新登录":"Session expired; sign in again","基础":"Base","加载费用估算失败，请刷新页面或重新登录":"Failed to load cost estimate; refresh the page or sign in again","加载告警配置失败，请刷新页面或重新登录":"Failed to load alert settings; refresh the page or sign in again","加载汇总数据失败，请刷新页面或重新登录":"Failed to load summary data; refresh the page or sign in again","加载历史趋势失败，请刷新页面或重新登录":"Failed to load history trend; refresh the page or sign in again","加载历史失败":"Failed to load history","加载失败":"Load failed","加载详情数据失败，请刷新页面或重新登录":"Failed to load details; refresh the page or sign in again","减少 R2 Class A 操作":"Reduce R2 Class A operations","减少不必要的 KV 读取":"Avoid unnecessary KV reads","减少不必要的 Put/List，合并写入，列表结果做缓存。":"Avoid unnecessary Put/List calls, batch writes and cache list results.","检测到 list 操作":"List operations detected","将静态资源、图片和大段 JSON 移到 Workers Static Assets 或 R2，用构建工具压缩代码。":"Move static assets, images and large JSON blobs to Workers Static Assets or R2, and minify with build tools.","脚本:":"Script:","脚本内容过大，跳过深度分析":"Script too large; deep analysis skipped","脚本体积偏大（超过 1.2 MB）":"Script bundle is large (over 1.2 MB)","脚本中存在 fetch 调用但没有使用 caches.default / caches.open，重复请求会反复回源。":"The script calls fetch without caches.default / caches.open, so repeated requests keep going back to origin.","今日":"Today","仅管理员手动触发；默认最多分析 6 个脚本（可用环境变量 OPTIMIZE_MAX_SCRIPTS 调整，最大 20）。需要 API Token 具备 Workers Scripts:Read 权限；分析过程不写 KV/D1。":"Triggered only by an admin. By default up to 6 scripts are analyzed (tunable via OPTIMIZE_MAX_SCRIPTS, max 20). The API token needs Workers Scripts:Read; analysis writes nothing to KV/D1.","开始分析":"Start analysis","可通过环境变量 PRICING_JSON 覆盖默认单价。":"Default unit prices can be overridden with the PRICING_JSON environment variable.","控制 KV 写入频率":"Throttle KV writes","控制单次请求的外部子请求数":"Limit external subrequests per request","冷却时间（分钟）":"Cooldown (minutes)","历史功能已通过 HISTORY_ENABLED=false 关闭":"History is disabled via HISTORY_ENABLED=false","没有成功发送的渠道，请检查告警配置":"No channel sent successfully; check alert settings","免费 KV 写额度约 1000/天；本 Worker 已按“到期才刷新、变化才写回”控制写放大，默认刷新间隔不低于 10 分钟；付费用户可设 FREE_TIER_GUARD=false":"Free KV writes are limited to about 1,000/day. This Worker already limits write amplification by refreshing only when due and writing back only on change, with a default refresh interval of at least 10 minutes. Paid users can set FREE_TIER_GUARD=false.","免费额度未计入套餐包含量；超出 Workers Paid 包含量才产生超额费用。":"Free tiers are not counted toward plan allowances; overage charges apply only beyond the Workers Paid included usage.","免费计划每个请求最多 50 个子请求，过多并发/串行外部请求容易超限。":"The free plan allows at most 50 subrequests per request; too many concurrent or sequential external calls can exceed it.","秒后再试":"seconds","您的 Cloudflare 账号邮箱":"Your Cloudflare account email","您的 Global API Key":"Your Global API Key","排名":"Rank","排行榜":"Leaderboard","配额":"Quota","配额已更新":"Quota updated","配置不完整，需要提供 Email+GlobalAPIKey 或 AccountID+APIToken":"Incomplete configuration: provide Email+GlobalAPIKey or AccountID+APIToken","配置列表为空，无法删除":"Account list is empty; nothing to delete","普通告警在 cron 和管理员手动刷新后评估；预测告警/每日报告只在 cron 中评估（预测需要 D1 历史，日报按 UTC 整点发送一次）。阈值填 0 表示不检查该项。":"Regular alerts are evaluated by cron and after an admin refresh; forecast alerts and the daily report are evaluated only by cron (forecasts need D1 history, the daily report is sent once per UTC hour tick). Set a threshold to 0 to skip that check.","企业微信群机器人":"WeCom group bot","启用 D1 预测告警（需绑定 D1）":"Enable D1 forecast alerts (requires D1)","启用 Telegram":"Enable Telegram","启用 Webhook":"Enable Webhook","启用每日用量报告":"Enable daily usage report","启用用量告警":"Enable usage alerts","强力驱动":"","切换显示模式":"Toggle display mode","切换语言":"Switch language","请求":"Requests","请求/月":"Requests/mo","请求次数":"Requests","请求过于频繁，请":"Too many requests; try again in","请求使用情况:":"Request usage:","请求体必须包含账号 ID":"Request body must include an account ID","请求体必须是 JSON 对象":"Request body must be a JSON object","请输入管理员密码":"Enter admin password","请输入管理员账号":"Enter admin username","请输入密码":"Please enter the password","请提供要删除的账号ID":"Provide the account ID to delete","请先绑定一个KV命名空间到变量KV":"Bind a KV namespace to the KV variable first","请先添加账号":"Add an account first","请先在变量中设置 PASSWORD 变量":"Set the PASSWORD variable first","趋势":"Trend","取消":"Cancel","缺少 Cache API 缓存":"No Cache API caching","确定要删除这个账号吗？":"Delete this account?","日报发送时间（UTC 小时）":"Daily report time (UTC hour)","日报已发送":"Daily report sent","日均请求":"Avg. daily requests","日期,Workers,Pages,合计,D1读取,D1写入,KV读取,KV写入,R2 ClassA,R2 ClassB":"Date,Workers,Pages,Total,D1 reads,D1 writes,KV reads,KV writes,R2 ClassA,R2 ClassB","日志调用较多":"Many logging calls","若全部升级 Workers Paid":"If all upgrade to Workers Paid","删除/列表（今日）":"Deletes/lists (today)","删除失败":"Delete failed","删除账号":"Delete account","删除账号失败，请查看 Worker 日志":"Failed to delete account; check Worker logs","尚未配置任何 Cloudflare 账号":"No Cloudflare account configured yet","设置保留期与清理任务，R2 配置生命周期规则，D1 定期 DELETE 过期行。":"Set retention periods and cleanup jobs, configure lifecycle rules for R2 and periodically DELETE expired rows from D1.","生产环境降低日志级别，只保留关键错误。":"Lower the log level in production and keep only critical errors.","失败:":" failed:","时间:":"Time:","使用 AbortSignal.timeout(...) 或自定义 AbortController 设置超时，并做失败降级。":"Use AbortSignal.timeout(...) or a custom AbortController to enforce timeouts, with failure fallbacks.","使用 eval / new Function":"Uses eval / new Function","使用 setInterval/setTimeout":"Uses setInterval/setTimeout","使用历史数据）":"using cached data)","数据点":"data points","数据点 ·":"data points ·","数据获取失败":"Failed to load data","数据接口请求失败（":"Data API request failed (","数据暂不可用":"Data temporarily unavailable","刷新估算":"Refresh estimate","刷新数据":"Refresh data","所有账号合计":"Total for all accounts","添加":"Add","添加失败":"Add failed","添加账号":"Add account","条告警":"alerts","条告警）":"alerts)","通用 JSON（自接 n8n/自建）":"Generic JSON (n8n / custom)","通用 Webhook":"Generic Webhook","通用优化建议":"General optimization tips","统计天数":"Statistics range (days)","退出管理面板":"Exit admin panel","外部 fetch 未设置超时":"External fetch has no timeout","外部请求挂起会拖长整个 Worker 请求，影响可用性。":"Hanging external requests lengthen the whole Worker request and hurt availability.","网络错误，请重试":"Network error, please retry","为高频请求启用 Cache API":"Enable Cache API for high-frequency requests","未登录或会话已过期":"Not signed in or session expired","未登录或会话已过期，请重新登录":"Not signed in or session expired; sign in again","未发现明显问题，可参考下方通用建议。":"No obvious issues found; see the general tips below.","未命名脚本":"Unnamed script","未命名账号":"Unnamed account","未启用 Telegram/Webhook 渠道":"No Telegram/Webhook channel enabled","未启用历史趋势：请在 Cloudflare Dashboard 给该 Worker 添加 D1 绑定（变量名建议":"History is not enabled: add a D1 binding to this Worker in the Cloudflare Dashboard (suggested variable name","未找到该账号":"Account not found","未找到账户":"Account not found","未找到账户数据":"No account data found","未找到指定账号":"Specified account not found","未找到ID为":"No account found with ID","未知":"Unknown","未知错误":"Unknown error","我的账号":"My account","无法验证该CF账号的API信息":"Unable to verify the API credentials for this Cloudflare account","无法自动匹配 Cloudflare 账号，请在账号配置中填写 AccountID":"Could not match a Cloudflare account automatically; enter the AccountID in the account settings","系统正在刷新数据，请稍后重试":"Data is being refreshed; try again later","下载":"Download","响应返回后的异步写入如果没有 waitUntil，可能在请求结束后被取消。":"Async writes after the response is returned may be cancelled once the request ends unless wrapped in waitUntil.","小时后达到额度":"hours to reach the quota","小时后达到阈值":"hours to reach the threshold","写操作可能未使用 ctx.waitUntil":"Writes may not use ctx.waitUntil","写入（今日）":"Writes (today)","选择账号":"Select account","选择账号后点击「开始分析」":"Select an account and click \"Start analysis\"","循环中串行 await":"Sequential await in a loop","验证方式":"Verification method","移除动态执行逻辑，改为静态分支或配置驱动。":"Remove dynamic execution and use static branches or configuration instead.","已发送":"sent","已配置，留空保持不变":"Configured; leave blank to keep unchanged","已删除":"deleted","优化建议":"Optimization tips","优先拆分/压缩脚本，或改用静态资源托管。":"Split/minify the script first, or host static assets separately.","由":"Powered by","预测告警 / 每日报告":"Forecast alerts / daily report","预测检查间隔（分钟）":"Forecast check interval (minutes)","预测提前量（小时）":"Forecast lead time (hours)","预览模式下，无法进行此操作":"This action is unavailable in preview mode","阈值:":"Threshold:","在 isolate 内做短 TTL 缓存，或把不常变化的配置放到 env/静态资源。":"Add short-TTL caches inside the isolate, or move rarely changing config to env/static assets.","在 isolate 内做短期缓存、合并重复读取，或把高频配置放到环境变量/静态资源。":"Add short-lived caches inside the isolate, merge duplicate reads, or move hot config to environment variables/static assets.","在循环里逐个 await 会显著拉长请求耗时并增加超时风险。":"Awaiting items one by one in a loop significantly lengthens request time and increases timeout risk.","暂无额度信息":"No quota information","暂无历史数据：绑定 D1 或等待每日快照":"No history yet: bind D1 or wait for the daily snapshot","暂无历史数据：等待下一次 cron/手动刷新后开始记录（每次刷新一个快照点）。":"No history yet; recording starts after the next cron run or manual refresh (one snapshot per refresh).","暂无每日历史：绑定 D1 可记录更细粒度趋势":"No daily history yet; bind D1 to record finer-grained trends","暂无数据":"No data","暂无账号":"No accounts","暂无账号，请点击上方按钮添加":"No accounts. Click the button above to add one.","暂无账号数据":"No account data","暂无账号用量数据":"No account usage data","账号":"Account","账号:":"Accounts:","账号「":"Account \"","账号备注":"Account label","账号或密码错误":"Incorrect username or password","账号列表格式不正确":"Invalid account list format","账号请求 Top:":"Top accounts by requests:","账号数量":"Accounts","账号添加成功":"Account added","账号已存在，已更新账号信息":"Account already exists; info updated","账户获取失败:":"Account fetch failed:","正在获取数据...":"Loading data...","只在数据变化时写入，合并批量更新，避免在每次请求路径中写 KV。":"Write only when data changes, batch updates and avoid KV writes in every request path.","指标:":"Metric:","重复请求直接回源会消耗 Worker 请求、CPU 和外部子请求额度。":"Serving repeated requests from origin consumes Worker requests, CPU and external subrequest quota.","重新加载":"Reload","资源额度细节":"Resource quota details","总计请求":"total requests","总配额":"Total quota","总请求":"Total requests","总请求:":"Total requests:","总请求阈值 %":"Total requests threshold %","总请求占比":"Share of total requests","最后更新:":"Last updated:","Class A（本月）":"Class A (this month)","Class B（本月）":"Class B (this month)","Cloudflare 额度汇总":"Cloudflare quota summary","Cloudflare 额度使用统计":"Cloudflare quota usage stats","CSV（按天历史，Excel 可直接打开）":"CSV (daily history, opens directly in Excel)","D1 存储":"D1 storage","D1 存储阈值 %":"D1 storage threshold %","D1 读取":"D1 reads","D1 读取行数":"D1 rows read","D1 读取阈值 %":"D1 reads threshold %","D1 历史":"D1 history","D1 写/月":"D1 writes/mo","D1 写入":"D1 writes","D1 写入行数":"D1 rows written","D1 写入阈值 %":"D1 writes threshold %","D1 行操作":"D1 row operations","D1: 读取":"D1: read","D1/KV 按 UTC 自然日统计，R2 操作按本月统计；存储为最近一次指标快照。":"D1/KV are counted per UTC calendar day and R2 operations per month; storage reflects the latest metric snapshot.","ℹ️ 数据正在刷新，本次返回缓存数据":"ℹ️ Data is refreshing; cached data returned this time","JSON 对象，可设置：":"JSON object. Available fields: ","JSON（含账号汇总 + 历史）":"JSON (account summary + history)","KV 存储":"KV storage","KV 存储阈值 %":"KV storage threshold %","KV 读取":"KV reads","KV 读取未配合缓存":"KV reads without caching","KV 读取阈值 %":"KV reads threshold %","KV 读写":"KV read/write","KV 每日快照":"KV daily snapshot","KV 免费额度仅 1000 写/天，同一 key 还有 1 次/秒限制。":"The free KV tier allows only 1,000 writes/day, and each key is limited to 1 write/second.","KV 免费额度为 10 万读/天，热点路径上的 KV get 很容易放大。":"The free KV tier allows 100,000 reads/day; KV gets on hot paths add up quickly.","KV 轻量历史仅记录汇总数据，单账号趋势请绑定 D1":"The lightweight KV history stores summary data only; bind D1 for per-account trends","KV 写/月":"KV writes/mo","KV 写入":"KV writes","KV 写入阈值 %":"KV writes threshold %","KV get 在热点路径中会消耗每日读额度，免费用户尤其明显。":"KV get on hot paths consumes the daily read quota, especially on the free plan.","KV list 与 R2 ListObjects 都属于高成本操作，频繁调用会快速消耗额度。":"KV list and R2 ListObjects are costly operations; frequent calls drain quota quickly.","KV: 读取":"KV: read","KV/D1/R2 的免费存储分别是 1GB/5GB/10GB，历史数据无限增长会逐渐逼近上限。":"Free storage for KV/D1/R2 is 1GB/5GB/10GB respectively; unbounded historical data will gradually approach these limits.","ListObjects/ListParts/PutObject 等 Class A 操作用量更大，免费 100 万/月。":"Class A operations such as ListObjects/ListParts/PutObject are more expensive, with a free allowance of 1 million/month.","Pages 请求":"Pages requests","R2 操作可能偏多":"R2 operations may be excessive","R2 存储":"R2 storage","R2 存储阈值 %":"R2 storage threshold %","R2 请求":"R2 requests","R2 A/月":"R2 A/mo","R2 Class A 操作":"R2 Class A operations","R2 Class A 阈值 %":"R2 Class A threshold %","R2 Class B 操作":"R2 Class B operations","R2 Class B 阈值 %":"R2 Class B threshold %","R2 PutObject/ListObjects 属于 Class A 操作，免费额度 100 万/月。":"R2 PutObject/ListObjects are Class A operations with a free allowance of 1 million/month.","Telegram Bot API（URL 直连）":"Telegram Bot API (direct URL)","UsagePanel 管理面板":"UsagePanel Admin","Webhook 平台":"Webhook platform","Worker 请求结束后定时器不一定继续执行，不能依赖它做后台任务。":"Timers may not keep running after a Worker request ends, so do not rely on them for background work.","Workers 请求":"Workers requests","Workers+Pages 请求":"Workers+Pages requests","Workers和Pages 面板右侧的 AccountID":"Account ID on the right of the Workers & Pages dashboard","费用估算":"Cost estimate","超额":"Overage","两步验证":"Two-step verification","生成密钥并启用":"Generate key and enable","当前验证码":"Current verification code","关闭两步验证":"Disable two-step verification","未启用。启用后登录需要额外输入验证器验证码。":"Not enabled. Once enabled, signing in requires a code from your authenticator app.","启用时间：":"Enabled at:","1. 在验证器 App 中添加以下密钥：":"1. Add the following secret to your authenticator app:","或导入：":"Or import:","输入 6 位验证码":"Enter the 6-digit code","验证并启用":"Verify and enable","两步验证已启用":"Two-step verification enabled","两步验证已关闭":"Two-step verification disabled","请输入正确的两步验证码":"Please enter a valid two-step verification code","验证码已使用，请等待下一个周期":"This code has already been used. Wait for the next period.","两步验证已启用，请先关闭":"Two-step verification is already enabled. Disable it first.","设置已过期，请重新生成密钥":"Setup expired. Generate a new key.","验证码错误":"Invalid code","验证码错误或已使用":"Invalid or already used code","两步验证未启用":"Two-step verification is not enabled","生成验证密钥失败":"Failed to generate verification key","仅管理员可查看审计日志":"Only administrators can view audit logs","审计日志":"Audit log","最近":"Recent","条（最多保留 200 条）":"entries (up to 200 retained)","暂无审计记录":"No audit records yet","审计日志仅管理员可查看":"Audit logs are visible to administrators only","只读账号：可以查看数据，但无法修改配置或执行写操作。":"Read-only account: you can view data but cannot change settings or perform write operations.","只读账号（":"Read-only account (","）：可以查看数据，但无法修改配置或执行写操作。":")：you can view data but cannot change settings or perform write operations.","只读账号无权执行此操作":"Read-only accounts cannot perform this action","只读账号无权强制刷新":"Read-only accounts cannot force refresh","Top 脚本":"Top scripts","Top 脚本与错误率":"Top scripts & error rate","时间范围":"Time range","查询":"Query","查询中...":"Querying...","脚本":"Script","请求数":"Requests","错误数":"Errors","错误率":"Error rate","该时间范围内没有脚本调用数据":"No script invocation data in this time range","按 Workers 脚本聚合请求数与错误数，最多显示 Top 10。需要 API Token 具备 Workers 分析数据读取权限；单次查询消耗 1 个子请求。":"Aggregates requests and errors by Worker script, showing the top 10. Requires an API Token with Workers analytics read permission; one subrequest per query.","错误":"Errors","查询失败，请刷新页面或重新登录":"Query failed. Refresh the page or sign in again.","Top 脚本查询失败":"Top scripts query failed","用量告警":"Usage alerts","历史趋势":"History trend","查看用量趋势（7 / 14 / 30 天）":"View usage trend (7 / 14 / 30 days)","用量趋势":"Usage trend","最后更新":"Last updated","数据已超过 2 个刷新周期未更新":"Data has not updated for more than 2 refresh cycles","部分账号的资源统计失败，显示用量可能偏低":"Some accounts failed resource stats; displayed usage may be lower","部分账号查询异常":"Some account queries abnormal","历史来源":"History source","导出时间":"Exported at","账号数":"Accounts","总用量":"Total usage","账号列表":"Accounts","告警配置":"Alert config","冷却分钟":"Cooldown (min)","阈值":"Thresholds","预测":"Forecast","每日报告":"Daily report","渠道":"Channels","用量排行榜":"Usage leaderboard","导出用量报告":"Export usage report","报告已开始下载":"Report download started","导出失败，请刷新页面或重新登录":"Export failed. Refresh the page or sign in again.","刷新":"Refresh","生成失败":"Generation failed","启用失败":"Enable failed","关闭失败":"Disable failed","万":"×10K","亿":"×100M","2-32 位字母、数字、下划线、点或短横线":"2–32 letters, numbers, underscores, dots or hyphens","至少 8 位；编辑时留空表示不修改":"At least 8 characters; leave blank when editing to keep unchanged","例如 Grafana / 状态页":"e.g. Grafana / status page","🔑 只读 Token":"🔑 Read-only tokens","👥 用户与权限":"👥 Users & permissions","💾 备份与恢复":"💾 Backup & restore","📜 告警历史":"📜 Alert history","📉 异常检测":"📉 Anomaly detection","修改管理员密码":"Change admin password","加载中...":"Loading...","导出加密备份":"Export encrypted backup","至少 8 位":"At least 8 characters","确认新密码":"Confirm new password","新增用户":"Add user","登录会话":"Login sessions","导入备份":"Import backup","只读用户":"Read-only user","确认修改":"Confirm change","用户名":"Username","管理员":"Administrator","新密码":"New password","清空":"Clear","检测":"Detect","名称":"Name","生成":"Generate","密码":"Password","角色":"Role"};

function 生成语言脚本() {
    const 字典JSON = JSON.stringify(多语言字典).replace(/</g, '\\u003c');
    const 代码 = [
        'const __语言字典 = ' + 字典JSON + ';',
        'const __字典键 = Object.keys(__语言字典).sort(function (a, b) { return b.length - a.length; });',
        'let __当前语言 = (function () { try { var saved = localStorage.getItem("lang"); if (saved === "en" || saved === "zh") return saved; } catch (e) {} return "zh"; })();',
        'const __文本原文 = new WeakMap();',
        'const __属性原文 = new WeakMap();',
        'function __含中文(文本) { return /[\\u4e00-\\u9fff]/.test(String(文本 == null ? "" : 文本)); }',
        'function __翻译文本(原文, 语言) {',
        '    var 文本 = String(原文 == null ? "" : 原文);',
        '    if (语言 !== "en") return 文本;',
        '    for (var i = 0; i < __字典键.length; i++) { var 键 = __字典键[i]; if (文本.indexOf(键) >= 0) 文本 = 文本.split(键).join(__语言字典[键]); }',
        '    return 文本;',
        '}',
        'function __翻译节点(节点) {',
        '    if (!节点) return;',
        '    var 原文 = __文本原文.get(节点);',
        '    if (原文 === undefined) { if (!__含中文(节点.nodeValue)) return; 原文 = 节点.nodeValue; __文本原文.set(节点, 原文); }',
        '    var 目标 = __翻译文本(原文, __当前语言);',
        '    if (节点.nodeValue !== 目标) 节点.nodeValue = 目标;',
        '}',
        'function __翻译属性(元素) {',
        '    if (!元素 || !元素.getAttribute) return;',
        '    var 列表 = ["placeholder", "title", "aria-label"];',
        '    var 记录 = __属性原文.get(元素);',
        '    if (!记录) { 记录 = {}; __属性原文.set(元素, 记录); }',
        '    for (var i = 0; i < 列表.length; i++) {',
        '        var 属性 = 列表[i];',
        '        if (!元素.hasAttribute(属性)) continue;',
        '        if (!(属性 in 记录)) 记录[属性] = 元素.getAttribute(属性);',
        '        var 目标 = __翻译文本(记录[属性], __当前语言);',
        '        if (元素.getAttribute(属性) !== 目标) 元素.setAttribute(属性, 目标);',
        '    }',
        '}',
        'function __应用语言(根节点) {',
        '    if (!根节点) return;',
        '    if (根节点.nodeType === 3) { __翻译节点(根节点); return; }',
        '    if (根节点.nodeType !== 1 && 根节点.nodeType !== 9 && 根节点.nodeType !== 11) return;',
        '    var 遍历 = document.createTreeWalker(根节点, NodeFilter.SHOW_TEXT, { acceptNode: function (节点) {',
        '        var 父 = 节点.parentElement;',
        '        if (!父) return NodeFilter.FILTER_REJECT;',
        '        if (/^(SCRIPT|STYLE|PRE|CODE|TEXTAREA)$/.test(父.tagName)) return NodeFilter.FILTER_REJECT;',
        '        if (__含中文(节点.nodeValue) || __文本原文.has(节点)) return NodeFilter.FILTER_ACCEPT;',
        '        return NodeFilter.FILTER_REJECT;',
        '    } });',
        '    var 节点;',
        '    while ((节点 = 遍历.nextNode())) __翻译节点(节点);',
        '    if (根节点.querySelectorAll) {',
        '        var 元素列表 = 根节点.querySelectorAll("[placeholder], [title], [aria-label]");',
        '        for (var i = 0; i < 元素列表.length; i++) __翻译属性(元素列表[i]);',
        '    }',
        '}',
        'function __翻译提示文本(文本) { return __翻译文本(文本, __当前语言); }',
        'function __更新语言按钮() { var 按钮 = document.getElementById("lang-text"); if (按钮) 按钮.textContent = __当前语言 === "en" ? "中文" : "EN"; }',
        'function 切换语言() { __当前语言 = __当前语言 === "en" ? "zh" : "en"; try { localStorage.setItem("lang", __当前语言); } catch (e) {} __应用语言(document.body); __更新语言按钮(); }',
        'function __初始化语言() {',
        '    __应用语言(document.body);',
        '    __更新语言按钮();',
        '    try { var 原confirm = window.confirm; window.confirm = function (文本) { return 原confirm(__翻译提示文本(文本)); }; var 原alert = window.alert; window.alert = function (文本) { return 原alert(__翻译提示文本(文本)); }; } catch (e) {}',
        '    try { var 观察器 = new MutationObserver(function (变化) { if (__当前语言 !== "en") return; for (var i = 0; i < 变化.length; i++) { var 新增 = 变化[i].addedNodes; for (var j = 0; j < 新增.length; j++) { var 节点 = 新增[j]; if (节点.nodeType === 1) __应用语言(节点); else if (节点.nodeType === 3) __翻译节点(节点); } } }); 观察器.observe(document.body, { childList: true, subtree: true }); } catch (e) {}',
        '}',
        'try { __初始化语言(); } catch (e) { console.error("i18n init failed", e); }'
    ];
    return 代码.join('\n');
}

////////////////////////////////功能函数//////////////////////////////////
const 免费额度 = {
    requestsDaily: 100000,
    d1RowsReadDaily: 5000000,
    d1RowsWrittenDaily: 100000,
    d1StorageBytes: 5 * 1024 * 1024 * 1024,
    kvReadsDaily: 100000,
    kvWritesDaily: 1000,
    kvDeletesDaily: 1000,
    kvListsDaily: 1000,
    kvStorageBytes: 1 * 1024 * 1024 * 1024,
    r2ClassAMonthly: 1000000,
    r2ClassBMonthly: 10000000,
    r2StorageBytes: 10 * 1024 * 1024 * 1024
};

const 默认单账号查询间隔毫秒 = 20 * 60 * 1000;
const 默认每轮最多外部子请求数 = 50;

const R2_CLASS_A_ACTIONS = new Set([
    'listbuckets', 'putbucket', 'listobjects', 'listobjectsv2', 'putobject', 'copyobject',
    'completemultipartupload', 'createmultipartupload', 'lifecyclestoragetiertransition',
    'listmultipartuploads', 'uploadpart', 'uploadpartcopy', 'listparts',
    'putbucketencryption', 'putbucketcors', 'putbucketlifecycleconfiguration'
]);

const R2_CLASS_B_ACTIONS = new Set([
    'headbucket', 'headobject', 'getobject', 'usagesummary', 'getbucketencryption',
    'getbucketlocation', 'getbucketcors', 'getbucketlifecycleconfiguration'
]);

const R2_FREE_ACTIONS = new Set(['deleteobject', 'deleteobjects', 'deletebucket', 'abortmultipartupload']);

/////////////////////////////////账号限额//////////////////////////////////

const 账号限额字段 = [
    'requestsDaily',
    'd1RowsReadDaily', 'd1RowsWrittenDaily', 'd1StorageBytes',
    'kvReadsDaily', 'kvWritesDaily', 'kvDeletesDaily', 'kvListsDaily', 'kvStorageBytes',
    'r2ClassAMonthly', 'r2ClassBMonthly', 'r2StorageBytes'
];

function 合并账号限额(原始限额) {
    const 限额 = { ...免费额度 };
    if (原始限额 && typeof 原始限额 === 'object' && !Array.isArray(原始限额)) {
        for (const 字段 of 账号限额字段) {
            const 数值 = Number(原始限额[字段]);
            if (Number.isFinite(数值) && 数值 > 0) 限额[字段] = 数值;
        }
    }
    return 限额;
}

// 把账号自定义额度写回统计数据；未配置的账号仍使用免费额度（行为与旧版一致）
function 应用账号限额(usage, account) {
    if (!usage) return usage;
    const 限额 = 合并账号限额(account?.Limits);
    usage.max = 限额.requestsDaily;
    const 资源 = usage.resources || {};
    if (资源.d1) {
        资源.d1.rowsReadLimit = 限额.d1RowsReadDaily;
        资源.d1.rowsWrittenLimit = 限额.d1RowsWrittenDaily;
        资源.d1.storageLimitBytes = 限额.d1StorageBytes;
    }
    if (资源.kv) {
        资源.kv.readsLimit = 限额.kvReadsDaily;
        资源.kv.writesLimit = 限额.kvWritesDaily;
        资源.kv.deletesLimit = 限额.kvDeletesDaily;
        资源.kv.listsLimit = 限额.kvListsDaily;
        资源.kv.storageLimitBytes = 限额.kvStorageBytes;
    }
    if (资源.r2) {
        资源.r2.classALimit = 限额.r2ClassAMonthly;
        资源.r2.classBLimit = 限额.r2ClassBMonthly;
        资源.r2.storageLimitBytes = 限额.r2StorageBytes;
    }
    return usage;
}

function 规范化账号限额输入(原始限额) {
    const 结果 = {};
    if (!原始限额 || typeof 原始限额 !== 'object' || Array.isArray(原始限额)) return 结果;
    for (const 字段 of 账号限额字段) {
        const 数值 = Number(原始限额[字段]);
        if (Number.isFinite(数值) && 数值 > 0) 结果[字段] = Math.floor(数值);
    }
    return 结果;
}

/////////////////////////////////用量告警//////////////////////////////////

const 告警指标定义 = [
    { key: 'requests', label: 'Workers+Pages 请求' },
    { key: 'd1RowsRead', label: 'D1 读取行数' },
    { key: 'd1RowsWritten', label: 'D1 写入行数' },
    { key: 'kvReads', label: 'KV 读取' },
    { key: 'kvWrites', label: 'KV 写入' },
    { key: 'r2ClassA', label: 'R2 Class A 操作' },
    { key: 'r2ClassB', label: 'R2 Class B 操作' },
    { key: 'd1Storage', label: 'D1 存储' },
    { key: 'kvStorage', label: 'KV 存储' },
    { key: 'r2Storage', label: 'R2 存储' }
];

const 支持的Webhook平台 = ['dingtalk', 'feishu', 'wecom', 'telegram', 'discord', 'slack', 'generic'];

function 有效Webhook列表(config) {
    if (!config) return [];
    if (Array.isArray(config.webhooks) && config.webhooks.length > 0) {
        return config.webhooks.filter(item => item && item.enabled !== false && item.url);
    }
    if (config.webhook?.enabled && config.webhook.url) return [config.webhook];
    return [];
}

function 是否静默时段(config) {
    const quiet = config?.quietHours;
    if (!quiet || quiet.enabled !== true) return false;
    const 开始 = Number(quiet.startUtc);
    const 结束 = Number(quiet.endUtc);
    if (!Number.isFinite(开始) || !Number.isFinite(结束) || 开始 === 结束) return false;
    const 小时 = new Date().getUTCHours();
    if (开始 < 结束) return 小时 >= 开始 && 小时 < 结束;
    return 小时 >= 开始 || 小时 < 结束;
}

function 创建默认告警配置() {
    return {
        enabled: false,
        cooldownMinutes: 180,
        thresholds: { requests: 80, d1RowsRead: 90, d1RowsWritten: 90, kvReads: 90, kvWrites: 90, r2ClassA: 90, r2ClassB: 90, d1Storage: 80, kvStorage: 80, r2Storage: 80 },
        telegram: { enabled: false, botToken: '', chatId: '' },
        webhook: { enabled: false, url: '', platform: 'generic' },
        webhooks: [],
        quietHours: { enabled: false, startUtc: 22, endUtc: 7 },
        rules: [],
        forecast: { enabled: true, hours: 24, checkMinutes: 60 },
        dailyReport: { enabled: false, hourUtc: 1 }
    };
}

function 规范化Webhook列表(原始) {
    const 列表 = Array.isArray(原始) ? 原始.slice(0, 5) : [];
    return 列表.map((item, index) => ({
        id: typeof item?.id === 'string' && item.id ? item.id : 'wh-' + (index + 1),
        name: typeof item?.name === 'string' ? item.name.trim().slice(0, 50) : ('Webhook ' + (index + 1)),
        enabled: item?.enabled !== false,
        url: typeof item?.url === 'string' ? item.url.trim() : '',
        platform: 支持的Webhook平台.includes(item?.platform) ? item.platform : 'generic'
    })).filter(item => item.url);
}

function 规范化告警规则(原始) {
    const 指标键列表 = new Set(告警指标定义.map(item => item.key));
    const 列表 = Array.isArray(原始) ? 原始.slice(0, 10) : [];
    return 列表.map((item, index) => {
        const 阈值 = Number(item?.threshold);
        return {
            id: typeof item?.id === 'string' && item.id ? item.id : 'rule-' + (index + 1),
            name: typeof item?.name === 'string' ? item.name.trim().slice(0, 50) : ('规则 ' + (index + 1)),
            enabled: item?.enabled !== false,
            metric: 指标键列表.has(item?.metric) ? item.metric : 'requests',
            scope: item?.scope === 'account' ? 'account' : 'total',
            accountId: item?.accountId === undefined || item?.accountId === null ? null : String(item.accountId),
            threshold: Number.isFinite(阈值) ? Math.min(100, Math.max(1, 阈值)) : 80,
            channels: Array.isArray(item?.channels) ? item.channels.filter(ch => ch === 'telegram' || ch === 'webhook') : ['telegram', 'webhook']
        };
    });
}

function 规范化告警配置(原始) {
    const 默认 = 创建默认告警配置();
    if (!原始 || typeof 原始 !== 'object' || Array.isArray(原始)) return 默认;
    const 阈值 = {};
    for (const { key } of 告警指标定义) {
        const 数值 = Number(原始.thresholds?.[key]);
        阈值[key] = Number.isFinite(数值) ? Math.min(100, Math.max(0, 数值)) : 默认.thresholds[key];
    }
    const 冷却 = Number(原始.cooldownMinutes);
    return {
        enabled: 原始.enabled === true,
        cooldownMinutes: Number.isFinite(冷却) ? Math.min(10080, Math.max(5, Math.floor(冷却))) : 默认.cooldownMinutes,
        thresholds: 阈值,
        telegram: {
            enabled: 原始.telegram?.enabled === true,
            botToken: typeof 原始.telegram?.botToken === 'string' ? 原始.telegram.botToken.trim() : '',
            chatId: typeof 原始.telegram?.chatId === 'string' ? 原始.telegram.chatId.trim() : ''
        },
        webhook: {
            enabled: 原始.webhook?.enabled === true,
            url: typeof 原始.webhook?.url === 'string' ? 原始.webhook.url.trim() : '',
            platform: 支持的Webhook平台.includes(原始.webhook?.platform) ? 原始.webhook.platform : 'generic'
        },
        webhooks: 规范化Webhook列表(原始.webhooks),
        quietHours: {
            enabled: 原始.quietHours?.enabled === true,
            startUtc: Number.isFinite(Number(原始.quietHours?.startUtc)) ? Math.min(23, Math.max(0, Math.floor(Number(原始.quietHours.startUtc)))) : 默认.quietHours.startUtc,
            endUtc: Number.isFinite(Number(原始.quietHours?.endUtc)) ? Math.min(23, Math.max(0, Math.floor(Number(原始.quietHours.endUtc)))) : 默认.quietHours.endUtc
        },
        rules: 规范化告警规则(原始.rules),
        forecast: {
            enabled: 原始.forecast?.enabled !== false,
            hours: Number.isFinite(Number(原始.forecast?.hours)) ? Math.min(168, Math.max(1, Math.floor(Number(原始.forecast.hours)))) : 默认.forecast.hours,
            checkMinutes: Number.isFinite(Number(原始.forecast?.checkMinutes)) ? Math.min(1440, Math.max(15, Math.floor(Number(原始.forecast.checkMinutes)))) : 默认.forecast.checkMinutes
        },
        dailyReport: {
            enabled: 原始.dailyReport?.enabled === true,
            hourUtc: Number.isFinite(Number(原始.dailyReport?.hourUtc)) ? Math.min(23, Math.max(0, Math.floor(Number(原始.dailyReport.hourUtc)))) : 默认.dailyReport.hourUtc
        }
    };
}

function 脱敏告警配置(config) {
    return {
        ...config,
        thresholds: { ...config.thresholds },
        telegram: {
            enabled: config.telegram.enabled,
            chatId: config.telegram.chatId,
            botToken: config.telegram.botToken ? 掩码敏感信息(config.telegram.botToken) : '',
            botTokenSet: !!config.telegram.botToken
        },
        webhook: {
            enabled: config.webhook.enabled,
            platform: config.webhook.platform || 'generic',
            url: config.webhook.url ? 掩码敏感信息(config.webhook.url) : '',
            urlSet: !!config.webhook.url
        },
        webhooks: (config.webhooks || []).map(item => ({
            id: item.id,
            name: item.name,
            enabled: item.enabled,
            platform: item.platform,
            url: item.url ? 掩码敏感信息(item.url) : '',
            urlSet: !!item.url
        })),
        quietHours: { ...config.quietHours },
        rules: (config.rules || []).map(item => ({ ...item, channels: [...(item.channels || [])] }))
    };
}

function 告警渠道数量(config) {
    let 数量 = 0;
    if (config.telegram?.enabled && config.telegram.botToken && config.telegram.chatId) 数量 += 1;
    const webhooks = 有效Webhook列表(config);
    数量 += webhooks.length;
    return 数量;
}

async function 读取告警配置(env) {
    try {
        return 规范化告警配置(await env.KV.get('alert_config.json', { type: 'json' }));
    } catch (error) {
        console.error('读取告警配置失败:', error.message);
        return 创建默认告警配置();
    }
}

async function 保存告警配置(env, config) {
    await env.KV.put('alert_config.json', JSON.stringify(规范化告警配置(config)));
}

function 格式告警数字(数值) {
    const 数字值 = Number(数值);
    if (!Number.isFinite(数字值)) return '0';
    return 数字值.toLocaleString('en-US');
}

// 返回本轮需要关注的告警（尚未做冷却过滤）
function 构建告警列表(usage_json, usage_config_json, config) {
    const 阈值 = config.thresholds || {};
    const 告警 = [];
    const 添加 = (键, 范围, 账号名, 指标键, 已用, 上限) => {
        const 阈值百分比 = Number(阈值[指标键]) || 0;
        const 已用数值 = Number(已用) || 0;
        const 上限数值 = Number(上限) || 0;
        if (阈值百分比 <= 0 || 上限数值 <= 0) return;
        const 百分比 = (已用数值 / 上限数值) * 100;
        if (!Number.isFinite(百分比) || 百分比 < 阈值百分比) return;
        告警.push({
            key: 键,
            scope: 范围,
            accountName: 账号名,
            metric: 指标键,
            metricLabel: (告警指标定义.find(item => item.key === 指标键) || {}).label || 指标键,
            used: 已用数值,
            limit: 上限数值,
            percent: Math.round(百分比 * 10) / 10,
            threshold: 阈值百分比
        });
    };

    添加('total:requests', 'total', '汇总', 'requests', usage_json?.total, usage_json?.max);

    for (const account of Array.isArray(usage_config_json) ? usage_config_json : []) {
        const usage = 补全账号Usage结构(account);
        if (!usage.success) continue;
        应用账号限额(usage, account);
        const 账号ID = String(account.ID ?? '');
        const 账号名 = String(account.Name || ('账号 ' + 账号ID));
        const 资源 = usage.resources || {};
        const d1 = 资源.d1 || {};
        const kv = 资源.kv || {};
        const r2 = 资源.r2 || {};
        添加(`acc:${账号ID}:requests`, 'account', 账号名, 'requests', usage.total, usage.max);
        添加(`acc:${账号ID}:d1RowsRead`, 'account', 账号名, 'd1RowsRead', d1.rowsRead, d1.rowsReadLimit);
        添加(`acc:${账号ID}:d1RowsWritten`, 'account', 账号名, 'd1RowsWritten', d1.rowsWritten, d1.rowsWrittenLimit);
        添加(`acc:${账号ID}:kvReads`, 'account', 账号名, 'kvReads', kv.reads, kv.readsLimit);
        添加(`acc:${账号ID}:kvWrites`, 'account', 账号名, 'kvWrites', kv.writes, kv.writesLimit);
        添加(`acc:${账号ID}:r2ClassA`, 'account', 账号名, 'r2ClassA', r2.classA, r2.classALimit);
        添加(`acc:${账号ID}:r2ClassB`, 'account', 账号名, 'r2ClassB', r2.classB, r2.classBLimit);
        添加(`acc:${账号ID}:d1Storage`, 'account', 账号名, 'd1Storage', d1.storageBytes, d1.storageLimitBytes);
        添加(`acc:${账号ID}:kvStorage`, 'account', 账号名, 'kvStorage', kv.storageBytes, kv.storageLimitBytes);
        添加(`acc:${账号ID}:r2Storage`, 'account', 账号名, 'r2Storage', r2.storageBytes, r2.storageLimitBytes);
    }
    return 告警;
}

function 格式化告警文本(alert) {
    const 范围 = alert.scope === 'total' ? '汇总' : `账号「${alert.accountName}」`;
    return [
        '[CF Usage Panel] ⚠️ 用量告警',
        `${范围}`,
        `指标: ${alert.metricLabel}`,
        `当前: ${格式告警数字(alert.used)} / ${格式告警数字(alert.limit)} (${alert.percent}%)`,
        `阈值: ${alert.threshold}%`,
        `时间: ${new Date().toISOString()}`
    ].join('\n');
}

async function 发送Telegram告警(config, 文本) {
    const telegram = config.telegram || {};
    if (!telegram.botToken || !telegram.chatId) return false;
    try {
        const 响应 = await fetch(`https://api.telegram.org/bot${telegram.botToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: telegram.chatId, text: 文本, disable_web_page_preview: true })
        });
        if (!响应.ok) console.error('Telegram 告警返回异常状态:', 响应.status);
        return 响应.ok;
    } catch (error) {
        console.error('Telegram 告警发送失败:', error.message);
        return false;
    }
}

function 构建Webhook请求体(platform, alert, 文本) {
    const 标题 = (文本 || '').split('\n')[0] || 'CF Usage Panel';
    switch (platform) {
        case 'dingtalk':
            return { msgtype: 'markdown', markdown: { title: 标题, text: 文本 } };
        case 'feishu':
            return { msg_type: 'text', content: { text: 文本 } };
        case 'wecom':
            return { msgtype: 'markdown', markdown: { content: 文本 } };
        case 'telegram':
            return { text: 文本, disable_web_page_preview: true };
        case 'discord':
            return { content: 文本.slice(0, 1900), username: 'CF Usage Panel' };
        case 'slack':
            return { text: 文本 };
        default:
            return {
                source: 'cf-usage-panel',
                type: 'usage_alert',
                alert,
                message: 文本,
                timestamp: new Date().toISOString()
            };
    }
}

async function 发送Webhook到地址(webhook, alert, 文本) {
    if (!webhook || !webhook.url) return false;
    try {
        const 请求体 = 构建Webhook请求体(webhook.platform || 'generic', alert, 文本);
        const 响应 = await fetch(webhook.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(请求体)
        });
        if (!响应.ok) console.error('Webhook 告警返回异常状态:', 响应.status);
        return 响应.ok;
    } catch (error) {
        console.error('Webhook 告警发送失败:', error.message);
        return false;
    }
}

async function 发送Webhook告警(config, alert, 文本) {
    return 发送Webhook到地址(config.webhook || {}, alert, 文本);
}

async function 发送告警到渠道(config, alert, 文本, 渠道白名单 = null) {
    const 允许 = Array.isArray(渠道白名单) && 渠道白名单.length > 0 ? 渠道白名单 : null;
    let 成功数 = 0;
    if (config.telegram?.enabled && config.telegram.botToken && config.telegram.chatId && (!允许 || 允许.includes('telegram'))) {
        if (await 发送Telegram告警(config, 文本)) 成功数 += 1;
    }
    if (!允许 || 允许.includes('webhook')) {
        for (const webhook of 有效Webhook列表(config)) {
            if (await 发送Webhook到地址(webhook, alert, 文本)) 成功数 += 1;
        }
    }
    return 成功数;
}

function 指标当前值与上限(usage, metric) {
    const 资源 = usage?.resources || {};
    const d1 = 资源.d1 || {};
    const kv = 资源.kv || {};
    const r2 = 资源.r2 || {};
    switch (metric) {
        case 'requests': return [Number(usage?.total) || 0, Number(usage?.max) || 0];
        case 'd1RowsRead': return [d1.rowsRead, d1.rowsReadLimit];
        case 'd1RowsWritten': return [d1.rowsWritten, d1.rowsWrittenLimit];
        case 'kvReads': return [kv.reads, kv.readsLimit];
        case 'kvWrites': return [kv.writes, kv.writesLimit];
        case 'r2ClassA': return [r2.classA, r2.classALimit];
        case 'r2ClassB': return [r2.classB, r2.classBLimit];
        case 'd1Storage': return [d1.storageBytes, d1.storageLimitBytes];
        case 'kvStorage': return [kv.storageBytes, kv.storageLimitBytes];
        case 'r2Storage': return [r2.storageBytes, r2.storageLimitBytes];
        default: return [0, 0];
    }
}

function 构建规则告警列表(usage_json, usage_config_json, config) {
    const 告警 = [];
    for (const 规则 of config.rules || []) {
        if (!规则.enabled) continue;
        if (规则.scope === 'account') {
            const 账号ID = 规则.accountId;
            const account = (Array.isArray(usage_config_json) ? usage_config_json : []).find(item => String(item.ID) === String(账号ID));
            if (!account) continue;
            const usage = 补全账号Usage结构(account);
            if (!usage.success) continue;
            应用账号限额(usage, account);
            const [已用, 上限] = 指标当前值与上限(usage, 规则.metric);
            const 上限值 = Number(上限) || 0;
            if (上限值 <= 0) continue;
            const 百分比 = (Number(已用) || 0) / 上限值 * 100;
            if (!Number.isFinite(百分比) || 百分比 < 规则.threshold) continue;
            告警.push({
                key: `rule:${规则.id}:acc:${账号ID}`,
                ruleId: 规则.id,
                ruleName: 规则.name,
                channels: 规则.channels,
                scope: 'account',
                accountName: String(account.Name || ('账号 ' + 账号ID)),
                metric: 规则.metric,
                metricLabel: (告警指标定义.find(item => item.key === 规则.metric) || {}).label || 规则.metric,
                used: Number(已用) || 0,
                limit: 上限值,
                percent: Math.round(百分比 * 10) / 10,
                threshold: 规则.threshold
            });
        } else {
            const [已用, 上限] = 指标当前值与上限(usage_json, 规则.metric);
            const 上限值 = Number(上限) || 0;
            if (上限值 <= 0) continue;
            const 百分比 = (Number(已用) || 0) / 上限值 * 100;
            if (!Number.isFinite(百分比) || 百分比 < 规则.threshold) continue;
            告警.push({
                key: `rule:${规则.id}:total`,
                ruleId: 规则.id,
                ruleName: 规则.name,
                channels: 规则.channels,
                scope: 'total',
                accountName: '汇总',
                metric: 规则.metric,
                metricLabel: (告警指标定义.find(item => item.key === 规则.metric) || {}).label || 规则.metric,
                used: Number(已用) || 0,
                limit: 上限值,
                percent: Math.round(百分比 * 10) / 10,
                threshold: 规则.threshold
            });
        }
    }
    return 告警;
}

async function 追加告警历史(env, 记录) {
    try {
        let 历史 = await env.KV.get('alert_history.json', { type: 'json' });
        if (!Array.isArray(历史)) 历史 = [];
        历史.unshift({
            time: new Date().toISOString(),
            key: String(记录?.key || ''),
            scope: String(记录?.scope || ''),
            accountName: String(记录?.accountName || ''),
            metricLabel: String(记录?.metricLabel || ''),
            percent: Number(记录?.percent) || 0,
            threshold: Number(记录?.threshold) || 0,
            ruleId: 记录?.ruleId || null,
            channelsSent: Number(记录?.channelsSent) || 0
        });
        await env.KV.put('alert_history.json', JSON.stringify(历史.slice(0, 100)), { expirationTtl: 60 * 86400 });
    } catch (error) {
        console.error('写入告警历史失败:', error.message);
    }
}

// 单轮最多发送 3 条告警，配合调度器预留的子请求预算，避免超出 Workers 免费额度
async function 评估并发送告警(env, usage_json, 预读取配置 = null) {
    const config = 预读取配置 || await 读取告警配置(env);
    if (!config.enabled || 告警渠道数量(config) === 0) return { sent: 0, candidates: 0 };

    // 复用刚刚刷新得到的配置快照（非枚举属性，不会出现在 JSON 响应里），避免 KV 最终一致性导致告警读到旧数据
    const usage_config_json = usage_json?.__config || await 读取账号配置(env);
    const 默认告警 = 构建告警列表(usage_json, usage_config_json, config);
    const 规则告警 = 构建规则告警列表(usage_json, usage_config_json, config);
    const 去重 = new Map();
    for (const alert of [...默认告警, ...规则告警]) {
        if (!去重.has(alert.key)) 去重.set(alert.key, alert);
    }
    const 候选 = Array.from(去重.values());
    if (候选.length === 0) return { sent: 0, candidates: 0 };
    if (是否静默时段(config)) return { sent: 0, candidates: 候选.length, quiet: true };

    let 状态 = {};
    try {
        状态 = (await env.KV.get('alert_state.json', { type: 'json' })) || {};
    } catch (error) {
        console.error('读取告警状态失败:', error.message);
    }
    const 冷却毫秒 = Math.max(1, Number(config.cooldownMinutes) || 180) * 60 * 1000;
    const 现在 = Date.now();
    const 待发送 = 候选.filter(alert => !状态[alert.key] || 现在 - Number(状态[alert.key]) >= 冷却毫秒).slice(0, 3);
    if (待发送.length === 0) return { sent: 0, candidates: 候选.length };

    let 成功数 = 0;
    let 状态已变化 = false;
    for (const alert of 待发送) {
        const 文本 = 格式化告警文本(alert);
        const 渠道成功数 = await 发送告警到渠道(config, alert, 文本, alert.channels);
        if (渠道成功数 > 0) {
            状态[alert.key] = 现在;
            状态已变化 = true;
            成功数 += 1;
            await 追加告警历史(env, { ...alert, channelsSent: 渠道成功数 });
        }
    }

    for (const 键 of Object.keys(状态)) {
        if (现在 - Number(状态[键]) > 冷却毫秒 * 4) delete 状态[键];
    }
    if (状态已变化) {
        try {
            await env.KV.put('alert_state.json', JSON.stringify(状态), { expirationTtl: 30 * 86400 });
        } catch (error) {
            console.error('保存告警状态失败:', error.message);
        }
    }
    return { sent: 成功数, candidates: 候选.length };
}

async function 发送测试告警(env) {
    const config = await 读取告警配置(env);
    const 文本 = `[CF Usage Panel] 测试消息 ✅\n告警渠道配置正常\n时间: ${new Date().toISOString()}`;
    const 结果 = { telegram: false, webhook: false, webhooks: [] };
    if (config.telegram.enabled && config.telegram.botToken && config.telegram.chatId) {
        结果.telegram = await 发送Telegram告警(config, 文本);
    }
    for (const webhook of 有效Webhook列表(config)) {
        const ok = await 发送Webhook到地址(webhook, { test: true }, 文本);
        结果.webhooks.push({ name: webhook.name || webhook.platform || 'webhook', platform: webhook.platform, ok });
        if (ok) 结果.webhook = true;
    }
    return 结果;
}

/////////////////////////////////预测告警 / 每日报告//////////////////////////////////

function 快照指标取值(row, 指标) {
    switch (指标) {
        case 'd1RowsRead': return Number(row.d1_rows_read) || 0;
        case 'd1RowsWritten': return Number(row.d1_rows_written) || 0;
        case 'kvReads': return Number(row.kv_reads) || 0;
        case 'kvWrites': return Number(row.kv_writes) || 0;
        case 'r2ClassA': return Number(row.r2_class_a) || 0;
        case 'r2ClassB': return Number(row.r2_class_b) || 0;
        case 'd1Storage': return Number(row.d1_storage_bytes) || 0;
        case 'kvStorage': return Number(row.kv_storage_bytes) || 0;
        case 'r2Storage': return Number(row.r2_storage_bytes) || 0;
        default: return (Number(row.pages) || 0) + (Number(row.workers) || 0);
    }
}

async function 查询预测快照(env, 小时 = 24) {
    if (!(await 确保历史表(env))) return [];
    const 起始 = Date.now() - Math.max(1, 小时) * 3600000;
    try {
        const 结果 = await env.DB.prepare(`SELECT captured_at, account_id, pages, workers,
            d1_rows_read, d1_rows_written, d1_storage_bytes, kv_reads, kv_writes, kv_storage_bytes,
            r2_class_a, r2_class_b, r2_storage_bytes
            FROM usage_snapshots WHERE captured_at >= ? ORDER BY captured_at DESC LIMIT 5000`).bind(起始).all();
        return Array.isArray(结果?.results) ? 结果.results.reverse() : [];
    } catch (error) {
        console.error('查询预测快照失败:', error.message);
        return [];
    }
}

// 基于 D1 历史快照，预测“按最近趋势多久会达到告警阈值”
function 构建预测候选(快照行列表, usage_json, usage_config_json, config) {
    const 序列 = new Map();
    const 添加点 = (键, 时间, 值) => {
        if (!序列.has(键)) 序列.set(键, new Map());
        const 时间点 = 序列.get(键);
        时间点.set(时间, (时间点.get(时间) || 0) + 值);
    };
    for (const row of 快照行列表) {
        const 时间 = Number(row.captured_at);
        if (!Number.isFinite(时间)) continue;
        const 账号键 = 'acc:' + String(row.account_id);
        for (const { key } of 告警指标定义) {
            const 值 = 快照指标取值(row, key);
            添加点(账号键 + '|' + key, 时间, 值);
            添加点('total|' + key, 时间, 值);
        }
    }
    const 转点列表 = 映射 => Array.from(映射.entries()).sort((a, b) => a[0] - b[0]).map(([t, v]) => ({ t, v }));
    const 候选 = [];
    const 检查 = (键前缀, 范围类型, 名称, 指标, 系列, 当前值, 上限) => {
        const 阈值百分比 = Number(config.thresholds?.[指标]) || 0;
        if (阈值百分比 <= 0 || !(上限 > 0)) return;
        const 目标值 = 上限 * 阈值百分比 / 100;
        if (当前值 >= 目标值) return; // 已到阈值由普通告警负责
        if (系列.length < 2) return;
        const 每小时斜率 = 计算每小时斜率(系列);
        if (!(每小时斜率 > 0)) return;
        const 小时 = (目标值 - 当前值) / 每小时斜率;
        if (!(小时 > 0) || 小时 > Number(config.forecast?.hours || 24)) return;
        const 指标标签 = (告警指标定义.find(item => item.key === 指标) || {}).label || 指标;
        候选.push({
            key: `forecast:${键前缀}:${指标}`,
            scope: 范围类型,
            accountName: 名称,
            metric: 指标,
            metricLabel: 指标标签,
            current: 当前值,
            target: 目标值,
            threshold: 阈值百分比,
            hoursToTarget: Math.round(小时 * 10) / 10
        });
    };

    for (const { key } of 告警指标定义) {
        const 系列映射 = 序列.get('total|' + key);
        if (!系列映射) continue;
        const 当前和上限 = 历史指标当前值和上限(usage_json, key);
        检查('total', 'total', '汇总', key, 转点列表(系列映射), 当前和上限.current, 当前和上限.limit);
    }

    for (const account of Array.isArray(usage_config_json) ? usage_config_json : []) {
        const usage = 补全账号Usage结构(account);
        if (!usage.success) continue;
        应用账号限额(usage, account);
        const 账号ID = String(account.ID ?? '');
        const 名称 = String(account.Name || ('账号 ' + 账号ID));
        for (const { key } of 告警指标定义) {
            const 系列映射 = 序列.get('acc:' + 账号ID + '|' + key);
            if (!系列映射) continue;
            const 当前和上限 = 历史指标当前值和上限(usage, key);
            检查('acc:' + 账号ID, 'account', 名称, key, 转点列表(系列映射), 当前和上限.current, 当前和上限.limit);
        }
    }
    return 候选;
}

function 格式化预测告警文本(alert) {
    const 范围 = alert.scope === 'total' ? '汇总' : `账号「${alert.accountName}」`;
    return [
        '[CF Usage Panel] 📈 用量预测告警',
        `范围: ${范围}`,
        `指标: ${alert.metricLabel}`,
        `当前: ${格式告警数字(alert.current)}，阈值 ${alert.threshold}%（${格式告警数字(alert.target)}）`,
        `按最近趋势预计约 ${alert.hoursToTarget} 小时后达到阈值`,
        `时间: ${new Date().toISOString()}`
    ].join('\n');
}

async function 发送文本到渠道(env, config, 文本, payload) {
    let 成功数 = 0;
    if (config.telegram.enabled && config.telegram.botToken && config.telegram.chatId) {
        if (await 发送Telegram告警(config, 文本)) 成功数 += 1;
    }
    for (const webhook of 有效Webhook列表(config)) {
        if (await 发送Webhook到地址(webhook, payload || {}, 文本)) 成功数 += 1;
    }
    return 成功数;
}

async function 评估预测告警(env, usage_json, config) {
    if (!config.enabled || !config.forecast?.enabled || 告警渠道数量(config) === 0) return 0;
    if (是否静默时段(config)) return 0;
    if (!历史功能已启用(env)) return 0;
    const 现在 = Date.now();
    const 检查间隔毫秒 = Math.max(15, Number(config.forecast.checkMinutes) || 60) * 60000;
    let 上次检查 = 0;
    try {
        上次检查 = Number(await env.KV.get('forecast_last_check')) || 0;
    } catch (error) {
        console.error('读取预测检查时间失败:', error.message);
    }
    if (现在 - 上次检查 < 检查间隔毫秒) return 0;

    const 快照行列表 = await 查询预测快照(env, Math.min(24, Math.max(6, Number(config.forecast.hours) || 24)));
    if (快照行列表.length === 0) {
        try { await env.KV.put('forecast_last_check', String(现在), { expirationTtl: 2 * 86400 }); } catch (error) { /* 忽略 */ }
        return 0;
    }
    const usage_config_json = usage_json?.__config || await 读取账号配置(env);
    const 候选 = 构建预测候选(快照行列表, usage_json, usage_config_json, config);
    if (候选.length === 0) {
        try { await env.KV.put('forecast_last_check', String(现在), { expirationTtl: 2 * 86400 }); } catch (error) { /* 忽略 */ }
        return 0;
    }

    let 状态 = {};
    try {
        状态 = (await env.KV.get('alert_state.json', { type: 'json' })) || {};
    } catch (error) {
        console.error('读取告警状态失败:', error.message);
    }
    const 冷却毫秒 = Math.max(1, Number(config.cooldownMinutes) || 180) * 60000;
    const 待发送 = 候选.filter(item => !状态[item.key] || 现在 - Number(状态[item.key]) >= 冷却毫秒).slice(0, 3);
    let 成功数 = 0;
    let 状态已变化 = false;
    for (const alert of 待发送) {
        const 文本 = 格式化预测告警文本(alert);
        const 成功 = await 发送文本到渠道(env, config, 文本, { source: 'cf-usage-panel', type: 'usage_forecast', alert, message: 文本, timestamp: new Date().toISOString() });
        if (成功 > 0) {
            状态[alert.key] = 现在;
            状态已变化 = true;
            成功数 += 1;
        }
    }
    for (const 键 of Object.keys(状态)) {
        if (现在 - Number(状态[键]) > 冷却毫秒 * 4) delete 状态[键];
    }
    if (状态已变化) {
        try { await env.KV.put('alert_state.json', JSON.stringify(状态), { expirationTtl: 30 * 86400 }); } catch (error) { console.error('保存告警状态失败:', error.message); }
    }
    try { await env.KV.put('forecast_last_check', String(现在), { expirationTtl: 2 * 86400 }); } catch (error) { console.error('保存预测检查时间失败:', error.message); }
    return 成功数;
}

function 用量百分比(已用, 上限) {
    const 上限数值 = Number(上限) || 0;
    if (上限数值 <= 0) return '0%';
    return ((Number(已用) || 0) / 上限数值 * 100).toFixed(1) + '%';
}

function 构建每日报告文本(usage_json, usage_config_json) {
    const 账号列表 = Array.isArray(usage_config_json) ? usage_config_json : [];
    const 刷新统计 = usage_json?.RefreshStats || {};
    const 资源 = usage_json?.resources || {};
    const d1 = 资源.d1 || {};
    const kv = 资源.kv || {};
    const r2 = 资源.r2 || {};
    const 账号排行 = 账号列表.map(account => {
        const usage = 补全账号Usage结构(account);
        if (!usage.success) return null;
        应用账号限额(usage, account);
        return { name: String(account.Name || ('账号 ' + String(account.ID ?? ''))), total: Number(usage.total) || 0 };
    }).filter(Boolean).sort((a, b) => b.total - a.total).slice(0, 5);
    const 行 = [
        '[CF Usage Panel] 📊 每日用量报告',
        `时间: ${new Date().toISOString()}`,
        `总请求: ${格式告警数字(usage_json?.total)} / ${格式告警数字(usage_json?.max)}（${用量百分比(usage_json?.total, usage_json?.max)}）`,
        `Workers: ${格式告警数字(usage_json?.workers)} | Pages: ${格式告警数字(usage_json?.pages)}`,
        `账号: ${账号列表.length} 个（本次刷新 ${Number(刷新统计.refreshed) || 0}，部分失败 ${Number(刷新统计.partial) || 0}，失败 ${Number(刷新统计.failed) || 0}）`,
        `D1: 读取 ${格式告警数字(d1.rowsRead)}/${格式告警数字(d1.rowsReadLimit)} | 写入 ${格式告警数字(d1.rowsWritten)}/${格式告警数字(d1.rowsWrittenLimit)} | 存储 ${用量百分比(d1.storageBytes, d1.storageLimitBytes)}`,
        `KV: 读取 ${格式告警数字(kv.reads)}/${格式告警数字(kv.readsLimit)} | 写入 ${格式告警数字(kv.writes)}/${格式告警数字(kv.writesLimit)} | 存储 ${用量百分比(kv.storageBytes, kv.storageLimitBytes)}`,
        `R2: ClassA ${格式告警数字(r2.classA)}/${格式告警数字(r2.classALimit)} | ClassB ${格式告警数字(r2.classB)}/${格式告警数字(r2.classBLimit)} | 存储 ${用量百分比(r2.storageBytes, r2.storageLimitBytes)}`
    ];
    if (账号排行.length > 0) {
        行.push('账号请求 Top:');
        账号排行.forEach((item, index) => 行.push(` ${index + 1}. ${item.name}: ${格式告警数字(item.total)}`));
    }
    return 行.join('\n');
}

async function 发送当前日报(env) {
    const [已保存Usage, 已保存配置] = await Promise.all([
        env.KV.get('usage.json', { type: 'json' }),
        读取账号配置(env)
    ]);
    const config = await 读取告警配置(env);
    if (告警渠道数量(config) === 0) return { sent: 0, msg: '未启用 Telegram/Webhook 渠道' };
    const usage_json = 补全Usage结构(已保存Usage || {});
    usage_json.total = (usage_json.pages || 0) + (usage_json.workers || 0);
    const 文本 = 构建每日报告文本(usage_json, 已保存配置);
    const 成功数 = await 发送文本到渠道(env, config, 文本, { source: 'cf-usage-panel', type: 'daily_report', message: 文本, timestamp: new Date().toISOString() });
    return { sent: 成功数, msg: 成功数 > 0 ? '日报已发送' : '发送失败' };
}

async function 评估每日报告(env, usage_json, config, scheduledTime) {
    if (!config.dailyReport?.enabled || 告警渠道数量(config) === 0) return 0;
    if (是否静默时段(config)) return 0;
    const 计划时间 = new Date(Number(scheduledTime) || Date.now());
    if (计划时间.getUTCHours() !== Number(config.dailyReport.hourUtc)) return 0;
    const 今天 = 计划时间.toISOString().slice(0, 10);
    let 上次发送日 = null;
    try {
        上次发送日 = await env.KV.get('daily_report_day');
    } catch (error) {
        console.error('读取日报发送记录失败:', error.message);
    }
    if (上次发送日 === 今天) return 0;
    const 配置列表 = usage_json?.__config || await 读取账号配置(env);
    const 文本 = 构建每日报告文本(usage_json, 配置列表);
    const 成功数 = await 发送文本到渠道(env, config, 文本, { source: 'cf-usage-panel', type: 'daily_report', message: 文本, timestamp: new Date().toISOString() });
    if (成功数 > 0) {
        try { await env.KV.put('daily_report_day', 今天, { expirationTtl: 3 * 86400 }); } catch (error) { console.error('保存日报发送记录失败:', error.message); }
    }
    return 成功数;
}

/////////////////////////////////健康检查 / Metrics / Badge//////////////////////////////////

async function 处理健康检查(env) {
    const [已保存Usage, 已保存配置] = await Promise.all([
        env.KV.get('usage.json', { type: 'json' }),
        读取账号配置(env)
    ]);
    const 最后更新 = Number(已保存Usage?.UpdateTime || 0) || 0;
    const 查询间隔 = 获取单账号查询间隔毫秒(env);
    const 年龄秒 = 最后更新 ? Math.round((Date.now() - 最后更新) / 1000) : null;
    const 状态 = !最后更新 ? 'uninitialized' : (Date.now() - 最后更新 > 查询间隔 * 2 ? 'stale' : 'ok');
    const 账号数量 = Array.isArray(已保存配置) ? 已保存配置.length : 0;
    const 响应体 = {
        status: 状态,
        lastUpdate: 最后更新 || null,
        ageSeconds: 年龄秒,
        accounts: 账号数量,
        refresh: 已保存Usage?.RefreshStats || null,
        freeTier: {
            guardEnabled: 免费档保护已启用(env),
            minRefreshIntervalMinutes: Math.round(免费档最小刷新间隔毫秒 / 60000),
            refreshIntervalMinutes: Math.round(查询间隔 / 60000),
            estimatedSubrequestsPerRefresh: Math.min(默认每轮最多外部子请求数, Math.max(账号数量, 1) * 5),
            estimatedKvWritesPerRefresh: 4,
            note: '免费 KV 写额度约 1000/天；本 Worker 已按“到期才刷新、变化才写回”控制写放大，默认刷新间隔不低于 10 分钟；付费用户可设 FREE_TIER_GUARD=false'
        },
        history: {
            enabled: 历史功能已启用(env),
            retentionDays: 获取历史保留天数(env),
            note: '绑定 D1（变量名 DB）后自动写入历史快照；未绑定时仅展示实时数据，可按需设置 HISTORY_ENABLED=false 关闭'
        },
        timestamp: new Date().toISOString()
    };
    return new Response(JSON.stringify(响应体), { status: 状态 === 'stale' ? 503 : 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
}

async function 校验Metrics访问(env, request) {
    if (!env.METRICS_TOKEN) return false; // 未配置 token 时回退到管理员会话
    const url = new URL(request.url);
    const 提供值 = url.searchParams.get('token') || String(request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
    return 恒定时间比较(提供值, env.METRICS_TOKEN);
}

function 转义Prometheus标签(value) {
    return String(value == null ? '' : value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

async function 处理Metrics(env) {
    const [usage, 已保存配置] = await Promise.all([
        env.KV.get('usage.json', { type: 'json' }),
        读取账号配置(env)
    ]);
    const 账号列表 = Array.isArray(已保存配置) ? 已保存配置 : [];
    const 资源 = usage?.resources || {};
    const 输出 = [];
    const 已声明 = new Set();
    const 添加指标 = (名称, 帮助, 值, 标签 = null) => {
        if (!已声明.has(名称)) {
            输出.push(`# HELP ${名称} ${帮助}`);
            输出.push(`# TYPE ${名称} gauge`);
            已声明.add(名称);
        }
        let 标签串 = '';
        if (标签) {
            const 对 = Object.keys(标签).map(键 => `${键}="${转义Prometheus标签(标签[键])}"`).join(',');
            if (对) 标签串 = `{${对}}`;
        }
        const 数值 = Number(值);
        输出.push(`${名称}${标签串} ${Number.isFinite(数值) ? 数值 : 0}`);
    };
    const 添加配额指标 = (前缀, 已用, 上限) => {
        添加指标(`cf_usage_${前缀}_used`, `${前缀} used`, 已用);
        添加指标(`cf_usage_${前缀}_limit`, `${前缀} limit`, 上限);
        const 百分比 = Number(上限) > 0 ? (Number(已用) / Number(上限)) * 100 : 0;
        添加指标(`cf_usage_${前缀}_percent`, `${前缀} percent`, 百分比);
    };

    const d1 = 资源.d1 || {};
    const kv = 资源.kv || {};
    const r2 = 资源.r2 || {};
    添加配额指标('requests', usage?.total, usage?.max);
    添加配额指标('d1_rows_read', d1.rowsRead, d1.rowsReadLimit);
    添加配额指标('d1_rows_written', d1.rowsWritten, d1.rowsWrittenLimit);
    添加配额指标('d1_storage_bytes', d1.storageBytes, d1.storageLimitBytes);
    添加配额指标('kv_reads', kv.reads, kv.readsLimit);
    添加配额指标('kv_writes', kv.writes, kv.writesLimit);
    添加配额指标('kv_storage_bytes', kv.storageBytes, kv.storageLimitBytes);
    添加配额指标('r2_class_a', r2.classA, r2.classALimit);
    添加配额指标('r2_class_b', r2.classB, r2.classBLimit);
    添加配额指标('r2_storage_bytes', r2.storageBytes, r2.storageLimitBytes);
    添加指标('cf_usage_workers_errors_total', 'Workers errors today (aggregated)', usage?.workersErrors);
    添加指标('cf_usage_workers_error_rate_percent', 'Workers error rate today (aggregated)', usage?.errorRate);
    添加指标('cf_usage_workers_subrequests_total', 'Workers subrequests today (aggregated)', usage?.workersSubrequests);
    添加指标('cf_usage_cpu_time_p50_microseconds', 'Workers CPU time P50 (max across accounts)', usage?.cpuTimeP50);
    添加指标('cf_usage_cpu_time_p99_microseconds', 'Workers CPU time P99 (max across accounts)', usage?.cpuTimeP99);
    添加指标('cf_usage_accounts_total', 'number of configured accounts', 账号列表.length);
    添加指标('cf_usage_last_update_timestamp_seconds', 'last usage update unix timestamp', Math.floor((Number(usage?.UpdateTime) || 0) / 1000));
    const 刷新统计 = usage?.RefreshStats || {};
    添加指标('cf_usage_refresh_refreshed', 'accounts refreshed in last run', 刷新统计.refreshed);
    添加指标('cf_usage_refresh_partial', 'accounts partially failed in last run', 刷新统计.partial);
    添加指标('cf_usage_refresh_failed', 'accounts failed in last run', 刷新统计.failed);
    添加指标('cf_usage_refresh_cached', 'accounts using cached data', 刷新统计.cached);

    for (const account of 账号列表) {
        const accountUsage = 补全账号Usage结构(account);
        应用账号限额(accountUsage, account);
        const 标签 = { account_id: String(account.ID ?? ''), account_name: String(account.Name || '') };
        添加指标('cf_usage_account_requests_used', 'per-account requests used', accountUsage.total, 标签);
        添加指标('cf_usage_account_requests_limit', 'per-account requests limit', accountUsage.max, 标签);
        添加指标('cf_usage_account_success', 'per-account usage fetch success', accountUsage.success ? 1 : 0, 标签);
        添加指标('cf_usage_account_workers_errors', 'per-account Workers errors today', accountUsage.workersErrors, 标签);
        添加指标('cf_usage_account_error_rate_percent', 'per-account Workers error rate percent', accountUsage.errorRate, 标签);
        添加指标('cf_usage_account_cpu_time_p99_microseconds', 'per-account Workers CPU P99 (µs)', accountUsage.cpuTimeP99, 标签);
    }

    return new Response(输出.join('\n') + '\n', { headers: { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' } });
}

async function 处理Badge(env) {
    let usage = null;
    try {
        usage = await env.KV.get('usage.json', { type: 'json' });
    } catch (error) {
        console.error('读取 Badge 数据失败:', error.message);
    }
    const 总用量 = Number(usage?.total) || 0;
    const 总上限 = Number(usage?.max) || 0;
    const 百分比 = 总上限 > 0 ? Math.min(999, (总用量 / 总上限) * 100) : 0;
    const 文本 = 百分比.toFixed(1) + '%';
    const 颜色 = 百分比 >= 100 ? '#e05d5d' : 百分比 >= 85 ? '#e0a030' : 百分比 >= 60 ? '#d4b106' : '#4caf50';
    const 左宽 = 104;
    const 右宽 = 64;
    const 总宽 = 左宽 + 右宽;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${总宽}" height="20" role="img" aria-label="CF usage: ${文本}">
  <title>CF usage: ${文本}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${总宽}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)"><rect width="${左宽}" height="20" fill="#555"/><rect x="${左宽}" width="${右宽}" height="20" fill="${颜色}"/><rect width="${总宽}" height="20" fill="url(#s)"/></g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${左宽 / 2}" y="15" fill="#010101" fill-opacity=".3">CF usage</text><text x="${左宽 / 2}" y="14">CF usage</text>
    <text x="${左宽 + 右宽 / 2}" y="15" fill="#010101" fill-opacity=".3">${文本}</text><text x="${左宽 + 右宽 / 2}" y="14">${文本}</text>
  </g>
</svg>`;
    return new Response(svg, { headers: { 'Content-Type': 'image/svg+xml;charset=UTF-8', 'Cache-Control': 'no-store' } });
}

/////////////////////////////////历史趋势（D1，可选绑定）//////////////////////////////////

let 历史表已就绪 = false;

function 历史功能已启用(env) {
    return !!(env && env.DB && typeof env.DB.prepare === 'function' && env.HISTORY_ENABLED !== 'false');
}

function 获取历史保留天数(env) {
    const 数值 = Number(env.HISTORY_RETENTION_DAYS || env.history_retention_days);
    return Number.isFinite(数值) ? Math.min(90, Math.max(7, Math.floor(数值))) : 30;
}

const 历史指标定义 = [
    { key: 'requests', label: 'Workers+Pages 请求', sql: '(pages + workers)' },
    { key: 'd1RowsRead', label: 'D1 读取行数', sql: 'd1_rows_read' },
    { key: 'd1RowsWritten', label: 'D1 写入行数', sql: 'd1_rows_written' },
    { key: 'kvReads', label: 'KV 读取', sql: 'kv_reads' },
    { key: 'kvWrites', label: 'KV 写入', sql: 'kv_writes' },
    { key: 'r2ClassA', label: 'R2 Class A 操作', sql: 'r2_class_a' },
    { key: 'r2ClassB', label: 'R2 Class B 操作', sql: 'r2_class_b' },
    { key: 'd1Storage', label: 'D1 存储', sql: 'd1_storage_bytes' },
    { key: 'kvStorage', label: 'KV 存储', sql: 'kv_storage_bytes' },
    { key: 'r2Storage', label: 'R2 存储', sql: 'r2_storage_bytes' }
];

function 规范化历史指标(原始) {
    const 指标 = String(原始 || 'requests');
    return 历史指标定义.some(item => item.key === 指标) ? 指标 : 'requests';
}

function 获取历史窗口(range) {
    const 键 = String(range || '24h');
    if (键 === '7d') return { key: '7d', 毫秒: 7 * 86400000, bucket毫秒: 3600000 };
    if (键 === '14d') return { key: '14d', 毫秒: 14 * 86400000, bucket毫秒: 2 * 3600000 };
    if (键 === '30d') return { key: '30d', 毫秒: 30 * 86400000, bucket毫秒: 6 * 3600000 };
    return { key: '24h', 毫秒: 86400000, bucket毫秒: 10 * 60000 };
}

async function 确保历史表(env) {
    if (!历史功能已启用(env)) return false;
    if (历史表已就绪) return true;
    try {
        await env.DB.batch([
            env.DB.prepare(`CREATE TABLE IF NOT EXISTS usage_snapshots (
                captured_at INTEGER NOT NULL,
                account_id TEXT NOT NULL,
                account_name TEXT,
                pages INTEGER NOT NULL DEFAULT 0,
                workers INTEGER NOT NULL DEFAULT 0,
                d1_rows_read INTEGER NOT NULL DEFAULT 0,
                d1_rows_written INTEGER NOT NULL DEFAULT 0,
                d1_storage_bytes INTEGER NOT NULL DEFAULT 0,
                kv_reads INTEGER NOT NULL DEFAULT 0,
                kv_writes INTEGER NOT NULL DEFAULT 0,
                kv_storage_bytes INTEGER NOT NULL DEFAULT 0,
                r2_class_a INTEGER NOT NULL DEFAULT 0,
                r2_class_b INTEGER NOT NULL DEFAULT 0,
                r2_storage_bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (account_id, captured_at)
            )`),
            env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_usage_snapshots_time ON usage_snapshots(captured_at)')
        ]);
        历史表已就绪 = true;
        return true;
    } catch (error) {
        console.error('初始化历史表失败:', error.message);
        return false;
    }
}

async function 清理历史(env, now = Date.now()) {
    try {
        const 保留天数 = 获取历史保留天数(env);
        const 今天 = new Date(now).toISOString().slice(0, 10);
        // 每天最多清理一次，避免频繁 DELETE 产生额外 rows written
        const 上次清理日 = await env.KV.get('history_cleanup_day');
        if (上次清理日 === 今天) return;
        const 截止时间 = now - 保留天数 * 86400000;
        await env.DB.prepare('DELETE FROM usage_snapshots WHERE captured_at < ?').bind(截止时间).run();
        await env.KV.put('history_cleanup_day', 今天, { expirationTtl: 3 * 86400 });
    } catch (error) {
        console.error('清理历史数据失败:', error.message);
    }
}

async function 写入历史快照(env, usage_config_json) {
    if (!(await 确保历史表(env))) return 0;
    if (!Array.isArray(usage_config_json) || usage_config_json.length === 0) return 0;
    const now = Date.now();
    const 语句 = [];
    for (const account of usage_config_json) {
        const usage = 补全账号Usage结构(account);
        if (!usage.success) continue;
        应用账号限额(usage, account);
        const 资源 = usage.resources || {};
        const d1 = 资源.d1 || {};
        const kv = 资源.kv || {};
        const r2 = 资源.r2 || {};
        语句.push(env.DB.prepare(`INSERT OR REPLACE INTO usage_snapshots
            (captured_at, account_id, account_name, pages, workers,
             d1_rows_read, d1_rows_written, d1_storage_bytes,
             kv_reads, kv_writes, kv_storage_bytes,
             r2_class_a, r2_class_b, r2_storage_bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
            now,
            String(account.ID ?? ''),
            String(account.Name || '').slice(0, 120),
            Number(usage.pages) || 0,
            Number(usage.workers) || 0,
            Number(d1.rowsRead) || 0,
            Number(d1.rowsWritten) || 0,
            Number(d1.storageBytes) || 0,
            Number(kv.reads) || 0,
            Number(kv.writes) || 0,
            Number(kv.storageBytes) || 0,
            Number(r2.classA) || 0,
            Number(r2.classB) || 0,
            Number(r2.storageBytes) || 0
        ));
    }
    if (语句.length === 0) return 0;
    try {
        // 分批写入，避免单次 batch 过大
        for (let i = 0; i < 语句.length; i += 100) {
            await env.DB.batch(语句.slice(i, i + 100));
        }
        await 清理历史(env, now);
        return 语句.length;
    } catch (error) {
        console.error('写入历史快照失败:', error.message);
        return 0;
    }
}

function 历史指标当前值和上限(usage, 指标) {
    const 资源 = usage?.resources || {};
    switch (指标) {
        case 'd1RowsRead': return { current: Number(资源.d1?.rowsRead) || 0, limit: Number(资源.d1?.rowsReadLimit) || 0 };
        case 'd1RowsWritten': return { current: Number(资源.d1?.rowsWritten) || 0, limit: Number(资源.d1?.rowsWrittenLimit) || 0 };
        case 'kvReads': return { current: Number(资源.kv?.reads) || 0, limit: Number(资源.kv?.readsLimit) || 0 };
        case 'kvWrites': return { current: Number(资源.kv?.writes) || 0, limit: Number(资源.kv?.writesLimit) || 0 };
        case 'r2ClassA': return { current: Number(资源.r2?.classA) || 0, limit: Number(资源.r2?.classALimit) || 0 };
        case 'r2ClassB': return { current: Number(资源.r2?.classB) || 0, limit: Number(资源.r2?.classBLimit) || 0 };
        case 'd1Storage': return { current: Number(资源.d1?.storageBytes) || 0, limit: Number(资源.d1?.storageLimitBytes) || 0 };
        case 'kvStorage': return { current: Number(资源.kv?.storageBytes) || 0, limit: Number(资源.kv?.storageLimitBytes) || 0 };
        case 'r2Storage': return { current: Number(资源.r2?.storageBytes) || 0, limit: Number(资源.r2?.storageLimitBytes) || 0 };
        default: return { current: Number(usage?.total) || 0, limit: Number(usage?.max) || 0 };
    }
}

// 只用最近一段数据做线性拟合，给出“按当前速率大约多久到额度”的粗略预测
// 最近不超过 24 个点的线性拟合斜率（单位：值/小时）
function 计算每小时斜率(points) {
    if (!Array.isArray(points) || points.length < 2) return 0;
    const 有效 = points.slice(-24).filter(item => Number.isFinite(item.t) && Number.isFinite(item.v));
    if (有效.length < 2) return 0;
    const 平均t = 有效.reduce((sum, item) => sum + item.t, 0) / 有效.length;
    const 平均v = 有效.reduce((sum, item) => sum + item.v, 0) / 有效.length;
    let 分子 = 0;
    let 分母 = 0;
    for (const item of 有效) {
        const dt = item.t - 平均t;
        分子 += dt * (item.v - 平均v);
        分母 += dt * dt;
    }
    if (分母 === 0) return 0;
    const 斜率 = (分子 / 分母) * 3600000;
    return Number.isFinite(斜率) ? 斜率 : 0;
}

function 计算额度预测(points, 当前值, 上限) {
    const 空结果 = { slopePerHour: 0, hoursToLimit: null };
    if (!Array.isArray(points) || points.length < 2 || !(Number(上限) > 0)) return 空结果;
    const 每小时斜率 = 计算每小时斜率(points);
    if (!Number.isFinite(每小时斜率) || 每小时斜率 <= 0) {
        return { slopePerHour: Math.round(每小时斜率 * 100) / 100, hoursToLimit: null };
    }
    const 当前 = Number(当前值) || 0;
    if (当前 >= Number(上限)) return { slopePerHour: Math.round(每小时斜率 * 100) / 100, hoursToLimit: 0 };
    const 小时 = (Number(上限) - 当前) / 每小时斜率;
    return { slopePerHour: Math.round(每小时斜率 * 100) / 100, hoursToLimit: Number.isFinite(小时) ? Math.round(小时 * 10) / 10 : null };
}

/////////////////////////////////KV 每日历史回退（未绑定 D1 时使用，每天最多 1 次写）//////////////////////////////////

const KV每日历史键 = 'usage_daily.json';

function 构建每日KV快照(usage_json) {
    const 资源 = usage_json?.resources || {};
    const d1 = 资源.d1 || {};
    const kv = 资源.kv || {};
    const r2 = 资源.r2 || {};
    return {
        date: new Date().toISOString().slice(0, 10),
        workers: Number(usage_json?.workers) || 0,
        pages: Number(usage_json?.pages) || 0,
        total: Number(usage_json?.total) || 0,
        max: Number(usage_json?.max) || 0,
        resources: {
            d1: {
                rowsRead: Number(d1.rowsRead) || 0,
                rowsWritten: Number(d1.rowsWritten) || 0,
                storageBytes: Number(d1.storageBytes) || 0,
                rowsReadLimit: Number(d1.rowsReadLimit) || 0,
                rowsWrittenLimit: Number(d1.rowsWrittenLimit) || 0,
                storageLimitBytes: Number(d1.storageLimitBytes) || 0
            },
            kv: {
                reads: Number(kv.reads) || 0,
                writes: Number(kv.writes) || 0,
                storageBytes: Number(kv.storageBytes) || 0,
                readsLimit: Number(kv.readsLimit) || 0,
                writesLimit: Number(kv.writesLimit) || 0,
                storageLimitBytes: Number(kv.storageLimitBytes) || 0
            },
            r2: {
                classA: Number(r2.classA) || 0,
                classB: Number(r2.classB) || 0,
                storageBytes: Number(r2.storageBytes) || 0,
                classALimit: Number(r2.classALimit) || 0,
                classBLimit: Number(r2.classBLimit) || 0,
                storageLimitBytes: Number(r2.storageLimitBytes) || 0
            }
        }
    };
}

// 仅在没有 D1 时启用；每天最多写 1 次（数据不变则不写），避免消耗免费 KV 写额度
async function 保存每日KV快照(env, usage_json) {
    if (历史功能已启用(env)) return;
    try {
        let 历史 = await env.KV.get(KV每日历史键, { type: 'json' });
        if (!历史 || typeof 历史 !== 'object' || Array.isArray(历史)) 历史 = {};
        const 快照 = 构建每日KV快照(usage_json);
        if (!快照.total && !快照.pages && !快照.workers) return;
        const 去掉更新时间 = 对象 => {
            const { UpdateTime, ...其余 } = 对象 || {};
            return JSON.stringify(其余);
        };
        const 现有 = 历史[快照.date];
        if (现有 && 去掉更新时间(现有) === 去掉更新时间(快照)) return;
        快照.UpdateTime = Date.now();
        历史[快照.date] = 快照;
        const 键列表 = Object.keys(历史).sort();
        if (键列表.length > 90) {
            for (const 键 of 键列表.slice(0, 键列表.length - 90)) delete 历史[键];
        }
        await env.KV.put(KV每日历史键, JSON.stringify(历史));
    } catch (error) {
        console.error('保存每日历史失败:', error.message);
    }
}

async function 读取每日KV历史(env) {
    try {
        const 历史 = await env.KV.get(KV每日历史键, { type: 'json' });
        if (!历史 || typeof 历史 !== 'object' || Array.isArray(历史)) return [];
        return Object.values(历史).filter(item => item && item.date).sort((a, b) => String(a.date).localeCompare(String(b.date)));
    } catch (error) {
        console.error('读取每日历史失败:', error.message);
        return [];
    }
}

function 读取每日指标(日快照, 指标) {
    const 资源 = 日快照?.resources || {};
    const d1 = 资源.d1 || {};
    const kv = 资源.kv || {};
    const r2 = 资源.r2 || {};
    switch (指标) {
        case 'd1RowsRead': return Number(d1.rowsRead) || 0;
        case 'd1RowsWritten': return Number(d1.rowsWritten) || 0;
        case 'kvReads': return Number(kv.reads) || 0;
        case 'kvWrites': return Number(kv.writes) || 0;
        case 'r2ClassA': return Number(r2.classA) || 0;
        case 'r2ClassB': return Number(r2.classB) || 0;
        case 'd1Storage': return Number(d1.storageBytes) || 0;
        case 'kvStorage': return Number(kv.storageBytes) || 0;
        case 'r2Storage': return Number(r2.storageBytes) || 0;
        default: return Number(日快照?.total) || 0;
    }
}

async function 处理KV历史查询(env, url) {
    const 指标 = 规范化历史指标(url.searchParams.get('metric'));
    const 账户 = String(url.searchParams.get('account') || 'all');
    const 窗口 = 获取历史窗口(url.searchParams.get('range'));
    if (账户 !== 'all') {
        return new Response(JSON.stringify({ historyEnabled: true, source: 'kv', points: [], msg: 'KV 轻量历史仅记录汇总数据，单账号趋势请绑定 D1' }), { headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    }
    const 历史 = await 读取每日KV历史(env);
    const 起始日期 = new Date(Date.now() - 窗口.毫秒).toISOString().slice(0, 10);
    const points = 历史
        .filter(item => String(item.date) >= 起始日期)
        .map(item => ({ t: Date.parse(String(item.date) + 'T00:00:00Z'), v: 读取每日指标(item, 指标) }))
        .filter(item => Number.isFinite(item.t));

    let 当前值 = 0;
    let 上限 = 0;
    try {
        const usage = 补全Usage结构((await env.KV.get('usage.json', { type: 'json' })) || {});
        const 当前 = 历史指标当前值和上限(usage, 指标);
        当前值 = 当前.current;
        上限 = 当前.limit;
    } catch (error) {
        console.error('读取 KV 历史当前值失败:', error.message);
    }
    return new Response(JSON.stringify({
        historyEnabled: true,
        source: 'kv',
        storage: 'kv',
        range: 窗口.key,
        bucketMs: 86400000,
        metric: 指标,
        account: 'all',
        points,
        current: 当前值,
        limit: 上限,
        forecast: 计算额度预测(points, 当前值, 上限),
        retentionDays: 90,
        msg: points.length > 0 ? undefined : '暂无每日历史：绑定 D1 可记录更细粒度趋势'
    }), { headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
}

async function 处理历史查询(env, url) {
    if (!历史功能已启用(env)) {
        if (env.HISTORY_ENABLED === 'false') {
            return new Response(JSON.stringify({ historyEnabled: false, points: [], msg: '历史功能已通过 HISTORY_ENABLED=false 关闭' }), { headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
        }
        return 处理KV历史查询(env, url);
    }
    const 指标 = 规范化历史指标(url.searchParams.get('metric'));
    const 账户 = String(url.searchParams.get('account') || 'all');
    const 窗口 = 获取历史窗口(url.searchParams.get('range'));
    const 开始时间 = Date.now() - 窗口.毫秒;
    const bucket表达式 = `CAST(captured_at / ${窗口.bucket毫秒} AS INTEGER) * ${窗口.bucket毫秒}`;
    const 指标定义 = 历史指标定义.find(item => item.key === 指标) || 历史指标定义[0];
    const 是存储指标 = 指标 === 'd1Storage' || 指标 === 'kvStorage' || 指标 === 'r2Storage';
    const 账户过滤 = 账户 === 'all' ? '' : ' AND account_id = ?';
    const 查询参数 = 账户 === 'all' ? [开始时间] : [开始时间, 账户];
    let 查询语句;
    if (是存储指标) {
        // 存储是瞬时值：同一时间桶内每个账号只取峰值，再跨账号相加，避免多次快照被重复累加
        查询语句 = `SELECT bucket, SUM(peak_value) AS value FROM (
            SELECT ${bucket表达式} AS bucket, account_id, MAX(${指标定义.sql}) AS peak_value
            FROM usage_snapshots WHERE captured_at >= ?${账户过滤}
            GROUP BY bucket, account_id
        ) GROUP BY bucket ORDER BY bucket ASC LIMIT 500`;
    } else {
        查询语句 = `SELECT ${bucket表达式} AS bucket, SUM(${指标定义.sql}) AS value
            FROM usage_snapshots WHERE captured_at >= ?${账户过滤}
            GROUP BY bucket ORDER BY bucket ASC LIMIT 500`;
    }
    let 查询结果;
    try {
        查询结果 = await env.DB.prepare(查询语句).bind(...查询参数).all();
    } catch (error) {
        console.error('查询历史数据失败:', error.message);
        return new Response(JSON.stringify({ historyEnabled: false, points: [], msg: '查询历史数据失败' }), { headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    }
    const 行列表 = Array.isArray(查询结果?.results) ? 查询结果.results : [];
    const points = 行列表.map(row => ({ t: Number(row.bucket), v: Number(row.value) || 0 }));

    let 当前值 = points.length > 0 ? points[points.length - 1].v : 0;
    let 上限 = 0;
    try {
        if (账户 === 'all') {
            const usage = 补全Usage结构((await env.KV.get('usage.json', { type: 'json' })) || {});
            const 当前 = 历史指标当前值和上限(usage, 指标);
            当前值 = 当前.current;
            上限 = 当前.limit;
        } else {
            const 配置列表 = await 读取账号配置(env);
            const account = Array.isArray(配置列表) ? 配置列表.find(item => String(item.ID) === 账户) : null;
            if (account) {
                const usage = 补全账号Usage结构(account);
                应用账号限额(usage, account);
                const 当前 = 历史指标当前值和上限(usage, 指标);
                当前值 = 当前.current;
                上限 = 当前.limit;
            }
        }
    } catch (error) {
        console.error('查询历史当前值失败:', error.message);
    }

    const 响应头 = { 'Content-Type': 'application/json;charset=UTF-8' };
    // 汇总趋势允许浏览器短暂缓存，降低公开页/重复刷新对 D1 读额度的消耗；单账号数据不缓存
    if (账户 === 'all') 响应头['Cache-Control'] = 'public, max-age=60';

    return new Response(JSON.stringify({
        historyEnabled: true,
        range: 窗口.key,
        bucketMs: 窗口.bucket毫秒,
        metric: 指标,
        account: 账户,
        points,
        current: 当前值,
        limit: 上限,
        forecast: 计算额度预测(points, 当前值, 上限),
        retentionDays: 获取历史保留天数(env)
    }), { headers: 响应头 });
}

/////////////////////////////////报告导出//////////////////////////////////

async function 读取导出历史(env, days) {
    const 截止 = Date.now() - days * 86400000;
    const 起始日期 = new Date(截止).toISOString().slice(0, 10);
    if (历史功能已启用(env)) {
        await 确保历史表(env);
        try {
            const 结果 = await env.DB.prepare(`SELECT CAST(captured_at / 86400000 AS INTEGER) * 86400000 AS bucket,
                SUM(pages) AS pages, SUM(workers) AS workers,
                SUM(d1_rows_read) AS d1_rows_read, SUM(d1_rows_written) AS d1_rows_written,
                SUM(kv_reads) AS kv_reads, SUM(kv_writes) AS kv_writes,
                SUM(r2_class_a) AS r2_class_a, SUM(r2_class_b) AS r2_class_b
                FROM usage_snapshots WHERE captured_at >= ? GROUP BY bucket ORDER BY bucket ASC`).bind(截止).all();
            const 行列表 = Array.isArray(结果?.results) ? 结果.results : [];
            return {
                source: 'd1',
                rows: 行列表.map(item => ({
                    date: new Date(Number(item.bucket)).toISOString().slice(0, 10),
                    pages: Number(item.pages) || 0,
                    workers: Number(item.workers) || 0,
                    total: (Number(item.pages) || 0) + (Number(item.workers) || 0),
                    d1Read: Number(item.d1_rows_read) || 0,
                    d1Write: Number(item.d1_rows_written) || 0,
                    kvRead: Number(item.kv_reads) || 0,
                    kvWrite: Number(item.kv_writes) || 0,
                    r2ClassA: Number(item.r2_class_a) || 0,
                    r2ClassB: Number(item.r2_class_b) || 0
                }))
            };
        } catch (error) {
            console.error('导出历史查询失败:', error.message);
        }
    }
    const 每日历史 = await 读取每日KV历史(env);
    return {
        source: 'kv',
        rows: 每日历史.filter(item => String(item.date) >= 起始日期).map(item => ({
            date: item.date,
            pages: Number(item.pages) || 0,
            workers: Number(item.workers) || 0,
            total: Number(item.total) || 0,
            d1Read: Number(item.resources?.d1?.rowsRead) || 0,
            d1Write: Number(item.resources?.d1?.rowsWritten) || 0,
            kvRead: Number(item.resources?.kv?.reads) || 0,
            kvWrite: Number(item.resources?.kv?.writes) || 0,
            r2ClassA: Number(item.resources?.r2?.classA) || 0,
            r2ClassB: Number(item.resources?.r2?.classB) || 0
        }))
    };
}

async function 检测用量异常(env, url) {
    if (!历史功能已启用(env)) {
        return new Response(JSON.stringify({ success: true, available: false, msg: '异常检测需要绑定 D1 历史', anomalies: [] }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    }
    if (!(await 确保历史表(env))) {
        return new Response(JSON.stringify({ success: false, available: false, msg: '历史表不可用', anomalies: [] }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    }
    const 天数 = Math.min(30, Math.max(2, Number(url.searchParams.get('days')) || 7));
    const 开始 = Date.now() - 天数 * 86400000;
    try {
        const 结果 = await env.DB.prepare(`SELECT CAST(captured_at / 3600000 AS INTEGER) * 3600000 AS bucket,
            SUM(pages + workers) AS requests,
            SUM(d1_rows_read) AS d1RowsRead,
            SUM(d1_rows_written) AS d1RowsWritten,
            SUM(kv_reads) AS kvReads,
            SUM(kv_writes) AS kvWrites,
            SUM(r2_class_a) AS r2ClassA,
            SUM(r2_class_b) AS r2ClassB
            FROM usage_snapshots WHERE captured_at >= ? GROUP BY bucket ORDER BY bucket ASC LIMIT 1000`).bind(开始).all();
        const 行列表 = Array.isArray(结果?.results) ? 结果.results : [];
        if (行列表.length < 6) {
            return new Response(JSON.stringify({ success: true, available: true, points: 行列表.length, anomalies: [], msg: '数据点不足，至少需要 6 个时间桶' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
        }
        const 指标 = [
            { key: 'requests', label: 'Workers+Pages 请求' },
            { key: 'd1RowsRead', label: 'D1 读取' },
            { key: 'd1RowsWritten', label: 'D1 写入' },
            { key: 'kvReads', label: 'KV 读取' },
            { key: 'kvWrites', label: 'KV 写入' },
            { key: 'r2ClassA', label: 'R2 Class A' },
            { key: 'r2ClassB', label: 'R2 Class B' }
        ];
        const 异常列表 = [];
        for (const 指标项 of 指标) {
            const 值列表 = 行列表.map(item => Number(item[指标项.key]) || 0);
            const 最新值 = 值列表[值列表.length - 1];
            const 基线 = 值列表.slice(0, -1);
            if (基线.length < 5) continue;
            const 均值 = 基线.reduce((sum, value) => sum + value, 0) / 基线.length;
            const 方差 = 基线.reduce((sum, value) => sum + (value - 均值) ** 2, 0) / 基线.length;
            const 标准差 = Math.sqrt(方差);
            if (标准差 <= 0) continue;
            const z = (最新值 - 均值) / 标准差;
            const 比率 = 均值 > 0 ? 最新值 / 均值 : (最新值 > 0 ? 99 : 1);
            if (z >= 3 && 比率 >= 1.5) {
                异常列表.push({
                    metric: 指标项.key,
                    label: 指标项.label,
                    latest: 最新值,
                    baselineMean: Math.round(均值 * 100) / 100,
                    zScore: Math.round(z * 100) / 100,
                    ratio: Math.round(比率 * 100) / 100
                });
            }
        }
        异常列表.sort((a, b) => b.zScore - a.zScore);
        return new Response(JSON.stringify({
            success: true,
            available: true,
            days: 天数,
            points: 行列表.length,
            anomalies: 异常列表,
            msg: 异常列表.length > 0 ? `检测到 ${异常列表.length} 项异常` : '未检测到明显异常',
            generatedAt: new Date().toISOString(),
            note: '基于最近时间桶与历史均值的 Z-Score（≥3 且 ≥1.5 倍）；D1/KV 为日累计计数器，跨 UTC 日重置时可能产生波动，仅作参考。'
        }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    } catch (error) {
        console.error('异常检测失败:', error.message);
        return new Response(JSON.stringify({ success: false, available: false, msg: '异常检测失败: ' + error.message, anomalies: [] }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    }
}

function 构建导出账号列表(配置列表) {
    return (Array.isArray(配置列表) ? 配置列表 : []).map(account => {
        const usage = 补全账号Usage结构(account);
        应用账号限额(usage, account);
        return {
            ID: account.ID,
            Name: account.Name || ('账号 ' + account.ID),
            AccountID: account.AccountID || null,
            Email: account.Email || null,
            Limits: account.Limits || null,
            UpdateTime: account.UpdateTime || null,
            Usage: {
                total: usage.total || 0,
                max: usage.max || 0,
                percent: usage.max > 0 ? Number((((usage.total || 0) / usage.max) * 100).toFixed(1)) : 0,
                workers: usage.workers || 0,
                pages: usage.pages || 0,
                resources: usage.resources || {}
            }
        };
    });
}

async function 处理导出报告(env, url) {
    const 格式 = String(url.searchParams.get('format') || 'json').toLowerCase() === 'csv' ? 'csv' : 'json';
    const 天数 = Math.min(365, Math.max(1, Number(url.searchParams.get('days')) || 30));
    const [配置列表, 告警配置] = await Promise.all([
        读取账号配置(env),
        读取告警配置(env)
    ]);
    const 账号列表 = 构建导出账号列表(配置列表);
    const 历史 = await 读取导出历史(env, 天数);
    const 总计 = 账号列表.reduce((sum, account) => sum + (Number(account.Usage.total) || 0), 0);

    if (格式 === 'csv') {
        let csv = '\uFEFF日期,Workers,Pages,合计,D1读取,D1写入,KV读取,KV写入,R2 ClassA,R2 ClassB\n';
        for (const 行 of 历史.rows) {
            csv += `${行.date},${行.workers},${行.pages},${行.total},${行.d1Read},${行.d1Write},${行.kvRead},${行.kvWrite},${行.r2ClassA},${行.r2ClassB}\n`;
        }
        return new Response(csv, { status: 200, headers: { 'Content-Type': 'text/csv;charset=utf-8', 'Content-Disposition': `attachment; filename="cf-usage-${new Date().toISOString().slice(0, 10)}.csv"` } });
    }

    const 报告 = {
        导出时间: new Date().toISOString(),
        统计天数: 天数,
        历史来源: 历史.source,
        账号数: 账号列表.length,
        总用量: 总计,
        账号列表,
        告警配置: {
            启用: 告警配置.enabled,
            冷却分钟: 告警配置.cooldownMinutes,
            阈值: 告警配置.thresholds,
            预测: 告警配置.forecast,
            每日报告: 告警配置.dailyReport,
            渠道: { telegram: 告警配置.telegram.enabled, webhook: 告警配置.webhook.enabled, webhook平台: 告警配置.webhook.platform }
        },
        历史: 历史.rows
    };
    return new Response(JSON.stringify(报告, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8', 'Content-Disposition': `attachment; filename="cf-usage-${new Date().toISOString().slice(0, 10)}.json"` } });
}

/////////////////////////////////用量优化建议//////////////////////////////////

const 通用优化建议列表 = [
    { ruleId: 'general_cache_api', severity: 'high', title: '为高频请求启用 Cache API', description: '重复请求直接回源会消耗 Worker 请求、CPU 和外部子请求额度。', suggestion: '对可缓存的 GET 响应使用 caches.default.match/put，并在响应上设置合理 Cache-Control。' },
    { ruleId: 'general_kv_reads', severity: 'high', title: '减少不必要的 KV 读取', description: 'KV 免费额度为 10 万读/天，热点路径上的 KV get 很容易放大。', suggestion: '在 isolate 内做短期缓存、合并重复读取，或把高频配置放到环境变量/静态资源。' },
    { ruleId: 'general_kv_writes', severity: 'high', title: '控制 KV 写入频率', description: 'KV 免费额度仅 1000 写/天，同一 key 还有 1 次/秒限制。', suggestion: '只在数据变化时写入，合并批量更新，避免在每次请求路径中写 KV。' },
    { ruleId: 'general_r2_class_a', severity: 'medium', title: '减少 R2 Class A 操作', description: 'ListObjects/ListParts/PutObject 等 Class A 操作用量更大，免费 100 万/月。', suggestion: '避免在请求路径中 List 全桶，必要时缓存列表结果或使用对象 key 直读。' },
    { ruleId: 'general_subrequests', severity: 'medium', title: '控制单次请求的外部子请求数', description: '免费计划每个请求最多 50 个子请求，过多并发/串行外部请求容易超限。', suggestion: '合并 API 调用、使用 Promise.all 限制并发，并做超时与失败降级。' },
    { ruleId: 'general_storage', severity: 'medium', title: '定期清理 D1/KV/R2 存储', description: 'KV/D1/R2 的免费存储分别是 1GB/5GB/10GB，历史数据无限增长会逐渐逼近上限。', suggestion: '设置保留期与清理任务，R2 配置生命周期规则，D1 定期 DELETE 过期行。' }
];

function 添加脚本优化建议(建议列表, 脚本名, 规则) {
    建议列表.push({ scriptName: 脚本名, ...规则 });
}

function 分析Worker脚本内容(脚本名, 内容, 建议列表) {
    if (!内容 || typeof 内容 !== 'string') return;
    const 长度 = 内容.length;
    const 有缓存 = /caches\.(default|open)/.test(内容);
    const 有fetch = /(^|[^\w.])fetch\s*\(/.test(内容);
    const 有KV = /KV|kv/.test(内容) && /\.(get|put|list|delete)\s*\(/.test(内容);
    const 有R2 = /R2|r2|BUCKET|bucket/.test(内容) && /\.(get|put|list|delete|head)\s*\(/.test(内容);
    const 有定时器 = /setInterval\s*\(/.test(内容) || /setTimeout\s*\(/.test(内容);
    const 有动态执行 = /\beval\s*\(/.test(内容) || /new\s+Function\s*\(/.test(内容);
    const 顺序await = /for\s*\([^)]*\)\s*\{[\s\S]{0,600}?await\s+/.test(内容);
    const 控制台次数 = (内容.match(/console\.(log|warn|error)\s*\(/g) || []).length;

    if (长度 > 1.2 * 1024 * 1024) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'bundle_too_large',
            severity: 'high',
            title: '脚本体积偏大（超过 1.2 MB）',
            description: '大体积脚本会增加部署、冷启动和内存压力，免费 Worker 还有体积上限。',
            suggestion: '将静态资源、图片和大段 JSON 移到 Workers Static Assets 或 R2，用构建工具压缩代码。'
        });
    }
    if (!有缓存 && 有fetch) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'missing-cache-api',
            severity: 'high',
            title: '缺少 Cache API 缓存',
            description: '脚本中存在 fetch 调用但没有使用 caches.default / caches.open，重复请求会反复回源。',
            suggestion: '对可缓存的 GET 响应使用 Cache API：match → 未命中再 fetch → waitUntil(put)。'
        });
    }
    if (/\.list\s*\(/.test(内容)) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'list-operation',
            severity: 'high',
            title: '检测到 list 操作',
            description: 'KV list 与 R2 ListObjects 都属于高成本操作，频繁调用会快速消耗额度。',
            suggestion: '缓存 list 结果、改为按已知 key 直读，或用 D1 维护索引。'
        });
    }
    if (有KV && !有缓存) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'kv-read-without-cache',
            severity: 'medium',
            title: 'KV 读取未配合缓存',
            description: 'KV get 在热点路径中会消耗每日读额度，免费用户尤其明显。',
            suggestion: '在 isolate 内做短 TTL 缓存，或把不常变化的配置放到 env/静态资源。'
        });
    }
    if (有R2 && /\.list\s*\(|\.put\s*\(/.test(内容) && !有缓存) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'r2-class-a',
            severity: 'medium',
            title: 'R2 操作可能偏多',
            description: 'R2 PutObject/ListObjects 属于 Class A 操作，免费额度 100 万/月。',
            suggestion: '减少不必要的 Put/List，合并写入，列表结果做缓存。'
        });
    }
    if (有定时器) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'timer-misuse',
            severity: 'medium',
            title: '使用 setInterval/setTimeout',
            description: 'Worker 请求结束后定时器不一定继续执行，不能依赖它做后台任务。',
            suggestion: '改用 Cron Triggers、Durable Objects Alarms 或 Queues 做定时/后台任务。'
        });
    }
    if (有动态执行) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'dynamic-eval',
            severity: 'medium',
            title: '使用 eval / new Function',
            description: '动态执行代码会带来安全风险和额外 CPU 开销，也不利于缓存。',
            suggestion: '移除动态执行逻辑，改为静态分支或配置驱动。'
        });
    }
    if (顺序await) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'sequential-await',
            severity: 'medium',
            title: '循环中串行 await',
            description: '在循环里逐个 await 会显著拉长请求耗时并增加超时风险。',
            suggestion: '改用 Promise.all 控制并发（注意免费计划 6 个并发连接限制）。'
        });
    }
    if (/\.put\s*\(/.test(内容) && !/waitUntil/.test(内容)) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'missing-waituntil',
            severity: 'low',
            title: '写操作可能未使用 ctx.waitUntil',
            description: '响应返回后的异步写入如果没有 waitUntil，可能在请求结束后被取消。',
            suggestion: '对非关键后台写入使用 ctx.waitUntil(...) 包裹。'
        });
    }
    if (控制台次数 > 20) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'excessive-console',
            severity: 'low',
            title: '日志调用较多',
            description: '大量 console 日志会占用日志额度并增加 CPU 开销。',
            suggestion: '生产环境降低日志级别，只保留关键错误。'
        });
    }
    if (有fetch && !/AbortSignal|AbortController/.test(内容)) {
        添加脚本优化建议(建议列表, 脚本名, {
            ruleId: 'fetch-no-timeout',
            severity: 'low',
            title: '外部 fetch 未设置超时',
            description: '外部请求挂起会拖长整个 Worker 请求，影响可用性。',
            suggestion: '使用 AbortSignal.timeout(...) 或自定义 AbortController 设置超时，并做失败降级。'
        });
    }
}

function 优化建议严重度排序(建议列表) {
    const 顺序 = { high: 0, medium: 1, low: 2 };
    return 建议列表.slice().sort((a, b) => (顺序[a.severity] ?? 3) - (顺序[b.severity] ?? 3));
}

async function 分析用量优化建议(env, url) {
    const fallback = (错误信息, 额外 = {}) => new Response(JSON.stringify({
        success: false,
        error: 错误信息,
        fallback: true,
        tips: 通用优化建议列表,
        ...额外
    }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });

    try {
        let 配置列表 = await 读取账号配置(env);
        if (!Array.isArray(配置列表) || 配置列表.length === 0) {
            return fallback('尚未配置任何 Cloudflare 账号', { accountName: null, suggestions: [] });
        }
        const 指定账号 = String(url.searchParams.get('account') || '');
        const account = 指定账号
            ? 配置列表.find(item => String(item.ID) === 指定账号)
            : 配置列表[0];
        if (!account) return fallback('未找到指定账号', { suggestions: [] });

        const API = 'https://api.cloudflare.com/client/v4';
        const hdr = account.APIToken
            ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${account.APIToken}` }
            : { 'Content-Type': 'application/json', 'X-AUTH-EMAIL': account.Email, 'X-AUTH-KEY': account.GlobalAPIKey };
        let accountId = account.AccountID || null;
        if (!accountId) {
            accountId = await 获取Cloudflare账户ID(API, hdr, account.Email);
        }

        // 限制本轮外部子请求数量：最多分析 OPTIMIZE_MAX_SCRIPTS 个脚本（默认 6，最多 20）
        const 最大脚本数 = Math.min(20, Math.max(1, Number(env.OPTIMIZE_MAX_SCRIPTS) || 6));
        const 列表响应 = await fetch(`${API}/accounts/${accountId}/workers/scripts`, { method: 'GET', headers: hdr });
        if (!列表响应.ok) {
            const 提示 = 列表响应.status === 403
                ? '当前 API Token 缺少 Workers Scripts:Read 权限，无法读取脚本内容；可继续参考通用建议。'
                : `读取 Workers 脚本列表失败（HTTP ${列表响应.status}）`;
            return fallback(提示, { accountName: account.Name || ('账号 ' + account.ID), permissionHint: 列表响应.status === 403, suggestions: [] });
        }
        const 列表数据 = await 列表响应.json();
        const 脚本列表 = Array.isArray(列表数据?.result) ? 列表数据.result : [];
        const 待分析 = 脚本列表.slice(0, 最大脚本数);
        const 建议列表 = [];
        let 已分析 = 0;

        for (const script of 待分析) {
            const 脚本名 = String(script.id || script.name || '未命名脚本');
            try {
                const 内容响应 = await fetch(`${API}/accounts/${accountId}/workers/scripts/${encodeURIComponent(脚本名)}`, { method: 'GET', headers: hdr });
                if (!内容响应.ok) continue;
                let 脚本内容 = '';
                const 文本 = await 内容响应.text();
                try {
                    const JSON数据 = JSON.parse(文本);
                    脚本内容 = JSON数据?.result?.script || JSON数据?.result || '';
                } catch (解析错误) {
                    脚本内容 = 文本;
                }
                if (typeof 脚本内容 !== 'string') 脚本内容 = '';
                已分析 += 1;
                if (脚本内容.length > 2 * 1024 * 1024) {
                    添加脚本优化建议(建议列表, 脚本名, {
                        ruleId: 'content_too_large',
                        severity: 'high',
                        title: '脚本内容过大，跳过深度分析',
                        description: '单脚本内容超过 2 MB，已跳过逐行分析以避免占用过多资源。',
                        suggestion: '优先拆分/压缩脚本，或改用静态资源托管。'
                    });
                    continue;
                }
                分析Worker脚本内容(脚本名, 脚本内容, 建议列表);
            } catch (内容错误) {
                console.error(`分析脚本 ${脚本名} 失败:`, 内容错误.message);
            }
        }

        return new Response(JSON.stringify({
            success: true,
            accountName: account.Name || ('账号 ' + account.ID),
            totalWorkers: 脚本列表.length,
            analyzedWorkers: 已分析,
            truncated: 脚本列表.length > 待分析.length,
            maxScripts: 最大脚本数,
            suggestions: 优化建议严重度排序(建议列表),
            tips: 通用优化建议列表,
            fetchedAt: new Date().toISOString()
        }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    } catch (error) {
        console.error('优化分析失败:', error.message);
        return fallback('优化分析失败: ' + error.message, { suggestions: [] });
    }
}

/////////////////////////////////费用估算（按 Workers Paid 公开价格）//////////////////////////////////

const 默认定价 = {
    workersBaseMonthly: 5,
    workersRequestsIncluded: 10000000,
    workersRequestsPerMillion: 0.30,
    kvReadsIncluded: 10000000,
    kvReadsPerMillion: 0.50,
    kvWritesIncluded: 1000000,
    kvWritesPerMillion: 5.00,
    kvDeletesIncluded: 1000000,
    kvDeletesPerMillion: 5.00,
    kvListsIncluded: 1000000,
    kvListsPerMillion: 5.00,
    kvStorageIncludedGb: 1,
    kvStoragePerGb: 0.50,
    d1RowsReadIncluded: 25000000000,
    d1RowsReadPerMillion: 0.001,
    d1RowsWrittenIncluded: 50000000,
    d1RowsWrittenPerMillion: 1.00,
    d1StorageIncludedGb: 5,
    d1StoragePerGb: 0.75,
    r2ClassAIncluded: 1000000,
    r2ClassAPerMillion: 4.50,
    r2ClassBIncluded: 10000000,
    r2ClassBPerMillion: 0.36,
    r2StorageIncludedGb: 10,
    r2StoragePerGb: 0.015
};

function 获取定价(env) {
    const 定价 = { ...默认定价 };
    if (env && env.PRICING_JSON) {
        try {
            const 自定义 = JSON.parse(env.PRICING_JSON);
            for (const 键 of Object.keys(默认定价)) {
                const 数值 = Number(自定义?.[键]);
                if (Number.isFinite(数值) && 数值 >= 0) 定价[键] = 数值;
            }
        } catch (error) {
            console.error('PRICING_JSON 解析失败，使用默认定价:', error.message);
        }
    }
    return 定价;
}

function 按百万计费(数量, 包含量, 每百万单价) {
    return Math.max(0, (Number(数量) || 0) - (Number(包含量) || 0)) / 1000000 * (Number(每百万单价) || 0);
}

function 字节转GB(字节) {
    return (Number(字节) || 0) / (1024 * 1024 * 1024);
}

function 金额取两位(数值) {
    return Math.round((Number(数值) || 0) * 100) / 100;
}

async function 计算费用估算(env) {
    const 定价 = 获取定价(env);
    const 配置列表 = await 读取账号配置(env);
    const 账号列表 = Array.isArray(配置列表) ? 配置列表 : [];
    const 结果账号 = [];
    let 总基础费用 = 0;
    let 总超额费用 = 0;

    for (const account of 账号列表) {
        const usage = 补全账号Usage结构(account);
        应用账号限额(usage, account);
        const 资源 = usage.resources || {};
        const d1 = 资源.d1 || {};
        const kv = 资源.kv || {};
        const r2 = 资源.r2 || {};
        const 月请求 = (Number(usage.total) || 0) * 30;
        const 月KV读 = (Number(kv.reads) || 0) * 30;
        const 月KV写 = (Number(kv.writes) || 0) * 30;
        const 月KV删 = (Number(kv.deletes) || 0) * 30;
        const 月KV列 = (Number(kv.lists) || 0) * 30;
        const 月D1读 = (Number(d1.rowsRead) || 0) * 30;
        const 月D1写 = (Number(d1.rowsWritten) || 0) * 30;
        const 月R2A = Number(r2.classA) || 0;
        const 月R2B = Number(r2.classB) || 0;
        const KV存储GB = 字节转GB(kv.storageBytes);
        const D1存储GB = 字节转GB(d1.storageBytes);
        const R2存储GB = 字节转GB(r2.storageBytes);

        const 超额 = {
            workersRequests: 按百万计费(月请求, 定价.workersRequestsIncluded, 定价.workersRequestsPerMillion),
            kvReads: 按百万计费(月KV读, 定价.kvReadsIncluded, 定价.kvReadsPerMillion),
            kvWrites: 按百万计费(月KV写, 定价.kvWritesIncluded, 定价.kvWritesPerMillion),
            kvDeletes: 按百万计费(月KV删, 定价.kvDeletesIncluded, 定价.kvDeletesPerMillion),
            kvLists: 按百万计费(月KV列, 定价.kvListsIncluded, 定价.kvListsPerMillion),
            kvStorage: Math.max(0, KV存储GB - 定价.kvStorageIncludedGb) * 定价.kvStoragePerGb,
            d1RowsRead: 按百万计费(月D1读, 定价.d1RowsReadIncluded, 定价.d1RowsReadPerMillion),
            d1RowsWritten: 按百万计费(月D1写, 定价.d1RowsWrittenIncluded, 定价.d1RowsWrittenPerMillion),
            d1Storage: Math.max(0, D1存储GB - 定价.d1StorageIncludedGb) * 定价.d1StoragePerGb,
            r2ClassA: 按百万计费(月R2A, 定价.r2ClassAIncluded, 定价.r2ClassAPerMillion),
            r2ClassB: 按百万计费(月R2B, 定价.r2ClassBIncluded, 定价.r2ClassBPerMillion),
            r2Storage: Math.max(0, R2存储GB - 定价.r2StorageIncludedGb) * 定价.r2StoragePerGb
        };
        const 超额合计 = Object.values(超额).reduce((sum, value) => sum + value, 0);
        总基础费用 += 定价.workersBaseMonthly;
        总超额费用 += 超额合计;
        结果账号.push({
            ID: account.ID,
            Name: account.Name || ('账号 ' + account.ID),
            基础费用: 金额取两位(定价.workersBaseMonthly),
            超额费用: 金额取两位(超额合计),
            估算月费: 金额取两位(定价.workersBaseMonthly + 超额合计),
            超额明细: Object.fromEntries(Object.entries(超额).map(([键, 值]) => [键, 金额取两位(值)])),
            投影月用量: {
                requests: 月请求,
                kvReads: 月KV读,
                kvWrites: 月KV写,
                kvDeletes: 月KV删,
                kvLists: 月KV列,
                d1RowsRead: 月D1读,
                d1RowsWritten: 月D1写,
                r2ClassA: 月R2A,
                r2ClassB: 月R2B
            },
            存储GB: {
                kv: Math.round(KV存储GB * 1000) / 1000,
                d1: Math.round(D1存储GB * 1000) / 1000,
                r2: Math.round(R2存储GB * 1000) / 1000
            }
        });
    }

    return {
        success: true,
        currency: 'USD',
        generatedAt: new Date().toISOString(),
        账号数: 账号列表.length,
        总基础费用: 金额取两位(总基础费用),
        总超额费用: 金额取两位(总超额费用),
        总估算月费: 金额取两位(总基础费用 + 总超额费用),
        账号: 结果账号,
        定价,
        假设: [
            '按当前日用量 × 30 天线性外推（R2 操作按本月累计值）；实际账单以 Cloudflare 为准。',
            '费用为每个账号升级 Workers Paid（$5/月/账号）后的估算，含基础订阅费；不含 CPU 时间、日志、队列、Durable Objects 等其他计费项。',
            '免费额度未计入套餐包含量；超出 Workers Paid 包含量才产生超额费用。',
            '可通过环境变量 PRICING_JSON 覆盖默认单价。'
        ]
    };
}

/////////////////////////////////Top N 脚本与错误率（管理员手动查询）//////////////////////////////////

async function 查询Top脚本(env, url) {
    const 回退 = (错误信息) => new Response(JSON.stringify({ success: false, error: 错误信息, fallback: true, scripts: [] }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    try {
        const 配置列表 = await 读取账号配置(env);
        if (!Array.isArray(配置列表) || 配置列表.length === 0) return 回退('尚未配置任何 Cloudflare 账号');
        const 指定账号 = String(url.searchParams.get('account') || '');
        const account = 指定账号 ? 配置列表.find(item => String(item.ID) === 指定账号) : 配置列表[0];
        if (!account) return 回退('未找到指定账号');
        const 范围 = String(url.searchParams.get('range') || '24h');
        const 范围毫秒 = 范围 === '7d' ? 7 * 86400000 : 范围 === '30d' ? 30 * 86400000 : 86400000;
        const 现在 = new Date();
        const 开始 = new Date(现在.getTime() - 范围毫秒);
        const API = 'https://api.cloudflare.com/client/v4';
        const hdr = account.APIToken
            ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${account.APIToken}` }
            : { 'Content-Type': 'application/json', 'X-AUTH-EMAIL': account.Email, 'X-AUTH-KEY': account.GlobalAPIKey };
        let accountId = account.AccountID || null;
        if (!accountId) accountId = await 获取Cloudflare账户ID(API, hdr, account.Email);

        const account_data = await 发送GraphQL请求(API, hdr, `query TopScripts($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
            viewer { accounts(filter: {accountTag: $AccountID}) {
                workersInvocationsAdaptive(limit: 1000, filter: $filter) {
                    sum { requests errors }
                    dimensions { scriptName }
                }
            } }
        }`, {
            AccountID: accountId,
            filter: { datetime_geq: 开始.toISOString(), datetime_leq: 现在.toISOString() }
        });

        const 聚合 = new Map();
        const 分组列表 = Array.isArray(account_data.workersInvocationsAdaptive) ? account_data.workersInvocationsAdaptive : [];
        for (const group of 分组列表) {
            const name = String(group?.dimensions?.scriptName || '未知脚本');
            const requests = Number(group?.sum?.requests) || 0;
            const errors = Number(group?.sum?.errors) || 0;
            if (!聚合.has(name)) 聚合.set(name, { name, requests: 0, errors: 0 });
            const 项 = 聚合.get(name);
            项.requests += requests;
            项.errors += errors;
        }
        const 脚本列表 = Array.from(聚合.values())
            .map(item => ({ ...item, errorRate: item.requests > 0 ? Math.round((item.errors / item.requests) * 10000) / 100 : 0 }))
            .sort((a, b) => b.requests - a.requests)
            .slice(0, 10);
        const 总请求 = Array.from(聚合.values()).reduce((sum, item) => sum + item.requests, 0);
        const 总错误 = Array.from(聚合.values()).reduce((sum, item) => sum + item.errors, 0);
        return new Response(JSON.stringify({
            success: true,
            accountName: account.Name || ('账号 ' + account.ID),
            range: 范围,
            scriptCount: 聚合.size,
            totalRequests: 总请求,
            totalErrors: 总错误,
            errorRate: 总请求 > 0 ? Math.round((总错误 / 总请求) * 10000) / 100 : 0,
            scripts: 脚本列表,
            fetchedAt: new Date().toISOString()
        }), { status: 200, headers: { 'Content-Type': 'application/json;charset=UTF-8' } });
    } catch (error) {
        console.error('Top 脚本查询失败:', error.message);
        return 回退('Top 脚本查询失败: ' + error.message);
    }
}

function 创建默认资源统计() {
    return {
        d1: {
            rowsRead: 0,
            rowsReadLimit: 免费额度.d1RowsReadDaily,
            rowsWritten: 0,
            rowsWrittenLimit: 免费额度.d1RowsWrittenDaily,
            readQueries: 0,
            writeQueries: 0,
            storageBytes: 0,
            storageLimitBytes: 免费额度.d1StorageBytes,
            databases: 0,
            period: 'day'
        },
        kv: {
            reads: 0,
            readsLimit: 免费额度.kvReadsDaily,
            writes: 0,
            writesLimit: 免费额度.kvWritesDaily,
            deletes: 0,
            deletesLimit: 免费额度.kvDeletesDaily,
            lists: 0,
            listsLimit: 免费额度.kvListsDaily,
            operations: 0,
            storageBytes: 0,
            storageLimitBytes: 免费额度.kvStorageBytes,
            keys: 0,
            namespaces: 0,
            period: 'day'
        },
        r2: {
            classA: 0,
            classALimit: 免费额度.r2ClassAMonthly,
            classB: 0,
            classBLimit: 免费额度.r2ClassBMonthly,
            free: 0,
            other: 0,
            operations: 0,
            storageBytes: 0,
            storageLimitBytes: 免费额度.r2StorageBytes,
            objects: 0,
            buckets: 0,
            period: 'month'
        }
    };
}

function 创建汇总资源统计() {
    const resources = 创建默认资源统计();
    resources.d1.rowsReadLimit = 0;
    resources.d1.rowsWrittenLimit = 0;
    resources.d1.storageLimitBytes = 0;
    resources.kv.readsLimit = 0;
    resources.kv.writesLimit = 0;
    resources.kv.deletesLimit = 0;
    resources.kv.listsLimit = 0;
    resources.kv.storageLimitBytes = 0;
    resources.r2.classALimit = 0;
    resources.r2.classBLimit = 0;
    resources.r2.storageLimitBytes = 0;
    return resources;
}

function 创建默认Usage(success = false, msg = '❌ 暂无用量数据') {
    return {
        success,
        pages: 0,
        workers: 0,
        total: 0,
        max: success ? 免费额度.requestsDaily : 0,
        resources: 创建默认资源统计(),
        UpdateTime: Date.now(),
        msg
    };
}

function 合并资源统计(base, extra = {}) {
    const merged = { ...base };
    for (const key of Object.keys(base)) {
        merged[key] = { ...base[key], ...(extra?.[key] || {}) };
    }
    return merged;
}

function 补全Usage结构(usage) {
    const source = usage || {};
    const base = 创建默认Usage(false);
    const normalized = { ...base, ...source };
    const updateTime = Number(source.UpdateTime || 0) || 0;
    const hasResourceData = !!source.resources;
    normalized.pages = Number(normalized.pages) || 0;
    normalized.workers = Number(normalized.workers) || 0;
    normalized.total = Number(normalized.total) || normalized.pages + normalized.workers;
    normalized.max = Number(normalized.max) || 免费额度.requestsDaily;
    normalized.UpdateTime = updateTime;
    normalized.resources = 合并资源统计(hasResourceData ? 创建默认资源统计() : 创建汇总资源统计(), normalized.resources || {});
    return normalized;
}

function 累加资源统计(target, source) {
    const data = 合并资源统计(创建默认资源统计(), source || {});

    target.d1.rowsRead += data.d1.rowsRead || 0;
    target.d1.rowsReadLimit += data.d1.rowsReadLimit || 免费额度.d1RowsReadDaily;
    target.d1.rowsWritten += data.d1.rowsWritten || 0;
    target.d1.rowsWrittenLimit += data.d1.rowsWrittenLimit || 免费额度.d1RowsWrittenDaily;
    target.d1.readQueries += data.d1.readQueries || 0;
    target.d1.writeQueries += data.d1.writeQueries || 0;
    target.d1.storageBytes += data.d1.storageBytes || 0;
    target.d1.storageLimitBytes += data.d1.storageLimitBytes || 免费额度.d1StorageBytes;
    target.d1.databases += data.d1.databases || 0;

    target.kv.reads += data.kv.reads || 0;
    target.kv.readsLimit += data.kv.readsLimit || 免费额度.kvReadsDaily;
    target.kv.writes += data.kv.writes || 0;
    target.kv.writesLimit += data.kv.writesLimit || 免费额度.kvWritesDaily;
    target.kv.deletes += data.kv.deletes || 0;
    target.kv.deletesLimit += data.kv.deletesLimit || 免费额度.kvDeletesDaily;
    target.kv.lists += data.kv.lists || 0;
    target.kv.listsLimit += data.kv.listsLimit || 免费额度.kvListsDaily;
    target.kv.operations += data.kv.operations || 0;
    target.kv.storageBytes += data.kv.storageBytes || 0;
    target.kv.storageLimitBytes += data.kv.storageLimitBytes || 免费额度.kvStorageBytes;
    target.kv.keys += data.kv.keys || 0;
    target.kv.namespaces += data.kv.namespaces || 0;

    target.r2.classA += data.r2.classA || 0;
    target.r2.classALimit += data.r2.classALimit || 免费额度.r2ClassAMonthly;
    target.r2.classB += data.r2.classB || 0;
    target.r2.classBLimit += data.r2.classBLimit || 免费额度.r2ClassBMonthly;
    target.r2.free += data.r2.free || 0;
    target.r2.other += data.r2.other || 0;
    target.r2.operations += data.r2.operations || 0;
    target.r2.storageBytes += data.r2.storageBytes || 0;
    target.r2.storageLimitBytes += data.r2.storageLimitBytes || 免费额度.r2StorageBytes;
    target.r2.objects += data.r2.objects || 0;
    target.r2.buckets += data.r2.buckets || 0;
}

function 获取统计时间窗口() {
    const now = new Date();
    const dayStart = new Date(now);
    dayStart.setUTCHours(0, 0, 0, 0);
    const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));

    return {
        nowIso: now.toISOString(),
        dayStartIso: dayStart.toISOString(),
        monthStartIso: monthStart.toISOString(),
        dayStartDate: dayStart.toISOString().slice(0, 10),
        monthStartDate: monthStart.toISOString().slice(0, 10),
        dateEnd: now.toISOString().slice(0, 10)
    };
}

const 免费档最小刷新间隔毫秒 = 10 * 60 * 1000;

function 免费档保护已启用(env = {}) {
    return env.FREE_TIER_GUARD === undefined ? true : 解析布尔变量(env.FREE_TIER_GUARD);
}

function 获取单账号查询间隔毫秒(env = {}) {
    let 间隔毫秒 = 默认单账号查询间隔毫秒;
    const ms = Number(env.ACCOUNT_CHECK_INTERVAL_MS || env.account_check_interval_ms);
    if (Number.isFinite(ms) && ms > 0) {
        间隔毫秒 = ms;
    } else {
        const minutes = Number(env.ACCOUNT_CHECK_INTERVAL_MINUTES || env.account_check_interval_minutes || env.CHECK_INTERVAL_MINUTES || env.check_interval_minutes);
        if (Number.isFinite(minutes) && minutes > 0) 间隔毫秒 = minutes * 60 * 1000;
    }
    // 默认按免费额度保护：刷新间隔不低于 10 分钟，避免 KV 写/子请求超额；付费用户可设 FREE_TIER_GUARD=false 关闭
    if (免费档保护已启用(env)) 间隔毫秒 = Math.max(间隔毫秒, 免费档最小刷新间隔毫秒);
    return 间隔毫秒;
}

function 获取每轮最多外部子请求数(env = {}) {
    const configured = Number(env.MAX_EXTERNAL_SUBREQUESTS_PER_RUN || env.max_external_subrequests_per_run);
    if (Number.isFinite(configured) && configured > 0) return Math.min(Math.max(1, Math.floor(configured)), 默认每轮最多外部子请求数);
    return 默认每轮最多外部子请求数;
}

function 估算账号查询外部子请求数(account = {}) {
    if (account.AccountID) return 4;
    if (account.Email && account.GlobalAPIKey) return 5;
    return 5;
}

function 获取账号最后更新时间(account) {
    return Number(account?.UpdateTime || account?.Usage?.UpdateTime || 0) || 0;
}

function 补全账号Usage结构(account) {
    const usage = 补全Usage结构(account?.Usage || {});
    delete usage.UpdateTime;
    return usage;
}

function 写入账号查询结果(account, usage, queryTime = Date.now()) {
    const normalized = 补全Usage结构(usage || {});
    normalized.UpdateTime = queryTime;
    account.Usage = 补全账号Usage结构({ ...account, Usage: normalized });
    account.UpdateTime = queryTime;
    account.LastCheckTime = queryTime;
    account.CheckFailCount = 0;
    delete account.NextCheckTime;
    if (normalized.partial) {
        account.LastCheckError = (normalized.errors || []).join('; ') || '部分资源统计失败';
        account.LastCheckErrorTime = queryTime;
    } else {
        delete account.LastCheckError;
        delete account.LastCheckErrorTime;
    }
    return normalized;
}

function 写入账号查询失败(account, error, queryTime = Date.now(), 退避基准毫秒 = 默认单账号查询间隔毫秒) {
    const lastUpdateTime = 获取账号最后更新时间(account);
    if (lastUpdateTime && !account.UpdateTime) account.UpdateTime = lastUpdateTime;
    account.LastCheckTime = queryTime;
    account.LastCheckErrorTime = queryTime;
    account.LastCheckError = typeof error === 'string' ? error : (error?.msg || error?.message || '查询失败');
    const 失败次数 = (Number(account.CheckFailCount) || 0) + 1;
    account.CheckFailCount = 失败次数;
    const 基准 = Number(退避基准毫秒) > 0 ? Number(退避基准毫秒) : 默认单账号查询间隔毫秒;
    const 退避毫秒 = Math.min(基准 * Math.pow(2, Math.min(失败次数 - 1, 6)), 24 * 60 * 60 * 1000);
    account.NextCheckTime = queryTime + 退避毫秒;
    account.Usage = 补全账号Usage结构(account);
    return account.Usage;
}

async function 读取缓存Usage(env) {
    try {
        const 已保存Usage = await env.KV.get('usage.json', { type: 'json' });
        if (!已保存Usage) return 创建默认Usage(false, '⚠️ 数据正在初始化，请稍后刷新');
        const usage = 补全Usage结构(已保存Usage);
        usage.success = true;
        usage.total = (usage.pages || 0) + (usage.workers || 0);
        usage.msg = '✅ 成功加载免费额度使用数据';
        return usage;
    } catch (error) {
        console.error('读取用量缓存失败:', error.message);
        return 创建默认Usage(false, '⚠️ 读取用量缓存失败');
    }
}

async function 更新请求数(env, options = {}) {
    const skipLock = options.skipLock === true;
    // 免费额度保护：没有账号到期时直接返回缓存，避免 cron/管理端每次调用都写锁键和汇总键
    if (!skipLock && !options.force && options.writeUsage !== true) {
        try {
            const 配置快照 = await 读取账号配置(env);
            const 已保存缓存 = await env.KV.get('usage.json', { type: 'json' });
            const 查询间隔 = Number(options.thresholdMs) || 获取单账号查询间隔毫秒(env);
            const 当前时间 = Date.now();
            const 账号列表 = Array.isArray(配置快照) ? 配置快照 : [];
            const 有到期账号 = 账号列表.some(account => {
                const 最后更新 = 获取账号最后更新时间(account);
                if (最后更新 && 当前时间 - 最后更新 <= 查询间隔) return false;
                const 退避时间 = Number(account.NextCheckTime) || 0;
                return !退避时间 || 当前时间 >= 退避时间;
            });
            if (已保存缓存 && (账号列表.length === 0 || !有到期账号)) {
                const 缓存 = 补全Usage结构(已保存缓存);
                缓存.success = true;
                缓存.total = (缓存.pages || 0) + (缓存.workers || 0);
                缓存.msg = '✅ 数据已是最新（未到刷新间隔）';
                return 缓存;
            }
        } catch (检查错误) {
            console.warn('检查刷新到期状态失败，继续尝试刷新:', 检查错误.message);
        }
    }
    const 锁令牌 = skipLock ? null : await 尝试获取刷新锁(env);
    const 锁获取时间 = 锁令牌 ? Date.now() : 0;
    if (!skipLock && !锁令牌) {
        const 缓存 = await 读取缓存Usage(env);
        缓存.msg = 'ℹ️ 数据正在刷新，本次返回缓存数据';
        return 缓存;
    }
    try {
        let usage_config_json = await 读取账号配置(env);
        let usage_json = 创建默认Usage(false);
        let 配置已变化 = false;

        if (!usage_config_json) {
            // 不存在则创建一个空的配置文件
            usage_config_json = [];
            await 保存账号配置(env, usage_config_json);
            配置已变化 = true;
            usage_json.success = true;
            usage_json.resources = 创建汇总资源统计();
            usage_json.UpdateTime = Date.now();
            usage_json.msg = '⚠️ 尚未添加任何Cloudflare账号';
            Object.defineProperty(usage_json, '__config', { value: usage_config_json, enumerable: false });
            await env.KV.put('usage.json', JSON.stringify(usage_json));
        } else if (Array.isArray(usage_config_json) && usage_config_json.length > 0) {
            const thresholdMs = Number(options.thresholdMs) || 获取单账号查询间隔毫秒(env);
            const 预留子请求 = Math.max(0, Number(options.reserveSubrequests) || 0);
            const externalSubrequestLimit = Math.max(1, 获取每轮最多外部子请求数(env) - 预留子请求);
            const now = Date.now();

            const accountStates = usage_config_json.map((account) => {
                const lastUpdateTime = 获取账号最后更新时间(account);
                account.Usage = 补全账号Usage结构(account);
                if (lastUpdateTime && !account.UpdateTime) account.UpdateTime = lastUpdateTime;
                if (lastUpdateTime && !account.LastCheckTime) account.LastCheckTime = lastUpdateTime;
                return { account, lastUpdateTime };
            });

            // 失败账号按指数退避，不在退避期内的账号不参与本轮刷新，避免挤占子请求预算
            let 因退避跳过 = 0;
            const expiredAccounts = accountStates
                .filter(item => {
                    const 已到查询间隔 = options.force || !item.lastUpdateTime || now - item.lastUpdateTime > thresholdMs;
                    if (!已到查询间隔) return false;
                    const 退避已过 = options.force || !item.account.NextCheckTime || now >= Number(item.account.NextCheckTime);
                    if (!退避已过) 因退避跳过 += 1;
                    return 退避已过;
                })
                .sort((a, b) => (a.lastUpdateTime || 0) - (b.lastUpdateTime || 0));

            const accountsToRefresh = [];
            let estimatedExternalSubrequests = 0;
            for (const item of expiredAccounts) {
                const accountSubrequests = 估算账号查询外部子请求数(item.account);
                if (estimatedExternalSubrequests + accountSubrequests > externalSubrequestLimit) continue;
                accountsToRefresh.push({ ...item, estimatedExternalSubrequests: accountSubrequests });
                estimatedExternalSubrequests += accountSubrequests;
            }

            let refreshedCount = 0;
            let partialRefreshCount = 0;
            let failedRefreshCount = 0;
            let resolvedAccountIDCount = 0;

            if (!options.skipRefresh) {
                await Promise.all(accountsToRefresh.map(async ({ account }) => {
                    try {
                        const usage = await getCloudflareUsage(account.Email, account.GlobalAPIKey, account.AccountID, account.APIToken);
                        if (!usage.success) {
                            写入账号查询失败(account, usage, Date.now(), thresholdMs);
                            failedRefreshCount += 1;
                            return;
                        }
                        if (!account.AccountID && usage.resolvedAccountID) {
                            account.AccountID = usage.resolvedAccountID;
                            resolvedAccountIDCount += 1;
                        }
                        应用账号限额(usage, account);
                        写入账号查询结果(account, usage, Date.now());
                        if (usage.partial) partialRefreshCount += 1;
                        else refreshedCount += 1;
                    } catch (error) {
                        failedRefreshCount += 1;
                        console.error(`账号 ${account.ID} 查询失败:`, error.message);
                        写入账号查询失败(account, error, Date.now(), thresholdMs);
                    }
                }));
            }

            const 本轮有变化 = refreshedCount > 0 || partialRefreshCount > 0 || failedRefreshCount > 0 || resolvedAccountIDCount > 0;
            if (本轮有变化) 配置已变化 = true;

            // 累加所有账号的使用数据，未达到刷新阈值或超过本轮上限的账号使用历史数据。
            let total_pages = 0;
            let total_workers = 0;
            let total_max = 0;
            let total_workers_errors = 0;
            let total_subrequests = 0;
            let max_cpu_p50 = 0;
            let max_cpu_p99 = 0;
            const total_resources = 创建汇总资源统计();

            for (const account of usage_config_json) {
                const usage = 补全账号Usage结构(account);
                应用账号限额(usage, account);
                account.Usage = usage;
                if (usage.success) {
                    total_pages += usage.pages || 0;
                    total_workers += usage.workers || 0;
                    total_max += usage.max || 免费额度.requestsDaily;
                    total_workers_errors += Number(usage.workersErrors) || 0;
                    total_subrequests += Number(usage.workersSubrequests) || 0;
                    max_cpu_p50 = Math.max(max_cpu_p50, Number(usage.cpuTimeP50) || 0);
                    max_cpu_p99 = Math.max(max_cpu_p99, Number(usage.cpuTimeP99) || 0);
                    累加资源统计(total_resources, usage.resources);
                }
            }

            usage_json.success = true;
            usage_json.pages = total_pages;
            usage_json.workers = total_workers;
            usage_json.total = total_pages + total_workers;
            usage_json.max = total_max;
            usage_json.workersErrors = total_workers_errors;
            usage_json.workersSubrequests = total_subrequests;
            usage_json.cpuTimeP50 = max_cpu_p50;
            usage_json.cpuTimeP99 = max_cpu_p99;
            usage_json.errorRate = total_workers > 0 ? Math.round((total_workers_errors / total_workers) * 10000) / 100 : 0;
            usage_json.resources = total_resources;
            usage_json.UpdateTime = Date.now();
            usage_json.RefreshStats = {
                refreshed: refreshedCount,
                partial: partialRefreshCount,
                failed: failedRefreshCount,
                cached: Math.max(usage_config_json.length - refreshedCount - partialRefreshCount - failedRefreshCount, 0),
                skippedByBackoff: 因退避跳过,
                skippedByLimit: Math.max(expiredAccounts.length - accountsToRefresh.length, 0),
                maxRefresh: accountsToRefresh.length,
                externalSubrequestsEstimated: estimatedExternalSubrequests,
                externalSubrequestLimit,
                reservedSubrequests: 预留子请求,
                perAccountExternalSubrequests: { withAccountId: 4, withoutAccountId: 5 },
                thresholdMs
            };
            if (failedRefreshCount > 0 || partialRefreshCount > 0) {
                usage_json.msg = `⚠️ 部分账号查询异常（成功 ${refreshedCount} 个，部分失败 ${partialRefreshCount} 个，失败 ${failedRefreshCount} 个，${usage_json.RefreshStats.cached} 个使用历史数据）`;
            } else {
                usage_json.msg = `✅ 成功更新免费额度使用数据（本次刷新 ${refreshedCount} 个账号，${usage_json.RefreshStats.cached} 个使用历史数据）`;
            }

            // 仅在数据实际变化时写回，避免 cron/管理端反复刷新造成 KV 写放大
            Object.defineProperty(usage_json, '__config', { value: usage_config_json, enumerable: false });
            if (配置已变化) await 保存账号配置(env, usage_config_json);
            if (配置已变化 || options.writeUsage === true) await env.KV.put('usage.json', JSON.stringify(usage_json));

            // 历史快照：D1 已绑定时写细粒度快照；未绑定时写 KV 每日快照（每天最多 1 次写）
            if (!options.skipRefresh && (refreshedCount > 0 || partialRefreshCount > 0)) {
                try {
                    if (历史功能已启用(env)) await 写入历史快照(env, usage_config_json);
                    else await 保存每日KV快照(env, usage_json);
                } catch (历史错误) {
                    console.error('写入历史数据失败:', 历史错误.message);
                }
            }
        } else {
            // 配置文件存在但为空数组或无效格式
            usage_json.success = true;
            usage_json.resources = 创建汇总资源统计();
            usage_json.UpdateTime = Date.now();
            usage_json.msg = '⚠️ 尚未添加任何Cloudflare账号';
            Object.defineProperty(usage_json, '__config', { value: usage_config_json, enumerable: false });
            if (配置已变化 || options.writeUsage === true) await env.KV.put('usage.json', JSON.stringify(usage_json));
        }

        return usage_json;
    } finally {
        if (锁令牌) await 释放刷新锁(env, 锁令牌, 锁获取时间);
    }
}

function 数字(value) {
    return Number(value) || 0;
}

function 合计请求数(groups) {
    return groups?.reduce((total, item) => total + 数字(item?.sum?.requests), 0) || 0;
}

function 规范化动作名称(action) {
    return String(action || '').replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function 选择最新分组(groups, idField, timeField) {
    const latest = new Map();
    for (const group of groups || []) {
        const dimensions = group?.dimensions || {};
        const id = dimensions[idField] || '__account';
        const time = String(dimensions[timeField] || '');
        const current = latest.get(id);
        if (!current || time >= current.time) latest.set(id, { time, group });
    }
    return Array.from(latest.values()).map(item => item.group);
}

async function 发送GraphQL请求(API, headers, query, variables) {
    const res = await fetch(`${API}/graphql`, {
        method: "POST",
        headers,
        body: JSON.stringify({ query, variables })
    });

    if (!res.ok) throw new Error(`查询失败: ${res.status}`);
    const result = await res.json();
    if (result.errors?.length) throw new Error(result.errors.map(error => error.message).join('; '));

    const account = result?.data?.viewer?.accounts?.[0];
    if (!account) throw new Error("未找到账户数据");
    return account;
}

async function 获取Cloudflare账户ID(API, headers, Email) {
    // 分页可避免多账号（超过单页上限）时漏查
    const r = await fetch(`${API}/accounts?page=1&per_page=50`, { method: "GET", headers });
    if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
    const d = await r.json();
    const 账号列表 = Array.isArray(d?.result) ? d.result : [];
    if (账号列表.length === 0) throw new Error("未找到账户");

    const 邮箱 = String(Email || '').toLowerCase();
    const 精确匹配 = 账号列表.find(account => String(account?.name || '').toLowerCase() === 邮箱);
    if (精确匹配?.id) return 精确匹配.id;

    const 前缀匹配 = 账号列表.find(account => 邮箱 && String(account?.name || '').toLowerCase().startsWith(邮箱));
    if (前缀匹配?.id) return 前缀匹配.id;

    // 只有一个账号时才允许兜底，多账号时必须显式配置 AccountID，避免静默统计错账号
    if (账号列表.length === 1 && 账号列表[0]?.id) return 账号列表[0].id;
    throw new Error('无法自动匹配 Cloudflare 账号，请在账号配置中填写 AccountID');
}

async function 查询WorkersPages统计(API, headers, AccountID, 时间窗口) {
    const account = await 发送GraphQL请求(API, headers, `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
        viewer { accounts(filter: {accountTag: $AccountID}) {
            pagesFunctionsInvocationsAdaptiveGroups(limit: 10000, filter: $filter) { sum { requests } }
            workersInvocationsAdaptive(limit: 10000, filter: $filter) {
                sum { requests errors subrequests }
                quantiles { cpuTimeP50 cpuTimeP99 }
            }
        } }
    }`, {
        AccountID,
        filter: { datetime_geq: 时间窗口.dayStartIso, datetime_leq: 时间窗口.nowIso }
    });

    const workersGroups = Array.isArray(account.workersInvocationsAdaptive) ? account.workersInvocationsAdaptive : [];
    const 汇总 = (field) => workersGroups.reduce((sum, group) => sum + (Number(group?.sum?.[field]) || 0), 0);
    const 取CPU = (field) => workersGroups.reduce((max, group) => Math.max(max, Number(group?.quantiles?.[field]) || 0), 0);
    return {
        pages: 合计请求数(account.pagesFunctionsInvocationsAdaptiveGroups),
        workers: 合计请求数(account.workersInvocationsAdaptive),
        workersErrors: 汇总('errors'),
        workersSubrequests: 汇总('subrequests'),
        cpuTimeP50: 取CPU('cpuTimeP50'),
        cpuTimeP99: 取CPU('cpuTimeP99')
    };
}

async function 查询D1统计(API, headers, AccountID, 时间窗口) {
    const d1 = 创建默认资源统计().d1;
    const account = await 发送GraphQL请求(API, headers, `query D1Usage($accountTag: String!, $dayStart: Date!, $dateEnd: Date!, $storageStart: Date!) {
        viewer { accounts(filter: {accountTag: $accountTag}) {
            d1AnalyticsAdaptiveGroups(limit: 10000, filter: {date_geq: $dayStart, date_leq: $dateEnd}) {
                sum { rowsRead rowsWritten readQueries writeQueries }
                dimensions { date databaseId }
            }
            d1StorageAdaptiveGroups(limit: 10000, filter: {date_geq: $storageStart, date_leq: $dateEnd}, orderBy: [date_DESC]) {
                max { databaseSizeBytes }
                dimensions { date databaseId }
            }
        } }
    }`, {
        accountTag: AccountID,
        dayStart: 时间窗口.dayStartDate,
        dateEnd: 时间窗口.dateEnd,
        storageStart: 时间窗口.monthStartDate
    });

    for (const group of account.d1AnalyticsAdaptiveGroups || []) {
        d1.rowsRead += 数字(group?.sum?.rowsRead);
        d1.rowsWritten += 数字(group?.sum?.rowsWritten);
        d1.readQueries += 数字(group?.sum?.readQueries);
        d1.writeQueries += 数字(group?.sum?.writeQueries);
    }

    const storageGroups = 选择最新分组(account.d1StorageAdaptiveGroups, 'databaseId', 'date');
    d1.databases = storageGroups.length;
    d1.storageBytes = storageGroups.reduce((total, group) => total + 数字(group?.max?.databaseSizeBytes), 0);
    return d1;
}

async function 查询KV统计(API, headers, AccountID, 时间窗口) {
    const kv = 创建默认资源统计().kv;
    const account = await 发送GraphQL请求(API, headers, `query KvUsage($accountTag: String!, $dayStart: Date!, $dateEnd: Date!, $storageStart: Date!) {
        viewer { accounts(filter: {accountTag: $accountTag}) {
            kvOperationsAdaptiveGroups(limit: 10000, filter: {date_geq: $dayStart, date_leq: $dateEnd}) {
                sum { requests }
                dimensions { actionType }
            }
            kvStorageAdaptiveGroups(limit: 10000, filter: {date_geq: $storageStart, date_leq: $dateEnd}, orderBy: [date_DESC]) {
                max { keyCount byteCount }
                dimensions { date namespaceId }
            }
        } }
    }`, {
        accountTag: AccountID,
        dayStart: 时间窗口.dayStartDate,
        dateEnd: 时间窗口.dateEnd,
        storageStart: 时间窗口.monthStartDate
    });

    for (const group of account.kvOperationsAdaptiveGroups || []) {
        const requests = 数字(group?.sum?.requests);
        const actionType = String(group?.dimensions?.actionType || '').toLowerCase();
        kv.operations += requests;

        if (actionType.includes('read')) kv.reads += requests;
        else if (actionType.includes('write')) kv.writes += requests;
        else if (actionType.includes('delete')) kv.deletes += requests;
        else if (actionType.includes('list')) kv.lists += requests;
    }

    const storageGroups = 选择最新分组(account.kvStorageAdaptiveGroups, 'namespaceId', 'date');
    kv.namespaces = storageGroups.length;
    kv.keys = storageGroups.reduce((total, group) => total + 数字(group?.max?.keyCount), 0);
    kv.storageBytes = storageGroups.reduce((total, group) => total + 数字(group?.max?.byteCount), 0);
    return kv;
}

async function 查询R2统计(API, headers, AccountID, 时间窗口) {
    const r2 = 创建默认资源统计().r2;
    const account = await 发送GraphQL请求(API, headers, `query R2Usage($accountTag: String!, $monthStart: Time!, $now: Time!) {
        viewer { accounts(filter: {accountTag: $accountTag}) {
            r2OperationsAdaptiveGroups(limit: 10000, filter: {datetime_geq: $monthStart, datetime_leq: $now}) {
                sum { requests }
                dimensions { actionType actionStatus }
            }
            r2StorageAdaptiveGroups(limit: 10000, filter: {datetime_geq: $monthStart, datetime_leq: $now}, orderBy: [datetime_DESC]) {
                max { objectCount uploadCount payloadSize metadataSize }
                dimensions { datetime bucketName }
            }
        } }
    }`, {
        accountTag: AccountID,
        monthStart: 时间窗口.monthStartIso,
        now: 时间窗口.nowIso
    });

    for (const group of account.r2OperationsAdaptiveGroups || []) {
        const status = String(group?.dimensions?.actionStatus || 'success').toLowerCase();
        if (status && status !== 'success') continue;

        const requests = 数字(group?.sum?.requests);
        const action = 规范化动作名称(group?.dimensions?.actionType);
        r2.operations += requests;

        if (R2_CLASS_A_ACTIONS.has(action)) r2.classA += requests;
        else if (R2_CLASS_B_ACTIONS.has(action)) r2.classB += requests;
        else if (R2_FREE_ACTIONS.has(action)) r2.free += requests;
        else r2.other += requests;
    }

    const storageGroups = 选择最新分组(account.r2StorageAdaptiveGroups, 'bucketName', 'datetime');
    r2.buckets = storageGroups.length;
    r2.objects = storageGroups.reduce((total, group) => total + 数字(group?.max?.objectCount), 0);
    r2.storageBytes = storageGroups.reduce((total, group) => total + 数字(group?.max?.payloadSize) + 数字(group?.max?.metadataSize), 0);
    return r2;
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
    const API = "https://api.cloudflare.com/client/v4";
    const cfg = { "Content-Type": "application/json" };
    const fallback = 创建默认Usage(false);
    fallback.max = 免费额度.requestsDaily;
    let resolvedAccountID = null;

    try {
        if (!AccountID && (!Email || !GlobalAPIKey)) return fallback;

        const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };
        if (!AccountID) {
            AccountID = await 获取Cloudflare账户ID(API, hdr, Email);
            resolvedAccountID = AccountID;
        }

        const 时间窗口 = 获取统计时间窗口();
        const usage = 创建默认Usage(true, '✅ 成功更新免费额度使用数据');
        const core = await 查询WorkersPages统计(API, hdr, AccountID, 时间窗口);

        usage.pages = core.pages;
        usage.workers = core.workers;
        usage.total = core.pages + core.workers;
        usage.max = 免费额度.requestsDaily;
        usage.workersErrors = core.workersErrors || 0;
        usage.workersSubrequests = core.workersSubrequests || 0;
        usage.cpuTimeP50 = core.cpuTimeP50 || 0;
        usage.cpuTimeP99 = core.cpuTimeP99 || 0;
        usage.errorRate = usage.workers > 0 ? Math.round((usage.workersErrors / usage.workers) * 10000) / 100 : 0;
        if (resolvedAccountID) usage.resolvedAccountID = resolvedAccountID;

        const errors = [];
        const safeQuery = async (label, query, defaultValue) => {
            try {
                return await query();
            } catch (error) {
                console.warn(`${label} 统计失败:`, error.message);
                errors.push(`${label}: ${error.message}`);
                return defaultValue;
            }
        };

        const [d1, kv, r2] = await Promise.all([
            safeQuery('D1', () => 查询D1统计(API, hdr, AccountID, 时间窗口), 创建默认资源统计().d1),
            safeQuery('KV', () => 查询KV统计(API, hdr, AccountID, 时间窗口), 创建默认资源统计().kv),
            safeQuery('R2', () => 查询R2统计(API, hdr, AccountID, 时间窗口), 创建默认资源统计().r2)
        ]);

        usage.resources.d1 = d1;
        usage.resources.kv = kv;
        usage.resources.r2 = r2;
        if (errors.length) {
            // 部分资源统计失败时保留 success（旧数据仍可累加），但显式标记 partial 供上层提示，避免被当成 0 用量。
            usage.partial = true;
            usage.errors = errors;
            usage.msg = '⚠️ 部分资源统计失败，用量可能偏低';
        }

        console.log(`统计结果 - Pages: ${usage.pages}, Workers: ${usage.workers}, D1读: ${d1.rowsRead}, KV读: ${kv.reads}, R2 A/B: ${r2.classA}/${r2.classB}`);
        return usage;

    } catch (error) {
        console.error('获取使用量错误:', error.message);
        if (resolvedAccountID) fallback.resolvedAccountID = resolvedAccountID;
        fallback.msg = '❌ 获取使用量失败: ' + error.message;
        return fallback;
    }
}

function 掩码敏感信息(文本, 前缀长度 = 3, 后缀长度 = 2) {
    if (!文本 || typeof 文本 !== 'string') return 文本;
    // 过短的值直接整体隐藏，避免暴露完整内容
    if (文本.length <= 前缀长度 + 后缀长度) return '*'.repeat(文本.length);

    const 前缀 = 文本.slice(0, 前缀长度);
    const 后缀 = 文本.slice(-后缀长度);
    const 星号数量 = 文本.length - 前缀长度 - 后缀长度;

    return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

////////////////////////////////HTML页面//////////////////////////////////

async function UsagePanel管理面板() {
    const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UsagePanel 管理面板</title>
    <link rel="icon" href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5uhbWfhjepEoUiM9phzhgJ/9658369030266cde9e35a3c5d4e4beb2/cloud-upload.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --accent: #a855f7;
            --background: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --stroke: rgba(255, 255, 255, 0.08);
            --danger: #ef4444;
            --heading-grad: linear-gradient(135deg, #fff 0%, #cbd5e1 100%);
            --item-bg: rgba(255, 255, 255, 0.03);
            --footer-color: rgba(255, 255, 255, 0.2);
            --footer-hover: rgba(255, 255, 255, 0.4);
            --track-bg: rgba(0, 0, 0, 0.2);
            --input-bg: rgba(0, 0, 0, 0.2);
        }

        :root.light-mode {
            --primary: #4f46e5;
            --primary-glow: rgba(79, 70, 229, 0.2);
            --accent: #9333ea;
            --background: #f1f5f9;
            --card-bg: rgba(255, 255, 255, 0.8);
            --text-main: #0f172a;
            --text-muted: #64748b;
            --stroke: rgba(0, 0, 0, 0.1);
            --danger: #dc2626;
            --heading-grad: linear-gradient(135deg, #1e293b 0%, #475569 100%);
            --item-bg: rgba(0, 0, 0, 0.03);
            --footer-color: rgba(15, 23, 42, 0.4);
            --footer-hover: var(--primary);
            --track-bg: rgba(0, 0, 0, 0.08);
            --input-bg: rgba(255, 255, 255, 0.8);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        html {
            scrollbar-gutter: stable both-edges;
        }

        @supports not (scrollbar-gutter: stable) {
            html { overflow-y: scroll; }
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--background);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.15) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .top-nav {
            width: 100%;
            max-width: 760px;
            display: flex;
            flex-wrap: wrap;
            justify-content: flex-end;
            gap: 1rem;
            margin-bottom: 1rem;
            animation: slideDown 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .nav-btn {
            padding: 0.6rem 1.2rem;
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--stroke);
            border-radius: 12px;
            color: var(--text-main);
            font-family: 'Outfit', sans-serif;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .nav-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-2px);
            border-color: var(--primary);
        }

        .nav-btn.logout:hover {
            border-color: var(--danger);
            color: var(--danger);
        }

        .container {
            width: 100%;
            max-width: 680px;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            animation: slideUp 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .glass-card {
            background: var(--card-bg);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--stroke);
            border-radius: 24px;
            padding: 2rem;
            min-width: 0;
            box-shadow: 
                0 25px 50px -12px rgba(0, 0, 0, 0.5),
                0 0 0 1px rgba(255, 255, 255, 0.05) inset;
        }

        .summary-card {
            position: static;
        }

        .accounts-card {
            min-width: 0;
        }

        header {
            margin-bottom: 1.5rem;
        }

        h1, h2 {
            font-size: 1.5rem;
            font-weight: 700;
            background: var(--heading-grad);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 1rem;
            letter-spacing: -0.01em;
        }

        .module-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .module-header h2 { margin-bottom: 0; }

        .add-btn {
            padding: 0.6rem 1.2rem;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border: none;
            border-radius: 12px;
            color: white;
            font-family: 'Outfit', sans-serif;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .add-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 8px 20px var(--primary-glow);
        }

        /* Usage Section Styles (from homepage) */
        .usage-section { margin-bottom: 2rem; position: relative; }
        .usage-header { display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 1rem; }
        .label { font-size: 0.9rem; color: var(--text-muted); font-weight: 500; }
        .percentage { font-family: 'Outfit', monospace; font-size: 1.25rem; font-weight: 600; color: var(--gradient-color, var(--text-main)); text-shadow: 0 0 20px var(--gradient-color-shadow, var(--primary-glow)); transition: color 0.6s ease, text-shadow 0.6s ease; }
        .progress-track { background: var(--track-bg); border: 1px solid var(--stroke); border-radius: 999px; height: 14px; overflow: hidden; position: relative; }
        .progress-bar { height: 100%; background: linear-gradient(90deg, #10b981 0%, #eab308 50%, #ef4444 100%); background-size: var(--bg-size, 100%); background-position: left; border-radius: 999px; width: 0%; transition: width 1.5s cubic-bezier(0.34, 1.56, 0.64, 1); position: relative; overflow: hidden; }
        .progress-bar::after { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent); transform: translateX(-100%); animation: shimmer 2.5s infinite; }
        .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1.5rem; }
        .mini-card { 
            background: var(--item-bg); 
            border: 1px solid var(--stroke); 
            border-radius: 16px; 
            padding: 1rem 1.25rem; 
            display: flex; 
            align-items: center; 
            gap: 1.25rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); 
        }
        .mini-card:hover { 
            background: rgba(99, 102, 241, 0.08); 
            transform: translateY(-4px); 
            border-color: var(--primary); 
            box-shadow: 0 10px 20px -5px rgba(0, 0, 0, 0.2);
        }
        .mini-icon { font-size: 1.75rem; margin-bottom: 0; line-height: 1; }
        .mini-info { display: flex; flex-direction: column; justify-content: center; }
        .mini-label { font-size: 0.7rem; text-transform: uppercase; color: var(--text-muted); margin-bottom: 0; letter-spacing: 0.05em; font-weight: 500; }
        .mini-value { font-size: 1.25rem; font-weight: 700; color: var(--text-main); line-height: 1.2; }
        .total-text { text-align: right; font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem; }
        .quota-details { margin-top: 1.25rem; overflow: hidden; }
        .quota-details[open] { display: flex; flex-direction: column; }
        .quota-details.quota-animating .quota-summary { pointer-events: none; }
        .quota-summary { list-style: none; background: linear-gradient(135deg, rgba(99, 102, 241, 0.16), rgba(14, 165, 233, 0.1)); border: 1px solid rgba(99, 102, 241, 0.5); border-radius: 14px; padding: 0.8rem 0.85rem; cursor: pointer; display: flex; justify-content: space-between; gap: 0.75rem; align-items: center; color: var(--text-main); font-size: 0.85rem; font-weight: 700; box-shadow: 0 12px 28px -18px var(--primary-glow), inset 0 1px 0 rgba(255,255,255,0.08); transition: all 0.3s ease; }
        .quota-summary::-webkit-details-marker { display: none; }
        .quota-summary:hover, .quota-summary:focus-visible { border-color: var(--primary); background: linear-gradient(135deg, rgba(99, 102, 241, 0.24), rgba(14, 165, 233, 0.14)); box-shadow: 0 16px 32px -18px var(--primary-glow), 0 0 0 3px rgba(99, 102, 241, 0.12); outline: none; }
        .quota-summary-title { min-width: 0; }
        .quota-summary::after { content: '展开细节'; color: #fff; background: var(--primary); border-radius: 999px; padding: 0.38rem 0.7rem; font-size: 0.75rem; font-weight: 700; white-space: nowrap; box-shadow: 0 10px 20px -12px var(--primary-glow); }
        .quota-details[open] .quota-summary::after { content: '收起细节'; }
        .quota-details[open] .quota-summary { order: 2; margin-top: 0.875rem; }
        .quota-summary-meta { color: var(--text-muted); font-size: 0.75rem; font-weight: 600; margin-left: auto; white-space: nowrap; }
        .quota-body { overflow: hidden; }
        .quota-details[open] .quota-body { order: 1; }
        .quota-details.quota-animating .quota-body { will-change: height, opacity, transform; }
        .quota-list { display: grid; gap: 0.875rem; margin-top: 0.875rem; }
        .quota-details[open] .quota-list { margin-top: 0; }
        .quota-item { background: var(--item-bg); border: 1px solid var(--stroke); border-radius: 14px; padding: 0.875rem 1rem; }
        .quota-group-head { display: flex; justify-content: space-between; gap: 0.75rem; align-items: center; margin-bottom: 0.75rem; }
        .quota-group-title { color: var(--text-main); font-size: 0.9rem; font-weight: 700; }
        .quota-group-meta { color: var(--text-muted); font-size: 0.75rem; font-variant-numeric: tabular-nums; text-align: right; }
        .quota-row { margin-top: 0.75rem; }
        .quota-group-head + .quota-row { margin-top: 0; }
        .quota-top { display: flex; justify-content: space-between; gap: 0.75rem; color: var(--text-muted); font-size: 0.78rem; margin-bottom: 0.55rem; }
        .quota-title { color: var(--text-main); font-weight: 600; }
        .quota-meta { text-align: right; font-variant-numeric: tabular-nums; }
        .quota-track { height: 7px; background: var(--track-bg); border: 1px solid var(--stroke); border-radius: 999px; overflow: hidden; }
        .quota-fill { height: 100%; border-radius: inherit; min-width: 0; transition: width 1s ease; }
        .resource-note { margin-top: 0.875rem; color: var(--text-muted); font-size: 0.75rem; line-height: 1.5; }

        /* Account List Styles */
        .account-list { display: flex; flex-direction: column; gap: 1rem; }
        .account-item {
            background: var(--item-bg);
            border: 1px solid var(--stroke);
            border-radius: 20px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            transition: all 0.3s ease;
        }
        .account-item:hover {
            border-color: rgba(99, 102, 241, 0.3);
            background: rgba(99, 102, 241, 0.02);
        }
        .account-info { display: flex; justify-content: space-between; align-items: center; }
        .account-name { font-weight: 600; font-size: 1.1rem; color: var(--text-main); display: flex; align-items: center; gap: 0.5rem; }
        .account-id { font-size: 0.8rem; color: var(--text-muted); font-family: monospace; }
        
        .delete-btn {
            padding: 0.5rem 1rem;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 10px;
            color: #fca5a5;
            font-size: 0.8rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .delete-btn:hover {
            background: var(--danger);
            color: white;
            border-color: var(--danger);
            box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
        }

        /* Modal Styles */
        .modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(8px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 2000;
            animation: fadeIn 0.3s ease;
        }
        .modal-overlay.active { display: flex; }
        .modal {
            background: var(--card-bg);
            backdrop-filter: blur(24px);
            border: 1px solid var(--stroke);
            border-radius: 24px;
            padding: 2rem;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            animation: modalSlideUp 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .modal h3 { margin-bottom: 1.5rem; text-align: center; }
        .input-group { margin-bottom: 1rem; }
        .input-group label { display: block; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.5rem; }
        .input-group input {
            width: 100%;
            padding: 0.75rem 1rem;
            background: var(--input-bg);
            border: 1px solid var(--stroke);
            border-radius: 12px;
            color: var(--text-main);
            outline: none;
            transition: border-color 0.3s;
        }
        .input-group input:focus { border-color: var(--primary); }
        .modal-actions { display: flex; gap: 1rem; margin-top: 1.5rem; }
        .modal-btn { flex: 1; padding: 0.75rem; border-radius: 12px; cursor: pointer; font-weight: 600; border: none; transition: all 0.3s; }
        .modal-btn.cancel { background: rgba(255, 255, 255, 0.05); color: var(--text-main); }
        .modal-btn.confirm { background: linear-gradient(135deg, var(--primary), var(--accent)); color: white; }
        .modal-btn:hover { transform: translateY(-2px); }

        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            color: white;
            padding: 1rem 1.5rem;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            z-index: 3000;
            opacity: 0;
            visibility: hidden;
            transform: translateX(30px) translateY(30px);
            transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .toast.active { 
            opacity: 1;
            visibility: visible;
            transform: translateX(0) translateY(0); 
        }

        @keyframes slideUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes modalSlideUp { from { opacity: 0; transform: translateY(30px) scale(0.95); } to { opacity: 1; transform: translateY(0) scale(1); } }
        @keyframes shimmer { 100% { transform: translateX(100%); } }

        .loading-spinner {
            width: 32px;
            height: 32px;
            border: 3px solid rgba(255,255,255,0.1);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .loading-wrap { display: flex; justify-content: center; padding: 3rem; }

        @media (min-width: 1024px) {
            .top-nav {
                max-width: 760px;
            }

            /* 管理页卡片较多，宽屏也保持单列纵向布局，避免多列网格导致卡片错位/重叠 */
            .container {
                max-width: 760px;
                display: flex;
                flex-direction: column;
                gap: 1.5rem;
            }

            .summary-card {
                position: static;
            }
        }

        .footer {
            grid-column: 1 / -1;
            margin-top: 2.5rem;
            text-align: center;
            font-size: 0.75rem;
            color: var(--footer-color);
            transition: color 0.3s;
        }
        
        .footer:hover {
            color: var(--footer-hover);
        }

        a.footer {
            color: inherit;
            text-decoration: none;
        }

        a.footer:hover {
            text-decoration: underline;
        }

        /* ============ 移动端响应式布局 ============ */
        @media (max-width: 768px) {
            body {
                padding: 1rem;
            }

            .top-nav {
                flex-wrap: wrap;
                gap: 0.5rem;
                margin-bottom: 1.5rem;
            }

            .nav-btn {
                padding: 0.5rem 0.8rem;
                font-size: 0.8rem;
                border-radius: 10px;
                flex: 1;
                min-width: calc(50% - 0.25rem);
                justify-content: center;
            }

            .nav-btn svg {
                width: 16px;
                height: 16px;
            }

            .container {
                max-width: 680px;
                display: flex;
                flex-direction: column;
                gap: 1.5rem;
            }

            .summary-card {
                position: static;
            }

            .glass-card {
                padding: 1.5rem;
                border-radius: 20px;
            }

            h1, h2 {
                font-size: 1.25rem;
                margin-bottom: 1rem;
            }

            .module-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
                margin-bottom: 1.5rem;
            }

            .add-btn {
                width: 100%;
                padding: 0.7rem 1rem;
            }

            .stats-grid {
                grid-template-columns: 1fr;
                gap: 0.75rem;
                margin-top: 1rem;
            }

            .mini-card {
                padding: 1rem;
                gap: 1rem;
            }

            .mini-icon {
                font-size: 1.5rem;
            }

            .mini-label {
                font-size: 0.65rem;
            }

            .mini-value {
                font-size: 1.1rem;
            }

            .account-item {
                padding: 1.25rem;
                border-radius: 16px;
                gap: 1rem;
            }

            .account-info {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
            }

            .delete-btn {
                width: 100%;
                text-align: center;
                padding: 0.6rem 1rem;
            }

            .usage-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }

            .percentage {
                font-size: 1.1rem;
            }

            .modal {
                max-width: calc(100% - 2rem);
                padding: 1.5rem;
                border-radius: 20px;
            }

            .modal h3 {
                font-size: 1.1rem;
                margin-bottom: 1.25rem;
            }

            .input-group {
                margin-bottom: 0.875rem;
            }

            .input-group input {
                padding: 0.65rem 0.875rem;
                font-size: 0.9rem;
            }

            .modal-actions {
                gap: 0.75rem;
                margin-top: 1.25rem;
            }

            .modal-btn {
                padding: 0.65rem;
                font-size: 0.9rem;
            }

            .toast {
                bottom: 1rem;
                right: 1rem;
                left: 1rem;
                padding: 0.875rem 1.25rem;
                font-size: 0.875rem;
                border-radius: 10px;
            }

            .footer {
                grid-column: auto;
                margin-top: 2rem;
                font-size: 0.7rem;
            }

            .total-text {
                font-size: 0.75rem;
            }

            .quota-top {
                flex-direction: column;
                gap: 0.35rem;
            }

            .quota-summary, .quota-group-head {
                align-items: flex-start;
                flex-direction: column;
                gap: 0.35rem;
            }

            .quota-summary-meta {
                margin-left: 0;
            }

            .quota-group-meta {
                text-align: left;
            }

            .quota-meta {
                text-align: left;
            }

            .account-id {
                font-size: 0.75rem;
                word-break: break-all;
            }
        }

        /* 超小屏幕优化 */
        @media (max-width: 420px) {
            body {
                padding: 0.75rem;
            }

            .glass-card {
                padding: 1.25rem;
                border-radius: 18px;
            }

            h1, h2 {
                font-size: 1.1rem;
            }

            .nav-btn {
                min-width: 100%;
                font-size: 0.75rem;
            }

            .stats-grid {
                gap: 0.5rem;
            }

            .mini-card {
                padding: 0.875rem;
            }

            .account-item {
                padding: 1rem;
            }

            .modal {
                padding: 1.25rem;
            }
        }
    </style>
</head>
<body>
    <div id="viewer-banner" style="display: none; position: sticky; top: 0; z-index: 1002; margin: 0 auto 1rem; max-width: 680px; padding: 0.6rem 0.9rem; border-radius: 10px; background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.45); color: #f59e0b; font-size: 0.8rem;">
        👁️ 只读账号：可以查看数据，但无法修改配置或执行写操作。
    </div>
    <div class="top-nav">
        <button class="nav-btn" onclick="toggleTheme()" id="theme-toggle">
            <svg id="sun-icon" style="display:none" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="18.36" x2="5.64" y2="19.78"></line><line x1="18.36" y1="4.22" x2="19.78" y2="5.64"></line></svg>
            <svg id="moon-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
            <span id="theme-text">切换显示模式</span>
        </button>
        <button class="nav-btn" onclick="切换语言()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
            <span id="lang-text">EN</span>
        </button>
        <button class="nav-btn" onclick="refreshUsage()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
            刷新数据
        </button>
        <button class="nav-btn" onclick="copyUsageAPI()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            复制 UsageAPI
        </button>
        <button class="nav-btn" onclick="openRankingModal()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line><line x1="3" y1="18" x2="3.01" y2="18"></line></svg>
            排行榜
        </button>
        <button class="nav-btn" onclick="openExportModal()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            导出报告
        </button>
        <button class="nav-btn" onclick="openTopScriptsModal()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
            Top 脚本
        </button>
        <button class="nav-btn" onclick="openOptimizeModal()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 18h6"></path><path d="M10 22h4"></path><path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"></path></svg>
            优化建议
        </button>
        <button class="nav-btn logout" onclick="logout()">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
            退出管理面板
        </button>
    </div>

    <div class="container">
        <div class="glass-card summary-card">
            <h1>Cloudflare 额度汇总</h1>
            <div id="summary-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>☁️ Cloudflare 账号管理</h2>
                <button class="add-btn" onclick="openAddModal()">添加账号</button>
            </div>
            <div id="config-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
            <div id="breakdown-content" style="margin-top: 1.25rem;"></div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>🔔 用量告警</h2>
                <button class="add-btn" onclick="loadAlertConfig()">重新加载</button>
            </div>
            <div id="alert-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>📜 告警历史</h2>
                <div style="display: flex; gap: 0.5rem;">
                    <button class="add-btn" onclick="loadAlertHistory()">刷新</button>
                    <button class="delete-btn" onclick="clearAlertHistory()">清空</button>
                </div>
            </div>
            <div id="alert-history-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>📉 异常检测</h2>
                <button class="add-btn" onclick="loadAnomalies()">检测</button>
            </div>
            <div id="anomaly-content">
                <div style="color: var(--text-muted); font-size: 0.82rem;">基于 D1 历史，检测最近时间桶相对历史均值的异常（需要绑定 D1）。</div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>📈 历史趋势</h2>
                <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    <select id="historyRange" onchange="loadHistory()" style="padding: 0.45rem 0.75rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); font-size: 0.8rem; outline: none;">
                        <option value="24h">24 小时</option>
                        <option value="7d">7 天</option>
                        <option value="30d">30 天</option>
                    </select>
                    <select id="historyMetric" onchange="loadHistory()" style="padding: 0.45rem 0.75rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); font-size: 0.8rem; outline: none;">
                        <option value="requests">请求</option>
                        <option value="d1RowsRead">D1 读取</option>
                        <option value="d1RowsWritten">D1 写入</option>
                        <option value="kvReads">KV 读取</option>
                        <option value="kvWrites">KV 写入</option>
                        <option value="r2ClassA">R2 Class A</option>
                        <option value="r2ClassB">R2 Class B</option>
                        <option value="d1Storage">D1 存储</option>
                        <option value="kvStorage">KV 存储</option>
                        <option value="r2Storage">R2 存储</option>
                    </select>
                    <select id="historyAccount" onchange="loadHistory()" style="padding: 0.45rem 0.75rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); font-size: 0.8rem; outline: none;">
                        <option value="all">汇总</option>
                    </select>
                </div>
            </div>
            <div id="history-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>💰 费用估算</h2>
                <button class="add-btn" onclick="loadCostEstimate()">刷新估算</button>
            </div>
            <div id="cost-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>🔐 两步验证</h2>
                <button class="add-btn" onclick="load2FAStatus()">刷新</button>
            </div>
            <div id="twofactor-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>🧾 审计日志</h2>
                <button class="add-btn" onclick="loadAuditLog()">刷新</button>
            </div>
            <div id="audit-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>👥 用户与权限</h2>
                <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                    <button class="add-btn" onclick="openUserModal()">新增用户</button>
                    <button class="nav-btn" onclick="openPasswordModal()">修改管理员密码</button>
                </div>
            </div>
            <div id="users-content">
                <div class="loading-wrap"><div class="loading-spinner"></div></div>
            </div>
            <div style="margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--stroke);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                    <h3 style="font-size: 0.95rem;">登录会话</h3>
                    <button class="nav-btn" onclick="loadSessions()" style="padding: 0.35rem 0.7rem; font-size: 0.75rem;">刷新会话</button>
                </div>
                <div id="sessions-content" style="font-size: 0.78rem; color: var(--text-muted);">加载中...</div>
            </div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>🔑 只读 Token</h2>
                <button class="nav-btn" onclick="loadTokens()">刷新</button>
            </div>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: flex-end; margin-bottom: 0.75rem;">
                <div class="input-group" style="flex: 1; min-width: 150px; margin: 0;"><label>名称</label><input type="text" id="tokenName" placeholder="例如 Grafana / 状态页"></div>
                <div class="input-group" style="flex: 1; min-width: 150px; margin: 0;"><label>授权账号（ID，逗号分隔；留空=全部）</label><input type="text" id="tokenAccounts" placeholder="1,2"></div>
                <div class="input-group" style="max-width: 130px; margin: 0;"><label>有效期（天）</label><input type="number" id="tokenExpiresDays" min="0" max="3650" value="0"></div>
                <button class="add-btn" onclick="createToken()">生成</button>
            </div>
            <div id="tokens-content" style="font-size: 0.8rem; color: var(--text-muted);">加载中...</div>
        </div>

        <div class="glass-card accounts-card">
            <div class="module-header">
                <h2>💾 备份与恢复</h2>
            </div>
            <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 0.75rem;">备份包含账号密钥与告警配置（不含会话/Token/2FA），使用口令 AES-GCM 加密。请妥善保存口令，丢失后无法恢复。</p>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: flex-end;">
                <div class="input-group" style="flex: 1; min-width: 180px; margin: 0;"><label>备份口令（至少 8 位）</label><input type="password" id="backupPassphrase" autocomplete="new-password"></div>
                <button class="add-btn" onclick="exportBackup()">导出加密备份</button>
                <input type="file" id="backupFile" accept=".json,application/json" style="display: none;" onchange="importBackup(this)">
                <button class="nav-btn" onclick="document.getElementById('backupFile').click()">导入备份</button>
            </div>
            <div id="backup-status" style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.5rem;"></div>
        </div>

        <div class="footer">
            由 <a href="https://github.com/cmliu/CF-Workers-UsagePanel" target="_blank" rel="noopener" class="footer">CF-Workers-UsagePanel</a> 强力驱动
        </div>
    </div>

    <!-- 添加账号模态框 -->
    <div class="modal-overlay" id="addModal">
        <div class="modal" style="max-width: 440px;">
            <h3>⚙️ 添加 Cloudflare 账号</h3>
            <div class="input-group">
                <label>账号备注</label>
                <input type="text" id="newName" placeholder="我的账号">
            </div>
            <div class="input-group">
                <label>验证方式</label>
                <select id="authMethod" onchange="switchAuthMethod()" style="width: 100%; padding: 0.75rem 1rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 12px; color: var(--text-main); outline: none; cursor: pointer; appearance: none; -webkit-appearance: none;">
                    <option value="token">Account ID + API Token</option>
                    <option value="global">Email + Global API Key</option>
                </select>
            </div>
            <div id="tokenFields">
                <div class="input-group">
                    <label>Account ID</label>
                    <input type="text" id="newAccountID" placeholder="Workers和Pages 面板右侧的 AccountID">
                </div>
                <div class="input-group">
                    <label>API Token</label>
                    <input type="password" id="newAPIToken" placeholder='包含"阅读分析数据和日志"权限的 API令牌'>
                </div>
            </div>
            <div id="globalFields" style="display: none;">
                <div class="input-group">
                    <label>Email</label>
                    <input type="email" id="newEmail" placeholder="您的 Cloudflare 账号邮箱">
                </div>
                <div class="input-group">
                    <label>Global API Key</label>
                    <input type="password" id="newGlobalAPIKey" placeholder="您的 Global API Key">
                </div>
            </div>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closeAddModal()">取消</button>
                <button class="modal-btn confirm" onclick="handleAddAccount()">添加</button>
            </div>
        </div>
    </div>

    <!-- Top 脚本与错误率模态框 -->
    <div class="modal-overlay" id="topScriptsModal">
        <div class="modal" style="max-width: 680px;">
            <h3>📊 Top 脚本与错误率</h3>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: flex-end; margin-bottom: 0.75rem;">
                <div class="input-group" style="flex: 1; min-width: 180px; margin: 0;">
                    <label>选择账号</label>
                    <select id="topScriptsAccount" style="width: 100%; padding: 0.65rem 0.9rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); outline: none;"></select>
                </div>
                <div class="input-group" style="margin: 0; min-width: 130px;">
                    <label>时间范围</label>
                    <select id="topScriptsRange" style="width: 100%; padding: 0.65rem 0.9rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); outline: none;">
                        <option value="24h">24 小时</option>
                        <option value="7d">7 天</option>
                        <option value="30d">30 天</option>
                    </select>
                </div>
                <button class="add-btn" onclick="loadTopScripts()">查询</button>
            </div>
            <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 0.75rem;">按 Workers 脚本聚合请求数与错误数，最多显示 Top 10。需要 API Token 具备 Workers 分析数据读取权限；单次查询消耗 1 个子请求。</p>
            <div id="topScriptsContent" style="min-height: 160px;">
                <div style="color: var(--text-muted); font-size: 0.85rem;">选择账号和时间范围后点击「查询」</div>
            </div>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closeTopScriptsModal()">关闭</button>
            </div>
        </div>
    </div>

    <!-- 用户编辑模态框 -->
    <div class="modal-overlay" id="userModal">
        <div class="modal" style="max-width: 560px;">
            <h3 id="userModalTitle">新增用户</h3>
            <div class="input-group">
                <label>用户名</label>
                <input type="text" id="userName" placeholder="2-32 位字母、数字、下划线、点或短横线" autocomplete="off">
            </div>
            <div class="input-group">
                <label>密码</label>
                <input type="password" id="userPassword" placeholder="至少 8 位；编辑时留空表示不修改" autocomplete="new-password">
            </div>
            <div class="input-group">
                <label>角色</label>
                <select id="userRole">
                    <option value="viewer">只读用户</option>
                    <option value="admin">管理员</option>
                </select>
            </div>
            <div class="input-group">
                <label>授权账号（账号 ID，逗号分隔；留空 = 全部）</label>
                <input type="text" id="userAccounts" placeholder="例如：1,2；留空表示全部账号">
            </div>
            <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 0.5rem;">只读用户只能查看授权账号；管理员拥有全部权限。密码使用 PBKDF2-SHA256 哈希后存 KV。</p>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closeUserModal()">取消</button>
                <button class="modal-btn confirm" onclick="saveUser()">保存</button>
            </div>
        </div>
    </div>

    <!-- 修改管理员密码模态框 -->
    <div class="modal-overlay" id="passwordModal">
        <div class="modal" style="max-width: 480px;">
            <h3>修改管理员密码</h3>
            <div class="input-group">
                <label>当前密码</label>
                <input type="password" id="currentAdminPassword" autocomplete="current-password">
            </div>
            <div class="input-group">
                <label>新密码</label>
                <input type="password" id="newAdminPassword" placeholder="至少 8 位" autocomplete="new-password">
            </div>
            <div class="input-group">
                <label>确认新密码</label>
                <input type="password" id="confirmAdminPassword" autocomplete="new-password">
            </div>
            <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 0.5rem;">修改成功后会吊销其它设备上的登录会话，当前会话保留。</p>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closePasswordModal()">取消</button>
                <button class="modal-btn confirm" onclick="saveAdminPassword()">确认修改</button>
            </div>
        </div>
    </div>

    <!-- 用量优化建议模态框 -->
    <div class="modal-overlay" id="optimizeModal">
        <div class="modal" style="max-width: 720px;">
            <h3>🧠 用量优化建议</h3>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: flex-end; margin-bottom: 0.75rem;">
                <div class="input-group" style="flex: 1; min-width: 200px; margin: 0;">
                    <label>选择账号</label>
                    <select id="optimizeAccount" style="width: 100%; padding: 0.7rem 0.9rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 12px; color: var(--text-main); outline: none;"></select>
                </div>
                <button class="add-btn" onclick="runOptimizeAnalysis()">开始分析</button>
            </div>
            <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.5; margin-bottom: 0.75rem;">
                仅管理员手动触发；默认最多分析 6 个脚本（可用环境变量 OPTIMIZE_MAX_SCRIPTS 调整，最大 20）。需要 API Token 具备 Workers Scripts:Read 权限；分析过程不写 KV/D1。
            </p>
            <div id="optimizeContent" style="min-height: 160px;">
                <div style="color: var(--text-muted); font-size: 0.85rem;">选择账号后点击「开始分析」</div>
            </div>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closeOptimizeModal()">关闭</button>
            </div>
        </div>
    </div>

    <!-- 用量排行榜模态框 -->
    <div class="modal-overlay" id="rankingModal">
        <div class="modal" style="max-width: 640px;">
            <h3>📊 用量排行榜</h3>
            <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem;">
                <button class="ranking-tab" data-tab="workers" onclick="switchRankingTab('workers', this)">Workers</button>
                <button class="ranking-tab" data-tab="pages" onclick="switchRankingTab('pages', this)">Pages</button>
                <button class="ranking-tab" data-tab="total" onclick="switchRankingTab('total', this)">总请求</button>
                <button class="ranking-tab" data-tab="d1" onclick="switchRankingTab('d1', this)">D1</button>
                <button class="ranking-tab" data-tab="kv" onclick="switchRankingTab('kv', this)">KV</button>
                <button class="ranking-tab" data-tab="r2" onclick="switchRankingTab('r2', this)">R2</button>
            </div>
            <div id="rankingContent" style="min-height: 180px;"></div>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closeRankingModal()">关闭</button>
            </div>
        </div>
    </div>

    <!-- 导出报告模态框 -->
    <div class="modal-overlay" id="exportModal">
        <div class="modal" style="max-width: 420px;">
            <h3>📤 导出用量报告</h3>
            <div class="input-group">
                <label>导出格式</label>
                <select id="exportFormat" style="width: 100%; padding: 0.75rem 1rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 12px; color: var(--text-main); outline: none;">
                    <option value="json">JSON（含账号汇总 + 历史）</option>
                    <option value="csv">CSV（按天历史，Excel 可直接打开）</option>
                </select>
            </div>
            <div class="input-group">
                <label>统计天数</label>
                <input type="number" id="exportDays" min="1" max="365" value="30">
            </div>
            <p style="font-size: 0.75rem; color: var(--text-muted); line-height: 1.5;">导出内容不包含 API Key / Bot Token / Webhook URL 等敏感信息；历史数据来自 D1，未绑定 D1 时使用 KV 每日快照。</p>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closeExportModal()">取消</button>
                <button class="modal-btn confirm" onclick="downloadReport()">下载</button>
            </div>
        </div>
    </div>

    <!-- 账号配额模态框 -->
    <div class="modal-overlay" id="limitsModal">
        <div class="modal" style="max-width: 560px;">
            <h3>⚙️ 账号配额设置</h3>
            <p style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.75rem; line-height: 1.5;">
                JSON 对象，可设置：requestsDaily、d1RowsReadDaily、d1RowsWrittenDaily、d1StorageBytes、
                kvReadsDaily、kvWritesDaily、kvDeletesDaily、kvListsDaily、kvStorageBytes、
                r2ClassAMonthly、r2ClassBMonthly、r2StorageBytes；留空恢复默认免费额度。
            </p>
            <textarea id="limitsJson" rows="9" style="width: 100%; padding: 0.75rem; border-radius: 12px; background: var(--input-bg); border: 1px solid var(--stroke); color: var(--text-main); font-family: monospace; font-size: 0.8rem; resize: vertical;"></textarea>
            <div class="modal-actions">
                <button class="modal-btn cancel" onclick="closeLimitsModal()">取消</button>
                <button class="modal-btn confirm" onclick="saveAccountLimits()">保存</button>
            </div>
        </div>
    </div>

    <div class="toast" id="toast"></div>

    <script>
        ${生成语言脚本()}
        function 转义HTML(value) {
            return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
            });
        }

        function 安全读取主题() {
            try { return localStorage.getItem('theme'); } catch (err) { return null; }
        }

        function 安全写入主题(value) {
            try { localStorage.setItem('theme', value); } catch (err) { /* 忽略存储不可用 */ }
        }

        function initTheme() {
            const savedTheme = 安全读取主题();
            const systemLight = window.matchMedia('(prefers-color-scheme: light)').matches;
            if (savedTheme === 'light' || (!savedTheme && systemLight)) {
                document.documentElement.classList.add('light-mode');
            }
            updateThemeIcons();
        }

        function toggleTheme() {
            const isLight = document.documentElement.classList.toggle('light-mode');
            安全写入主题(isLight ? 'light' : 'dark');
            updateThemeIcons();
        }

        function updateThemeIcons() {
            const isLight = document.documentElement.classList.contains('light-mode');
            document.getElementById('sun-icon').style.display = isLight ? 'none' : 'block';
            document.getElementById('moon-icon').style.display = isLight ? 'block' : 'none';
        }

        initTheme();
        
        function showToast(msg) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.classList.add('active');
            setTimeout(() => toast.classList.remove('active'), 3000);
        }

        function copyUsageAPI() {
            const url = window.location.origin + '/usage.json';
            navigator.clipboard.writeText(url).then(() => {
                showToast('✅ UsageAPI 已复制到粘贴板');
            }).catch(() => showToast('❌ 复制失败，请手动复制'));
        }

        async function logout() {
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch (err) {
                console.error('登出请求失败:', err);
            } finally {
                window.location.href = '/';
            }
        }

        async function refreshUsage() {
            try {
                showToast('⏳ 正在刷新数据...');
                const res = await fetch('/admin/usage.json?force=1');
                if (!res.ok) throw new Error('会话已过期，请重新登录');
                const data = await res.json();
                await Promise.all([fetchSummary(), fetchConfig()]);
                showToast(data.msg || '✅ 数据已刷新');
            } catch (err) {
                console.error(err);
                showToast('❌ 刷新失败');
            }
        }

        let 当前配额账号ID = null;

        function openLimitsModal(id, limits) {
            当前配额账号ID = id;
            document.getElementById('limitsJson').value = limits && Object.keys(limits).length > 0 ? JSON.stringify(limits, null, 2) : '';
            document.getElementById('limitsModal').classList.add('active');
        }

        function closeLimitsModal() {
            document.getElementById('limitsModal').classList.remove('active');
            当前配额账号ID = null;
        }

        async function saveAccountLimits() {
            if (当前配额账号ID === null) return;
            let limits = {};
            const 文本 = document.getElementById('limitsJson').value.trim();
            if (文本) {
                try {
                    limits = JSON.parse(文本);
                } catch (err) {
                    showToast('❌ JSON 格式错误');
                    return;
                }
            }
            try {
                const res = await fetch('/admin/account-limits', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ID: 当前配额账号ID, Limits: limits })
                });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '保存失败');
                showToast('✅ 账号配额已更新');
                closeLimitsModal();
                await Promise.all([fetchSummary(), fetchConfig()]);
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '保存失败'));
            }
        }

        function renderAlertForm(config) {
            const th = config.thresholds || {};
            const tg = config.telegram || {};
            const wh = config.webhook || {};
            const fc = config.forecast || {};
            const dr = config.dailyReport || {};
            const 阈值字段 = [
                ['requests', '总请求阈值 %'],
                ['d1RowsRead', 'D1 读取阈值 %'],
                ['d1RowsWritten', 'D1 写入阈值 %'],
                ['kvReads', 'KV 读取阈值 %'],
                ['kvWrites', 'KV 写入阈值 %'],
                ['r2ClassA', 'R2 Class A 阈值 %'],
                ['r2ClassB', 'R2 Class B 阈值 %'],
                ['d1Storage', 'D1 存储阈值 %'],
                ['kvStorage', 'KV 存储阈值 %'],
                ['r2Storage', 'R2 存储阈值 %']
            ];
            const 阈值输入 = 阈值字段.map(function (item) {
                return '<div class="input-group"><label>' + item[1] + '</label><input type="number" min="0" max="100" id="th-' + item[0] + '" value="' + (Number(th[item[0]]) || 0) + '"></div>';
            }).join('');
            document.getElementById('alert-content').innerHTML = \`
                <div style="display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; margin-bottom: 1rem;">
                    <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.9rem;">
                        <input type="checkbox" id="alertEnabled" \${config.enabled ? 'checked' : ''}> 启用用量告警
                    </label>
                    <div class="input-group" style="margin: 0; max-width: 190px;">
                        <label>冷却时间（分钟）</label>
                        <input type="number" id="alertCooldown" min="5" max="10080" value="\${Number(config.cooldownMinutes) || 180}">
                    </div>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.75rem;">\${阈值输入}</div>
                <h3 style="margin: 1rem 0 0.5rem; font-size: 0.95rem;">Telegram</h3>
                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; margin-bottom: 0.5rem;">
                    <input type="checkbox" id="telegramEnabled" \${tg.enabled ? 'checked' : ''}> 启用 Telegram
                </label>
                <div class="input-group">
                    <label>Bot Token</label>
                    <input type="password" id="telegramBotToken" placeholder="\${tg.botTokenSet ? '已配置，留空保持不变' : '123456:ABC...'}" value="">
                </div>
                <div class="input-group">
                    <label>Chat ID</label>
                    <input type="text" id="telegramChatId" placeholder="例如 123456789" value="\${转义HTML(tg.chatId || '')}">
                </div>
                <h3 style="margin: 1rem 0 0.5rem; font-size: 0.95rem;">通用 Webhook</h3>
                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; margin-bottom: 0.5rem;">
                    <input type="checkbox" id="webhookEnabled" \${wh.enabled ? 'checked' : ''}> 启用 Webhook
                </label>
                <div class="input-group">
                    <label>Webhook 平台</label>
                    <select id="webhookPlatform" style="width: 100%; padding: 0.75rem 1rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 12px; color: var(--text-main); outline: none;">
                        <option value="generic" \${wh.platform === 'generic' || !wh.platform ? 'selected' : ''}>通用 JSON（自接 n8n/自建）</option>
                        <option value="dingtalk" \${wh.platform === 'dingtalk' ? 'selected' : ''}>钉钉机器人</option>
                        <option value="feishu" \${wh.platform === 'feishu' ? 'selected' : ''}>飞书机器人</option>
                        <option value="wecom" \${wh.platform === 'wecom' ? 'selected' : ''}>企业微信群机器人</option>
                        <option value="telegram" \${wh.platform === 'telegram' ? 'selected' : ''}>Telegram Bot API（URL 直连）</option>
                        <option value="discord" \${wh.platform === 'discord' ? 'selected' : ''}>Discord Webhook</option>
                        <option value="slack" \${wh.platform === 'slack' ? 'selected' : ''}>Slack Incoming Webhook</option>
                    </select>
                </div>
                <div class="input-group">
                    <label>Webhook URL</label>
                    <input type="password" id="webhookUrl" placeholder="\${wh.urlSet ? '已配置，留空保持不变' : 'https://example.com/webhook'}" value="">
                </div>
                <h3 style="margin: 1rem 0 0.5rem; font-size: 0.95rem;">其他 Webhook（多目标，可选）</h3>
                <div class="input-group">
                    <label>Webhooks JSON 数组</label>
                    <textarea id="webhooksJson" rows="4" style="width: 100%; padding: 0.65rem 0.9rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); font-family: monospace; font-size: 0.75rem; outline: none;">\${转义HTML(JSON.stringify(config.webhooks || [], null, 2))}</textarea>
                </div>
                <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.5;">字段：name、url、platform（generic/dingtalk/feishu/wecom/telegram/discord/slack）、enabled。留空数组时使用上面的单一 Webhook。最多 5 个。</p>
                <h3 style="margin: 1rem 0 0.5rem; font-size: 0.95rem;">静默时段</h3>
                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; margin-bottom: 0.5rem;">
                    <input type="checkbox" id="quietEnabled" \${config.quietHours?.enabled ? 'checked' : ''}> 启用静默时段（UTC 小时，静默期间不发送告警/预测/日报）
                </label>
                <div style="display: flex; gap: 0.75rem; flex-wrap: wrap;">
                    <div class="input-group" style="max-width: 150px;"><label>开始（UTC）</label><input type="number" id="quietStart" min="0" max="23" value="\${Number(config.quietHours?.startUtc ?? 22)}"></div>
                    <div class="input-group" style="max-width: 150px;"><label>结束（UTC）</label><input type="number" id="quietEnd" min="0" max="23" value="\${Number(config.quietHours?.endUtc ?? 7)}"></div>
                </div>
                <h3 style="margin: 1rem 0 0.5rem; font-size: 0.95rem;">自定义告警规则</h3>
                <div class="input-group">
                    <label>规则 JSON 数组</label>
                    <textarea id="alertRulesJson" rows="5" style="width: 100%; padding: 0.65rem 0.9rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); font-family: monospace; font-size: 0.75rem; outline: none;">\${转义HTML(JSON.stringify(config.rules || [], null, 2))}</textarea>
                </div>
                <p style="font-size: 0.72rem; color: var(--text-muted); line-height: 1.5;">字段：name、metric（requests/d1RowsRead/.../r2Storage）、scope（total/account）、accountId（scope=account 时必填）、threshold（1-100）、channels（telegram/webhook）、enabled。最多 10 条；与固定阈值告警同时评估。</p>
                <h3 style="margin: 1rem 0 0.5rem; font-size: 0.95rem;">预测告警 / 每日报告</h3>
                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; margin-bottom: 0.5rem;">
                    <input type="checkbox" id="forecastEnabled" \${fc.enabled ? 'checked' : ''}> 启用 D1 预测告警（需绑定 D1）
                </label>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.75rem;">
                    <div class="input-group">
                        <label>预测提前量（小时）</label>
                        <input type="number" id="forecastHours" min="1" max="168" value="\${Number(fc.hours) || 24}">
                    </div>
                    <div class="input-group">
                        <label>预测检查间隔（分钟）</label>
                        <input type="number" id="forecastCheckMinutes" min="15" max="1440" value="\${Number(fc.checkMinutes) || 60}">
                    </div>
                </div>
                <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; margin: 0.5rem 0;">
                    <input type="checkbox" id="dailyReportEnabled" \${dr.enabled ? 'checked' : ''}> 启用每日用量报告
                </label>
                <div class="input-group" style="max-width: 220px;">
                    <label>日报发送时间（UTC 小时）</label>
                    <input type="number" id="dailyReportHourUtc" min="0" max="23" value="\${Number.isFinite(Number(dr.hourUtc)) ? Number(dr.hourUtc) : 1}">
                </div>
                <div style="display: flex; gap: 0.75rem; margin-top: 1rem; flex-wrap: wrap;">
                    <button class="modal-btn confirm" onclick="saveAlertConfig()">保存设置</button>
                    <button class="modal-btn cancel" onclick="sendAlertTest()">发送测试消息</button>
                    <button class="modal-btn cancel" onclick="sendDailyReportTest()">发送日报测试</button>
                </div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.75rem; line-height: 1.5;">
                    普通告警在 cron 和管理员手动刷新后评估；预测告警/每日报告只在 cron 中评估（预测需要 D1 历史，日报按 UTC 整点发送一次）。阈值填 0 表示不检查该项。
                </div>
            \`;
        }

        async function loadAlertConfig() {
            const 容器 = document.getElementById('alert-content');
            try {
                const res = await fetch('/admin/alerts.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                renderAlertForm(await res.json());
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger)">加载告警配置失败，请刷新页面或重新登录</div>';
            }
        }

        async function loadAlertHistory() {
            const 容器 = document.getElementById('alert-history-content');
            if (!容器) return;
            try {
                const res = await fetch('/admin/alerts/history.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                const 历史 = await res.json();
                if (!Array.isArray(历史) || 历史.length === 0) {
                    容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">暂无告警历史</div>';
                    return;
                }
                let html = '';
                for (const 条目 of 历史.slice(0, 50)) {
                    html += '<div style="display: flex; justify-content: space-between; gap: 0.5rem; padding: 0.4rem 0; border-bottom: 1px solid var(--stroke); font-size: 0.78rem;">' +
                        '<div><div>' + 转义HTML(条目.metricLabel || '') + ' · ' + 转义HTML(条目.scope === 'total' ? '汇总' : (条目.accountName || '')) +
                        (条目.ruleId ? ' · 规则' : '') + '</div>' +
                        '<div style="font-size: 0.7rem; color: var(--text-muted);">' + 转义HTML(条目.time ? new Date(条目.time).toLocaleString() : '') +
                        ' · ' + Number(条目.percent || 0).toFixed(1) + '% / 阈值 ' + Number(条目.threshold || 0) + '% · ' + Number(条目.channelsSent || 0) + ' 个渠道</div></div>' +
                        '<div style="font-size: 0.72rem; color: var(--text-muted); white-space: nowrap;">' + 转义HTML(条目.accountName || '') + '</div></div>';
                }
                容器.innerHTML = html;
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">告警历史加载失败</div>';
            }
        }

        async function loadAnomalies() {
            const 容器 = document.getElementById('anomaly-content');
            if (!容器) return;
            容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">检测中...</div>';
            try {
                const res = await fetch('/admin/anomaly.json?t=' + Date.now());
                if (!res.ok) throw new Error('检测失败');
                const 数据 = await res.json();
                if (!数据.available) {
                    容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">' + 转义HTML(数据.msg || '异常检测不可用') + '</div>';
                    return;
                }
                if (!Array.isArray(数据.anomalies) || 数据.anomalies.length === 0) {
                    容器.innerHTML = '<div style="color: #4ade80; font-size: 0.82rem;">✅ ' + 转义HTML(数据.msg || '未检测到明显异常') + '</div>' +
                        '<div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.4rem;">' + 转义HTML(数据.note || '') + '</div>';
                    return;
                }
                let html = '<div style="color: #f59e0b; font-size: 0.82rem; margin-bottom: 0.5rem;">⚠️ ' + 转义HTML(数据.msg || '') + '</div>';
                for (const 异常 of 数据.anomalies) {
                    html += '<div style="padding: 0.4rem 0; border-bottom: 1px solid var(--stroke); font-size: 0.78rem;">' +
                        '<div style="display: flex; justify-content: space-between;"><span>' + 转义HTML(异常.label || '') + '</span><span>Z=' + Number(异常.zScore || 0).toFixed(2) + ' · ' + Number(异常.ratio || 0).toFixed(2) + 'x</span></div>' +
                        '<div style="font-size: 0.7rem; color: var(--text-muted);">当前 ' + Number(异常.latest || 0).toLocaleString() + ' · 历史均值 ' + Number(异常.baselineMean || 0).toLocaleString() + '</div></div>';
                }
                html += '<div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.5rem;">' + 转义HTML(数据.note || '') + '</div>';
                容器.innerHTML = html;
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.82rem;">异常检测失败</div>';
            }
        }

        async function clearAlertHistory() {
            if (!confirm('确认清空全部告警历史？')) return;
            try {
                const res = await fetch('/admin/alerts/history/clear', { method: 'POST' });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '清空失败');
                showToast('✅ 告警历史已清空');
                loadAlertHistory();
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '清空失败'));
            }
        }

        async function saveAlertConfig() {
            const thresholds = {};
            ['requests', 'd1RowsRead', 'd1RowsWritten', 'kvReads', 'kvWrites', 'r2ClassA', 'r2ClassB', 'd1Storage', 'kvStorage', 'r2Storage'].forEach(function (key) {
                const 输入 = document.getElementById('th-' + key);
                thresholds[key] = 输入 ? (Number(输入.value) || 0) : 0;
            });
            let webhooks = [];
            let rules = [];
            try {
                const webhooks文本 = document.getElementById('webhooksJson').value.trim();
                if (webhooks文本) webhooks = JSON.parse(webhooks文本);
                if (!Array.isArray(webhooks)) throw new Error('Webhooks 必须是数组');
                const rules文本 = document.getElementById('alertRulesJson').value.trim();
                if (rules文本) rules = JSON.parse(rules文本);
                if (!Array.isArray(rules)) throw new Error('告警规则必须是数组');
            } catch (e) {
                showToast('❌ ' + (e.message || 'JSON 格式错误'));
                return;
            }
            const body = {
                enabled: document.getElementById('alertEnabled').checked,
                cooldownMinutes: Number(document.getElementById('alertCooldown').value) || 180,
                thresholds: thresholds,
                webhooks: webhooks,
                quietHours: {
                    enabled: document.getElementById('quietEnabled').checked,
                    startUtc: Number(document.getElementById('quietStart').value) || 0,
                    endUtc: Number(document.getElementById('quietEnd').value) || 0
                },
                rules: rules,
                telegram: {
                    enabled: document.getElementById('telegramEnabled').checked,
                    botToken: document.getElementById('telegramBotToken').value,
                    chatId: document.getElementById('telegramChatId').value
                },
                webhook: {
                    enabled: document.getElementById('webhookEnabled').checked,
                    url: document.getElementById('webhookUrl').value,
                    platform: document.getElementById('webhookPlatform').value
                },
                forecast: {
                    enabled: document.getElementById('forecastEnabled').checked,
                    hours: Number(document.getElementById('forecastHours').value) || 24,
                    checkMinutes: Number(document.getElementById('forecastCheckMinutes').value) || 60
                },
                dailyReport: {
                    enabled: document.getElementById('dailyReportEnabled').checked,
                    hourUtc: Number(document.getElementById('dailyReportHourUtc').value) || 0
                }
            };
            try {
                const res = await fetch('/admin/alerts.json', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '保存失败');
                showToast('✅ 告警设置已保存');
                renderAlertForm(data.config);
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '保存失败'));
            }
        }

        async function sendAlertTest() {
            try {
                const res = await fetch('/admin/alerts/test', { method: 'POST' });
                const data = await res.json();
                showToast(data.success ? '✅ 测试消息已发送' : '❌ ' + (data.msg || '发送失败'));
            } catch (err) {
                console.error(err);
                showToast('❌ 发送测试消息失败');
            }
        }

        async function sendDailyReportTest() {
            try {
                const res = await fetch('/admin/report/test', { method: 'POST' });
                const data = await res.json();
                showToast(data.success ? '✅ 日报已发送' : '❌ ' + (data.msg || '发送失败'));
            } catch (err) {
                console.error(err);
                showToast('❌ 发送日报失败');
            }
        }

        let 最新账号配置 = [];
        let 排行榜数据 = null;
        let 当前排行标签 = 'workers';

        function 渲染账号明细(accounts) {
            const 容器 = document.getElementById('breakdown-content');
            if (!容器) return;
            const 列表 = (accounts || []).filter(account => (account.Usage && (account.Usage.total || 0)) > 0)
                .sort((a, b) => ((b.Usage && b.Usage.total) || 0) - ((a.Usage && a.Usage.total) || 0));
            if (列表.length === 0) {
                容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">暂无账号用量数据</div>';
                return;
            }
            const 颜色列表 = ['#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#06b6d4', '#ef4444', '#84cc16'];
            let html = '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">' +
                '<span style="font-size: 0.9rem; font-weight: 600;">各账号用量明细</span>' +
                '<span style="font-size: 0.7rem; background: var(--primary); color: #fff; padding: 0.15rem 0.5rem; border-radius: 99px;">' + 列表.length + '</span></div>';
            let 总请求 = 0;
            列表.forEach(function (account, index) {
                const usage = account.Usage || {};
                const total = Number(usage.total) || 0;
                const max = Number(usage.max) || 0;
                const percent = max > 0 ? Math.min(100, total / max * 100) : 0;
                const 颜色 = 颜色列表[index % 颜色列表.length];
                总请求 += total;
                html += '<div style="padding: 0.55rem 0; border-bottom: 1px solid var(--stroke);">' +
                    '<div style="display: flex; justify-content: space-between; gap: 0.5rem; font-size: 0.82rem;">' +
                    '<span style="display: flex; align-items: center; gap: 0.4rem; min-width: 0;"><span style="width: 9px; height: 9px; border-radius: 3px; background: ' + 颜色 + '; flex-shrink: 0;"></span><span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">' + 转义HTML(account.Name || ('账号 ' + account.ID)) + '</span></span>' +
                    '<span style="color: ' + 颜色 + '; font-variant-numeric: tabular-nums;">' + percent.toFixed(1) + '%</span></div>' +
                    '<div style="font-size: 0.72rem; color: var(--text-muted); margin: 0.25rem 0;">W: ' + formatNumber(usage.workers || 0) + ' · P: ' + formatNumber(usage.pages || 0) + ' · 合计 ' + formatNumber(total) + ' / ' + formatNumber(max) + '</div>' +
                    '<div style="height: 5px; border-radius: 99px; background: var(--track-bg); overflow: hidden;"><div style="width: ' + percent.toFixed(1) + '%; height: 100%; background: ' + 颜色 + ';"></div></div>' +
                    '</div>';
            });
            html += '<div style="display: flex; justify-content: space-between; font-size: 0.8rem; padding-top: 0.6rem; color: var(--text-muted);"><span>所有账号合计</span><span>' + formatNumber(总请求) + ' 请求</span></div>';
            容器.innerHTML = html;
        }

        function 计算排行榜(accounts) {
            const 列表 = (accounts || []).map(function (account) {
                const usage = account.Usage || {};
                const resources = usage.resources || {};
                const d1 = resources.d1 || {};
                const kv = resources.kv || {};
                const r2 = resources.r2 || {};
                return {
                    name: account.Name || ('账号 ' + account.ID),
                    workers: Number(usage.workers) || 0,
                    pages: Number(usage.pages) || 0,
                    total: Number(usage.total) || 0,
                    d1: (Number(d1.rowsRead) || 0) + (Number(d1.rowsWritten) || 0),
                    kv: (Number(kv.reads) || 0) + (Number(kv.writes) || 0),
                    r2: (Number(r2.classA) || 0) + (Number(r2.classB) || 0)
                };
            });
            const 排名 = function (key) {
                return 列表.slice().sort(function (a, b) { return b[key] - a[key]; })
                    .map(function (item, index) { return { rank: index + 1, name: item.name, value: item[key] }; });
            };
            return { workers: 排名('workers'), pages: 排名('pages'), total: 排名('total'), d1: 排名('d1'), kv: 排名('kv'), r2: 排名('r2') };
        }

        function 重置排行按钮() {
            document.querySelectorAll('.ranking-tab').forEach(function (btn) {
                btn.style.cssText = 'padding: 0.4rem 0.7rem; border-radius: 8px; border: 1px solid var(--stroke); background: var(--input-bg); color: var(--text-main); cursor: pointer; font-size: 0.78rem;';
            });
        }

        function 高亮排行按钮(tab) {
            重置排行按钮();
            const 按钮 = document.querySelector('.ranking-tab[data-tab="' + tab + '"]');
            if (按钮) { 按钮.style.background = 'var(--primary)'; 按钮.style.color = '#fff'; 按钮.style.borderColor = 'transparent'; }
        }

        function renderRanking(tab) {
            const 容器 = document.getElementById('rankingContent');
            const 列表 = (排行榜数据 || {})[tab] || [];
            if (列表.length === 0) { 容器.innerHTML = '<p style="text-align:center;color:var(--text-muted);padding:2rem;">暂无数据</p>'; return; }
            const 标签 = { workers: 'Workers 请求', pages: 'Pages 请求', total: '总请求', d1: 'D1 行操作', kv: 'KV 读写', r2: 'R2 请求' };
            let html = '<table style="width:100%;border-collapse:collapse;font-size:0.85rem;"><thead><tr>' +
                '<th style="text-align:left;padding:0.4rem;color:var(--text-muted);font-weight:500;">排名</th>' +
                '<th style="text-align:left;padding:0.4rem;color:var(--text-muted);font-weight:500;">账号</th>' +
                '<th style="text-align:right;padding:0.4rem;color:var(--text-muted);font-weight:500;">' + (标签[tab] || tab) + '</th></tr></thead><tbody>';
            列表.forEach(function (item) {
                const 颜色 = item.rank === 1 ? '#e0a030' : item.rank === 2 ? '#94a3b8' : item.rank === 3 ? '#b45309' : 'var(--text-muted)';
                html += '<tr><td style="padding:0.4rem;"><span style="display:inline-block;min-width:1.6rem;text-align:center;border-radius:6px;color:' + 颜色 + ';font-weight:600;">' + item.rank + '</span></td>' +
                    '<td style="padding:0.4rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:16rem;">' + 转义HTML(item.name) + '</td>' +
                    '<td style="padding:0.4rem;text-align:right;font-variant-numeric:tabular-nums;">' + formatNumber(item.value) + '</td></tr>';
            });
            html += '</tbody></table>';
            容器.innerHTML = html;
        }

        function openRankingModal() {
            if (!排行榜数据) 排行榜数据 = 计算排行榜(最新账号配置);
            document.getElementById('rankingModal').classList.add('active');
            当前排行标签 = 'workers';
            高亮排行按钮(当前排行标签);
            renderRanking(当前排行标签);
        }

        function closeRankingModal() {
            document.getElementById('rankingModal').classList.remove('active');
        }

        function switchRankingTab(tab, btn) {
            当前排行标签 = tab;
            高亮排行按钮(tab);
            renderRanking(tab);
        }

        function openExportModal() {
            document.getElementById('exportModal').classList.add('active');
        }

        function closeExportModal() {
            document.getElementById('exportModal').classList.remove('active');
        }

        async function downloadReport() {
            const 格式 = document.getElementById('exportFormat').value;
            const 天数 = Math.max(1, Math.min(365, Number(document.getElementById('exportDays').value) || 30));
            try {
                const res = await fetch('/admin/report/export?format=' + encodeURIComponent(格式) + '&days=' + 天数);
                if (!res.ok) throw new Error('HTTP ' + res.status);
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'cf-usage-' + new Date().toISOString().slice(0, 10) + '.' + 格式;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                closeExportModal();
                showToast('✅ 报告已开始下载');
            } catch (err) {
                console.error(err);
                showToast('❌ 导出失败，请刷新页面或重新登录');
            }
        }

        document.getElementById('rankingModal').addEventListener('click', function (e) { if (e.target === this) closeRankingModal(); });
        document.getElementById('exportModal').addEventListener('click', function (e) { if (e.target === this) closeExportModal(); });

        function 填充优化账号选项() {
            const 选择器 = document.getElementById('optimizeAccount');
            if (!选择器) return;
            选择器.innerHTML = '';
            if (最新账号配置.length === 0) {
                const 选项 = document.createElement('option');
                选项.value = '';
                选项.textContent = '暂无账号';
                选择器.appendChild(选项);
                return;
            }
            for (const account of 最新账号配置) {
                const 选项 = document.createElement('option');
                选项.value = String(account.ID);
                选项.textContent = account.Name || ('账号 ' + account.ID);
                选择器.appendChild(选项);
            }
        }

        function openOptimizeModal() {
            填充优化账号选项();
            document.getElementById('optimizeModal').classList.add('active');
        }

        function closeOptimizeModal() {
            document.getElementById('optimizeModal').classList.remove('active');
        }

        function 优化建议颜色(severity) {
            return severity === 'high' ? '#ef4444' : severity === 'medium' ? '#f59e0b' : '#94a3b8';
        }

        function 渲染优化通用建议(tips) {
            if (!Array.isArray(tips) || tips.length === 0) return '';
            let html = '<h4 style="margin: 1rem 0 0.5rem; font-size: 0.85rem;">通用优化建议</h4>';
            for (const tip of tips) {
                html += '<div style="padding: 0.5rem 0; border-bottom: 1px solid var(--stroke);">' +
                    '<div style="font-size: 0.8rem; font-weight: 600;">' + 转义HTML(tip.title || '') + '</div>' +
                    '<div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">' + 转义HTML(tip.description || '') + '</div>' +
                    '<div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">' + 转义HTML(tip.suggestion || '') + '</div></div>';
            }
            return html;
        }

        function renderOptimizeResult(data) {
            const 容器 = document.getElementById('optimizeContent');
            if (!data || data.success !== true) {
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.82rem; margin-bottom: 0.5rem;">' + 转义HTML((data && data.error) || '分析失败') + '</div>' + 渲染优化通用建议(data && data.tips);
                return;
            }
            const 建议列表 = data.suggestions || [];
            let html = '<div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.6rem;">账号 ' + 转义HTML(data.accountName || '') +
                ' · ' + Number(data.totalWorkers || 0) + ' 个 Worker，分析 ' + Number(data.analyzedWorkers || 0) + ' 个' + (data.truncated ? '（已截断）' : '') + '</div>';
            if (建议列表.length === 0) {
                html += '<div style="color: var(--text-muted); font-size: 0.82rem;">未发现明显问题，可参考下方通用建议。</div>';
            }
            for (const 建议 of 建议列表) {
                const 颜色 = 优化建议颜色(建议.severity);
                html += '<div style="border-left: 3px solid ' + 颜色 + '; padding: 0.4rem 0 0.6rem 0.6rem; margin-bottom: 0.4rem;">' +
                    '<div style="font-size: 0.82rem; font-weight: 600;">' + 转义HTML(建议.title || '') +
                    ' <span style="font-size: 0.65rem; color: ' + 颜色 + '; border: 1px solid ' + 颜色 + '; padding: 0.05rem 0.3rem; border-radius: 5px;">' + 转义HTML(建议.severity || '') + '</span></div>' +
                    '<div style="font-size: 0.74rem; color: var(--text-muted); margin-top: 0.2rem;">' + 转义HTML(建议.description || '') + '</div>' +
                    '<div style="font-size: 0.74rem; color: var(--text-main); margin-top: 0.25rem; white-space: pre-wrap;">' + 转义HTML(建议.suggestion || '') + '</div>' +
                    '<div style="font-size: 0.68rem; color: var(--text-muted); margin-top: 0.2rem;">脚本: ' + 转义HTML(建议.scriptName || '') + '</div></div>';
            }
            html += 渲染优化通用建议(data.tips);
            容器.innerHTML = html;
        }

        async function runOptimizeAnalysis() {
            const 容器 = document.getElementById('optimizeContent');
            const 选择器 = document.getElementById('optimizeAccount');
            const 账号ID = 选择器 ? 选择器.value : '';
            if (!账号ID) {
                显示消息('请先添加账号');
                return;
            }
            容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">分析中，可能需要几秒...</div>';
            try {
                const res = await fetch('/admin/optimize/analyze?account=' + encodeURIComponent(账号ID));
                if (!res.ok) throw new Error('HTTP ' + res.status);
                renderOptimizeResult(await res.json());
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.82rem;">分析失败，请刷新页面或重新登录</div>';
            }
        }

        document.getElementById('optimizeModal').addEventListener('click', function (e) { if (e.target === this) closeOptimizeModal(); });

        function 填充Top脚本账号选项() {
            const 选择器 = document.getElementById('topScriptsAccount');
            if (!选择器) return;
            选择器.innerHTML = '';
            if (最新账号配置.length === 0) {
                const 选项 = document.createElement('option');
                选项.value = '';
                选项.textContent = '暂无账号';
                选择器.appendChild(选项);
                return;
            }
            for (const account of 最新账号配置) {
                const 选项 = document.createElement('option');
                选项.value = String(account.ID);
                选项.textContent = account.Name || ('账号 ' + account.ID);
                选择器.appendChild(选项);
            }
        }

        function openTopScriptsModal() {
            填充Top脚本账号选项();
            document.getElementById('topScriptsModal').classList.add('active');
        }

        function closeTopScriptsModal() {
            document.getElementById('topScriptsModal').classList.remove('active');
        }

        function renderTopScripts(data) {
            const 容器 = document.getElementById('topScriptsContent');
            if (!data || data.success !== true) {
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.82rem;">' + 转义HTML((data && data.error) || '查询失败') + '</div>';
                return;
            }
            let html = '<div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.6rem;">' +
                转义HTML(data.accountName || '') + ' · ' + 转义HTML(data.range || '') +
                ' · 总请求 ' + formatNumber(data.totalRequests || 0) + ' · 错误 ' + formatNumber(data.totalErrors || 0) +
                ' · 错误率 ' + Number(data.errorRate || 0).toFixed(2) + '%</div>';
            const 列表 = data.scripts || [];
            if (列表.length === 0) {
                html += '<div style="color: var(--text-muted); font-size: 0.82rem;">该时间范围内没有脚本调用数据</div>';
            } else {
                html += '<div style="overflow-x: auto;"><table style="width: 100%; border-collapse: collapse; font-size: 0.8rem;"><thead><tr>' +
                    '<th style="text-align: left; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">脚本</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">请求数</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">错误数</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">错误率</th></tr></thead><tbody>';
                for (const 脚本 of 列表) {
                    const 错误率 = Number(脚本.errorRate || 0);
                    const 颜色 = 错误率 >= 5 ? '#ef4444' : 错误率 >= 1 ? '#f59e0b' : 'var(--text-main)';
                    html += '<tr>' +
                        '<td style="padding: 0.4rem; max-width: 18rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">' + 转义HTML(脚本.name || '') + '</td>' +
                        '<td style="padding: 0.4rem; text-align: right; font-variant-numeric: tabular-nums;">' + formatNumber(脚本.requests || 0) + '</td>' +
                        '<td style="padding: 0.4rem; text-align: right; font-variant-numeric: tabular-nums;">' + formatNumber(脚本.errors || 0) + '</td>' +
                        '<td style="padding: 0.4rem; text-align: right; color: ' + 颜色 + '; font-variant-numeric: tabular-nums;">' + 错误率.toFixed(2) + '%</td></tr>';
                }
                html += '</tbody></table></div>';
            }
            容器.innerHTML = html;
        }

        async function loadTopScripts() {
            const 容器 = document.getElementById('topScriptsContent');
            const 账户 = document.getElementById('topScriptsAccount').value;
            const 范围 = document.getElementById('topScriptsRange').value;
            if (!账户) {
                显示消息('请先添加账号');
                return;
            }
            容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.82rem;">查询中...</div>';
            try {
                const res = await fetch('/admin/top-scripts?account=' + encodeURIComponent(账户) + '&range=' + encodeURIComponent(范围));
                if (!res.ok) throw new Error('HTTP ' + res.status);
                renderTopScripts(await res.json());
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.82rem;">查询失败，请刷新页面或重新登录</div>';
            }
        }

        document.getElementById('topScriptsModal').addEventListener('click', function (e) { if (e.target === this) closeTopScriptsModal(); });

        let 历史账号列表 = [];

        function 更新历史账号选项() {
            const 选择器 = document.getElementById('historyAccount');
            if (!选择器) return;
            const 当前值 = 选择器.value || 'all';
            选择器.innerHTML = '<option value="all">汇总</option>';
            for (const 账号 of 历史账号列表) {
                const 选项 = document.createElement('option');
                选项.value = String(账号.ID);
                选项.textContent = 账号.Name;
                选择器.appendChild(选项);
            }
            选择器.value = Array.from(选择器.options).some(item => item.value === 当前值) ? 当前值 : 'all';
        }

        function 格式化历史值(指标, 数值) {
            if (指标 === 'd1Storage' || 指标 === 'kvStorage' || 指标 === 'r2Storage') return formatBytes(数值);
            return formatNumber(数值);
        }

        function 渲染历史图表(容器, 数据) {
            if (!数据 || 数据.historyEnabled === false) {
                容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem; line-height: 1.6;">未启用历史趋势：请在 Cloudflare Dashboard 给该 Worker 添加 D1 绑定（变量名建议 <b>DB</b>），绑定后刷新页面即可开始记录。</div>';
                return;
            }
            const 点列表 = 数据.points || [];
            if (点列表.length === 0) {
                容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem; line-height: 1.6;">暂无历史数据：等待下一次 cron/手动刷新后开始记录（每次刷新一个快照点）。</div>';
                return;
            }
            const 宽 = 640, 高 = 190, 左 = 56, 右 = 14, 上 = 14, 下 = 30;
            const 值列表 = 点列表.map(item => Number(item.v) || 0);
            const 最大值 = Math.max.apply(null, 值列表.concat([1]));
            const 缩放最大 = 最大值 * 1.08;
            const 最小时间 = 点列表[0].t;
            const 最大时间 = 点列表[点列表.length - 1].t;
            const X = function (t) { return 左 + (最大时间 === 最小时间 ? 0 : (t - 最小时间) / (最大时间 - 最小时间)) * (宽 - 左 - 右); };
            const Y = function (v) { return 上 + (1 - v / 缩放最大) * (高 - 上 - 下); };
            const 时间格式 = function (t) {
                const d = new Date(t);
                const p = function (n) { return String(n).padStart(2, '0'); };
                return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
            };
            const 网格线 = [0, 0.25, 0.5, 0.75, 1].map(function (比例) {
                const y = 上 + 比例 * (高 - 上 - 下);
                const 对应值 = 缩放最大 * (1 - 比例);
                return '<line x1="' + 左 + '" y1="' + y.toFixed(1) + '" x2="' + (宽 - 右) + '" y2="' + y.toFixed(1) + '" stroke="currentColor" stroke-opacity="0.08"/>' +
                    '<text x="' + (左 - 6) + '" y="' + (y + 3).toFixed(1) + '" text-anchor="end" fill="currentColor" fill-opacity="0.45" font-size="9">' + 转义HTML(格式化历史值(数据.metric, 对应值)) + '</text>';
            }).join('');
            const 折线点 = 点列表.map(function (item) { return X(item.t).toFixed(1) + ',' + Y(item.v).toFixed(1); }).join(' ');
            const 面积路径 = 'M ' + X(最小时间).toFixed(1) + ',' + (高 - 下) + ' L ' + 点列表.map(function (item) { return X(item.t).toFixed(1) + ',' + Y(item.v).toFixed(1); }).join(' L ') + ' L ' + X(最大时间).toFixed(1) + ',' + (高 - 下) + ' Z';
            const 末值 = 值列表[值列表.length - 1];
            const 预测 = 数据.forecast || {};
            let 预测文本 = '';
            if (Number(数据.limit) > 0) {
                const 百分比 = Math.min(999, (Number(数据.current) / Number(数据.limit)) * 100).toFixed(1);
                预测文本 = '当前 ' + 格式化历史值(数据.metric, 数据.current) + ' / ' + 格式化历史值(数据.metric, 数据.limit) + '（' + 百分比 + '%）';
                if (预测.hoursToLimit === 0) 预测文本 += '，已超过额度';
                else if (预测.hoursToLimit !== null && 预测.hoursToLimit !== undefined) 预测文本 += '，按当前速率约 ' + 预测.hoursToLimit + ' 小时后达到额度';
                else if (Number(预测.slopePerHour) > 0) 预测文本 += '，按当前速率预计仍有余量';
            } else {
                预测文本 = '暂无额度信息';
            }
            容器.innerHTML = '<svg viewBox="0 0 ' + 宽 + ' ' + 高 + '" style="width:100%;height:auto;display:block;color:var(--text-main);" role="img" aria-label="历史趋势">' +
                网格线 +
                '<path d="' + 面积路径 + '" fill="#6366f1" fill-opacity="0.12"/>' +
                '<polyline points="' + 折线点 + '" fill="none" stroke="#6366f1" stroke-width="2" stroke-linejoin="round"/>' +
                '<circle cx="' + X(最大时间).toFixed(1) + '" cy="' + Y(末值).toFixed(1) + '" r="3.2" fill="#6366f1"/>' +
                '<text x="' + 左 + '" y="' + (高 - 10) + '" fill="currentColor" fill-opacity="0.45" font-size="9">' + 转义HTML(时间格式(最小时间)) + '</text>' +
                '<text x="' + (宽 - 右) + '" y="' + (高 - 10) + '" text-anchor="end" fill="currentColor" fill-opacity="0.45" font-size="9">' + 转义HTML(时间格式(最大时间)) + '</text>' +
                '</svg>' +
                '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:0.5rem;">' + 转义HTML(预测文本) + '</div>';
        }

        async function loadHistory() {
            const 容器 = document.getElementById('history-content');
            const 范围 = document.getElementById('historyRange').value;
            const 指标 = document.getElementById('historyMetric').value;
            const 账户 = document.getElementById('historyAccount').value;
            try {
                const res = await fetch('/history?range=' + encodeURIComponent(范围) + '&metric=' + encodeURIComponent(指标) + '&account=' + encodeURIComponent(账户));
                if (!res.ok) throw new Error('加载历史失败');
                渲染历史图表(容器, await res.json());
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger)">加载历史趋势失败，请刷新页面或重新登录</div>';
            }
        }

        function 渲染费用估算(data) {
            const 容器 = document.getElementById('cost-content');
            if (!data || data.success !== true) {
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.85rem;">加载费用估算失败，请刷新页面或重新登录</div>';
                return;
            }
            const 元 = function (值) { return '$' + (Number(值) || 0).toFixed(2); };
            const 万 = function (值) {
                const 数值 = Number(值) || 0;
                if (数值 >= 100000000) return (数值 / 100000000).toFixed(2) + ' 亿';
                if (数值 >= 10000) return (数值 / 10000).toFixed(1) + ' 万';
                return String(Math.round(数值));
            };
            let html = '<div style="display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 1rem;">' +
                '<div style="flex: 1; min-width: 180px; padding: 0.75rem 0.9rem; border-radius: 12px; background: var(--item-bg);">' +
                '<div style="font-size: 0.75rem; color: var(--text-muted);">若全部升级 Workers Paid</div>' +
                '<div style="font-size: 1.45rem; font-weight: 700; margin-top: 0.2rem;">' + 元(data.总估算月费) + '<span style="font-size: 0.75rem; font-weight: 400; color: var(--text-muted);">/月</span></div>' +
                '<div style="font-size: 0.68rem; color: var(--text-muted); margin-top: 0.2rem;">基础 ' + 元(data.总基础费用) + ' + 超额 ' + 元(data.总超额费用) + '</div></div>' +
                '<div style="flex: 1; min-width: 180px; padding: 0.75rem 0.9rem; border-radius: 12px; background: var(--item-bg);">' +
                '<div style="font-size: 0.75rem; color: var(--text-muted);">账号数量</div>' +
                '<div style="font-size: 1.45rem; font-weight: 700; margin-top: 0.2rem;">' + Number(data.账号数 || 0) + '</div>' +
                '<div style="font-size: 0.68rem; color: var(--text-muted); margin-top: 0.2rem;">按每个账号独立 Workers Paid 估算</div></div>' +
                '</div>';

            const 账号列表 = data.账号 || [];
            if (账号列表.length === 0) {
                html += '<div style="color: var(--text-muted); font-size: 0.85rem;">暂无账号数据</div>';
            } else {
                html += '<div style="overflow-x: auto;"><table style="width: 100%; border-collapse: collapse; font-size: 0.8rem;"><thead><tr>' +
                    '<th style="text-align: left; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">账号</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">估算月费</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">请求/月</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">KV 写/月</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">D1 写/月</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted); font-weight: 500;">R2 A/月</th>' +
                    '</tr></thead><tbody>';
                for (const 账号 of 账号列表) {
                    const 超额 = 账号.超额明细 || {};
                    const 主要超额 = [
                        ['请求', 超额.workersRequests],
                        ['KV', (超额.kvReads || 0) + (超额.kvWrites || 0) + (超额.kvDeletes || 0) + (超额.kvLists || 0) + (超额.kvStorage || 0)],
                        ['D1', (超额.d1RowsRead || 0) + (超额.d1RowsWritten || 0) + (超额.d1Storage || 0)],
                        ['R2', (超额.r2ClassA || 0) + (超额.r2ClassB || 0) + (超额.r2Storage || 0)]
                    ].filter(item => item[1] > 0).map(item => item[0] + ' ' + 元(item[1])).join(' · ');
                    html += '<tr>' +
                        '<td style="padding: 0.45rem 0.4rem; max-width: 15rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">' + 转义HTML(账号.Name || '') + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem; text-align: right; font-weight: 600;">' + 元(账号.估算月费) + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem; text-align: right;">' + 万(账号.投影月用量?.requests) + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem; text-align: right;">' + 万(账号.投影月用量?.kvWrites) + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem; text-align: right;">' + 万(账号.投影月用量?.d1RowsWritten) + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem; text-align: right;">' + 万(账号.投影月用量?.r2ClassA) + '</td>' +
                        '</tr>' +
                        (主要超额 ? '<tr><td colspan="6" style="padding: 0 0.4rem 0.5rem; font-size: 0.68rem; color: var(--text-muted);">超额：' + 转义HTML(主要超额) + '</td></tr>' : '');
                }
                html += '</tbody></table></div>';
            }
            html += '<div style="font-size: 0.68rem; color: var(--text-muted); margin-top: 0.6rem; line-height: 1.6;">' +
                (data.假设 || []).map(function (文字) { return 转义HTML(文字); }).join('<br>') + '</div>';
            容器.innerHTML = html;
        }

        async function loadCostEstimate() {
            const 容器 = document.getElementById('cost-content');
            if (!容器) return;
            try {
                const res = await fetch('/admin/cost.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                渲染费用估算(await res.json());
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.85rem;">加载费用估算失败，请刷新页面或重新登录</div>';
            }
        }

        const 两步验证输入样式 = 'width: 100%; padding: 0.65rem 0.9rem; background: var(--input-bg); border: 1px solid var(--stroke); border-radius: 10px; color: var(--text-main); outline: none; font-size: 0.85rem;';

        function 渲染两步验证(data) {
            const 容器 = document.getElementById('twofactor-content');
            if (!data || data.success !== true) {
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.85rem;">加载两步验证状态失败，请刷新页面或重新登录</div>';
                return;
            }
            if (data.enabled) {
                const 启用时间 = data.enabledAt ? new Date(data.enabledAt).toLocaleString() : '未知';
                容器.innerHTML = '<div style="font-size: 0.85rem; color: #4ade80;">✅ 两步验证已启用</div>' +
                    '<div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.2rem;">启用时间：' + 转义HTML(启用时间) + '。登录时需要输入验证器中的 6 位验证码；剩余恢复码 ' + Number(data.backupRemaining || 0) + ' 个。</div>' +
                    '<div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: flex-end; margin-top: 0.75rem;">' +
                    '<input type="text" id="twofaDisableCode" inputmode="numeric" maxlength="6" placeholder="当前验证码" style="' + 两步验证输入样式 + ' max-width: 180px;">' +
                    '<button class="delete-btn" onclick="disable2FA()">关闭两步验证</button></div>';
                return;
            }
            容器.innerHTML = '<div style="font-size: 0.85rem; color: var(--text-muted);">未启用。启用后登录需要额外输入验证器验证码。</div>' +
                '<button class="add-btn" onclick="setup2FA()" style="margin-top: 0.75rem;">生成密钥并启用</button>';
        }

        async function load2FAStatus() {
            const 容器 = document.getElementById('twofactor-content');
            if (!容器) return;
            try {
                const res = await fetch('/admin/2fa.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                渲染两步验证(await res.json());
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.85rem;">加载两步验证状态失败，请刷新页面或重新登录</div>';
            }
        }

        async function setup2FA() {
            const 容器 = document.getElementById('twofactor-content');
            try {
                const res = await fetch('/admin/2fa/setup', { method: 'POST' });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '生成失败');
                容器.innerHTML = '<div style="font-size: 0.85rem;">1. 在验证器 App 中添加以下密钥：</div>' +
                    '<div style="margin: 0.5rem 0; padding: 0.6rem 0.75rem; border-radius: 10px; background: var(--input-bg); font-family: monospace; font-size: 0.78rem; word-break: break-all;">' + 转义HTML(data.secret) + '</div>' +
                    '<div style="font-size: 0.72rem; color: var(--text-muted); word-break: break-all;">或导入：' + 转义HTML(data.otpauth) + '</div>' +
                    '<div style="display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: flex-end; margin-top: 0.75rem;">' +
                    '<input type="text" id="twofaEnableCode" inputmode="numeric" maxlength="6" placeholder="输入 6 位验证码" style="' + 两步验证输入样式 + ' max-width: 200px;">' +
                    '<button class="add-btn" onclick="enable2FA()">验证并启用</button></div>';
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--danger); font-size: 0.85rem;">' + 转义HTML(err.message || '生成验证密钥失败') + '</div>';
            }
        }

        async function enable2FA() {
            const 输入 = document.getElementById('twofaEnableCode');
            const 验证码 = 输入 ? 输入.value.trim() : '';
            try {
                const res = await fetch('/admin/2fa/enable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: 验证码 }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '启用失败');
                showToast('✅ 两步验证已启用');
                const 容器 = document.getElementById('twofactor-content');
                const 恢复码 = Array.isArray(data.backupCodes) ? data.backupCodes : [];
                if (恢复码.length > 0) {
                    容器.innerHTML = '<div style="font-size: 0.85rem; color: #4ade80;">✅ 两步验证已启用</div>' +
                        '<div style="font-size: 0.78rem; margin-top: 0.5rem; color: #f59e0b;">请立即保存以下恢复码（只显示这一次），验证器丢失时可用其中一个登录：</div>' +
                        '<div style="margin: 0.6rem 0; padding: 0.7rem 0.9rem; border-radius: 10px; background: var(--input-bg); font-family: monospace; font-size: 0.9rem; line-height: 1.8; white-space: pre-wrap;">' + 恢复码.map(code => 转义HTML(code)).join('\\n') + '</div>' +
                        '<button class="add-btn" onclick="load2FAStatus()">我已保存，继续</button>';
                } else {
                    load2FAStatus();
                }
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '启用失败'));
            }
        }

        async function disable2FA() {
            const 输入 = document.getElementById('twofaDisableCode');
            const 验证码 = 输入 ? 输入.value.trim() : '';
            try {
                const res = await fetch('/admin/2fa/disable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: 验证码 }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '关闭失败');
                showToast('✅ 两步验证已关闭');
                load2FAStatus();
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '关闭失败'));
            }
        }

        async function loadSessionInfo() {
            try {
                const res = await fetch('/api/status?t=' + Date.now());
                if (!res.ok) return;
                const data = await res.json();
                if (data.role !== 'admin') {
                    const 横幅 = document.getElementById('viewer-banner');
                    if (横幅) {
                        横幅.textContent = '👁️ 只读账号（' + (data.username || 'viewer') + '）：可以查看数据，但无法修改配置或执行写操作。';
                        横幅.style.display = 'block';
                    }
                }
            } catch (err) {
                console.error('读取登录身份失败:', err);
            }
        }

        async function loadAuditLog() {
            const 容器 = document.getElementById('audit-content');
            if (!容器) return;
            try {
                const res = await fetch('/admin/audit.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                const 日志 = await res.json();
                if (!Array.isArray(日志) || 日志.length === 0) {
                    容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">暂无审计记录</div>';
                    return;
                }
                let html = '<div style="font-size: 0.72rem; color: var(--text-muted); margin-bottom: 0.5rem;">最近 ' + 日志.length + ' 条（最多保留 200 条）</div>';
                for (const 条目 of 日志.slice(0, 30)) {
                    html += '<div style="padding: 0.45rem 0; border-bottom: 1px solid var(--stroke); font-size: 0.78rem;">' +
                        '<div style="display: flex; justify-content: space-between; gap: 0.5rem;"><span>' + 转义HTML(条目.action || '') + '</span>' +
                        '<span style="color: var(--text-muted); font-size: 0.7rem;">' + 转义HTML(条目.time ? new Date(条目.time).toLocaleString() : '') + '</span></div>' +
                        '<div style="color: var(--text-muted); font-size: 0.7rem; margin-top: 0.15rem;">' + 转义HTML(条目.user || '') + ' (' + 转义HTML(条目.role || '') + ') · ' + 转义HTML(条目.detail || '') + '</div></div>';
                }
                容器.innerHTML = html;
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">审计日志仅管理员可查看</div>';
            }
        }

        let 缓存用户列表 = [];
        let 编辑用户ID = null;

        function 解析账号范围(文本) {
            const 列表 = String(文本 || '').split(/[,，\s]+/).map(item => item.trim()).filter(Boolean);
            return 列表.length > 0 ? 列表 : null;
        }

        async function loadUsers() {
            const 容器 = document.getElementById('users-content');
            if (!容器) return;
            try {
                const res = await fetch('/admin/users.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                const 数据 = await res.json();
                缓存用户列表 = 数据.users || [];
                let html = '<div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.6rem;">主管理员：<strong style="color: var(--text-main);">' + 转义HTML(数据.admin?.username || 'admin') + '</strong>' +
                    (数据.admin?.passwordChanged ? '（已通过面板修改密码）' : '（环境变量 PASSWORD）') + '</div>';
                html += '<div style="overflow-x: auto;"><table style="width: 100%; border-collapse: collapse; font-size: 0.8rem;"><thead><tr>' +
                    '<th style="text-align: left; padding: 0.4rem; color: var(--text-muted);">用户</th>' +
                    '<th style="text-align: left; padding: 0.4rem; color: var(--text-muted);">角色</th>' +
                    '<th style="text-align: left; padding: 0.4rem; color: var(--text-muted);">授权账号</th>' +
                    '<th style="text-align: left; padding: 0.4rem; color: var(--text-muted);">状态</th>' +
                    '<th style="text-align: right; padding: 0.4rem; color: var(--text-muted);">操作</th></tr></thead><tbody>';
                if (缓存用户列表.length === 0) {
                    html += '<tr><td colspan="5" style="padding: 0.6rem 0.4rem; color: var(--text-muted);">暂无面板用户；可通过「新增用户」创建只读或管理员账号。</td></tr>';
                }
                for (const 用户 of 缓存用户列表) {
                    const 范围 = Array.isArray(用户.accounts) && 用户.accounts.length > 0 ? 用户.accounts.join(', ') : '全部';
                    html += '<tr>' +
                        '<td style="padding: 0.45rem 0.4rem;">' + 转义HTML(用户.username) + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem;">' + (用户.role === 'admin' ? '管理员' : '只读') + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem; color: var(--text-muted);">' + 转义HTML(范围) + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem;">' + (用户.disabled ? '<span style="color:#f59e0b;">已禁用</span>' : '<span style="color:#4ade80;">启用</span>') + '</td>' +
                        '<td style="padding: 0.45rem 0.4rem; text-align: right; white-space: nowrap;">' +
                        '<button class="nav-btn" style="padding: 0.25rem 0.5rem; font-size: 0.72rem;" onclick="openUserModal(\\'' + 转义HTML(用户.id) + '\\')">编辑</button> ' +
                        '<button class="delete-btn" style="padding: 0.25rem 0.5rem; font-size: 0.72rem;" onclick="deleteUser(\\'' + 转义HTML(用户.id) + '\\', \\'' + 转义HTML(用户.username) + '\\')">删除</button>' +
                        '</td></tr>';
                }
                html += '</tbody></table></div>';
                if (Array.isArray(数据.envViewers) && 数据.envViewers.length > 0) {
                    html += '<div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 0.6rem;">环境变量只读用户：' + 数据.envViewers.map(item => 转义HTML(item.username)).join('、') + '（如需在面板内管理，请迁移到上面的用户列表）</div>';
                }
                容器.innerHTML = html;
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">用户管理仅管理员可用</div>';
            }
        }

        function openUserModal(id) {
            编辑用户ID = id || null;
            const 用户 = id ? 缓存用户列表.find(item => String(item.id) === String(id)) : null;
            document.getElementById('userModalTitle').textContent = id ? '编辑用户' : '新增用户';
            document.getElementById('userName').value = 用户 ? 用户.username : '';
            document.getElementById('userPassword').value = '';
            document.getElementById('userRole').value = 用户 ? 用户.role : 'viewer';
            document.getElementById('userAccounts').value = 用户 && Array.isArray(用户.accounts) ? 用户.accounts.join(',') : '';
            document.getElementById('userModal').classList.add('active');
        }

        function closeUserModal() {
            document.getElementById('userModal').classList.remove('active');
        }

        async function saveUser() {
            const username = document.getElementById('userName').value.trim();
            const password = document.getElementById('userPassword').value;
            const role = document.getElementById('userRole').value;
            const accounts = 解析账号范围(document.getElementById('userAccounts').value);
            if (!username) { 显示消息('请输入用户名'); return; }
            if (!编辑用户ID && password.length < 8) { 显示消息('密码至少 8 位'); return; }
            const body = { username, role, accounts };
            if (password) body.password = password;
            try {
                const url = 编辑用户ID ? '/admin/users/update' : '/admin/users/add';
                if (编辑用户ID) body.id = 编辑用户ID;
                const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '保存失败');
                showToast('✅ 用户已保存');
                closeUserModal();
                loadUsers();
                loadSessions();
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '保存失败'));
            }
        }

        async function deleteUser(id, username) {
            if (!confirm('确认删除用户 ' + username + '？该操作不可恢复。')) return;
            try {
                const res = await fetch('/admin/users/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '删除失败');
                showToast('✅ 用户已删除');
                loadUsers();
                loadSessions();
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '删除失败'));
            }
        }

        function openPasswordModal() {
            document.getElementById('currentAdminPassword').value = '';
            document.getElementById('newAdminPassword').value = '';
            document.getElementById('confirmAdminPassword').value = '';
            document.getElementById('passwordModal').classList.add('active');
        }

        function closePasswordModal() {
            document.getElementById('passwordModal').classList.remove('active');
        }

        async function saveAdminPassword() {
            const currentPassword = document.getElementById('currentAdminPassword').value;
            const newPassword = document.getElementById('newAdminPassword').value;
            const confirmPassword = document.getElementById('confirmAdminPassword').value;
            if (newPassword.length < 8) { 显示消息('新密码至少 8 位'); return; }
            if (newPassword !== confirmPassword) { 显示消息('两次输入的新密码不一致'); return; }
            try {
                const res = await fetch('/admin/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ currentPassword, newPassword }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '修改失败');
                showToast('✅ ' + (data.msg || '密码已修改'));
                closePasswordModal();
                loadUsers();
                loadSessions();
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '修改失败'));
            }
        }

        async function loadSessions() {
            const 容器 = document.getElementById('sessions-content');
            if (!容器) return;
            try {
                const res = await fetch('/admin/sessions.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                const 数据 = await res.json();
                const 列表 = 数据.sessions || [];
                if (列表.length === 0) {
                    容器.innerHTML = '<div style="color: var(--text-muted);">暂无登录会话</div>';
                    return;
                }
                let html = '';
                for (const 会话 of 列表) {
                    html += '<div style="display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; padding: 0.4rem 0; border-bottom: 1px solid var(--stroke);">' +
                        '<div style="min-width: 0;"><div>' + 转义HTML(会话.username || '') + ' <span style="color: var(--text-muted);">(' + 转义HTML(会话.role || '') + ')</span>' +
                        (会话.current ? ' <span style="color:#4ade80; font-size: 0.68rem;">当前</span>' : '') + '</div>' +
                        '<div style="color: var(--text-muted); font-size: 0.68rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">' +
                        转义HTML(会话.createdAt ? new Date(会话.createdAt).toLocaleString() : '') + ' · ' + 转义HTML(会话.ip || '-') + ' · ' + 转义HTML(会话.ua || '') + '</div></div>' +
                        (会话.current ? '' : '<button class="delete-btn" style="padding: 0.25rem 0.5rem; font-size: 0.7rem; white-space: nowrap;" onclick="revokeSession(\\'' + 转义HTML(会话.suffix) + '\\')">吊销</button>') +
                        '</div>';
                }
                容器.innerHTML = html;
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--text-muted);">会话列表仅管理员可查看</div>';
            }
        }

        async function revokeSession(suffix) {
            if (!confirm('确认吊销该会话？')) return;
            try {
                const res = await fetch('/admin/sessions/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ suffix }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '吊销失败');
                showToast('✅ 会话已吊销');
                loadSessions();
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '吊销失败'));
            }
        }

        async function loadTokens() {
            const 容器 = document.getElementById('tokens-content');
            if (!容器) return;
            try {
                const res = await fetch('/admin/tokens.json?t=' + Date.now());
                if (!res.ok) throw new Error('加载失败');
                const 数据 = await res.json();
                const 列表 = 数据.tokens || [];
                if (列表.length === 0) {
                    容器.innerHTML = '<div style="color: var(--text-muted);">暂无只读 Token</div>';
                    return;
                }
                let html = '';
                for (const 记录 of 列表) {
                    const 范围 = Array.isArray(记录.accounts) && 记录.accounts.length > 0 ? 记录.accounts.join(', ') : '全部';
                    const 过期 = 记录.expiresAt ? new Date(记录.expiresAt).toLocaleString() : '永不过期';
                    html += '<div style="display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; padding: 0.45rem 0; border-bottom: 1px solid var(--stroke);">' +
                        '<div><div>' + 转义HTML(记录.name || '') + ' <span style="color: var(--text-muted); font-size: 0.7rem;">' + 转义HTML(记录.prefix || '') + '</span></div>' +
                        '<div style="color: var(--text-muted); font-size: 0.7rem;">账号范围：' + 转义HTML(范围) + ' · 过期：' + 转义HTML(过期) + '</div></div>' +
                        '<button class="delete-btn" style="padding: 0.25rem 0.5rem; font-size: 0.7rem;" onclick="revokeToken(\\'' + 转义HTML(记录.id) + '\\')">吊销</button></div>';
                }
                容器.innerHTML = html;
            } catch (err) {
                console.error(err);
                容器.innerHTML = '<div style="color: var(--text-muted);">只读 Token 仅管理员可管理</div>';
            }
        }

        async function createToken() {
            const name = document.getElementById('tokenName').value.trim();
            const accounts = 解析账号范围(document.getElementById('tokenAccounts').value);
            const expiresDays = Number(document.getElementById('tokenExpiresDays').value) || 0;
            try {
                const res = await fetch('/admin/tokens/add', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, accounts, expiresDays }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '生成失败');
                const 容器 = document.getElementById('tokens-content');
                容器.innerHTML = '<div style="color: #f59e0b; font-size: 0.8rem;">Token 只显示一次，请立即保存：</div>' +
                    '<div style="margin: 0.5rem 0; padding: 0.6rem 0.75rem; border-radius: 10px; background: var(--input-bg); font-family: monospace; font-size: 0.8rem; word-break: break-all;">' + 转义HTML(data.token) + '</div>' +
                    '<button class="add-btn" onclick="loadTokens()">我已保存</button>';
                showToast('✅ 只读 Token 已生成');
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '生成失败'));
            }
        }

        async function revokeToken(id) {
            if (!confirm('确认吊销该只读 Token？使用它的集成会立即失效。')) return;
            try {
                const res = await fetch('/admin/tokens/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '吊销失败');
                showToast('✅ Token 已吊销');
                loadTokens();
            } catch (err) {
                console.error(err);
                showToast('❌ ' + (err.message || '吊销失败'));
            }
        }

        async function exportBackup() {
            const passphrase = document.getElementById('backupPassphrase').value;
            if (passphrase.length < 8) { 显示消息('备份口令至少 8 位'); return; }
            try {
                const res = await fetch('/admin/backup/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '导出失败');
                const 文本 = JSON.stringify(data.backup, null, 2);
                const blob = new Blob([文本], { type: 'application/json' });
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'cf-usage-panel-backup-' + new Date().toISOString().slice(0, 10) + '.json';
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(a.href);
                document.getElementById('backup-status').textContent = '✅ 备份已开始下载（' + Math.round(文本.length / 1024) + ' KB）';
            } catch (err) {
                console.error(err);
                document.getElementById('backup-status').textContent = '❌ ' + (err.message || '导出失败');
            }
        }

        async function importBackup(input) {
            const file = input.files && input.files[0];
            if (!file) return;
            const passphrase = document.getElementById('backupPassphrase').value;
            if (passphrase.length < 8) { 显示消息('请先输入备份口令（至少 8 位）'); input.value = ''; return; }
            if (!confirm('导入会覆盖当前账号配置（告警配置也会更新），确认继续？')) { input.value = ''; return; }
            try {
                const 文本 = await file.text();
                const backup = JSON.parse(文本);
                const res = await fetch('/admin/backup/import', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ passphrase, backup }) });
                const data = await res.json();
                if (!data.success) throw new Error(data.msg || '导入失败');
                document.getElementById('backup-status').textContent = '✅ ' + (data.msg || '导入成功');
                showToast('✅ 备份已导入');
                fetchSummary();
                fetchConfig();
            } catch (err) {
                console.error(err);
                document.getElementById('backup-status').textContent = '❌ ' + (err.message || '导入失败');
            } finally {
                input.value = '';
            }
        }

        // 根据百分比计算颜色（绿 -> 黄 -> 红）
        function getGradientColor(percent) {
            percent = Math.max(0, Math.min(100, percent));
            
            let r, g, b;
            
            if (percent <= 50) {
                // 绿色 (16, 185, 129) 到 黄色 (234, 179, 8)
                const t = percent / 50;
                r = Math.round(16 + (234 - 16) * t);
                g = Math.round(185 + (179 - 185) * t);
                b = Math.round(129 - 129 * t);
            } else {
                // 黄色 (234, 179, 8) 到 红色 (239, 68, 68)
                const t = (percent - 50) / 50;
                r = Math.round(234 + (239 - 234) * t);
                g = Math.round(179 - 179 * t);
                b = Math.round(8 + (68 - 8) * t);
            }
            
            return \`rgb(\${r}, \${g}, \${b})\`;
        }

        // 获取对应百分比的色阴影
        function getGradientShadow(percent) {
            const color = getGradientColor(percent);
            const rgb = color.match(/\\d+/g);
            return \`rgba(\${rgb[0]}, \${rgb[1]}, \${rgb[2]}, 0.4)\`;
        }

        // 应用颜色到进度条容器
        function applyGradientColor(container, percent) {
            const color = getGradientColor(percent);
            const shadow = getGradientShadow(percent);
            container.style.setProperty('--gradient-color', color);
            container.style.setProperty('--gradient-color-shadow', \`0 0 20px \${shadow}\`);
            
            // 设置进度条背景大小，让渐变正确显示
            const bar = container.querySelector('.progress-bar');
            if (bar && percent > 0) {
                const bgSize = (100 / percent) * 100;
                bar.style.setProperty('--bg-size', \`\${bgSize}%\`);
            }
        }

        function percentOf(used, limit) {
            used = Number(used) || 0;
            limit = Number(limit) || 0;
            return limit > 0 ? Math.min((used / limit) * 100, 100) : 0;
        }

        function formatNumber(value) {
            return (Number(value) || 0).toLocaleString();
        }

        function formatBytes(bytes) {
            bytes = Number(bytes) || 0;
            if (bytes >= 1024 * 1024 * 1024) return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
            if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return bytes.toLocaleString() + ' B';
        }

        function getResources(data) {
            return (data && data.resources) || { d1: {}, kv: {}, r2: {} };
        }

        function renderQuotaBar(label, used, limit, formatter) {
            formatter = formatter || formatNumber;
            const percent = percentOf(used, limit);
            const color = getGradientColor(percent);
            return '<div class="quota-row">' +
                '<div class="quota-top">' +
                    '<span class="quota-title">' + label + '</span>' +
                    '<span class="quota-meta">' + formatter(used) + ' / ' + formatter(limit) + ' · ' + percent.toFixed(1) + '%</span>' +
                '</div>' +
                '<div class="quota-track"><div class="quota-fill" style="width:' + percent + '%; background:' + color + '"></div></div>' +
            '</div>';
        }

        function renderQuotaGroup(title, meta, rows) {
            return '<div class="quota-item">' +
                '<div class="quota-group-head">' +
                    '<span class="quota-group-title">' + title + '</span>' +
                    '<span class="quota-group-meta">' + meta + '</span>' +
                '</div>' +
                rows.join('') +
            '</div>';
        }

        function renderResourceQuotas(resources) {
            const d1 = resources.d1 || {};
            const kv = resources.kv || {};
            const r2 = resources.r2 || {};
            return '<details class="quota-details">' +
                '<summary class="quota-summary"><span class="quota-summary-title">资源额度细节</span><span class="quota-summary-meta">KV / D1 / R2</span></summary>' +
                '<div class="quota-body"><div class="quota-list">' +
                    renderQuotaGroup('KV', formatNumber(kv.namespaces || 0) + ' 个命名空间', [
                        renderQuotaBar('读取（今日）', kv.reads, kv.readsLimit),
                        renderQuotaBar('写入（今日）', kv.writes, kv.writesLimit),
                        renderQuotaBar('删除/列表（今日）', (kv.deletes || 0) + (kv.lists || 0), (kv.deletesLimit || 0) + (kv.listsLimit || 0)),
                        renderQuotaBar('存储', kv.storageBytes, kv.storageLimitBytes, formatBytes)
                    ]) +
                    renderQuotaGroup('D1', formatNumber(d1.databases || 0) + ' 个数据库', [
                        renderQuotaBar('读取（今日）', d1.rowsRead, d1.rowsReadLimit),
                        renderQuotaBar('写入（今日）', d1.rowsWritten, d1.rowsWrittenLimit),
                        renderQuotaBar('存储', d1.storageBytes, d1.storageLimitBytes, formatBytes)
                    ]) +
                    renderQuotaGroup('R2', formatNumber(r2.buckets || 0) + ' 个存储桶', [
                        renderQuotaBar('Class A（本月）', r2.classA, r2.classALimit),
                        renderQuotaBar('Class B（本月）', r2.classB, r2.classBLimit),
                        renderQuotaBar('存储', r2.storageBytes, r2.storageLimitBytes, formatBytes)
                    ]) +
                '</div><div class="resource-note">D1/KV 按 UTC 自然日统计，R2 操作按本月统计；存储为最近一次指标快照。</div></div>' +
            '</details>';
        }

        function prefersReducedMotion() {
            return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        }

        function isDesktopAdminView() {
            return window.matchMedia && window.matchMedia('(min-width: 1024px)').matches;
        }

        function resetQuotaBody(body) {
            body.style.height = '';
            body.style.opacity = '';
            body.style.transform = '';
            body.style.overflow = '';
        }

        function animateQuotaDetails(details, opening) {
            const body = details.querySelector('.quota-body');
            if (!body || typeof body.animate !== 'function') {
                details.open = opening;
                return;
            }

            details.classList.add('quota-animating');
            body.style.overflow = 'hidden';

            if (opening) {
                details.open = true;
                body.style.height = '0px';
                body.style.opacity = '0';
                body.style.transform = 'translateY(6px)';
            } else {
                body.style.height = body.scrollHeight + 'px';
                body.style.opacity = '1';
                body.style.transform = 'translateY(0)';
            }

            const startHeight = opening ? 0 : body.scrollHeight;
            const endHeight = opening ? body.scrollHeight : 0;
            const animation = body.animate([
                { height: startHeight + 'px', opacity: opening ? 0 : 1, transform: opening ? 'translateY(6px)' : 'translateY(0)' },
                { height: endHeight + 'px', opacity: opening ? 1 : 0, transform: opening ? 'translateY(0)' : 'translateY(6px)' }
            ], {
                duration: 260,
                easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
                fill: 'forwards'
            });

            animation.onfinish = () => {
                animation.cancel();
                if (!opening) details.open = false;
                resetQuotaBody(body);
                details.classList.remove('quota-animating');
            };

            animation.oncancel = () => {
                resetQuotaBody(body);
                details.classList.remove('quota-animating');
            };
        }

        function bindQuotaDetailsAnimations(scope, defaultOpenOnDesktop = false) {
            if (!scope) return;
            scope.querySelectorAll('.quota-details').forEach(details => {
                if (details.dataset.quotaAnimationBound) return;
                const summary = details.querySelector('.quota-summary');
                const body = details.querySelector('.quota-body');
                if (!summary || !body) return;
                if (defaultOpenOnDesktop && isDesktopAdminView()) details.open = true;

                details.dataset.quotaAnimationBound = 'true';
                summary.addEventListener('click', (event) => {
                    if (prefersReducedMotion() || typeof body.animate !== 'function') return;
                    event.preventDefault();
                    if (details.classList.contains('quota-animating')) return;
                    animateQuotaDetails(details, !details.open);
                });
            });
        }

        async function fetchSummary() {
            const container = document.getElementById('summary-content');
            try {
                const res = await fetch('/admin/usage.json?t=' + Date.now());
                if (!res.ok) throw new Error('会话已过期，请重新登录');
                const data = await res.json();
                
                const total = data.total || 0;
                const max = data.max || 100000;
                const percent = Math.min((total / max) * 100, 100).toFixed(1);
                const resources = getResources(data);
                
                container.innerHTML = \`
                    <div class="usage-section">
                        <div class="usage-header">
                            <span class="label">总请求占比</span>
                            <span class="percentage">\${percent}%</span>
                        </div>
                        <div class="progress-track">
                            <div class="progress-bar" style="width: \${percent}%"></div>
                        </div>
                        <div class="total-text">
                            \${total.toLocaleString()} / \${max.toLocaleString()} 总计请求
                        </div>
                        <div class="total-text" style="font-size: 0.75rem; opacity: 0.75; margin-top: 0.35rem;">
                            最后更新: \${data.UpdateTime ? new Date(data.UpdateTime).toLocaleString() : '未知'}
                        </div>
                    </div>
                    <div class="stats-grid">
                        <div class="mini-card">
                            <div class="mini-icon">🔶</div>
                            <div class="mini-info">
                                <div class="mini-label">Workers</div>
                                <div class="mini-value">\${(data.workers || 0).toLocaleString()}</div>
                            </div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-icon">⚡️</div>
                            <div class="mini-info">
                                <div class="mini-label">Pages</div>
                                <div class="mini-value">\${(data.pages || 0).toLocaleString()}</div>
                            </div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-icon">🧯</div>
                            <div class="mini-info">
                                <div class="mini-label">错误率</div>
                                <div class="mini-value">\${Number(data.errorRate || 0).toFixed(2)}%</div>
                            </div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-icon">⏱️</div>
                            <div class="mini-info">
                                <div class="mini-label">CPU P99</div>
                                <div class="mini-value">\${Number(data.cpuTimeP99 || 0).toFixed(0)} µs</div>
                            </div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-icon">🔁</div>
                            <div class="mini-info">
                                <div class="mini-label">子请求</div>
                                <div class="mini-value">\${(data.workersSubrequests || 0).toLocaleString()}</div>
                            </div>
                        </div>
                    </div>
                    \${renderResourceQuotas(resources)}
                \`;
                bindQuotaDetailsAnimations(container, true);
                
                // 应用颜色到百分数
                const usageSection = container.querySelector('.usage-section');
                applyGradientColor(usageSection, percent);

                if (data.RefreshStats && data.RefreshStats.partial > 0) {
                    const warn = document.createElement('div');
                    warn.style.cssText = 'margin-top: 0.75rem; color: var(--danger); font-size: 0.85rem;';
                    warn.textContent = '⚠️ ' + data.RefreshStats.partial + ' 个账号的部分资源统计失败，显示用量可能偏低';
                    container.appendChild(warn);
                }
                const 刷新间隔 = Number((data.RefreshStats && data.RefreshStats.thresholdMs) || 1200000);
                if (data.UpdateTime && Date.now() - Number(data.UpdateTime) > 刷新间隔 * 2) {
                    const staleWarn = document.createElement('div');
                    staleWarn.style.cssText = 'margin-top: 0.75rem; color: var(--danger); font-size: 0.85rem;';
                    staleWarn.textContent = '⚠️ 数据已超过 2 个刷新周期未更新，请检查 cron 或手动刷新';
                    container.appendChild(staleWarn);
                }
            } catch (err) {
                console.error(err);
                container.innerHTML = '<div style="color: var(--danger)">加载汇总数据失败，请刷新页面或重新登录</div>';
            }
        }

        async function fetchConfig() {
            const container = document.getElementById('config-content');
            try {
                const res = await fetch('/admin/config.json?t=' + Date.now());
                if (!res.ok) throw new Error('会话已过期，请重新登录');
                const data = await res.json();
                if (!Array.isArray(data)) throw new Error('账号列表格式不正确');
                历史账号列表 = data.map(item => ({ ID: item.ID, Name: item.Name || ('账号 ' + item.ID) }));
                更新历史账号选项();
                最新账号配置 = data;
                排行榜数据 = null;
                渲染账号明细(data);
                
                if (data.length === 0) {
                    container.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 2rem;">暂无账号，请点击上方按钮添加</div>';
                    return;
                }

                container.innerHTML = '<div class="account-list">' + data.map(acc => {
                    const usage = acc.Usage || {};
                    const resources = getResources(usage);
                    const total = usage.total || 0;
                    const max = usage.max || 100000;
                    const percent = Math.min((total / max) * 100, 100).toFixed(1);
                    const updateTimeValue = acc.UpdateTime || acc.LastCheckTime;
                    const updateTime = updateTimeValue ? new Date(updateTimeValue).toLocaleString() : '从未更新';
                    const percentColor = getGradientColor(percent);
                    const bgSize = percent > 0 ? (100 / percent) * 100 : 100;
                    const 账号名称 = 转义HTML(acc.Name || '未命名账号');
                    const 账号标识 = acc.AccountID ? '🔒 AccountID: ' + 转义HTML(acc.AccountID) : '📧 Email: ' + 转义HTML(acc.Email);
                    const 账号ID = Number(acc.ID) || 0;
                    
                    return \`
                        <div class="account-item">
                            <div class="account-info">
                                <div>
                                    <div class="account-name">🔑 \${账号名称}</div>
                                    <div class="account-id">\${账号标识}</div>
                                    <div class="account-id" style="margin-top: 4px; opacity: 0.8;">🕒 更新时间: \${转义HTML(updateTime)}</div>
                                </div>
                                <div style="display: flex; gap: 0.5rem;">
                                    <button class="delete-btn" style="background: var(--primary);" data-limits-id="\${账号ID}">配额</button>
                                    <button class="delete-btn" data-id="\${账号ID}">删除账号</button>
                                </div>
                            </div>
                            <div class="usage-section" style="margin-bottom: 0">
                                <div class="usage-header">
                                    <span class="label">请求使用情况: \${total.toLocaleString()} / \${max.toLocaleString()} <b style="color: \${percentColor}; margin-left: 4px;">\${percent}%</b></span>
                                    <span class="label" style="font-size: 0.8rem; font-variant-numeric: tabular-nums;">
                                        W: \${(usage.workers || 0).toLocaleString()} | P: \${(usage.pages || 0).toLocaleString()}
                                    </span>
                                </div>
                                <div class="progress-track" style="height: 8px">
                                    <div class="progress-bar" style="width: \${percent}%; --bg-size: \${bgSize}%"></div>
                                </div>
                            </div>
                            \${renderResourceQuotas(resources)}
                        </div>
                    \`;
                }).join('') + '</div>';
                container.querySelectorAll('.delete-btn[data-id]').forEach(btn => {
                    btn.addEventListener('click', () => deleteAccount(Number(btn.dataset.id)));
                });
                container.querySelectorAll('[data-limits-id]').forEach(btn => {
                    const 账号ID = Number(btn.dataset.limitsId);
                    const 账号配置 = data.find(item => Number(item.ID) === 账号ID);
                    btn.addEventListener('click', () => openLimitsModal(账号ID, 账号配置 ? 账号配置.Limits : null));
                });
                bindQuotaDetailsAnimations(container);
            } catch (err) {
                console.error(err);
                container.innerHTML = '<div style="color: var(--danger)">加载详情数据失败，请刷新页面或重新登录</div>';
            }
        }

        function openAddModal() { 
            document.getElementById('addModal').classList.add('active'); 
            document.getElementById('authMethod').value = 'token';
            switchAuthMethod();
        }

        function switchAuthMethod() {
            const method = document.getElementById('authMethod').value;
            document.getElementById('tokenFields').style.display = method === 'token' ? 'block' : 'none';
            document.getElementById('globalFields').style.display = method === 'global' ? 'block' : 'none';
        }

        function closeAddModal() { 
            document.getElementById('addModal').classList.remove('active');
            document.getElementById('newName').value = '';
            document.getElementById('newAccountID').value = '';
            document.getElementById('newAPIToken').value = '';
            document.getElementById('newEmail').value = '';
            document.getElementById('newGlobalAPIKey').value = '';
        }

        let 正在添加账号 = false;
        let 正在删除账号 = false;

        async function handleAddAccount() {
            if (正在添加账号) return;
            const name = document.getElementById('newName').value;
            const method = document.getElementById('authMethod').value;
            
            let accountID = null, apiToken = null, email = null, globalAPIKey = null;

            if (method === 'token') {
                accountID = document.getElementById('newAccountID').value;
                apiToken = document.getElementById('newAPIToken').value;
                if (!name || !accountID || !apiToken) {
                    showToast('⚠️ 请填写完整信息');
                    return;
                }
            } else {
                email = document.getElementById('newEmail').value;
                globalAPIKey = document.getElementById('newGlobalAPIKey').value;
                if (!name || !email || !globalAPIKey) {
                    showToast('⚠️ 请填写完整信息');
                    return;
                }
            }

            正在添加账号 = true;
            try {
                const res = await fetch('/api/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        Name: name, 
                        AccountID: accountID, 
                        APIToken: apiToken,
                        Email: email,
                        GlobalAPIKey: globalAPIKey
                    })
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ 添加成功，正在更新数据...');
                    closeAddModal();
                    setTimeout(() => {
                        fetchSummary();
                        fetchConfig();
                    }, 300);
                } else {
                    showToast('❌ ' + (data.msg || '添加失败'));
                }
            } catch (err) {
                console.error(err);
                showToast('❌ 网络错误');
            } finally {
                正在添加账号 = false;
            }
        }

        async function deleteAccount(id) {
            if (正在删除账号) return;
            if (!confirm('确定要删除这个账号吗？')) return;
            正在删除账号 = true;
            try {
                const res = await fetch('/api/del', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ID: id })
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ 删除成功，正在更新数据...');
                    setTimeout(() => {
                        fetchSummary();
                        fetchConfig();
                    }, 300);
                } else {
                    showToast('❌ ' + (data.msg || '删除失败'));
                }
            } catch (err) {
                console.error(err);
                showToast('❌ 网络错误');
            } finally {
                正在删除账号 = false;
            }
        }

        // 初始加载
        fetchSummary().then(() => fetchConfig()).then(function () { loadHistory(); loadCostEstimate(); load2FAStatus(); loadAuditLog(); });
        loadAlertConfig();
        loadAlertHistory();
        loadSessionInfo();
        loadUsers();
        loadSessions();
        loadTokens();
    </script>
</body>
</html>`;
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } })
}


async function UsagePanel主页() {
    const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloudflare 额度使用统计</title>
    <link rel="icon" href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5uhbWfhjepEoUiM9phzhgJ/9658369030266cde9e35a3c5d4e4beb2/cloud-upload.svg">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.4);
            --accent: #a855f7;
            --background: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --stroke: rgba(255, 255, 255, 0.08);
            --heading-grad: linear-gradient(135deg, #fff 0%, #cbd5e1 100%);
            --footer-color: rgba(255, 255, 255, 0.2);
            --footer-hover: rgba(255, 255, 255, 0.4);
            --item-bg: rgba(255, 255, 255, 0.03);
            --track-bg: rgba(0, 0, 0, 0.2);
        }

        :root.light-mode {
            --primary: #4f46e5;
            --primary-glow: rgba(79, 70, 229, 0.2);
            --accent: #9333ea;
            --background: #f1f5f9;
            --card-bg: rgba(255, 255, 255, 0.8);
            --text-main: #0f172a;
            --text-muted: #64748b;
            --stroke: rgba(0, 0, 0, 0.1);
            --heading-grad: linear-gradient(135deg, #1e293b 0%, #475569 100%);
            --footer-color: rgba(15, 23, 42, 0.4);
            --footer-hover: var(--primary);
            --item-bg: rgba(0, 0, 0, 0.03);
            --track-bg: rgba(0, 0, 0, 0.08);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        html {
            scrollbar-gutter: stable both-edges;
        }

        @supports not (scrollbar-gutter: stable) {
            html { overflow-y: scroll; }
        }

        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--background);
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(168, 85, 247, 0.15) 0px, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 1.5rem;
        }

        .container {
            width: 100%;
            max-width: 500px;
            animation: slideUp 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .glass-card {
            background: var(--card-bg);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--stroke);
            border-radius: 24px;
            padding: 2.5rem;
            box-shadow: 
                0 25px 50px -12px rgba(0, 0, 0, 0.5),
                0 0 0 1px rgba(255, 255, 255, 0.05) inset;
        }

        header {
            text-align: center;
            margin-bottom: 2.5rem;
        }

        h1 {
            font-size: 1.5rem;
            font-weight: 700;
            background: var(--heading-grad);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 0.5rem;
            letter-spacing: -0.01em;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid rgba(99, 102, 241, 0.2);
            border-radius: 99px;
            font-size: 0.75rem;
            color: #818cf8;
            font-weight: 500;
        }

        .status-dot {
            width: 6px;
            height: 6px;
            background: #818cf8;
            border-radius: 50%;
            box-shadow: 0 0 8px var(--primary);
            animation: statusPulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }

        @keyframes statusPulse {
            0%, 100% {
                box-shadow: 0 0 8px var(--primary), 0 0 0 0 rgba(129, 140, 248, 0.7);
                transform: scale(1);
            }
            50% {
                box-shadow: 0 0 12px var(--primary), 0 0 0 6px rgba(129, 140, 248, 0);
                transform: scale(1.2);
            }
        }

        .usage-section {
            margin-bottom: 2rem;
            position: relative;
        }

        .usage-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            margin-bottom: 1rem;
        }

        .label {
            font-size: 0.9rem;
            color: var(--text-muted);
            font-weight: 500;
        }

        .percentage {
            font-family: 'Outfit', monospace;
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--gradient-color, var(--text-main));
            text-shadow: 0 0 20px var(--gradient-color-shadow, var(--primary-glow));
            transition: color 0.6s ease, text-shadow 0.6s ease;
        }

        .progress-track {
            background: var(--track-bg);
            border: 1px solid var(--stroke);
            border-radius: 999px;
            height: 14px;
            overflow: hidden;
            position: relative;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);
        }

        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #10b981 0%, #eab308 50%, #ef4444 100%);
            background-size: var(--bg-size, 100%);
            background-position: left;
            border-radius: 999px;
            width: 0%;
            transition: width 1.5s cubic-bezier(0.34, 1.56, 0.64, 1);
            position: relative;
            overflow: hidden;
        }
        
        .progress-bar::after {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            transform: translateX(-100%);
            animation: shimmer 2.5s infinite;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-top: 1.5rem;
        }

        .mini-card { 
            background: var(--item-bg); 
            border: 1px solid var(--stroke); 
            border-radius: 16px; 
            padding: 1rem 1.25rem; 
            display: flex; 
            align-items: center; 
            gap: 1.25rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); 
            position: relative;
            overflow: hidden;
        }
        .mini-card:hover { 
            background: rgba(99, 102, 241, 0.08); 
            transform: translateY(-4px); 
            border-color: var(--primary); 
            box-shadow: 0 10px 20px -5px rgba(0, 0, 0, 0.2);
        }
        .mini-icon { 
            font-size: 1.75rem; 
            margin-bottom: 0; 
            line-height: 1;
            filter: drop-shadow(0 0 10px rgba(255,255,255,0.1));
        }
        .mini-info { display: flex; flex-direction: column; justify-content: center; }
        .mini-label { 
            font-size: 0.7rem; 
            text-transform: uppercase; 
            letter-spacing: 0.05em;
            color: var(--text-muted); 
            margin-bottom: 0; 
            font-weight: 500;
        }
        .mini-value { 
            font-size: 1.25rem; 
            font-weight: 700; 
            color: var(--text-main); 
            line-height: 1.2;
        }

        .total-text {
            text-align: right;
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-top: 0.5rem;
            font-variant-numeric: tabular-nums;
        }

        .quota-details { margin-top: 1.25rem; overflow: hidden; }
        .quota-details[open] { display: flex; flex-direction: column; }
        .quota-details.quota-animating .quota-summary { pointer-events: none; }
        .quota-summary { list-style: none; background: linear-gradient(135deg, rgba(99, 102, 241, 0.16), rgba(14, 165, 233, 0.1)); border: 1px solid rgba(99, 102, 241, 0.5); border-radius: 14px; padding: 0.8rem 0.85rem; cursor: pointer; display: flex; justify-content: space-between; gap: 0.75rem; align-items: center; color: var(--text-main); font-size: 0.85rem; font-weight: 700; box-shadow: 0 12px 28px -18px var(--primary-glow), inset 0 1px 0 rgba(255,255,255,0.08); transition: all 0.3s ease; }
        .quota-summary::-webkit-details-marker { display: none; }
        .quota-summary:hover, .quota-summary:focus-visible { border-color: var(--primary); background: linear-gradient(135deg, rgba(99, 102, 241, 0.24), rgba(14, 165, 233, 0.14)); box-shadow: 0 16px 32px -18px var(--primary-glow), 0 0 0 3px rgba(99, 102, 241, 0.12); outline: none; }
        .quota-summary-title { min-width: 0; }
        .quota-summary::after { content: '展开细节'; color: #fff; background: var(--primary); border-radius: 999px; padding: 0.38rem 0.7rem; font-size: 0.75rem; font-weight: 700; white-space: nowrap; box-shadow: 0 10px 20px -12px var(--primary-glow); }
        .quota-details[open] .quota-summary::after { content: '收起细节'; }
        .quota-details[open] .quota-summary { order: 2; margin-top: 0.875rem; }
        .quota-summary-meta { color: var(--text-muted); font-size: 0.75rem; font-weight: 600; margin-left: auto; white-space: nowrap; }
        .quota-body { overflow: hidden; }
        .quota-details[open] .quota-body { order: 1; }
        .quota-details.quota-animating .quota-body { will-change: height, opacity, transform; }
        .quota-list { display: grid; gap: 0.875rem; margin-top: 0.875rem; }
        .quota-details[open] .quota-list { margin-top: 0; }
        .quota-item { background: var(--item-bg); border: 1px solid var(--stroke); border-radius: 14px; padding: 0.875rem 1rem; }
        .quota-group-head { display: flex; justify-content: space-between; gap: 0.75rem; align-items: center; margin-bottom: 0.75rem; }
        .quota-group-title { color: var(--text-main); font-size: 0.9rem; font-weight: 700; }
        .quota-group-meta { color: var(--text-muted); font-size: 0.75rem; font-variant-numeric: tabular-nums; text-align: right; }
        .quota-row { margin-top: 0.75rem; }
        .quota-group-head + .quota-row { margin-top: 0; }
        .quota-top { display: flex; justify-content: space-between; gap: 0.75rem; color: var(--text-muted); font-size: 0.78rem; margin-bottom: 0.55rem; }
        .quota-title { color: var(--text-main); font-weight: 600; }
        .quota-meta { text-align: right; font-variant-numeric: tabular-nums; }
        .quota-track { height: 7px; background: var(--track-bg); border: 1px solid var(--stroke); border-radius: 999px; overflow: hidden; }
        .quota-fill { height: 100%; border-radius: inherit; min-width: 0; transition: width 1s ease; }
        .resource-note { margin-top: 0.875rem; color: var(--text-muted); font-size: 0.75rem; line-height: 1.5; }

        .footer {
            margin-top: 2.5rem;
            text-align: center;
            font-size: 0.75rem;
            color: var(--footer-color);
            transition: color 0.3s;
        }
        
        .footer:hover {
            color: var(--footer-hover);
        }

        /* 管理员登录气泡 */
        .admin-bubble {
            position: fixed;
            top: 1.5rem;
            right: 1.5rem;
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            cursor: pointer;
            box-shadow: 0 8px 24px rgba(99, 102, 241, 0.4);
            transition: all 0.3s ease;
            z-index: 1001;
        }

        .admin-bubble:hover {
            transform: scale(1.1);
            box-shadow: 0 12px 32px rgba(99, 102, 241, 0.5);
        }

        .admin-bubble svg {
            width: 24px;
            height: 24px;
            fill: white;
        }

        /* 登录模态框 */
        .login-modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(8px);
            -webkit-backdrop-filter: blur(8px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 2000;
            animation: fadeIn 0.3s ease;
        }

        .login-modal-overlay.active {
            display: flex;
        }

        .login-modal {
            background: var(--card-bg);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid var(--stroke);
            border-radius: 20px;
            padding: 2rem;
            max-width: 360px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            animation: modalSlideUp 0.4s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes modalSlideUp {
            from { opacity: 0; transform: translateY(30px) scale(0.95); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .login-modal h2 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            text-align: center;
            background: var(--heading-grad);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .login-input {
            width: 100%;
            padding: 0.875rem 1rem;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            color: var(--text-main);
            font-size: 1rem;
            font-family: 'Outfit', sans-serif;
            outline: none;
            transition: all 0.3s ease;
            margin-bottom: 1rem;
        }

        .login-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }

        .login-input::placeholder {
            color: var(--text-muted);
        }

        :root.light-mode .login-input {
            background: rgba(79, 70, 229, 0.08);
            border-color: rgba(79, 70, 229, 0.2);
        }

        :root.light-mode .login-input:focus {
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.15);
        }

        .login-btn {
            width: 100%;
            padding: 0.875rem;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            border: none;
            border-radius: 12px;
            color: white;
            font-size: 1rem;
            font-weight: 600;
            font-family: 'Outfit', sans-serif;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 24px rgba(99, 102, 241, 0.4);
        }

        :root.light-mode .login-btn:hover {
            box-shadow: 0 8px 24px rgba(79, 70, 229, 0.35);
        }

        .login-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .login-error {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            padding: 0.75rem 1rem;
            border-radius: 10px;
            font-size: 0.85rem;
            margin-bottom: 1rem;
            border: 1px solid rgba(239, 68, 68, 0.2);
            text-align: center;
            display: none;
        }

        .login-error.show {
            display: block;
            animation: shake 0.4s ease;
        }

        :root.light-mode .login-error {
            background: rgba(239, 68, 68, 0.08);
            color: #dc2626;
            border-color: rgba(239, 68, 68, 0.3);
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-8px); }
            75% { transform: translateX(8px); }
        }

        .close-modal {
            position: absolute;
            top: 1rem;
            right: 1rem;
            width: 32px;
            height: 32px;
            background: rgba(255, 255, 255, 0.1);
            border: none;
            border-radius: 50%;
            color: var(--text-muted);
            font-size: 1.25rem;
            cursor: pointer;
            display: flex;
            justify-content: center;
            align-items: center;
            transition: all 0.3s ease;
        }

        .close-modal:hover {
            background: rgba(255, 255, 255, 0.2);
            color: white;
        }

        .login-modal-wrapper {
            position: relative;
        }

        .toast-notification {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: linear-gradient(135deg, rgba(168, 85, 247, 0.95), rgba(99, 102, 241, 0.95));
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border: 1px solid rgba(168, 85, 247, 0.5);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            color: #fff;
            font-size: 0.95rem;
            font-weight: 500;
            box-shadow: 0 15px 35px rgba(168, 85, 247, 0.3), 0 0 1px rgba(255,255,255,0.1) inset;
            animation: toastSlideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            z-index: 1000;
            max-width: 300px;
            word-break: break-word;
        }

        @keyframes toastSlideIn {
            from { opacity: 0; transform: translateX(30px) translateY(30px); }
            to { opacity: 1; transform: translateX(0) translateY(0); }
        }

        .loading-container {
            min-height: 200px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            gap: 1rem;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            border-top-color: var(--primary);
            animation: spin 1s ease-in-out infinite;
        }

        .error-msg {
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            padding: 1rem;
            border-radius: 12px;
            font-size: 0.9rem;
            border: 1px solid rgba(239, 68, 68, 0.2);
            text-align: center;
        }

        /* 主题切换气泡 */
        .theme-bubble {
            position: fixed;
            top: 1.5rem;
            left: 1.5rem;
            width: 48px;
            height: 48px;
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--stroke);
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            cursor: pointer;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
            transition: all 0.3s ease;
            z-index: 1001;
            color: var(--text-main);
        }

        .theme-bubble:hover {
            transform: scale(1.1);
            border-color: var(--primary);
        }

        .theme-bubble svg { width: 22px; height: 22px; stroke: currentColor; }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @keyframes shimmer {
            100% { transform: translateX(100%); }
        }

        /* ============ 移动端响应式优化 ============ */
        @media (max-width: 768px) {
            body {
                padding: 1rem;
            }

            .container {
                max-width: 100%;
            }

            .glass-card {
                padding: 1.5rem;
                border-radius: 20px;
            }

            header {
                margin-bottom: 2rem;
            }

            h1 {
                font-size: 1.25rem;
                margin-bottom: 0.75rem;
            }

            .status-badge {
                padding: 5px 10px;
                font-size: 0.7rem;
                gap: 4px;
            }

            .status-dot {
                width: 5px;
                height: 5px;
            }

            .usage-section {
                margin-bottom: 1.5rem;
            }

            .usage-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
                margin-bottom: 0.75rem;
            }

            .label {
                font-size: 0.85rem;
            }

            .percentage {
                font-size: 1.1rem;
            }

            .progress-track {
                height: 12px;
            }

            .stats-grid {
                grid-template-columns: 1fr;
                gap: 0.75rem;
                margin-top: 1.25rem;
            }

            .mini-card {
                padding: 0.875rem 1rem;
                gap: 1rem;
            }

            .mini-icon {
                font-size: 1.5rem;
            }

            .mini-label {
                font-size: 0.65rem;
            }

            .mini-value {
                font-size: 1.1rem;
            }

            .total-text {
                font-size: 0.75rem;
                margin-top: 0.375rem;
            }

            .quota-top {
                flex-direction: column;
                gap: 0.35rem;
            }

            .quota-summary, .quota-group-head {
                align-items: flex-start;
                flex-direction: column;
                gap: 0.35rem;
            }

            .quota-summary-meta {
                margin-left: 0;
            }

            .quota-group-meta {
                text-align: left;
            }

            .quota-meta {
                text-align: left;
            }

            .footer {
                margin-top: 2rem;
                font-size: 0.7rem;
            }

            .theme-bubble {
                top: 1rem;
                left: 1rem;
                width: 44px;
                height: 44px;
            }

            .theme-bubble svg {
                width: 20px;
                height: 20px;
            }

            .admin-bubble {
                top: 1rem;
                right: 1rem;
                width: 44px;
                height: 44px;
            }

            .admin-bubble svg {
                width: 22px;
                height: 22px;
            }

            .login-modal {
                max-width: calc(100% - 2rem);
                padding: 1.5rem;
                border-radius: 18px;
            }

            .login-modal h2 {
                font-size: 1.1rem;
                margin-bottom: 1.25rem;
            }

            .login-input {
                padding: 0.75rem 0.875rem;
                font-size: 0.95rem;
                margin-bottom: 0.875rem;
                border-radius: 10px;
            }

            .login-btn {
                padding: 0.75rem 1rem;
                font-size: 0.95rem;
                border-radius: 10px;
            }

            .close-modal {
                width: 28px;
                height: 28px;
                font-size: 1.1rem;
                top: 0.75rem;
                right: 0.75rem;
            }

            .login-error {
                padding: 0.65rem 0.875rem;
                font-size: 0.8rem;
                border-radius: 8px;
                margin-bottom: 0.875rem;
            }

            .toast-notification {
                bottom: 1.5rem;
                right: 1rem;
                left: 1rem;
                padding: 1rem 1.25rem;
                font-size: 0.875rem;
                border-radius: 10px;
            }

            .loading-container {
                min-height: 150px;
                gap: 0.75rem;
            }

            .spinner {
                width: 36px;
                height: 36px;
                border-width: 2px;
            }

            .error-msg {
                padding: 0.875rem;
                font-size: 0.85rem;
                border-radius: 10px;
            }
        }

        /* 超小屏幕优化 (max-width: 480px) */
        @media (max-width: 480px) {
            body {
                padding: 0.75rem;
                min-height: 100vh;
            }

            .container {
                max-width: 100%;
            }

            .glass-card {
                padding: 1.25rem;
                border-radius: 16px;
                box-shadow: 
                    0 15px 30px -8px rgba(0, 0, 0, 0.5),
                    0 0 0 1px rgba(255, 255, 255, 0.05) inset;
            }

            header {
                margin-bottom: 1.5rem;
            }

            h1 {
                font-size: 1.15rem;
                margin-bottom: 0.5rem;
            }

            .status-badge {
                padding: 4px 8px;
                font-size: 0.65rem;
                gap: 3px;
            }

            .usage-section {
                margin-bottom: 1.25rem;
            }

            .usage-header {
                gap: 0.25rem;
                margin-bottom: 0.625rem;
            }

            .label {
                font-size: 0.8rem;
            }

            .percentage {
                font-size: 1rem;
            }

            .progress-track {
                height: 10px;
                border-radius: 999px;
            }

            .stats-grid {
                gap: 0.5rem;
                margin-top: 1rem;
            }

            .mini-card {
                padding: 0.75rem 0.875rem;
                gap: 0.875rem;
            }

            .mini-card:hover {
                transform: translateY(-2px);
            }

            .mini-icon {
                font-size: 1.4rem;
            }

            .mini-label {
                font-size: 0.6rem;
                letter-spacing: 0.03em;
            }

            .mini-value {
                font-size: 1rem;
            }

            .total-text {
                font-size: 0.7rem;
            }

            .footer {
                margin-top: 1.5rem;
                font-size: 0.65rem;
            }

            .theme-bubble, .admin-bubble {
                width: 40px;
                height: 40px;
                top: 0.75rem;
            }

            .theme-bubble {
                left: 0.75rem;
            }

            .admin-bubble {
                right: 0.75rem;
            }

            .theme-bubble svg, .admin-bubble svg {
                width: 18px;
                height: 18px;
            }

            .login-modal-overlay {
                padding: 1rem;
            }

            .login-modal {
                max-width: 100%;
                width: 100%;
                padding: 1.25rem;
                border-radius: 16px;
            }

            .login-modal h2 {
                font-size: 1rem;
                margin-bottom: 1rem;
            }

            .login-input {
                padding: 0.65rem 0.75rem;
                font-size: 0.9rem;
                margin-bottom: 0.75rem;
                border-radius: 8px;
            }

            .login-input::placeholder {
                font-size: 0.9rem;
            }

            .login-btn {
                padding: 0.65rem 0.875rem;
                font-size: 0.9rem;
            }

            .close-modal {
                width: 26px;
                height: 26px;
                font-size: 1rem;
                top: 0.5rem;
                right: 0.5rem;
            }

            .login-error {
                padding: 0.6rem 0.75rem;
                font-size: 0.75rem;
                margin-bottom: 0.75rem;
            }

            .toast-notification {
                bottom: 1rem;
                right: 0.75rem;
                left: 0.75rem;
                padding: 0.875rem 1rem;
                font-size: 0.8rem;
                max-width: 100%;
            }

            .loading-container {
                min-height: 120px;
                gap: 0.5rem;
            }

            .spinner {
                width: 32px;
                height: 32px;
                border-width: 2px;
            }

            .error-msg {
                padding: 0.75rem;
                font-size: 0.8rem;
            }
        }

        /* 竖屏超大手机优化 (min-height: 800px) */
        @media (min-height: 800px) and (max-width: 768px) {
            body {
                justify-content: flex-start;
                padding-top: 3rem;
                padding-bottom: 2rem;
            }

            .container {
                margin: 0 auto;
            }
        }
    </style>
</head>
<body>
    <!-- 主题切换气泡 -->
    <div class="theme-bubble" onclick="toggleTheme()" title="切换显示模式">
        <svg id="sun-icon" style="display:none" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="18.36" x2="5.64" y2="19.78"></line><line x1="18.36" y1="4.22" x2="19.78" y2="5.64"></line></svg>
        <svg id="moon-icon" viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
    </div>

    <!-- 语言切换气泡 -->
    <div class="admin-bubble" onclick="切换语言()" style="right: 4.6rem; background: var(--card-bg); color: var(--text-main); border: 1px solid var(--stroke); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);" title="切换语言">
        <span id="lang-text" style="font-size: 0.8rem; font-weight: 600;">EN</span>
    </div>

    <!-- 管理员登录气泡 -->
    <div class="admin-bubble" onclick="openLoginModal()" title="管理员登录">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
        </svg>
    </div>

    <!-- 登录模态框 -->
    <div class="login-modal-overlay" id="loginModal">
        <div class="login-modal-wrapper">
            <div class="login-modal">
                <button class="close-modal" onclick="closeLoginModal()">&times;</button>
                <h2>🔐 管理员登录</h2>
                <div class="login-error" id="loginError"></div>
                <input type="text" class="login-input" id="adminUsername" placeholder="请输入管理员账号" onkeydown="if(event.key==='Enter')document.getElementById('adminPassword').focus()">
                <input type="password" class="login-input" id="adminPassword" placeholder="请输入管理员密码" onkeydown="if(event.key==='Enter')document.getElementById('adminTotp').focus()">
                <input type="text" class="login-input" id="adminTotp" inputmode="text" maxlength="12" autocomplete="one-time-code" placeholder="两步验证码或恢复码（如已启用）" onkeydown="if(event.key==='Enter')handleLogin()">
                <button class="login-btn" id="loginBtn" onclick="handleLogin()">登 录</button>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="glass-card">
            <header>
                <h1>☁️ Cloudflare 额度统计</h1>
                <div class="status-badge">
                    <div class="status-dot"></div>
                    <span>System Online</span>
                </div>
            </header>

            <div id="content">
                <div class="loading-container">
                    <div class="spinner"></div>
                    <div style="color: var(--text-muted); font-size: 0.9rem;">正在获取数据...</div>
                </div>
            </div>

            <div id="history-toggle" style="display: flex; justify-content: center; margin-top: 1rem;">
                <button type="button" onclick="loadPublicHistory(7)" style="padding: 0.55rem 1rem; border-radius: 999px; border: 1px solid var(--stroke); background: var(--item-bg); color: var(--text-main); cursor: pointer; font-size: 0.8rem;">
                    📈 查看用量趋势（7 / 14 / 30 天）
                </button>
            </div>

            <div id="history-card" style="display: none; margin-top: 1rem; border-top: 1px solid var(--stroke); padding-top: 1rem; width: 100%;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; flex-wrap: wrap;">
                    <span style="font-size: 0.85rem; color: var(--text-muted);">📈 用量趋势</span>
                    <div style="display: flex; gap: 0.35rem;">
                        <button type="button" class="history-range-btn" data-days="7" onclick="switchHomeRange(this, 7)" style="padding: 0.25rem 0.6rem; border-radius: 999px; border: 1px solid var(--stroke); background: var(--item-bg); color: var(--text-main); cursor: pointer; font-size: 0.72rem;">7 天</button>
                        <button type="button" class="history-range-btn" data-days="14" onclick="switchHomeRange(this, 14)" style="padding: 0.25rem 0.6rem; border-radius: 999px; border: 1px solid var(--stroke); background: var(--item-bg); color: var(--text-main); cursor: pointer; font-size: 0.72rem;">14 天</button>
                        <button type="button" class="history-range-btn" data-days="30" onclick="switchHomeRange(this, 30)" style="padding: 0.25rem 0.6rem; border-radius: 999px; border: 1px solid var(--stroke); background: var(--item-bg); color: var(--text-main); cursor: pointer; font-size: 0.72rem;">30 天</button>
                    </div>
                </div>
                <div id="history-hint" style="font-size: 0.7rem; color: var(--text-muted); margin-bottom: 0.35rem;"></div>
                <div id="public-history"></div>
                <div id="home-chart-summary" style="display: none; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; margin-top: 0.6rem;">
                    <div style="text-align: center; padding: 0.4rem; border-radius: 10px; background: var(--item-bg);">
                        <div id="homeStatAvg" style="font-size: 0.95rem; font-weight: 600;">--</div>
                        <div style="font-size: 0.68rem; color: var(--text-muted);">日均请求</div>
                    </div>
                    <div style="text-align: center; padding: 0.4rem; border-radius: 10px; background: var(--item-bg);">
                        <div id="homeStatPeak" style="font-size: 0.95rem; font-weight: 600;">--</div>
                        <div style="font-size: 0.68rem; color: var(--text-muted);">峰值</div>
                    </div>
                    <div style="text-align: center; padding: 0.4rem; border-radius: 10px; background: var(--item-bg);">
                        <div id="homeStatTrend" style="font-size: 0.95rem; font-weight: 600;">--</div>
                        <div style="font-size: 0.68rem; color: var(--text-muted);">趋势</div>
                    </div>
                </div>
            </div>

            <div class="footer">
                由 <a href="https://github.com/cmliu/CF-Workers-UsagePanel" target="_blank" rel="noopener" class="footer">CF-Workers-UsagePanel</a> 强力驱动
            </div>
        </div>
    </div>

    <script>
        ${生成语言脚本()}
        function 安全读取主题() {
            try { return localStorage.getItem('theme'); } catch (err) { return null; }
        }

        function 安全写入主题(value) {
            try { localStorage.setItem('theme', value); } catch (err) { /* 忽略存储不可用 */ }
        }

        function initTheme() {
            const savedTheme = 安全读取主题();
            const systemLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
            if (savedTheme === 'light' || (!savedTheme && systemLight)) {
                document.documentElement.classList.add('light-mode');
            }
            updateThemeIcons();
        }

        function toggleTheme() {
            const isLight = document.documentElement.classList.toggle('light-mode');
            安全写入主题(isLight ? 'light' : 'dark');
            updateThemeIcons();
        }

        function updateThemeIcons() {
            const isLight = document.documentElement.classList.contains('light-mode');
            const sun = document.getElementById('sun-icon');
            const moon = document.getElementById('moon-icon');
            if (sun) sun.style.display = isLight ? 'none' : 'block';
            if (moon) moon.style.display = isLight ? 'block' : 'none';
        }

        initTheme();

        // 根据百分比计算颜色（绿 -> 黄 -> 红）
        function getGradientColor(percent) {
            percent = Math.max(0, Math.min(100, percent));
            
            let r, g, b;
            
            if (percent <= 50) {
                // 绿色 (16, 185, 129) 到 黄色 (234, 179, 8)
                const t = percent / 50;
                r = Math.round(16 + (234 - 16) * t);
                g = Math.round(185 + (179 - 185) * t);
                b = Math.round(129 - 129 * t);
            } else {
                // 黄色 (234, 179, 8) 到 红色 (239, 68, 68)
                const t = (percent - 50) / 50;
                r = Math.round(234 + (239 - 234) * t);
                g = Math.round(179 - 179 * t);
                b = Math.round(8 + (68 - 8) * t);
            }
            
            return \`rgb(\${r}, \${g}, \${b})\`;
        }

        // 获取对应百分比的色阴影
        function getGradientShadow(percent) {
            const color = getGradientColor(percent);
            const rgb = color.match(/\\d+/g);
            return \`rgba(\${rgb[0]}, \${rgb[1]}, \${rgb[2]}, 0.4)\`;
        }

        // 应用颜色到进度条容器
        function applyGradientColor(container, percent) {
            const color = getGradientColor(percent);
            const shadow = getGradientShadow(percent);
            container.style.setProperty('--gradient-color', color);
            container.style.setProperty('--gradient-color-shadow', \`0 0 20px \${shadow}\`);
            
            // 设置进度条背景大小，让渐变正确显示
            const bar = container.querySelector('.progress-bar');
            if (bar && percent > 0) {
                const bgSize = (100 / percent) * 100;
                bar.style.setProperty('--bg-size', \`\${bgSize}%\`);
            }
        }

        function percentOf(used, limit) {
            used = Number(used) || 0;
            limit = Number(limit) || 0;
            return limit > 0 ? Math.min((used / limit) * 100, 100) : 0;
        }

        function formatNumber(value) {
            return (Number(value) || 0).toLocaleString();
        }

        function formatBytes(bytes) {
            bytes = Number(bytes) || 0;
            if (bytes >= 1024 * 1024 * 1024) return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
            if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + ' MB';
            if (bytes >= 1024) return (bytes / 1024).toFixed(2) + ' KB';
            return bytes.toLocaleString() + ' B';
        }

        function getResources(data) {
            return (data && data.resources) || { d1: {}, kv: {}, r2: {} };
        }

        function renderQuotaBar(label, used, limit, formatter) {
            formatter = formatter || formatNumber;
            const percent = percentOf(used, limit);
            const color = getGradientColor(percent);
            return '<div class="quota-row">' +
                '<div class="quota-top">' +
                    '<span class="quota-title">' + label + '</span>' +
                    '<span class="quota-meta">' + formatter(used) + ' / ' + formatter(limit) + ' · ' + percent.toFixed(1) + '%</span>' +
                '</div>' +
                '<div class="quota-track"><div class="quota-fill" style="width:' + percent + '%; background:' + color + '"></div></div>' +
            '</div>';
        }

        function renderQuotaGroup(title, meta, rows) {
            return '<div class="quota-item">' +
                '<div class="quota-group-head">' +
                    '<span class="quota-group-title">' + title + '</span>' +
                    '<span class="quota-group-meta">' + meta + '</span>' +
                '</div>' +
                rows.join('') +
            '</div>';
        }

        function renderResourceQuotas(resources) {
            const d1 = resources.d1 || {};
            const kv = resources.kv || {};
            const r2 = resources.r2 || {};
            return '<details class="quota-details">' +
                '<summary class="quota-summary"><span class="quota-summary-title">资源额度细节</span><span class="quota-summary-meta">KV / D1 / R2</span></summary>' +
                '<div class="quota-body"><div class="quota-list">' +
                    renderQuotaGroup('KV', formatNumber(kv.namespaces || 0) + ' 个命名空间', [
                        renderQuotaBar('读取（今日）', kv.reads, kv.readsLimit),
                        renderQuotaBar('写入（今日）', kv.writes, kv.writesLimit),
                        renderQuotaBar('删除/列表（今日）', (kv.deletes || 0) + (kv.lists || 0), (kv.deletesLimit || 0) + (kv.listsLimit || 0)),
                        renderQuotaBar('存储', kv.storageBytes, kv.storageLimitBytes, formatBytes)
                    ]) +
                    renderQuotaGroup('D1', formatNumber(d1.databases || 0) + ' 个数据库', [
                        renderQuotaBar('读取（今日）', d1.rowsRead, d1.rowsReadLimit),
                        renderQuotaBar('写入（今日）', d1.rowsWritten, d1.rowsWrittenLimit),
                        renderQuotaBar('存储', d1.storageBytes, d1.storageLimitBytes, formatBytes)
                    ]) +
                    renderQuotaGroup('R2', formatNumber(r2.buckets || 0) + ' 个存储桶', [
                        renderQuotaBar('Class A（本月）', r2.classA, r2.classALimit),
                        renderQuotaBar('Class B（本月）', r2.classB, r2.classBLimit),
                        renderQuotaBar('存储', r2.storageBytes, r2.storageLimitBytes, formatBytes)
                    ]) +
                '</div><div class="resource-note">D1/KV 按 UTC 自然日统计，R2 操作按本月统计；存储为最近一次指标快照。</div></div>' +
            '</details>';
        }

        function prefersReducedMotion() {
            return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        }

        function resetQuotaBody(body) {
            body.style.height = '';
            body.style.opacity = '';
            body.style.transform = '';
            body.style.overflow = '';
        }

        function animateQuotaDetails(details, opening) {
            const body = details.querySelector('.quota-body');
            if (!body || typeof body.animate !== 'function') {
                details.open = opening;
                return;
            }

            details.classList.add('quota-animating');
            body.style.overflow = 'hidden';

            if (opening) {
                details.open = true;
                body.style.height = '0px';
                body.style.opacity = '0';
                body.style.transform = 'translateY(6px)';
            } else {
                body.style.height = body.scrollHeight + 'px';
                body.style.opacity = '1';
                body.style.transform = 'translateY(0)';
            }

            const startHeight = opening ? 0 : body.scrollHeight;
            const endHeight = opening ? body.scrollHeight : 0;
            const animation = body.animate([
                { height: startHeight + 'px', opacity: opening ? 0 : 1, transform: opening ? 'translateY(6px)' : 'translateY(0)' },
                { height: endHeight + 'px', opacity: opening ? 1 : 0, transform: opening ? 'translateY(0)' : 'translateY(6px)' }
            ], {
                duration: 260,
                easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
                fill: 'forwards'
            });

            animation.onfinish = () => {
                animation.cancel();
                if (!opening) details.open = false;
                resetQuotaBody(body);
                details.classList.remove('quota-animating');
            };

            animation.oncancel = () => {
                resetQuotaBody(body);
                details.classList.remove('quota-animating');
            };
        }

        function bindQuotaDetailsAnimations(scope) {
            if (!scope) return;
            scope.querySelectorAll('.quota-details').forEach(details => {
                if (details.dataset.quotaAnimationBound) return;
                const summary = details.querySelector('.quota-summary');
                const body = details.querySelector('.quota-body');
                if (!summary || !body) return;

                details.dataset.quotaAnimationBound = 'true';
                summary.addEventListener('click', (event) => {
                    if (prefersReducedMotion() || typeof body.animate !== 'function') return;
                    event.preventDefault();
                    if (details.classList.contains('quota-animating')) return;
                    animateQuotaDetails(details, !details.open);
                });
            });
        }

        function 显示消息(msg) {
            if (!msg) return;
            const msgElement = document.createElement('div');
            msgElement.className = 'toast-notification';
            msgElement.textContent = msg;
            document.body.appendChild(msgElement);
            setTimeout(() => {
                msgElement.style.opacity = '0';
                msgElement.style.transition = 'opacity 0.4s ease';
                setTimeout(() => msgElement.remove(), 400);
            }, 3000);
        }

        async function fetchUsage() {
            const content = document.getElementById('content');
            try {
                const response = await fetch('/usage.json?t=' + Date.now());
                if (!response.ok) throw new Error('数据接口请求失败（' + response.status + '）');
                const data = await response.json();
                if (!data.success) throw new Error(data.msg || '数据暂不可用');

                const total = data.total || 0;
                const max = data.max || 100000;
                const percent = Math.min((total / max) * 100, 100).toFixed(1);
                const resources = getResources(data);
                
                content.innerHTML = \`
                    <div class="usage-section">
                        <div class="usage-header">
                            <span class="label">总配额</span>
                            <span class="percentage">\${percent}%</span>
                        </div>
                        <div class="progress-track">
                            <div class="progress-bar" style="width: 0%"></div>
                        </div>
                        <div class="total-text">
                            \${total.toLocaleString()} / \${max.toLocaleString()} 请求次数
                        </div>
                        <div class="total-text" style="font-size: 0.75rem; opacity: 0.75; margin-top: 0.35rem;">
                            最后更新: \${data.UpdateTime ? new Date(data.UpdateTime).toLocaleString() : '未知'}
                        </div>
                    </div>

                    <div class="stats-grid">
                        <div class="mini-card">
                            <div class="mini-icon">🔶</div>
                            <div class="mini-info">
                                <div class="mini-label">Workers</div>
                                <div class="mini-value">\${(data.workers || 0).toLocaleString()}</div>
                            </div>
                        </div>
                        <div class="mini-card">
                            <div class="mini-icon">⚡️</div>
                            <div class="mini-info">
                                <div class="mini-label">Pages</div>
                                <div class="mini-value">\${(data.pages || 0).toLocaleString()}</div>
                            </div>
                        </div>
                    </div>
                    \${renderResourceQuotas(resources)}
                \`;
                bindQuotaDetailsAnimations(content);

                // Animate progress bar and apply colors
                requestAnimationFrame(() => {
                    const usageSection = content.querySelector('.usage-section');
                    const bar = content.querySelector('.progress-bar');
                    if(usageSection) applyGradientColor(usageSection, percent);
                    if(bar) bar.style.width = percent + '%';
                });

                if (data.RefreshStats && data.RefreshStats.partial > 0) {
                    const warn = document.createElement('div');
                    warn.style.cssText = 'margin-top: 0.75rem; color: var(--danger); font-size: 0.85rem;';
                    warn.textContent = '⚠️ 部分账号的资源统计失败，显示用量可能偏低';
                    content.appendChild(warn);
                }
                const 刷新间隔 = Number((data.RefreshStats && data.RefreshStats.thresholdMs) || 1200000);
                if (data.UpdateTime && Date.now() - Number(data.UpdateTime) > 刷新间隔 * 2) {
                    const staleWarn = document.createElement('div');
                    staleWarn.style.cssText = 'margin-top: 0.75rem; color: var(--danger); font-size: 0.85rem;';
                    staleWarn.textContent = '⚠️ 数据已超过 2 个刷新周期未更新';
                    content.appendChild(staleWarn);
                }

                if (data.msg) 显示消息(data.msg);
            } catch (error) {
                console.error(error);
                content.innerHTML = '<div class="error-msg"><div style="margin-bottom: 0.25rem; font-weight: 600;">数据获取失败</div><div class="error-detail" style="font-size: 0.8rem; opacity: 0.8;"></div></div>';
                const detail = content.querySelector('.error-detail');
                if (detail) detail.textContent = error.message || '未知错误';
            }
        }
        
        function 设置首页范围按钮(days) {
            document.querySelectorAll('.history-range-btn').forEach(function (btn) {
                const 激活 = Number(btn.dataset.days) === Number(days);
                btn.style.background = 激活 ? 'var(--primary)' : 'var(--item-bg)';
                btn.style.color = 激活 ? '#fff' : 'var(--text-main)';
                btn.style.borderColor = 激活 ? 'transparent' : 'var(--stroke)';
            });
        }

        function 渲染公开历史(容器, 数据) {
            const 卡片 = document.getElementById('history-card');
            if (!数据 || 数据.historyEnabled === false || !Array.isArray(数据.points) || 数据.points.length === 0) {
                if (卡片) 卡片.style.display = 'none';
                return;
            }
            if (卡片) 卡片.style.display = 'block';
            const 提示 = document.getElementById('history-hint');
            if (提示) 提示.textContent = 数据.points.length + ' 个数据点 · ' + (数据.source === 'kv' ? 'KV 每日快照' : 'D1 历史');
            const 点列表 = 数据.points;
            const 宽 = 600, 高 = 110, 左 = 6, 右 = 6, 上 = 8, 下 = 16;
            const 值列表 = 点列表.map(function (item) { return Number(item.v) || 0; });
            const 最大值 = Math.max.apply(null, 值列表.concat([1]));
            const 最小时间 = 点列表[0].t;
            const 最大时间 = 点列表[点列表.length - 1].t;
            const X = function (t) { return 左 + (最大时间 === 最小时间 ? 0 : (t - 最小时间) / (最大时间 - 最小时间)) * (宽 - 左 - 右); };
            const Y = function (v) { return 上 + (1 - v / (最大值 * 1.1)) * (高 - 上 - 下); };
            const 折线 = 点列表.map(function (item) { return X(item.t).toFixed(1) + ',' + Y(item.v).toFixed(1); }).join(' ');
            const 面积 = 'M ' + X(最小时间).toFixed(1) + ',' + (高 - 下) + ' L ' + 点列表.map(function (item) { return X(item.t).toFixed(1) + ',' + Y(item.v).toFixed(1); }).join(' L ') + ' L ' + X(最大时间).toFixed(1) + ',' + (高 - 下) + ' Z';
            容器.innerHTML = '<svg viewBox="0 0 ' + 宽 + ' ' + 高 + '" style="width: 100%; height: auto; display: block;" role="img" aria-label="用量趋势">' +
                '<path d="' + 面积 + '" fill="#6366f1" fill-opacity="0.15"/>' +
                '<polyline points="' + 折线 + '" fill="none" stroke="#6366f1" stroke-width="2" stroke-linejoin="round"/>' +
                '</svg>';

            const 平均值 = 值列表.reduce(function (sum, value) { return sum + value; }, 0) / 值列表.length;
            const 峰值 = Math.max.apply(null, 值列表);
            const 首值 = 值列表[0];
            const 末值 = 值列表[值列表.length - 1];
            const 走势 = 首值 > 0 ? ((末值 - 首值) / 首值) * 100 : (末值 > 0 ? 100 : 0);
            const 日均元素 = document.getElementById('homeStatAvg');
            const 峰值元素 = document.getElementById('homeStatPeak');
            const 趋势元素 = document.getElementById('homeStatTrend');
            if (日均元素) 日均元素.textContent = formatNumber(Math.round(平均值));
            if (峰值元素) 峰值元素.textContent = formatNumber(峰值);
            if (趋势元素) {
                趋势元素.textContent = (走势 >= 0 ? '+' : '') + 走势.toFixed(1) + '%';
                趋势元素.style.color = 走势 >= 0 ? '#f87171' : '#4ade80';
            }
            const 摘要容器 = document.getElementById('home-chart-summary');
            if (摘要容器) 摘要容器.style.display = 'grid';
        }

        async function loadPublicHistory(days) {
            const 容器 = document.getElementById('public-history');
            if (!容器) return;
            const 天数 = [7, 14, 30].includes(Number(days)) ? Number(days) : 7;
            try {
                const res = await fetch('/history?range=' + 天数 + 'd&metric=requests&account=all');
                if (!res.ok) return;
                const 数据 = await res.json();
                if (数据 && 数据.historyEnabled !== false && Array.isArray(数据.points) && 数据.points.length > 0) {
                    设置首页范围按钮(天数);
                    渲染公开历史(容器, 数据);
                    const 按钮容器 = document.getElementById('history-toggle');
                    if (按钮容器) 按钮容器.style.display = 'none';
                } else {
                    显示消息('暂无历史数据：绑定 D1 或等待每日快照');
                }
            } catch (err) {
                console.error('加载公开历史失败:', err);
            }
        }

        function switchHomeRange(btn, days) {
            设置首页范围按钮(days);
            loadPublicHistory(days);
        }

        fetchUsage();

        // 管理员登录相关函数
        function openLoginModal() {
            document.getElementById('loginModal').classList.add('active');
            document.getElementById('adminUsername').focus();
        }

        function closeLoginModal() {
            document.getElementById('loginModal').classList.remove('active');
            document.getElementById('adminUsername').value = '';
            document.getElementById('adminPassword').value = '';
            const 验证码输入 = document.getElementById('adminTotp');
            if (验证码输入) 验证码输入.value = '';
            document.getElementById('loginError').classList.remove('show');
        }

        // 点击模态框外部关闭
        document.getElementById('loginModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeLoginModal();
            }
        });

        // ESC键关闭模态框
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeLoginModal();
            }
        });

        async function handleLogin() {
            const username = document.getElementById('adminUsername').value || 'admin';
            const password = document.getElementById('adminPassword').value;
            const totp输入 = document.getElementById('adminTotp');
            const totp = totp输入 ? totp输入.value.trim() : '';
            const loginBtn = document.getElementById('loginBtn');
            const errorDiv = document.getElementById('loginError');

            if (loginBtn.disabled) return;

            if (!password) {
                errorDiv.textContent = '请输入密码';
                errorDiv.classList.add('show');
                document.getElementById('adminPassword').focus();
                return;
            }

            loginBtn.disabled = true;
            loginBtn.textContent = '登录中...';
            errorDiv.classList.remove('show');

            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password, totp })
                });

                const data = await response.json();

                if (data.success) {
                    // 登录成功，跳转到管理面板
                    window.location.href = '/admin';
                } else {
                    errorDiv.textContent = data.msg || '登录失败';
                    errorDiv.classList.add('show');
                    if (data.need2fa && totp输入) totp输入.focus();
                    else document.getElementById('adminUsername').select();
                }
            } catch (err) {
                errorDiv.textContent = '网络错误，请重试';
                errorDiv.classList.add('show');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = '登 录';
            }
        }

    </script>
</body>
</html>`;
    return new Response(html, { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } })
}

