// sentry-agent 前端逻辑：WS 实时推送 + 轮询兜底（WS 断线时降级轮询，方案 3.8）。
// 分区导航（按代码顺序）：
//   1 常量与全局状态 state｜2 通用工具函数｜3 图表主题与渲染（ECharts，含 3.5 全球攻击地图）
//   4 非表格渲染（KPI/态势/TOP/事件流）｜5 表格行级 diff 渲染框架
//   6 数据拉取（轮询与 WS 共用）｜7 交互与联动（含四明细表折叠组件）｜8 WS 实时推送（8.5 数据导出与卡头 CSV 导出）｜9 初始化
// 迭代历史见 git log 与 docs/verification/。
(function () {
  'use strict';

  // ===== 模块 1：常量与全局状态 =====
  var WS_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';
  var POLL_MS = 5000;
  var RANGE_LABEL = { '1h': '近 1 小时', '24h': '今日', '7d': '近 7 天', '30d': '近 30 天' };
  // DEV-FE-002 PF-04：DOM 规模控制（技术方案 §11.3 <2000 验收线）——
  // 每表首屏行数上限 TABLE_PAGE + 滚动到底自动加载下一批（轻量方案，不引入虚拟化库）
  // R-07（reviewer）：MAX_TABLE_PAGE 上限保护——滚动加载最多渲染 200 行/表
  var TABLE_PAGE = 60;
  var MAX_TABLE_PAGE = 200;
  // DEV-FE-002 竞态缓解：connections 端点不支持 range 参数，用其原生 since 参数实现范围过滤
  var RANGE_SEC = { '1h': 3600, '24h': 86400, '7d': 604800, '30d': 2592000 };
  // DEV-GEO-001：ISO 3166-1 alpha-2 → world.json 英文名映射（名称与 geojson
  // properties.name 精确一致；未列出的 code 无地图形状，列表仍展示）。
  // world.json 来源：johan/world.geo.json（Apache-2.0，https://github.com/johan/world.geo.json），
  // 已本地化嵌入（internal/web/static/world.json）并按 Apache-2.0 保留归属声明。
  // MaxMind 名称（zh-CN/en）仅用于列表/导出；地图上色依赖本映射。
  var GEO_CODE_NAME = {
    AF: 'Afghanistan', AL: 'Albania', DZ: 'Algeria', AO: 'Angola', AQ: 'Antarctica', AR: 'Argentina',
    AM: 'Armenia', AU: 'Australia', AT: 'Austria', AZ: 'Azerbaijan', BD: 'Bangladesh', BY: 'Belarus',
    BE: 'Belgium', BZ: 'Belize', BJ: 'Benin', BM: 'Bermuda', BT: 'Bhutan', BO: 'Bolivia',
    BA: 'Bosnia and Herzegovina', BW: 'Botswana', BR: 'Brazil', BN: 'Brunei', BG: 'Bulgaria', BF: 'Burkina Faso',
    BI: 'Burundi', KH: 'Cambodia', CM: 'Cameroon', CA: 'Canada', CF: 'Central African Republic', TD: 'Chad',
    CL: 'Chile', CN: 'China', CO: 'Colombia', CR: 'Costa Rica', HR: 'Croatia', CU: 'Cuba',
    CY: 'Cyprus', CZ: 'Czech Republic', CD: 'Democratic Republic of the Congo', DK: 'Denmark', DJ: 'Djibouti', DO: 'Dominican Republic',
    TL: 'East Timor', EC: 'Ecuador', EG: 'Egypt', SV: 'El Salvador', GQ: 'Equatorial Guinea', ER: 'Eritrea',
    EE: 'Estonia', ET: 'Ethiopia', FK: 'Falkland Islands', FJ: 'Fiji', FI: 'Finland', FR: 'France',
    GF: 'French Guiana', TF: 'French Southern and Antarctic Lands', GA: 'Gabon', GM: 'Gambia', GE: 'Georgia', DE: 'Germany',
    GH: 'Ghana', GR: 'Greece', GL: 'Greenland', GT: 'Guatemala', GN: 'Guinea', GW: 'Guinea Bissau',
    GY: 'Guyana', HT: 'Haiti', HN: 'Honduras', HU: 'Hungary', IS: 'Iceland', IN: 'India',
    ID: 'Indonesia', IR: 'Iran', IQ: 'Iraq', IE: 'Ireland', IL: 'Israel', IT: 'Italy',
    CI: 'Ivory Coast', JM: 'Jamaica', JP: 'Japan', JO: 'Jordan', KZ: 'Kazakhstan', KE: 'Kenya',
    XK: 'Kosovo', KW: 'Kuwait', KG: 'Kyrgyzstan', LA: 'Laos', LV: 'Latvia', LB: 'Lebanon',
    LS: 'Lesotho', LR: 'Liberia', LY: 'Libya', LT: 'Lithuania', LU: 'Luxembourg', MK: 'Macedonia',
    MG: 'Madagascar', MW: 'Malawi', MY: 'Malaysia', ML: 'Mali', MT: 'Malta', MR: 'Mauritania',
    MX: 'Mexico', MD: 'Moldova', MN: 'Mongolia', ME: 'Montenegro', MA: 'Morocco', MZ: 'Mozambique',
    MM: 'Myanmar', NA: 'Namibia', NP: 'Nepal', NL: 'Netherlands', NC: 'New Caledonia', NZ: 'New Zealand',
    NI: 'Nicaragua', NE: 'Niger', NG: 'Nigeria', KP: 'North Korea', NO: 'Norway', OM: 'Oman',
    PK: 'Pakistan', PA: 'Panama', PG: 'Papua New Guinea', PY: 'Paraguay', PE: 'Peru', PH: 'Philippines',
    PL: 'Poland', PT: 'Portugal', PR: 'Puerto Rico', QA: 'Qatar', RS: 'Republic of Serbia', CG: 'Republic of the Congo',
    RO: 'Romania', RU: 'Russia', RW: 'Rwanda', SA: 'Saudi Arabia', SN: 'Senegal', SL: 'Sierra Leone',
    SK: 'Slovakia', SI: 'Slovenia', SB: 'Solomon Islands', SO: 'Somalia', ZA: 'South Africa', KR: 'South Korea',
    SS: 'South Sudan', ES: 'Spain', LK: 'Sri Lanka', SD: 'Sudan', SR: 'Suriname', SZ: 'Swaziland',
    SE: 'Sweden', CH: 'Switzerland', SY: 'Syria', TW: 'Taiwan', TJ: 'Tajikistan', TH: 'Thailand',
    BS: 'The Bahamas', TG: 'Togo', TT: 'Trinidad and Tobago', TN: 'Tunisia', TR: 'Turkey', TM: 'Turkmenistan',
    UG: 'Uganda', UA: 'Ukraine', AE: 'United Arab Emirates', GB: 'United Kingdom', TZ: 'United Republic of Tanzania', US: 'United States of America',
    UY: 'Uruguay', UZ: 'Uzbekistan', VU: 'Vanuatu', VE: 'Venezuela', VN: 'Vietnam', PS: 'West Bank',
    EH: 'Western Sahara', YE: 'Yemen', ZM: 'Zambia', ZW: 'Zimbabwe'
  };
  var state = {
    ws: null, wsMode: false,
    range: '24h',
    filter: null,            // null 或 { type:'port'|'src', value }（TOP 点击联动）
    attack: { ports: null, sources: null, ssh: null, bans: null }, // bans：P3-1 封禁名单（不随 range 变化）
    // T2 重构：各表状态收敛 state.tables[id] = { rows, sort, page }（rows 数据缓存 /
    // sort 排序 { key, dir } / page 滚动加载当前页数），按 index.html 全部表 id 显式声明，
    // 消除原 state.xxxRows 运行期隐式挂载与 id.replace('-table','Rows') 字符串耦合
    tables: {
      'snap-table': { rows: null, sort: null, page: 0 },
      'conn-table': { rows: null, sort: null, page: 0 },
      'hp-table': { rows: null, sort: null, page: 0 },
      'hpd-table': { rows: null, sort: null, page: 0 },
      'ssh-table': { rows: null, sort: null, page: 0 },
      'fw-table': { rows: null, sort: null, page: 0 }
    },
    sshResult: '',           // SSH 表结果过滤：'' 全部 / 0 失败 / 1 成功
    fwAction: '',            // 防火墙表动作过滤：'' 全部 / inbound / reject / drop / accept
    summary: null,           // summary 缓存（态势条/KPI/风险评分）
    fwTimeline: null,        // firewall/timeline 桶缓存（趋势图三通道/FW spark/风险评分/态势条）
    // DEV-GEO-001：全球攻击地图状态（rows 全量缓存，country/min 前端本地过滤——交互零延迟、
    // 不消耗 heavy 限流桶；导出请求携带过滤参数走后端同口径）
    geo: { rows: null, country: '', min: 0, mmdbOk: false },
    // DEV-HONEY-001/002：蜜罐凭据捕获状态（rows/dict 数据缓存已收敛至 state.tables 的
    // hp-table/hpd-table；proto 前端筛选走后端参数；revealed 密码显示集合按行唯一键 __k
    // 记忆——行对象每轮重建，须独立持久化）。
    hp: { proto: '', revealed: {} },
    worldLoaded: false,      // world.json 已注册标志（一次性 fetch/registerMap）
    attackDataFailed: false, // 攻击数据源失败标志——每轮 pollAttack 开头重置，成功回调不覆盖
    sshTimelineOk: true,     // ssh/timeline 独立就绪标志（fwTimeline 成功不覆盖它）
    disk24: null,            // 磁盘 24h 序列（磁盘卡 spark/trend）
    sparkLoaded: false,      // 磁盘 spark 首轮已请求
    sitCollapsed: false,     // 态势条折叠状态
    // P0：竞态缓解 / 可见性门控 / 折叠与刷新状态
    reqSeq: 0,               // RB-01/N-1：请求序号——setRange/applyFilter 自增，fetchJSON 回调前校验
    summaryFailed: false,    // RB-02：summary 请求失败标志（态势头失败态 + 错误横幅）
    activePanel: 'overview', // 当前激活页签（可见性门控 + 分档轮询挂载依据）
    resourceData: null,      // 资源图数据缓存（切回总览页补渲染用）
    topPorts: [],            // summary.top_ports 缓存（切回总览页补渲染用）
    eventExpanded: false,    // 事件流"展开全部"状态（默认 3 条）
    // P1：全局错误横幅连续失败计数（7.2 完整实现：任一 errCb 累计，summary 成功清零）
    failStreak: 0,           // 连续失败事件累计计数——≥2 显示错误横幅，summary 成功清零
    // T1：IP 画像弹层状态（当前展示 IP + 在途请求标志；同 IP 去抖、切 IP 重置）
    ipProf: { ip: null, loading: false }
  };
  var statusEl = document.getElementById('conn-status');

  // ===== 模块 2：通用工具 =====
  // 零填充两位数（各时间格式化共用；原 5 处内联 p(n) 收敛单点，T3 重构）
  function pad2(n) { return n < 10 ? '0' + n : '' + n; }
  function ip(v) {
    if (v <= 0) return '-';
    return [(v >>> 24), (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.');
  }
  // IPv6 文本截断（连接表地址列展示用；超长地址尾部省略）
  function truncIp6(s, n) {
    s = String(s || '');
    if (s.length <= n) { return s; }
    return s.slice(0, n - 1) + '…';
  }
  // conn 地址列：IPv4 点分 + 端口；IPv6 归源（数值 0、文本在 *_ip6）显示 [addr]:port
  // （功能审计 Minor-2：不再显示不可辨识的 '-:port'）
  function connAddr(num, port, ip6) {
    if (!num && ip6) { return '[' + truncIp6(ip6, 26) + ']:' + port; }
    return ip(num) + ':' + port;
  }
  // escapeHtml（R-08）：字符串字段一律转义后渲染（防未来 raw/detail 等日志字段接入表格时的 XSS）。
  // P1 行级 diff 后表格统一走 textContent（自动转义），此函数用于事件流内联 HTML 拼接。
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmtTime(ts) {
    var d = new Date(ts * 1000);
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }
  // 带日期时间（7d/30d 范围需要）
  function fmtTimeFull(ts) {
    var d = new Date(ts * 1000);
    return pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }
  // 可见性门控——document.hidden 或非激活面板时跳过渲染（态势条为全局 chrome 不受门控）
  function vis(panel) { return !document.hidden && state.activePanel === panel; }
  function tbody(id) { return document.querySelector('#' + id + ' tbody'); }
  // colspan 取表头列数，三态占位行跨全列；同时清空行级 diff 缓存（DEV-FE-003 PF-3）
  function setTableState(id, cls, text) {
    var tb = tbody(id);
    if (!tb) return;
    tb.__diff = null;
    var colspan = tb.parentElement.querySelectorAll('thead th').length || 1;
    tb.innerHTML = '<tr><td colspan="' + colspan + '" class="' + cls + '">' + text + '</td></tr>';
  }
  function sortRows(rows, key, dir) {
    if (!key) return rows;
    var out = rows.slice();
    out.sort(function (a, b) {
      var av = a[key], bv = b[key];
      var r;
      if (typeof av === 'number' && typeof bv === 'number') { r = av - bv; }
      else { r = String(av).localeCompare(String(bv)); }
      return dir === 'desc' ? -r : r;
    });
    return out;
  }
  // 图表 aria 降级（DEV-FE-003 6.5）：数据渲染时同步更新 aria-label（setAttribute 无 HTML 解析，无 XSS 面）
  function setAria(id, label) {
    var el = document.getElementById(id);
    if (el) { el.setAttribute('aria-label', label); }
  }
  function resetTablePages() {
    Object.keys(state.tables).forEach(function (id) { state.tables[id].page = 0; });
  }
  // 滚动到底加载下一批（轻量分页：每表首轮 TABLE_PAGE 行；MAX_TABLE_PAGE 上限保护防 DOM 无限增长）
  function bindScrollLoad(id, renderFn) {
    var tb = document.getElementById(id);
    if (!tb) return;
    var sc = tb.parentElement;
    if (!sc || sc.__scrollBound) return;
    sc.__scrollBound = true;
    sc.addEventListener('scroll', function () {
      if (sc.scrollTop + sc.clientHeight >= sc.scrollHeight - 60) {
        var t = state.tables[id];
        var cur = (t && t.page) || TABLE_PAGE;
        var total = (t && t.rows) ? t.rows.length : 0;
        if (total <= cur) { return; }
        t.page = Math.min(cur + TABLE_PAGE, MAX_TABLE_PAGE);
        renderFn();
      }
    });
  }
  function rangeQS() { return 'range=' + state.range; }
  function sinceQS() { return 'since=' + (Math.floor(Date.now() / 1000) - RANGE_SEC[state.range]); }
  function touchFreshness() {
    var el = document.getElementById('freshness');
    if (!el) return;
    var d = new Date();
    var t = pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    el.textContent = (state.wsMode ? '' : '降级轮询 · ') + '更新于 ' + t;
    el.classList.toggle('warn', !state.wsMode);
  }
  // 全局错误横幅（DEV-FE-003 7.2）：连续失败事件累计 ≥2 次显示（R-04 口径注：非严格按轮，
  // 同轮多源失败会提前累计；summary 成功清零恢复——实际横幅主要反映 summary 与攻击源失败，
  // 明细表失败有局部 error-row 兜底）
  function showErrorBanner() { var el = document.getElementById('error-banner'); if (el) { el.style.display = 'block'; } }
  function hideErrorBanner() { var el = document.getElementById('error-banner'); if (el) { el.style.display = 'none'; } }
  function noteFailure() {
    state.failStreak++;
    if (state.failStreak >= 2) { showErrorBanner(); }
  }
  function noteSuccess() {
    state.failStreak = 0;
    hideErrorBanner();
  }


  // ===== 模块 3：图表主题与渲染（ECharts） =====
  // 主题（DEV-019：色值跟随 CSS 设计系统"冷石墨·冰蓝"；低饱和网格轴线/tooltip 悬浮层）
  var charts = {};
  var TI = {
    accent: '#58a6ff',      // 图表数据强调色（与 CSS --accent-strong 统一 #58A6FF，方案 4.1 消除双蓝）
    text: '#E8EEF5',        // 主文字（与 CSS --text 同步）
    dim: '#8A94A3',         // 刻度/次级（与 CSS --text-dim 同步）
    grid: 'rgba(232,238,245,0.06)', // 网格线（更低对比，退后一档）
    axis: 'rgba(232,238,245,0.12)', // 坐标轴线
    warn: '#d29922',        // 警告（低饱和）
    danger: '#f85149',      // 危险
    ok: '#3fb950',          // 成功
    chart: ['#58a6ff', '#e09a4b', '#5fb877', '#d66a86'] // 6 色→4 色低饱和序（前 4 色顺序不变：chart[1] 橙=net Tx/disk、chart[2] 绿=mem）
  };
  function chart(id) {
    if (!charts[id]) { charts[id] = echarts.init(document.getElementById(id)); }
    return charts[id];
  }
  var axis = function () {
    return {
      axisLine: { lineStyle: { color: TI.axis } },
      axisLabel: { color: TI.dim, fontSize: 12 },
      splitLine: { lineStyle: { color: TI.grid } }
    };
  };
  // 面积渐变 0.25→0.05 透明度，折线实色无发光
  function lineSeries(name, data, color, area) {
    return {
      name: name, type: 'line', data: data, smooth: true, symbol: 'none',
      lineStyle: { width: 1.75, color: color },
      itemStyle: { color: color },
      areaStyle: area ? {
        color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
          { offset: 0, color: color + '40' }, { offset: 1, color: color + '0D' }
        ])
      } : undefined
    };
  }
  // tooltip formatter（DEV-FE-003 6.1）：单位 + 语义色 marker——marker 色取自 series 色
  // （如"入站探测"红点 = TI.danger、"拦截"蓝点 = TI.accent、"SSH 失败"琥珀点 = TI.warn），formatter 补单位文案
  function makeTipFmt(units) {
    return function (params) {
      var rows = params.map(function (p) {
        var u = units[p.seriesName] || '';
        return p.marker + ' ' + p.seriesName + '：' + p.value + (u ? ' ' + u : '');
      });
      var cat = params[0] && params[0].axisValue != null ? params[0].axisValue : '';
      return (cat ? cat + '<br/>' : '') + rows.join('<br/>');
    };
  }
  function baseOption(labels, yMax, units) {
    return {
      // DEV-020 F4：right 14→48 给最右时间标签留完整空间
      grid: { left: 44, right: 48, top: 18, bottom: 22 },
      // tooltip 悬浮层（--bg-raised）+ 柔和投影；DEV-FE-003：axisPointer cross 十字线（方案 6.1）
      tooltip: { trigger: 'axis', backgroundColor: '#232C38', borderColor: '#2A3441',
        borderWidth: 1, borderRadius: 6, padding: [8, 12],
        extraCssText: 'box-shadow: 0 6px 20px rgba(0,0,0,0.4);',
        textStyle: { color: '#E8EEF5', fontSize: 12 },
        axisPointer: { type: 'cross', lineStyle: { color: 'rgba(232,238,245,0.25)', type: 'dashed' },
          label: { backgroundColor: '#232C38', color: '#8A94A3', borderColor: '#2A3441', fontSize: 11 } },
        formatter: units ? makeTipFmt(units) : undefined },
      // ECharts 过渡动画 420ms cubicOut（5s 轮询刷新干脆利落，一次性非循环）；
      // DEV-047 C3：animationDurationUpdate 300ms 显式确认——setOption 更新走该时长
      // （gauge 风险仪表指针切换缓动由此生效；ECharts 默认亦为 300，此处显式固化）
      animationDuration: 420, animationEasing: 'cubicOut', animationDurationUpdate: 300,
      xAxis: Object.assign({ type: 'category', data: labels, boundaryGap: false }, axis()),
      yAxis: Object.assign({ type: 'value', max: yMax }, axis())
    };
  }
  // DEV-FE-003 6.3：7d/30d dataZoom slider 低饱和样式（--bg-card 底 + --border 描边语义）
  function zoomSlider() {
    return {
      type: 'slider', height: 14, bottom: 2,
      borderColor: '#2A3441', backgroundColor: 'transparent',
      fillerColor: 'rgba(76,154,255,0.08)',
      handleStyle: { color: '#4C9AFF', borderColor: '#4C9AFF' },
      moveHandleStyle: { color: '#8A94A3' },
      textStyle: { color: '#8A94A3', fontSize: 11 },
      dataBackground: { lineStyle: { color: '#2A3441', width: 1 }, areaStyle: { color: 'rgba(232,238,245,0.05)' } }
    };
  }
  function zoomData(longRange) {
    return longRange ? [{ type: 'inside' }, zoomSlider()] : undefined;
  }
  // 网络速率 B/s 刻度格式化（K/M 缩写）
  function fmtBps(v) {
    if (v >= 1000000) { return (v / 1000000).toFixed(1) + 'M'; }
    if (v >= 1000) { return Math.round(v / 1000) + 'K'; }
    return String(v);
  }
  // 攻击页图表空数据占位（ECharts 空画布之上覆盖"暂无数据"）
  function setChartEmpty(id, empty) {
    var el = document.getElementById(id);
    if (el) { el.classList.toggle('chart-empty', empty); }
  }

  function renderResource(data) {
    if (!vis('overview')) { return; } // 隐藏面板不 setOption
    var labels = data.labels;
    var units = { 'CPU': '%', '内存': '%', '磁盘': '%', 'Rx': 'B/s', 'Tx': 'B/s' };
    chart('chart-cpu').setOption(Object.assign(baseOption(labels, 100, units), {
      series: [lineSeries('CPU', data.cpu, TI.accent, true)]
    }), true);
    chart('chart-mem').setOption(Object.assign(baseOption(labels, 100, units), {
      series: [lineSeries('内存', data.mem, TI.chart[2], true)]
    }), true);
    chart('chart-disk').setOption(Object.assign(baseOption(labels, 100, units), {
      series: [lineSeries('磁盘', data.disk, TI.chart[1], true)]
    }), true);
    // net 图专用 yAxis：min:0 + scale:true（尖峰不超刻度）+ splitNumber 显式分段 + K/M 缩写。
    // axisLabel（含 formatter）必须放在合并序列最后（DEV-013：Object.assign 源覆盖目标）
    var netY = Object.assign({ type: 'value', min: 0, scale: true, splitNumber: 5 }, axis(), {
      axisLabel: { color: TI.dim, fontSize: 12, formatter: fmtBps }
    });
    chart('chart-net').setOption(Object.assign(baseOption(labels, undefined, units), { yAxis: netY, series: [
      lineSeries('Rx', data.rx, TI.accent, true),
      lineSeries('Tx', data.tx, TI.chart[1], true)
    ] }), true);
    // DEV-FE-003 6.5：图表 aria 降级（读屏可获取图表结论）
    var last = labels.length - 1;
    setAria('chart-cpu', 'CPU 使用率图：最近 1 小时，当前 ' + (last >= 0 ? data.cpu[last] : '-') + '%');
    setAria('chart-mem', '内存使用率图：最近 1 小时，当前 ' + (last >= 0 ? data.mem[last] : '-') + '%');
    setAria('chart-disk', '磁盘使用率图：最近 1 小时，当前 ' + (last >= 0 ? data.disk[last] : '-') + '%');
    setAria('chart-net', '网络速率图：最近 1 小时，当前 Rx ' + (last >= 0 ? data.rx[last] : 0) + ' B/s，Tx ' + (last >= 0 ? data.tx[last] : 0) + ' B/s');
  }

  // 风险评分（gauge + 三通道分解条）。
  // 公式（前端实现）：总分 = min(ssh_fail/200,1)*40 + min(fw_blocked/1000,1)*40
  //        + clamp((disk-50)/40,0,1)*20，0-100。
  // 权重 40/40/20（DEV-GEO-001：封禁通道移除后重新平衡——攻击行为两通道占主导，
  // 磁盘资源维度保持原 20 权重）；阈值按单机 1C1G 场景经验设定；无漏洞/CVSS/情报字段。
  // DEV-045：FW 通道改用"拦截"口径（drop+reject 累计）——inbound 为入站观察
  // （扫描器探测，量大）不计入威胁动作，避免评分恒饱和；30d 视图累计必然饱和虚高、
  // 跨 range 不可比，属设计口径（UI 已加口径注）。
  // DEV-047 D2：风险评分计算提取（renderRisk 与 KPI"风险评分"卡共用，DRY 防口径漂移）
  function riskParts() {
    var s = state.summary;
    if (!s) { return null; }
    var fwBlocked = 0;
    (state.fwTimeline || []).forEach(function (b) { fwBlocked += (b.drop || 0) + (b.reject || 0); });
    var sshFail = s.ssh_fail || 0, disk = s.disk_percent;
    var fSsh = Math.min(sshFail / 200, 1), fFw = Math.min(fwBlocked / 1000, 1),
      fDisk = Math.max(0, Math.min((disk - 50) / 40, 1));
    var score = Math.round(fSsh * 40 + fFw * 40 + fDisk * 20);
    return { score: score, fSsh: fSsh, fFw: fFw, fDisk: fDisk,
      sshFail: sshFail, fwBlocked: fwBlocked, disk: disk };
  }
  function renderRisk() {
    if (!vis('overview')) { return; } // 隐藏面板不渲染
    var p = riskParts();
    if (!p) { return; } // summary 未到（保留旧图，行为与重构前一致）
    // 攻击数据源失败时评分卡显示失败态（与态势条一致），不保留旧值/0 误导
    if (state.attackDataFailed || !state.sshTimelineOk || state.summaryFailed) {
      var failOpt = {
        series: [{
          type: 'gauge', startAngle: 210, endAngle: -30, min: 0, max: 100,
          radius: '92%', center: ['50%', '58%'],
          axisLine: { lineStyle: { width: 12, color: [[0.3, TI.ok], [0.6, TI.warn], [1, TI.danger]] } },
          pointer: { show: false }, axisTick: { show: false }, splitLine: { show: false },
          axisLabel: { show: false },
          title: { show: true, offsetCenter: [0, '68%'], fontSize: 11, color: '#8A94A3' },
          detail: { offsetCenter: [0, '12%'], fontSize: 24, fontWeight: 600, color: '#8A94A3',
            fontFamily: 'Consolas, monospace', formatter: function () { return '--'; } },
          data: [{ value: 0, name: '数据加载失败' }]
        }]
      };
      chart('chart-risk').setOption(failOpt, true);
      setAria('chart-risk', '风险评分图：数据加载失败');
      var names = ['risk-ssh-v', 'risk-fw-v', 'risk-disk-v'];
      names.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) { el.textContent = '--'; }
      });
      return;
    }
    var score = p.score;
    var bar = function (id, v, valTxt) {
      var b = document.getElementById(id);
      if (b) { b.style.width = Math.round(v * 100) + '%'; b.style.background = v >= 0.6 ? TI.danger : (v >= 0.3 ? TI.warn : TI.ok); }
      var vt = document.getElementById(id.replace('-bar', '-v'));
      if (vt) { vt.textContent = valTxt; }
    };
    bar('risk-ssh-bar', p.fSsh, p.sshFail);
    bar('risk-fw-bar', p.fFw, p.fwBlocked);
    bar('risk-disk-bar', p.fDisk, p.disk >= 0 ? p.disk.toFixed(0) + '%' : '-');
    var opt = {
      animationDurationUpdate: 300, // DEV-047 C3：gauge 指针更新缓动显式确认（300ms 一次性）
      series: [{
        type: 'gauge', startAngle: 210, endAngle: -30, min: 0, max: 100,
        radius: '92%', center: ['50%', '58%'],
        axisLine: { lineStyle: { width: 12, color: [[0.3, TI.ok], [0.6, TI.warn], [1, TI.danger]] } },
        pointer: { length: '58%', width: 3, itemStyle: { color: '#8A94A3' } },
        axisTick: { show: false }, splitLine: { show: false },
        axisLabel: { show: false },
        title: { show: true, offsetCenter: [0, '68%'], fontSize: 11, color: '#8A94A3' },
        detail: { valueAnimation: false, offsetCenter: [0, '12%'], fontSize: 24, fontWeight: 600,
          color: score >= 60 ? TI.danger : (score >= 30 ? TI.warn : TI.ok), fontFamily: 'Consolas, monospace' },
        data: [{ value: score, name: '风险评分' }]
      }]
    };
    chart('chart-risk').setOption(opt, true);
    setAria('chart-risk', '风险评分图：当前 ' + score + '/100');
  }

  // 攻击趋势三通道（DEV-045：SSH 失败 + 入站探测 inbound 主通道 + 拦截 drop/reject 辅通道，
  // 按 fw 桶时间轴对齐；inbound 为扫描器流量观察，拦截为实际威胁动作）
  function renderAttackTrend() {
    if (!vis('overview')) { return; } // 隐藏面板不渲染
    var fwB = state.fwTimeline || [];
    var sshMap = {};
    (state.attack.ssh || []).forEach(function (p) { sshMap[p.ts] = p.hits; });
    var labels = [], inD = [], blkD = [], sshD = [];
    var longRange = (state.range === '7d' || state.range === '30d');
    fwB.forEach(function (b) {
      labels.push(longRange ? fmtTimeFull(b.ts) : fmtTime(b.ts));
      inD.push(b.inbound || 0);
      blkD.push((b.drop || 0) + (b.reject || 0));
      sshD.push(sshMap[b.ts] || 0);
    });
    var opt = baseOption(labels, undefined, { '入站探测': '次', '拦截': '次', 'SSH 失败': '次' });
    opt.grid = { left: 44, right: 56, top: 34, bottom: longRange ? 34 : 22 }; // DEV-FE-003：dataZoom 时底部让位；DEV-047 D3：right 56 容纳右轴刻度
    opt.legend = { top: 2, right: 6, textStyle: { color: '#8A94A3', fontSize: 11 }, itemWidth: 12, itemHeight: 8 };
    if (longRange) { opt.dataZoom = zoomData(true); } // DEV-FE-003 6.3：7d/30d 启用（1h/24h 保持紧凑）
    // DEV-047 D3：双 Y 轴——入站探测（扫描器量级大）走左轴；拦截（drop+reject）与 SSH 失败走右轴；
    // 右轴关闭 splitLine 避免双网格线；图例/tooltip 按 seriesName 自适应，无需改动
    opt.yAxis = [
      Object.assign({ type: 'value' }, axis()),
      Object.assign({ type: 'value' }, axis(), { splitLine: { show: false } })
    ];
    opt.series = [
      lineSeries('入站探测', inD, TI.danger, true),
      lineSeries('拦截', blkD, TI.accent, true),
      lineSeries('SSH 失败', sshD, TI.warn, true)
    ];
    opt.series[1].yAxisIndex = 1;
    opt.series[2].yAxisIndex = 1;
    chart('chart-attack-trend').setOption(opt, true);
    // 零攻击状态（全部通道为 0 时显示绿色文字行；失败时不显示——R-03/R-16：不得误报"无攻击记录"）
    var inSum = 0, blkSum = 0, sshSum = 0;
    inD.forEach(function (v) { inSum += v; });
    blkD.forEach(function (v) { blkSum += v; });
    sshD.forEach(function (v) { sshSum += v; });
    var badge = document.getElementById('zero-attack-badge');
    if (badge) { badge.style.display = (inSum === 0 && blkSum === 0 && sshSum === 0 && !state.attackDataFailed && state.sshTimelineOk) ? 'block' : 'none'; }
    setAria('chart-attack-trend', '攻击趋势图：入站探测 ' + inSum + ' 次，拦截 ' + blkSum + ' 次，SSH 失败 ' + sshSum + ' 次');
  }

  // 攻击页三图（端口 TOP / 来源 TOP / SSH 时间线）+ 点击联动
  function renderAttacks(ports, sources, ssh) {
    if (!vis('attack')) { return; } // 隐藏面板不 setOption
    setChartEmpty('chart-ports', !ports.length);
    setChartEmpty('chart-sources', !sources.length);
    setChartEmpty('chart-ssh', !ssh.length);
    // barMaxWidth：sources 图单柱场景用 48（多柱时 48 为上限不超标）
    // DEV-047 E2：hover 增强——常态柱体 opacity 0.85，hover 提亮（echarts.color.lift 同色系亮色）
    // + opacity 1 + 顶部数值标签浮现（一次性交互响应，非持续动画）
    var barSeries = function (data, color, name, maxWidth) {
      return {
        name: name, type: 'bar', data: data, barMaxWidth: maxWidth || 22,
        itemStyle: { color: color, borderRadius: [3, 3, 0, 0], opacity: 0.85 },
        emphasis: {
          itemStyle: { color: echarts.color.lift(color, 0.15), opacity: 1 },
          label: { show: true, position: 'top', color: '#E8EEF5', fontSize: 12,
            fontFamily: 'Consolas, monospace', formatter: function (p) { return p.value; } }
        }
      };
    };
    var portsOpt = baseOption(ports.map(function (p) { return ':' + p.dst_port; }), undefined, { '命中': '次' });
    portsOpt.xAxis.boundaryGap = true;
    chart('chart-ports').setOption(Object.assign(portsOpt, {
      series: [barSeries(ports.map(function (p) { return p.hits; }), TI.danger, '命中')]
    }), true);
    var srcOpt = baseOption(sources.map(function (s) { return ip(s.src_ip); }), undefined, { '命中': '次' });
    srcOpt.xAxis.boundaryGap = true;
    // IP 标签长（最长 15 字符），rotate 45° + 底部留白 70，避免被卡片右边界裁切
    srcOpt.xAxis.axisLabel.rotate = 45;
    srcOpt.grid.bottom = 70;
    chart('chart-sources').setOption(Object.assign(srcOpt, {
      series: [barSeries(sources.map(function (s) { return s.hits; }), TI.warn, '命中', 48)]
    }), true);
    var longRange = (state.range === '7d' || state.range === '30d');
    var sshLabels = longRange
      ? ssh.map(function (p) { return fmtTimeFull(p.ts); })
      : ssh.map(function (p) { return fmtTime(p.ts); });
    var sshOpt = baseOption(sshLabels, undefined, { '失败': '次' });
    sshOpt.xAxis.boundaryGap = true;
    if (longRange) { sshOpt.dataZoom = zoomData(true); sshOpt.grid.bottom = 34; } // DEV-FE-003 6.3
    chart('chart-ssh').setOption(Object.assign(sshOpt, {
      series: [barSeries(ssh.map(function (p) { return p.hits; }), TI.accent, '失败')]
    }), true);
    // 点击柱条 → 联动过滤；handler 从 state.attack 读最新数据（避免闭包捕获首次渲染的旧数组）
    var c1 = chart('chart-ports');
    if (!c1.__clickBound) {
      c1.on('click', function (params) {
        var cur = state.attack.ports;
        if (!cur || params.dataIndex === undefined || !cur[params.dataIndex]) return;
        applyFilter({ type: 'port', value: cur[params.dataIndex].dst_port }, '攻击页');
      });
      c1.__clickBound = true;
    }
    var c2 = chart('chart-sources');
    if (!c2.__clickBound) {
      c2.on('click', function (params) {
        var cur = state.attack.sources;
        if (!cur || params.dataIndex === undefined || !cur[params.dataIndex]) return;
        applyFilter({ type: 'src', value: cur[params.dataIndex].src_ip }, '攻击页');
      });
      c2.__clickBound = true;
    }
    // DEV-FE-003 6.5：图表 aria 降级
    setAria('chart-ports', '被攻击端口 TOP 图：' + ports.slice(0, 5).map(function (p) { return '端口 ' + p.dst_port + ' ' + p.hits + ' 次'; }).join('，'));
    setAria('chart-sources', '攻击源 IP TOP 图：' + sources.slice(0, 5).map(function (s) { return ip(s.src_ip) + ' ' + s.hits + ' 次'; }).join('，'));
    var sshTotal = 0;
    ssh.forEach(function (p) { sshTotal += p.hits; });
    setAria('chart-ssh', 'SSH 失败时间线图：共 ' + sshTotal + ' 次失败（' + ssh.length + ' 个时间桶）');
  }


  // ===== 模块 3.5：全球攻击地图（DEV-GEO-001） =====
  // world.json（本地 embed）一次性加载注册；GEO_CODE_NAME 映射 ISO code → geojson 英文名。
  // 视觉纪律：冷石墨→冰蓝低饱和色阶（visualMap 色块，无发光/无气泡动画）。
  function loadWorldMap(cb) {
    if (state.worldLoaded) { cb(); return; }
    fetch('/world.json').then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.json();
    }).then(function (geo) {
      try {
        echarts.registerMap('world', geo);
        state.worldLoaded = true;
      } catch (e) { /* 注册失败：地图区留空，列表仍可用 */ }
      cb();
    }).catch(function () { cb(); });
  }
  var GEO_NAME_CODE = null;
  function geoNameToCode(name) {
    if (!GEO_NAME_CODE) {
      GEO_NAME_CODE = {};
      Object.keys(GEO_CODE_NAME).forEach(function (k) { GEO_NAME_CODE[GEO_CODE_NAME[k]] = k; });
    }
    return GEO_NAME_CODE[name] || '';
  }
  // 国家筛选/次数阈值统一入口（下拉/地图点击/清除共用；本地过滤零请求）
  function setGeoCountry(code) {
    state.geo.country = code || '';
    var sel = document.getElementById('geo-country-filter');
    if (sel) { sel.value = state.geo.country; }
    renderGeo();
    renderGeoSources();
  }
  // 国家下拉重建（数据驱动：当前 rows 出现过的国家；保留现有选择）
  function rebuildCountryOptions(rows) {
    var sel = document.getElementById('geo-country-filter');
    if (!sel) return;
    var cur = state.geo.country, codes = {};
    var html = '<option value="">全部国家/地区</option>';
    rows.forEach(function (r) {
      if (r.country_code === 'Unknown' || codes[r.country_code]) { return; }
      codes[r.country_code] = true;
      html += '<option value="' + escapeHtml(r.country_code) + '">' + escapeHtml(r.country_name) + '</option>';
    });
    sel.innerHTML = html;
    if (cur) { sel.value = cur; }
  }
  function renderGeo() {
    if (!vis('attack')) { return; } // 隐藏面板不渲染
    var rows = state.geo.rows;
    var el = document.getElementById('chart-world');
    if (!el) { return; }
    var note = document.getElementById('geo-mmdb-note');
    if (note) {
      if (state.geo.rows && !state.geo.mmdbOk) {
        note.style.display = 'inline';
        note.textContent = '未配置 GeoIP 库（agent 启动后自动拉取，可手动运行 docs/verification/tools/fetch_geolite2.sh），国家显示 Unknown';
      } else { note.style.display = 'none'; }
    }
    if (!rows) { return; } // 加载中（保留旧图）
    var badge = document.getElementById('zero-geo-badge');
    if (badge) { badge.style.display = rows.length ? 'none' : 'block'; }
    rebuildCountryOptions(rows);
    loadWorldMap(function () {
      if (!state.worldLoaded) { return; }
      // 国家聚合：country_code → geojson 名；Unknown/无映射 code 不入地图（列表仍展示）
      var byCountry = {};
      var filtered = rows.filter(function (r) {
        if (state.geo.country && r.country_code !== state.geo.country) { return false; }
        if (state.geo.min > 0 && r.count < state.geo.min) { return false; }
        return true;
      });
      filtered.forEach(function (r) {
        if (r.country_code === 'Unknown') { return; }
        var n = GEO_CODE_NAME[r.country_code];
        if (!n) { return; }
        byCountry[n] = (byCountry[n] || 0) + r.count;
      });
      var data = Object.keys(byCountry).map(function (n) { return { name: n, value: byCountry[n] }; });
      var max = 1;
      data.forEach(function (d) { if (d.value > max) { max = d.value; } });
      var opt = {
        tooltip: {
          trigger: 'item', backgroundColor: '#232C38', borderColor: '#2A3441', borderWidth: 1,
          borderRadius: 6, padding: [8, 12], textStyle: { color: '#E8EEF5', fontSize: 12 },
          formatter: function (p) {
            return p.name + '：<b style="font-family:Consolas,monospace;">' + p.value + '</b> 次 SSH 失败' +
              (state.geo.country && p.name === GEO_CODE_NAME[state.geo.country] ? '（当前筛选）' : '');
          }
        },
        visualMap: {
          show: true, min: 0, max: max, left: 8, bottom: 8, calculable: false,
          text: ['高', '低'], textStyle: { color: '#8A94A3', fontSize: 11 },
          inRange: { color: ['#0E1319', '#1B232D', '#3B5F8A', '#58A6FF'] },
          itemWidth: 10, itemHeight: 80
        },
        series: [{
          name: 'SSH 失败', type: 'map', map: 'world', roam: false, data: data,
          label: { show: false },
          itemStyle: { borderColor: '#2A3441', borderWidth: 0.6, areaColor: '#0E1319' },
          emphasis: { label: { show: true, color: '#E8EEF5', fontSize: 11 },
            itemStyle: { areaColor: '#58A6FF' } },
          select: { itemStyle: { areaColor: 'rgba(76,154,255,0.35)', borderColor: '#58A6FF', borderWidth: 1 } },
          selectedMode: state.geo.country ? 'single' : false
        }]
      };
      var wc = chart('chart-world');
      // 点击国家 → 筛选该国家（再次点击取消）；联动下方列表与导出
      if (!wc.__geoClickBound) {
        wc.on('click', function (params) {
          var code = geoNameToCode(params.name);
          if (!code) { return; }
          setGeoCountry(state.geo.country === code ? '' : code);
        });
        wc.__geoClickBound = true;
      }
      wc.setOption(opt, true);
    });
  }
  // TOP 榜通用渲染（T4：三胞胎榜合并——rank + 主字段 + bar 百分比条 + hits 横向榜，
  // renderGeoSources / renderMiniTop / renderTopSourcesMini 三处共用）。
  // items 空时显示空态文案后返回；差异点全部回调化，保持三处行为不变：
  //   emptyText   空态文案（字符串或函数；geo 的空态双文案依赖筛选状态故用函数）
  //   rank(i)     序号 HTML 片段（三处格式不同：1 / 空 / #1）
  //   label(r)    主字段 HTML 片段（调用方负责转义或保证纯数值拼接，见各处 R-12 注）
  // barPct(r)   百分比条宽度数值（0-100，max 基准由调用方闭包确定；省略则不渲染条段）
  //   barColor    百分比条内联背景（可选；缺省走 CSS 默认色）
  //   hits(r)     命中数文本
  //   title(r)    li.title（可选）
  //   onRowClick(r) li 点击回调（可选）
  //   trailing(r) 行尾追加节点工厂（可选，如复制按钮）
  function renderMiniList(ulId, items, opts) {
    var ul = document.getElementById(ulId);
    if (!ul) return;
    if (!items || !items.length) {
      var et = opts.emptyText;
      ul.innerHTML = '<li style="color:var(--text-dim);cursor:default;">' +
        (typeof et === 'function' ? et() : (et || '暂无数据')) + '</li>';
      return;
    }
    ul.innerHTML = '';
    items.forEach(function (r, i) {
      var li = document.createElement('li');
      if (opts.title) { li.title = opts.title(r); }
      if (opts.onRowClick) { li.addEventListener('click', function () { opts.onRowClick(r); }); }
      // barPct 省略时跳过百分比条段（P3-1 封禁名单榜无数量维度）
      li.innerHTML = '<span class="rank">' + opts.rank(i) + '</span>' +
        opts.label(r) +
        (opts.barPct
          ? '<span class="bar-wrap"><span class="bar" style="width:' + opts.barPct(r) + '%' +
            (opts.barColor ? ';background:' + opts.barColor : '') + '"></span></span>'
          : '') +
        '<span class="hits">' + opts.hits(r) + '</span>';
      if (opts.trailing) { li.appendChild(opts.trailing(r)); }
      ul.appendChild(li);
    });
  }
  // 地图卡内攻击源列表（SSH 失败口径 TOP10，联动国家/阈值筛选；点击复制 IP）
  function renderGeoSources() {
    if (!vis('attack')) { return; }
    var rows = state.geo.rows;
    if (!rows) {
      var ul0 = document.getElementById('geo-sources-list');
      if (ul0) { ul0.innerHTML = '<li style="color:var(--text-dim);cursor:default;">加载中…</li>'; }
      return;
    }
    var list = rows.filter(function (r) {
      if (state.geo.country && r.country_code !== state.geo.country) { return false; }
      if (state.geo.min > 0 && r.count < state.geo.min) { return false; }
      return true;
    });
    var top = list.slice(0, 10);
    var max = top.length ? (top[0].count || 1) : 1;
    renderMiniList('geo-sources-list', top, {
      // 空态双文案：有数据但被筛选清空 vs 无数据
      emptyText: function () { return rows.length ? '当前筛选无匹配来源 IP（清除筛选查看全部）' : '暂无 SSH 失败来源'; },
      rank: function (i) { return '#' + (i + 1); },
      label: function (r) {
        // T1：IP 文本 ip-prof 点击打开画像（data-ip 与文本均 escapeHtml 转义）
        return '<span class="src-ip ip-prof" data-ip="' + escapeHtml(r.ip) + '" title="点击查看 IP 画像">' + escapeHtml(r.ip) + '</span>' +
          '<span class="port" style="width:auto;color:var(--text-dim);">' +
          escapeHtml(r.country_name === 'Unknown' ? '未知' : r.country_name) + '</span>';
      },
      barPct: function (r) { return Math.round(r.count / max * 100); },
      barColor: 'var(--accent)',
      hits: function (r) { return r.count; },
      title: function (r) { return r.ip + '（' + r.country_name + '）累计 ' + r.count + ' 次'; },
      trailing: function (r) { return makeCopyBtn(r.ip); }
    });
  }
  // P3-1：当前封禁名单榜（fail2ban 实时快照，60s 服务端刷新；点击行复制 IP——
  // 与 geo 榜交互一致）。数据与时间范围无关（当前在封集合），不随 range 清空。
  function renderBansActive() {
    if (!vis('attack')) { return; }
    var rows = state.attack.bans;
    if (!rows) {
      var ul0 = document.getElementById('bans-active-mini');
      if (ul0) { ul0.innerHTML = '<li style="color:var(--text-dim);cursor:default;">加载中…</li>'; }
      return;
    }
    renderMiniList('bans-active-mini', rows.slice(0, 50), {
      emptyText: '当前无封禁 IP（fail2ban 未启用或无在封记录）',
      rank: function (i) { return '#' + (i + 1); },
      label: function (r) {
        // T1：IP 文本 ip-prof 点击打开画像（escapeHtml 转义 data-ip 属性值）
        return '<span class="src-ip ip-prof" data-ip="' + escapeHtml(r) + '" title="点击查看 IP 画像">' + escapeHtml(r) + '</span>';
      },
      hits: function () { return ''; },
      title: function (r) { return r + '（点击查看画像，按钮复制）'; },
      trailing: function (r) { return makeCopyBtn(r); }
    });
  }
  // 复制按钮工厂（T3：geo 攻击源列表与 TOP 攻击源迷你榜共用，原两份重复实现收敛单点）。
  // text 待复制文本；failText 复制失败文案（迷你榜历史文案为"失败"与 geo 的"复制失败"不同，参数保留差异）。
  function makeCopyBtn(text, failText) {
    var btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.textContent = '复制';
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      function done(ok) {
        btn.textContent = ok ? '已复制' : (failText || '复制失败');
        btn.classList.toggle('copied', ok);
        setTimeout(function () { btn.textContent = '复制'; btn.classList.remove('copied'); }, 1500);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      } else { done(false); }
    });
    return btn;
  }
  // a.click() 下载触发段统一（T3：geoExport/honeyCredExport/doExport 三处共用；
  // blob 场景由调用方在触发后自行 revokeObjectURL）
  function triggerDownload(href, filename) {
    var a = document.createElement('a');
    a.href = href;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
  // 地图 CSV 导出（携带当前 range/country/min_count 筛选）
  function geoExport() {
    var q = 'range=' + state.range;
    if (state.geo.country) { q += '&country=' + encodeURIComponent(state.geo.country); }
    if (state.geo.min > 0) { q += '&min_count=' + state.geo.min; }
    triggerDownload('/api/v1/export/attacks_csv?' + q, 'sentry_attacks_geo_' + state.range + '.csv');
  }


  // ===== 模块 4：非表格渲染（KPI / 态势 / TOP / 事件流） =====
  // count-up（DEV-047 C1：600ms rAF 一次性滚动；5s 轮询下动画不重叠；
  // 系统开启"减弱动效"时直接落值；负数/千分位格式由调用侧既有格式逻辑保持）
  function countUp(el, to, dec) {
    if (!el) return;
    var cur = parseFloat(el.dataset.cur);
    if (isNaN(cur)) { cur = 0; }
    if (cur === to || (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches)) {
      el.textContent = dec ? to.toFixed(dec) : String(to); el.dataset.cur = to; return;
    }
    var t0 = null, dur = 600;
    function step(ts) {
      if (!t0) { t0 = ts; }
      var p = Math.min((ts - t0) / dur, 1);
      var v = cur + (to - cur) * p;
      el.textContent = dec ? v.toFixed(dec) : String(Math.round(v));
      if (p < 1) { requestAnimationFrame(step); } else { el.dataset.cur = to; }
    }
    requestAnimationFrame(step);
  }
  // 迷你 sparkline（内联 SVG polyline，零 ECharts 实例开销；降采样 ≤32 点）
  function sparkSVG(el, values, color) {
    if (!el) return;
    if (!values || values.length === 0) {
      el.innerHTML = '<svg viewBox="0 0 160 26" preserveAspectRatio="none">' +
        '<line x1="2" y1="13" x2="158" y2="13" stroke="' + color + '" stroke-width="1" opacity="0.16"/></svg>';
      return;
    }
    if (values.length === 1) {
      el.innerHTML = '<svg viewBox="0 0 160 26" preserveAspectRatio="none">' +
        '<circle cx="80" cy="13" r="1.8" fill="' + color + '" opacity="0.7"/></svg>';
      return;
    }
    var W = 160, H = 26, PAD = 2;
    var step = Math.max(1, Math.floor(values.length / 32));
    var pts = [];
    for (var i = 0; i < values.length; i += step) { pts.push(values[i]); }
    var min = Math.min.apply(null, pts), max = Math.max.apply(null, pts);
    var span = (max - min) || 1;
    var x = function (i) { return PAD + (W - PAD * 2) * i / (pts.length - 1); };
    var y = function (v) { return PAD + (H - PAD * 2) * (1 - (v - min) / span); };
    var d = pts.map(function (v, i) { return (i ? 'L' : 'M') + x(i).toFixed(1) + ',' + y(v).toFixed(1); }).join(' ');
    var area = 'M' + x(0).toFixed(1) + ',' + H + ' ' + pts.map(function (v, i) { return 'L' + x(i).toFixed(1) + ',' + y(v).toFixed(1); }).join(' ') + ' L' + x(pts.length - 1).toFixed(1) + ',' + H + ' Z';
    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' +
      '<path d="' + area + '" fill="' + color + '" opacity="0.18"/>' +
      '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="1.5"/></svg>';
  }
  // 环比箭头：窗口内前/后半段对比（后端无上一窗口偏移参数，等效近似）
  function trendArrow(arr) {
    if (!arr || arr.length < 4) { return { cls: 'flat', text: '' }; }
    var half = Math.floor(arr.length / 2), a = 0, b = 0;
    for (var i = 0; i < half; i++) { a += arr[i]; }
    for (var i = half; i < arr.length; i++) { b += arr[i]; }
    if (a === 0 && b === 0) { return { cls: 'flat', text: '—' }; }
    if (a === 0 && b > 0) { return { cls: 'up', text: '↑ 新增' }; } // R-07：避免 ↑1000% 式夸张百分比
    var pct = Math.round((b - a) / a * 100);
    if (pct > 0) { return { cls: 'up', text: '↑' + pct + '%' }; }
    if (pct < 0) { return { cls: 'down', text: '↓' + Math.abs(pct) + '%' }; }
    return { cls: 'flat', text: '→ 0%' };
  }

  // 态势结论条（可折叠；数据：summary + fwTimeline）。
  // DEV-045 口径：入站探测数 = fwTimeline inbound 累计（扫描器流量展示）；
  // 拦截数 = drop + reject 累计（实际威胁动作）。与攻击趋势图/TOP 端口一致。
  // 态势条不显示源数（top_sources 无 action 过滤 + LIMIT 10 封顶，避免虚假精确，D-23）。
  function renderSituation() {
    var bar = document.getElementById('situation-bar');
    var txt = document.getElementById('situation-text');
    if (!bar || !txt) { return; }
    var s = state.summary, fwT = state.fwTimeline;
    // 任一攻击数据源请求失败 → 显示错误态而非"计算中"/"正常"（含 sshTimelineOk 独立跟踪 + summaryFailed）
    if (state.attackDataFailed || !state.sshTimelineOk || state.summaryFailed) {
      txt.textContent = '态势数据加载失败，请稍后重试';
      bar.className = 'warn';
    } else if (!s || !fwT) {
      txt.textContent = '态势计算中…';
      bar.className = 'warn';
    } else {
      var fwInbound = 0, fwBlocked = 0;
      fwT.forEach(function (b) { fwInbound += b.inbound || 0; fwBlocked += (b.drop || 0) + (b.reject || 0); });
      var sshFail = s.ssh_fail || 0;
      var attacking = (fwInbound > 0) || (sshFail > 0);
      if (attacking) {
        var topPort = (s.top_ports && s.top_ports[0]) ? ':' + Number(s.top_ports[0].dst_port) : '-';
        txt.innerHTML = '共 <span class="sit-num">' + Number(fwInbound) + '</span> 次入站探测（拦截 <span class="sit-num">' + Number(fwBlocked) +
          '</span> 次）、<span class="sit-num">' + Number(sshFail) +
          '</span> 次 SSH 失败，TOP 被攻击端口 <span class="sit-num">' + topPort + '</span>';
        bar.className = 'warn';
      } else {
        txt.textContent = '✓ 当前态势正常（所选范围无攻击事件）';
        bar.className = 'ok';
      }
    }
    if (state.sitCollapsed) { bar.classList.add('collapsed'); } else { bar.classList.remove('collapsed'); }
  }

  // KPI 卡（语义色 + 环比 + sparkline + count-up）
  // DEV-FE-003 7.2：骨架加载（summary 未到，一次性 shimmer）+ 失败分支（summaryFailed → -- + 失败色，R2-02 遗留）
  function setKpiSkeleton(on) {
    document.querySelectorAll('.kpi-row .kpi').forEach(function (k) { k.classList.toggle('kpi-skeleton', on); });
  }
  function renderKPI() {
    if (!vis('overview')) { return; } // 隐藏面板不渲染
    var s = state.summary;
    if (state.summaryFailed) {
      // 失败分支：主值 -- + 失败色，spark/trend 清空为基线（不保留旧值误导）；active-conns 走 WS 实时通道不动
      setKpiSkeleton(false);
      ['today-fw', 'today-sshfail', 'disk-pct', 'risk-score'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) { el.className = 'v danger'; el.textContent = '--'; }
      });
      sparkSVG(document.getElementById('spark-fw'), [], TI.danger);
      sparkSVG(document.getElementById('spark-ssh'), [], TI.warn);
      sparkSVG(document.getElementById('spark-disk'), [], TI.chart[1]);
      ['trend-fw', 'trend-ssh', 'trend-disk'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) { el.className = 'trend flat'; el.textContent = ''; }
      });
      return;
    }
    if (!s) { setKpiSkeleton(true); return; } // 骨架加载（首次/切 range 后 summary 未到）
    setKpiSkeleton(false);
    // 活跃连接（WS 实时通道更新；WS 断开降级时轮询写入）
    var ac = document.getElementById('active-conns');
    if (ac && (ac.textContent === '-' || !state.wsMode)) { ac.textContent = s.active_conns; }
    var fwEl = document.getElementById('today-fw');
    if (fwEl) { fwEl.className = 'v warn'; countUp(fwEl, s.fw_events || 0); }
    var sshEl = document.getElementById('today-sshfail');
    if (sshEl) { sshEl.className = 'v ' + ((s.ssh_fail || 0) > 0 ? 'danger' : 'ok'); countUp(sshEl, s.ssh_fail || 0); }
    // 磁盘：带 % 且 WS resource 帧也在更新，直接赋值不 count-up（避免动画与实时通道打架）
    var diskEl = document.getElementById('disk-pct');
    var dp = s.disk_percent;
    if (diskEl) {
      diskEl.className = 'v ' + (dp >= 80 ? 'danger' : (dp >= 60 ? 'warn' : 'ok'));
      if (dp >= 0) { diskEl.textContent = dp.toFixed(1) + '%'; }
    }
    // DEV-047 D2：风险评分 KPI（与 gauge 同口径 riskParts）。攻击数据源失败时显示 --（不保留旧值误导）
    var riskEl = document.getElementById('risk-score');
    var riskFail = state.attackDataFailed || !state.sshTimelineOk || state.summaryFailed;
    if (riskFail) {
      if (riskEl) { riskEl.className = 'v danger'; riskEl.textContent = '--'; }
    } else {
      if (riskEl) {
        var rp = riskParts();
        if (rp) {
          riskEl.className = 'v ' + (rp.score >= 60 ? 'danger' : (rp.score >= 30 ? 'warn' : 'ok'));
          countUp(riskEl, rp.score);
        }
      }
    }
    // SSH 卡 spark/trend（复用 ssh/timeline 序列）
    var sshArr = (state.attack.ssh || []).map(function (p) { return p.hits; });
    sparkSVG(document.getElementById('spark-ssh'), sshArr, TI.warn);
    var ts = trendArrow(sshArr);
    var el = document.getElementById('trend-ssh');
    if (el) { el.className = 'trend ' + ts.cls; el.textContent = ts.text; }
    // FW 卡 spark/trend（复用 firewall/timeline inbound 序列——DEV-045：主通道为入站探测）
    var fwArr = (state.fwTimeline || []).map(function (b) { return b.inbound || 0; });
    sparkSVG(document.getElementById('spark-fw'), fwArr, TI.danger);
    var tf = trendArrow(fwArr);
    el = document.getElementById('trend-fw');
    if (el) { el.className = 'trend ' + tf.cls; el.textContent = tf.text; }
    // 磁盘卡 spark/trend（固定 24h 序列，首轮加载，见 pollOverview sparkLoaded 段）
    if (state.disk24) {
      sparkSVG(document.getElementById('spark-disk'), state.disk24, TI.chart[1]);
      var td = trendArrow(state.disk24);
      el = document.getElementById('trend-disk');
      if (el) { el.className = 'trend ' + td.cls; el.textContent = td.text; }
    }
  }

  // 总览被攻击端口 TOP5 迷你榜（复用 summary.top_ports，零额外请求）
  function renderMiniTop(ports) {
    if (!vis('overview')) { return; }
    var max = ports && ports.length ? (ports[0].hits || 1) : 1;
    renderMiniList('top-ports-mini', ports, {
      emptyText: '暂无被攻击端口数据',
      rank: function (i) { return i + 1; },
      // R-12 注：mini-top 用 innerHTML 拼接数值字段（dst_port/hits 为后端 int64 数字，
      // ip() 位运算输出纯数字串），无注入面；若未来字段类型字符串化须改 textContent 分段构建
      label: function (p) { return '<span class="port">:' + p.dst_port + '</span>'; },
      barPct: function (p) { return Math.round(p.hits / max * 100); },
      hits: function (p) { return p.hits; },
      title: function () { return '点击跳转攻击页过滤该端口'; },
      onRowClick: function (p) {
        switchPanel('attack');
        applyFilter({ type: 'port', value: p.dst_port }, '总览');
      }
    });
  }

  // TOP 攻击源迷你榜（横向条 + 复制 IP，clipboard API）
  function renderTopSourcesMini() {
    if (!vis('overview')) { return; }
    var srcs = state.attack.sources || [];
    var max = srcs.length ? (srcs[0].hits || 1) : 1;
    renderMiniList('top-sources-mini', srcs, {
      emptyText: '暂无攻击源',
      rank: function () { return ''; },
      // T1：IP 文本 ip-prof 点击打开画像（ip() 输出仅含 [0-9.]，无注入面，R-12 同口径）
      label: function (s2) {
        var s3 = ip(s2.src_ip);
        return '<span class="src-ip ip-prof" data-ip="' + s3 + '" title="点击查看 IP 画像">' + s3 + '</span>';
      },
      barPct: function (s2) { return Math.round(s2.hits / max * 100); },
      barColor: 'var(--warn)',
      hits: function (s2) { return s2.hits; },
      trailing: function (s2) { return makeCopyBtn(ip(s2.src_ip), '失败'); }
    });
  }

  // 事件摘要流（两类混排，10 分钟窗口分组，最新 20 条；WS 新条目高亮淡入）。
  // DEV-FE-002：默认折叠 3 条 + 展开全部；条目点击跳转攻击页对应表。
  // DEV-FE-003 PF-3：行级更新——按 key 复用行元素（box.__diff 缓存），无变化行零 DOM 写入
  var streamKeys = {};        // 上轮 key 集合（对比出新增条目）
  var streamRendered = false; // 首轮渲染不判新（避免首屏全部闪烁）
  var suppressStreamNew = false; // R-03：展开/收起动作抑制本轮新条目高亮（避免折叠行展开时误报事件突增）
  function renderEventStream() {
    if (!vis('overview')) { return; } // 隐藏面板不渲染（streamKeys 下轮随数据自然收敛）
    var box = document.getElementById('event-stream');
    if (!box) { return; }
    var items = [];
    (state.tables['ssh-table'].rows || []).forEach(function (r) {
      if (r.result === 0) {
        var u = escapeHtml(r.username), ipStr = ip(r.src_ip);
        items.push({ ts: r.ts, type: 'ssh', srcIp: r.src_ip,
          text: 'SSH 失败 <b>' + u + '</b> @ <b>' + ipStr + '</b>', plain: 'SSH 失败 ' + r.username + ' @ ' + ipStr });
      }
    });
    (state.tables['fw-table'].rows || []).forEach(function (r) {
      // DEV-045：事件流仅展示拦截类动作（reject/drop）——inbound 扫描探测量级占 98%+，
      // 且趋势图/KPI/FW 表格已承载展示，避免刷屏挤出 SSH 失败等高信号事件
      if (r.action === 'reject' || r.action === 'drop') {
        var a = r.action, sIp = ip(r.src_ip);
        var label = a === 'reject' ? '拦截' : '丢弃';
        items.push({ ts: r.ts, type: 'fw', srcIp: r.src_ip,
          text: '外部威胁 ' + label + ' <b>' + sIp + '</b> → :<b>' + r.dst_port + '</b>',
          plain: '外部威胁 ' + label + ' ' + sIp + ' → :' + r.dst_port });
      }
    });
    items.sort(function (a, b) { return b.ts - a.ts; });
    items = items.slice(0, 20);
    // 折叠头实时显示最近 1 条摘要（保留"活动感"且不占高度）
    var sumEl = document.getElementById('event-fold-summary');
    if (sumEl) { sumEl.textContent = items.length ? '最近：' + items[0].plain : ''; }
    // 空态（"暂无事件"；清空 diff 缓存）
    if (!items.length) {
      box.innerHTML = '<div class="ev-empty">暂无事件</div>';
      box.__diff = null;
      streamKeys = {};
      streamRendered = true;
      var btn0 = document.getElementById('event-expand-btn');
      if (btn0) { btn0.style.display = 'none'; }
      return;
    }
    var shown = state.eventExpanded ? items : items.slice(0, 3);
    // 分组：10 分钟窗口（ts - ts%600）
    var groups = [];
    shown.forEach(function (it) {
      var wk = it.ts - (it.ts % 600);
      var g = groups[groups.length - 1];
      if (!g || g.key !== wk) { g = { key: wk, list: [] }; groups.push(g); }
      g.list.push(it);
    });
    // 扁平化行列表（分组标题 + 条目），行级 diff 渲染
    var rows = [], seq = {};
    groups.forEach(function (g) {
      rows.push({ kind: 'title', key: 'g:' + g.key, text: fmtTimeFull(g.key) });
      g.list.forEach(function (it) {
        var base = it.type + ':' + it.ts;
        seq[base] = (seq[base] || 0) + 1;
        rows.push({ kind: 'item', key: base + ':' + seq[base], it: it });
      });
    });
    var cache = box.__diff || (box.__diff = { map: {} });
    var map = cache.map, seen = {}, newKeys = {};
    // 清理孤儿元素（空态"暂无事件"等非 diff 管理节点，box.__diff 清空后残留）
    for (var i = box.children.length - 1; i >= 0; i--) {
      var orphan = box.children[i];
      if (!orphan.__key || !map[orphan.__key]) { box.removeChild(orphan); }
    }
    rows.forEach(function (row) {
      var el = map[row.key];
      if (!el) {
        if (row.kind === 'title') {
          el = document.createElement('div');
          el.className = 'ev-group-title';
        } else {
          el = document.createElement('div');
          el.className = 'ev-item';
          el.title = '点击跳转攻击页查看明细';
          el.innerHTML = '<span class="ev-bar"></span><span class="ev-dot"></span><span class="ev-time"></span><span class="ev-text"></span>';
          // 点击：跳转攻击页对应表（SSH/fw 预置源 IP 过滤）
          el.addEventListener('click', function () {
            var it = el.__row;
            applyFilter({ type: 'src', value: it.srcIp }, '总览'); switchPanel('attack');
          });
          if (streamRendered && !streamKeys[row.key] && !suppressStreamNew) {
            el.classList.add('stream-new'); // 新条目高亮淡入 600ms
            // R2-04：动画结束后移除标记类（状态自净，防维护期误触发）
            el.addEventListener('animationend', function () { el.classList.remove('stream-new'); }, { once: true });
          }
        }
        el.__key = row.key; // diff 归属标记（孤儿清理识别）
        map[row.key] = el;
        box.appendChild(el);
      }
      el.__row = row.it || row;
      if (row.kind === 'title') {
        if (el.__t !== row.text) { el.textContent = row.text; el.__t = row.text; }
      } else {
        var it = row.it;
        var ch = el.children;
        ch[0].className = 'ev-bar ' + it.type;
        ch[1].className = 'ev-dot ' + it.type;
        var tstr = fmtTime(it.ts);
        if (ch[2].__t !== tstr) { ch[2].textContent = tstr; ch[2].__t = tstr; }
        if (ch[3].__h !== it.text) { ch[3].innerHTML = it.text; ch[3].__h = it.text; } // it.text 已含 escapeHtml 拼接
      }
      seen[row.key] = true;
      newKeys[row.key] = true;
      box.appendChild(el); // 按序重排
    });
    Object.keys(map).forEach(function (k) {
      if (!seen[k]) {
        var el = map[k];
        if (el.parentNode) { el.parentNode.removeChild(el); }
        delete map[k];
      }
    });
    streamKeys = newKeys;
    streamRendered = true;
    suppressStreamNew = false; // R-03：本轮抑制标记消费后复位
    // 展开/收起按钮（默认 3 条 → "展开全部（N 条）"；展开后 "收起"）
    var btn = document.getElementById('event-expand-btn');
    if (btn) {
      if (items.length > 3) {
        btn.style.display = 'block';
        btn.textContent = state.eventExpanded ? '收起' : '展开全部（' + items.length + ' 条）';
      } else {
        btn.style.display = 'none';
      }
    }
  }

  // ===== 模块 5：表格行级 diff 渲染框架（PF-3，方案 7.4/8.2） =====
  // 机制：首轮建行（tb.__diff.map 缓存 key→tr）+ 后续轮按行 key 复用 tr、仅更新变化的
  // 文本节点（__text/__html 快照比较，变化才写 DOM）+ 按序 appendChild 重排 + 消失行删除。
  // 排序/过滤/联动逻辑完全不变，仅替换"每轮 tbody.innerHTML 全量重建"机制（方案 9.2 第 4 条铁律）。
  // mk(row) → { key, cls, title, click, cells: [{ text（纯文本，textContent 写入自动防 XSS）
  //             | html（仅受控拼接，须已 escapeHtml）, cls, title, click }] }
  // 事件绑定：tr/cell 的 click 首轮绑定一次，handler 通过 tr.__row 读取最新数据（避免闭包过期）。
  // 行 key 约定：各表 render 函数先按"内容组合 + 同键序号"计算 __k（内容变化驱动；
  // R-06 注：排序键不在内容组合内时（如 conn 按 packets 排），同内容多行在排序切换后序号重排
  // 导致少量行重建——纯性能影响，功能正确）。
  function renderTableDiff(tb, rows, mk) {
    var cache = tb.__diff || (tb.__diff = { map: {} });
    var map = cache.map, seen = {};
    // 清理非 diff 管理行（三态占位行残留：setTableState 写入 innerHTML 并清 __diff 后，
    // 占位行不在 map 中，须在下次建行前移除，否则与数据行共存）
    for (var i = tb.children.length - 1; i >= 0; i--) {
      var orphan = tb.children[i];
      if (!orphan.__key || !map[orphan.__key]) { tb.removeChild(orphan); }
    }
    rows.forEach(function (row) {
      var d = mk(row);
      var tr = map[d.key];
      if (!tr) {
        tr = document.createElement('tr');
        map[d.key] = tr;
        tr.__key = d.key; // diff 归属标记（供孤儿行清理识别）
        d.cells.forEach(function (cell) {
          var td = document.createElement('td');
          tr.appendChild(td);
          if (cell.click) {
            td.addEventListener('click', function (ev) {
              ev.stopPropagation();
              cell.click(tr.__row, ev);
            });
          }
        });
        if (d.click) {
          tr.addEventListener('click', function () { d.click(tr.__row); });
        }
        tb.appendChild(tr);
      }
      tr.__row = row;
      // 行级属性（cls 重算含 row-danger/row-warn/row-highlight/row-clickable 等）
      var cls = d.cls || '';
      if (tr.__cls !== cls) { tr.className = cls; tr.__cls = cls; }
      var title = d.title || '';
      if (tr.__title !== title) { tr.title = title; tr.__title = title; }
      // 单元格更新：比较快照，仅变化时写入（R-11：text/html 快照互斥——切换写入方式时清另一快照，
      // 避免残留旧快照导致后续轮跳过写入）
      var tds = tr.children;
      d.cells.forEach(function (cell, j) {
        var td = tds[j];
        if (!td) { return; }
        if (cell.html !== undefined) {
          if (td.__html !== cell.html) { td.innerHTML = cell.html; td.__html = cell.html; }
          td.__text = undefined;
        } else if (cell.text !== undefined) {
          if (td.__text !== cell.text) { td.textContent = cell.text; td.__text = cell.text; }
          td.__html = undefined;
        }
        var ccls = cell.cls || '';
        if (td.__cls !== ccls) { td.className = ccls; td.__cls = ccls; }
        var ctitle = cell.title || '';
        if (td.__title !== ctitle) { td.title = ctitle; td.__title = ctitle; }
      });
      seen[d.key] = true;
      tb.appendChild(tr); // 按当前顺序重排（已存在则移动节点）
    });
    // 删除本轮消失的行
    Object.keys(map).forEach(function (k) {
      if (!seen[k]) {
        var tr = map[k];
        if (tr.parentNode) { tr.parentNode.removeChild(tr); }
        delete map[k];
      }
    });
  }
  // 表格渲染公共脚手架（T1：6 个 render 的 15-20 行前奏收敛单点）。
  // 流程：可见性门控 → tbody 存在 → 三态（loading/empty，处理后返回 null，调用方直接 return）
  // → opts.onRows 顺序敏感回调（蜜罐两表的小计更新依赖原始 rows 长度，须在排序分页前执行）
  // → 排序 → 滚动分页 → 行键去重（D-B 审计缺陷修复逻辑单点保留：内容组合 + 同键序号
  // 保证 __k 行级唯一，排序键不在内容组合时同内容行切换排序会重建——纯性能影响，功能正确）。
  // opts：visKey 可见面板；emptyText 空态文案；keyBase(r) 行键内容组合（各表不同）；
  //       keyPrefix 行键前缀（hpd 用 'd-' 与明细表 hp-table 键空间隔离）；onRows(rows) 回调。
  // 返回 null（三态已处理）或就绪行数组（已排序、已分页、已打 __k）。
  function prepTable(id, rows, opts) {
    if (!vis(opts.visKey)) { return null; }
    if (!tbody(id)) { return null; }
    if (!rows) { setTableState(id, 'loading-row', '加载中…'); return null; }
    if (!rows.length) { setTableState(id, 'empty-row', opts.emptyText); return null; }
    if (opts.onRows) { opts.onRows(rows); }
    var s = state.tables[id].sort;
    var out = sortRows(rows, s && s.key, s && s.dir);
    out = out.slice(0, state.tables[id].page || TABLE_PAGE);
    var seen = {};
    out.forEach(function (r) {
      var base = opts.keyBase(r);
      seen[base] = (seen[base] || 0) + 1;
      r.__k = (opts.keyPrefix || '') + base + '#' + seen[base];
    });
    return out;
  }
  // 密码遮蔽单元格工厂（T1：hp-table 明细表与 hpd-table 字典表逐字重复段收敛单点）。
  // 遮蔽态由 state.hp.revealed[行唯一键 __k] 决定，点击切换单行（D-B audit Major 修复：
  // 原 ts|proto|src|user 键粒度太粗会整组揭示，行级键仅切换单行）；rerender 为各自表重渲染入口。
  function maskedPwCell(row, rerender) {
    var masked = !state.hp.revealed[row.__k];
    return {
      text: masked ? '••••（点击显示）' : (row.password || '(空)'),
      cls: (masked ? 'hp-pw masked ' : 'hp-pw ') + 'clickable',
      title: masked ? '点击显示密码（本地敏感数据）' : '点击遮蔽',
      click: function (r2) {
        var rk = r2.__k;
        state.hp.revealed[rk] = !state.hp.revealed[rk];
        rerender();
      }
    };
  }
  // 各表渲染入口：三态 → 排序 → 分页 → 计算行 key → 行级 diff
  function renderSSH() {
    if (isFolded('ssh-table')) { return; } // 折叠态跳过表体渲染（rows 缓存照常更新，事件流不受影响）
    var rows = prepTable('ssh-table', state.tables['ssh-table'].rows, {
      visKey: 'attack', emptyText: '暂无 SSH 登录尝试',
      keyBase: function (r) { return r.ts + '|' + r.src_ip + '|' + r.result + '|' + r.username + '|' + r.auth_method; }
    });
    if (!rows) { return; }
    renderTableDiff(tbody('ssh-table'), rows, function (r) {
      return {
        key: r.__k,
        cls: (r.result === 0 ? 'row-danger ' : '') + 'row-clickable',
        title: '点击过滤该源 IP',
        click: function (row) { applyFilter({ type: 'src', value: row.src_ip }, '攻击页'); },
        cells: [
          { text: fmtTimeFull(r.ts), cls: 'ts-cell' },
          // T1：源 IP 点击打开画像（renderTableDiff cell.click 自带 stopPropagation），行点击过滤不受影响
          { text: ip(r.src_ip), cls: 'num ip-prof', title: '点击查看 IP 画像',
            click: function (row) { openIpProfile(ip(row.src_ip)); } },
          { text: r.username }, { text: r.auth_method },
          { text: r.result === 1 ? '成功' : '失败' },
          { text: r.fingerprint }, { text: r.detail }
        ]
      };
    });
  }
  function renderFW() {
    if (isFolded('fw-table')) { return; } // 折叠态跳过表体渲染（rows 缓存照常更新，事件流不受影响）
    var rows = prepTable('fw-table', state.tables['fw-table'].rows, {
      visKey: 'attack', emptyText: '暂无外部威胁事件',
      keyBase: function (r) { return r.ts + '|' + r.src_ip + '|' + r.dst_port + '|' + r.action + '|' + (r.raw || '').slice(0, 16); }
    });
    if (!rows) { return; }
    renderTableDiff(tbody('fw-table'), rows, function (r) {
      // 源 IP 单元格与目的端口单元格独立点击（stopPropagation 由框架保证）；行点击过滤源 IP
      return {
        key: r.__k,
        cls: ((r.action === 'drop' || r.action === 'reject') ? 'row-danger ' : '') + 'row-clickable',
        title: '点击过滤该源 IP',
        click: function (row) { applyFilter({ type: 'src', value: row.src_ip }, '攻击页'); },
        cells: [
          { text: fmtTimeFull(r.ts), cls: 'ts-cell' },
          { text: r.action },
          { text: r.chain },
          { text: r.proto, cls: 'num' },
          // T1：源 IP 点击改为打开画像（原独立点击过滤由行点击保留）
          { text: ip(r.src_ip) + ':' + r.src_port, cls: 'num ip-prof', title: '点击查看 IP 画像（行点击过滤该源 IP）',
            click: function (row) { openIpProfile(ip(row.src_ip)); } },
          { text: ip(r.dst_ip) + ':' + r.dst_port, cls: 'num clickable dst-cell', title: '点击过滤该目的端口',
            click: function (row) { applyFilter({ type: 'port', value: row.dst_port }, '攻击页'); } },
          { text: (r.raw || '').slice(0, 60), cls: 'raw-cell', title: r.raw }
        ]
      };
    });
  }
  // 封禁记录表已随 DEV-GEO-001 移除（renderBans/gotoBanIp 删除；后端 /api/v1/bans 保留不动）
  // DEV-HONEY-001：蜜罐凭据表渲染（三态 + 行级 diff + 密码遮蔽点击切换 + 捕获小计）。
  function renderHoneypot() {
    if (isFolded('hp-table')) { return; } // 折叠态跳过表体渲染（fetch 已整体门控，此处兜底切页补渲染路径）
    var rows = prepTable('hp-table', state.tables['hp-table'].rows, {
      visKey: 'attack', emptyText: '暂无蜜罐捕获记录',
      keyBase: function (r) { return r.ts + '|' + r.proto + '|' + r.src_ip + '|' + r.username + '|' + (r.password || '').slice(0, 8); },
      // 捕获小计（原始 rows 口径，须在排序分页前执行——onRows 保证顺序）
      onRows: function (rows) {
        var totalEl = document.getElementById('hp-total');
        if (totalEl) { totalEl.textContent = '捕获 ' + rows.length + ' 条'; }
      }
    });
    if (!rows) { return; }
    renderTableDiff(tbody('hp-table'), rows, function (r) {
      return {
        key: r.__k,
        cells: [
          { text: fmtTimeFull(r.ts), cls: 'ts-cell' },
          { text: r.proto, cls: 'num' },
          // T1：源 IP（后端字符串）点击打开画像，textContent 渲染无注入面
          { text: r.src_ip, cls: 'num ip-prof', title: '点击查看 IP 画像',
            click: function (row) { openIpProfile(String(row.src_ip || '')); } },
          { text: r.username },
          maskedPwCell(r, renderHoneypot),
          { text: r.extra, cls: 'raw-cell', title: r.extra }
        ]
      };
    });
  }
  // DEV-HONEY-002：凭据字典聚合表渲染（去重聚合行 + 密码遮蔽点击切换 + 类型徽标）。
  // 行键 d- 前缀与明细表（hp-table）键空间隔离——共用 state.hp.revealed 集合但不互串。
  function renderHoneyCredDict() {
    var rows = prepTable('hpd-table', state.tables['hpd-table'].rows, {
      visKey: 'attack', emptyText: '暂无凭据字典（蜜罐未启用或未捕获）',
      keyPrefix: 'd-',
      // 行键用全量 password（功能审计 Minor-4：8 字符截断 + 聚合行重排会使已揭示
      // 标记落到相邻行；键仅在本地内存，无泄露面）
      keyBase: function (r) { return r.proto + '|' + r.username + '|' + (r.password || ''); },
      // 去重小计（原始 rows 口径，须在排序分页前执行——onRows 保证顺序）
      onRows: function (rows) {
        var totalEl = document.getElementById('hpd-total');
        if (totalEl) {
          var pl = 0;
          rows.forEach(function (r) { if (r.kind === 'plaintext') { pl++; } });
          totalEl.textContent = '去重 ' + rows.length + ' 组（明文 ' + pl + '）';
        }
      }
    });
    if (!rows) { return; }
    var kindText = { plaintext: '明文', hash: '摘要', none: '无认证' };
    var kindTitle = {
      plaintext: '明文捕获（可直接入爆破字典）',
      hash: '不可逆摘要（mysql SHA1 链 / smb NTLMv2 / mongodb SCRAM），无法还原明文',
      none: '协议无认证机制（rdp/memcached），无凭据可捕获'
    };
    renderTableDiff(tbody('hpd-table'), rows, function (r) {
      return {
        key: r.__k,
        cells: [
          { text: r.proto, cls: 'num' },
          { text: r.username || '(空)' },
          maskedPwCell(r, renderHoneyCredDict),
          { text: kindText[r.kind] || r.kind, cls: 'hpd-kind ' + (r.kind || ''),
            title: kindTitle[r.kind] || '' },
          { text: r.count, cls: 'num' },
          { text: fmtTimeFull(r.first_ts), cls: 'ts-cell' },
          { text: fmtTimeFull(r.last_ts), cls: 'ts-cell' },
          { text: r.src_ip_cnt, cls: 'num' }
        ]
      };
    });
  }
  function renderSnap() {
    var rows = prepTable('snap-table', state.tables['snap-table'].rows, {
      visKey: 'conn', emptyText: '暂无连接快照',
      keyBase: function (c) { return c.src_ip + '|' + c.src_port + '|' + c.dst_ip + '|' + c.dst_port + '|' + c.proto; }
    });
    if (!rows) { return; }
    renderTableDiff(tbody('snap-table'), rows, function (c) {
      return {
        key: c.__k, cls: '', title: '',
        cells: [
          { text: c.proto }, { text: c.state },
          { text: c.src_ip + ':' + c.src_port },
          { text: c.dst_ip + ':' + c.dst_port },
          { text: c.pid, cls: 'num' }
        ]
      };
    });
  }
  function renderConns() {
    if (isFolded('conn-table')) { return; } // 折叠态跳过表体渲染（fetch 已整体门控，此处兜底切页补渲染路径）
    var rows = prepTable('conn-table', state.tables['conn-table'].rows, {
      visKey: 'conn', emptyText: '暂无连接事件',
      keyBase: function (c) { return c.ts + '|' + c.src_ip + '|' + c.src_port + '|' + c.dst_port + '|' + c.ev_type; }
    });
    if (!rows) { return; }
    renderTableDiff(tbody('conn-table'), rows, function (c) {
      var type = ['', 'NEW', 'UPDATE', 'DESTROY'][c.ev_type] || c.ev_type;
      // IPv6 归源行（src_ip=0）：地址列显示 [IPv6]:port 且不提供画像入口
      // （0.0.0.0 占位不支持画像，功能审计 Minor-2）；行级"点击过滤该源 IP"保留
      // （filter 为数值 0，过滤 IPv6 归源行仍有效）。
      var srcCell = { text: connAddr(c.src_ip, c.src_port, c.src_ip6), cls: 'ip-prof', title: '点击查看 IP 画像',
        click: function (row) { openIpProfile(ip(row.src_ip)); } };
      if (!c.src_ip) {
        srcCell = { text: connAddr(c.src_ip, c.src_port, c.src_ip6), title: 'IPv6 归源连接（不支持 IP 画像）' };
      }
      return {
        key: c.__k,
        cls: (c.ev_type === 3 ? 'row-warn ' : '') + 'row-clickable',
        title: '点击过滤该源 IP',
        click: function (row) { applyFilter({ type: 'src', value: row.src_ip }, '连接页'); },
        cells: [
          { text: fmtTimeFull(c.ts), cls: 'ts-cell' },
          { text: type }, { text: c.proto },
          // T1：源 IP 点击打开画像
          srcCell,
          { text: connAddr(c.dst_ip, c.dst_port, c.dst_ip6) },
          { text: c.packets + '/' + c.bytes, cls: 'num' }
        ]
      };
    });
  }


  // ===== 模块 6：数据拉取（轮询与 WS 共用；range/filter 参数化） =====
  // R-02：检查 r.ok——HTTP 5xx 时走 errCb（错误态），避免误报"暂无数据"
  // RB-01/N-1：回调前校验请求序号——setRange/applyFilter 自增 state.reqSeq 后，
  // 旧 range/旧 filter 的在途响应（尤其 30d 聚合 30s 超时窗口）一律丢弃，杜绝混合口径覆盖新 state。
  // DEV-FE-003 7.2：所有 errCb 统一调 noteFailure()（全局错误横幅连续失败计数）；summary 成功清零恢复
  function fetchJSON(path, cb, errCb) {
    var seq = state.reqSeq;
    fetch(path).then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.json();
    }).then(function (d) {
      if (seq !== state.reqSeq) { return; } // 过期响应丢弃（RB-01）
      cb(d);
    }).catch(function () {
      if (seq !== state.reqSeq) { return; } // 过期失败同样丢弃
      if (errCb) { errCb(); }
    });
  }
  // DEV-FE-003 MA-1：connections 查询逻辑收敛（原 pollConns 与 applyFilter 双处重复，MA-01 修复）
  function fetchConns() {
    // 折叠门控（T-EXPORT）：conn-table 折叠时不拉取不渲染，展开切换时 toggleFold 强制补拉一次
    if (isFolded('conn-table')) { return; }
    // 预览量 100→50：明细数据走 /api/v1/export/table 离线导出，表格仅保留最近 50 条预览
    var connQS = '/api/v1/connections?limit=50&' + sinceQS();
    if (state.filter && state.filter.type === 'port') { connQS += '&dst_port=' + state.filter.value; }
    if (state.filter && state.filter.type === 'src') { connQS += '&src_ip=' + state.filter.value; }
    fetchJSON(connQS, function (d) {
      state.tables['conn-table'].rows = d.rows || [];
      renderConns();
    }, function () { noteFailure(); setTableState('conn-table', 'error-row', '加载失败，请稍后重试'); });
  }
  // 蜜罐凭据捕获明细（原 pollAttack 内联段提取；T-EXPORT：hp-table 折叠时不拉取，
  // 展开切换时 toggleFold 强制补拉；hpd 凭据字典聚合路不受折叠影响，仍在 pollAttack 内联）
  function fetchHpEvents() {
    if (isFolded('hp-table')) { return; }
    // 预览量 200→50（明细走导出）
    var hpQS = '/api/v1/honeypot/events?limit=50&' + rangeQS();
    if (state.hp.proto !== '') { hpQS += '&proto=' + state.hp.proto; }
    fetchJSON(hpQS, function (d) {
      state.tables['hp-table'].rows = d.rows || [];
      renderHoneypot();
    }, function () { noteFailure(); setTableState('hp-table', 'error-row', '加载失败，请稍后重试'); });
  }

  function pollOverview() {
    // 总览（跟随全局 range；KPI 由 renderKPI 统一渲染 count-up/语义色/骨架）
    // RB-02：summary 补 errCb——失败置 summaryFailed + 态势头失败态 + 全局错误横幅；
    // 成功恢复时清除标志并隐藏横幅（P1：noteSuccess 清零 failStreak）
    fetchJSON('/api/v1/summary?' + rangeQS(), function (d) {
      state.summary = d;
      state.summaryFailed = false;
      noteSuccess();
      touchFreshness();
      state.topPorts = d.top_ports || []; // 缓存供切回总览页补渲染
      // active-conns：WS 正常时由 conn_stats 帧 1s 更新；WS 断开降级时轮询写入
      var ac = document.getElementById('active-conns');
      if (ac && (ac.textContent === '-' || !state.wsMode)) { ac.textContent = d.active_conns; }
      renderMiniTop(state.topPorts);
      renderKPI();
      renderRisk();
      renderSituation();
    }, function () {
      state.summaryFailed = true;
      noteFailure();
      renderSituation();
      renderKPI(); // P1：KPI 失败分支（-- + 失败色）
    });
    // 资源：固定 1h 实时视图（7d/30d 点数超轻量上限，资源图属实时监控用途）
    fetchJSON('/api/v1/resources?range=1h&step=60s', function (d) {
      var labels = [], cpu = [], mem = [], disk = [], rx = [], tx = [];
      (d.points || []).forEach(function (p) {
        labels.push(fmtTime(p.ts));
        cpu.push(p.cpu == null ? 0 : +p.cpu.toFixed(1));
        mem.push(p.mem == null ? 0 : +p.mem.toFixed(1));
        disk.push(p.disk == null ? 0 : +p.disk.toFixed(1));
        rx.push(p.net_rx_bps || 0); tx.push(p.net_tx_bps || 0);
      });
      state.resourceData = { labels: labels, cpu: cpu, mem: mem, disk: disk, rx: rx, tx: tx }; // 缓存补渲染
      renderResource(state.resourceData);
    }, function () { noteFailure(); });
    // 磁盘卡 24h sparkline（固定 24h 口径，仅首轮请求一次；失败下轮重试）。
    // 注：resources?range=24h&step=60s 每 bucket 60 秒（后端聚合步长），spark 显示时由 sparkSVG 降采样 ≤32 点；
    if (!state.sparkLoaded) {
      fetchJSON('/api/v1/resources?range=24h&step=60s', function (d) {
        var seq = [];
        (d.points || []).forEach(function (p) { if (p.disk != null) { seq.push(+p.disk.toFixed(1)); } });
        state.disk24 = seq;
        state.sparkLoaded = true;
        renderKPI();
      }, function () { /* 失败：保持 sparkLoaded=false，下轮轮询重试 */ });
    }
    // 低频档（方案 7.4）：snapshot/connections 仅连接页激活时拉取
    if (state.activePanel === 'conn') { pollConns(); }
  }
  // 连接页专属拉取（snapshot 20s 采集源 + connections 事件流；connections 查询收敛至 fetchConns）
  function pollConns() {
    fetchJSON('/api/v1/snapshot', function (d) {
      state.tables['snap-table'].rows = d.rows || [];
      renderSnap();
    }, function () { noteFailure(); setTableState('snap-table', 'error-row', '加载失败，请稍后重试'); });
    fetchConns();
  }

  function pollAttack() {
    // 轮询开头重置失败标志（成功回调不覆盖——仅设置不覆盖，避免 fwTimeline 成功掩盖同轮其他源失败）
    state.attackDataFailed = false;
    fetchJSON('/api/v1/attacks/top_ports?top=10&' + rangeQS(), function (d) { state.attack.ports = d.rows || []; renderIf(); },
      function () { state.attack.ports = null; state.attackDataFailed = true; noteFailure(); renderSituation(); setChartEmpty('chart-ports', false); if (charts['chart-ports']) { charts['chart-ports'].clear(); } });
    fetchJSON('/api/v1/attacks/top_sources?top=10&' + rangeQS(), function (d) {
      state.attack.sources = d.rows || []; // Go 空切片序列化为 null，须兜底 []（renderTopSourcesMini 用）
      renderIf();
      renderTopSourcesMini();
      renderSituation();
    }, function () { state.attack.sources = null; state.attackDataFailed = true; noteFailure(); renderSituation(); renderRisk(); setChartEmpty('chart-sources', false); if (charts['chart-sources']) { charts['chart-sources'].clear(); } });
    fetchJSON('/api/v1/ssh/timeline?' + rangeQS(), function (d) {
      state.attack.ssh = d.rows || [];
      state.sshTimelineOk = true;
      renderIf();
      renderAttackTrend();
      renderKPI();
    }, function () { state.sshTimelineOk = false; state.attack.ssh = null; state.attackDataFailed = true; noteFailure(); renderAttackTrend(); renderSituation(); renderRisk(); setChartEmpty('chart-ssh', false); if (charts['chart-ssh']) { charts['chart-ssh'].clear(); } });
    // 防火墙小时聚合时间线（三通道图 + FW 卡 spark/trend + 风险评分/态势条数据源）。
    // 成功回调不重置 attackDataFailed（避免掩盖同轮其他源失败）；RB-01：range 回显叠加校验
    fetchJSON('/api/v1/firewall/timeline?' + rangeQS(), function (d) {
      if (d.range && d.range !== state.range) { return; } // 旧 range 在途响应丢弃（叠加校验）
      // DEV-045：桶映射保留 drop/accept 兼容字段，新增 reject/inbound（inbound 为入站探测主通道）
      state.fwTimeline = (d.buckets || []).map(function (b) {
        return { ts: b.ts, drop: b.drop || 0, accept: b.accept || 0, reject: b.reject || 0, inbound: b.inbound || 0 };
      });
      renderAttackTrend();
      renderKPI();
      renderRisk();
      renderSituation(); // 态势条 drop 口径依赖 fwTimeline，须在其就绪后重算
    }, function () { state.fwTimeline = null; state.attackDataFailed = true; noteFailure(); renderAttackTrend(); renderSituation(); renderRisk(); });
    // 全球攻击地图数据（DEV-GEO-001；SSH 失败按来源 IP 聚合，country/min 前端本地过滤。
    // 30d 视图随 pollAttack 降频自动降频；失败时地图置空态、列表置失败行）
    fetchJSON('/api/v1/attacks/geo?' + rangeQS(), function (d) {
      state.geo.rows = d.rows || [];
      state.geo.mmdbOk = !!d.mmdb_ok;
      renderGeo();
      renderGeoSources();
    }, function () {
      state.geo.rows = null;
      noteFailure();
      setChartEmpty('chart-world', false);
      var gl = document.getElementById('geo-sources-list');
      if (gl) { gl.innerHTML = '<li style="color:var(--danger);cursor:default;">地图数据加载失败</li>'; }
    });
    // P3-1：当前封禁名单（fail2ban 实时快照；与 range 无关故不带 rangeQS，不参与 attackDataFailed）
    fetchJSON('/api/v1/bans/active', function (d) {
      state.attack.bans = d.rows || [];
      renderBansActive();
      // T3：封禁变化告警——与上次快照对比，新增 IP → toast + 通知（首轮仅记基线）
      var rows = d.rows || [];
      if (lastBans !== null) {
        var prev = {};
        lastBans.forEach(function (r) { prev[r] = true; });
        var added = [];
        rows.forEach(function (r) { if (!prev[r]) { added.push(r); } });
        if (added.length) {
          var list = added.slice(0, 3).join('、') + (added.length > 3 ? ' 等 ' + added.length + ' 个' : '');
          showToast('新增封禁：' + list, 'warn');
          notify('sentry-agent', '新增封禁：' + list);
        }
      }
      lastBans = rows;
    }, function () {
      state.attack.bans = null;
      renderBansActive();
    });
    // SSH 尝试明细（跟随 range + src_ip 联动过滤；result=0 失败）。
    // T-EXPORT：轮询保留（总览事件流 renderEventStream 依赖 rows 混排，不能停拉），
    // limit 200→50；折叠时 renderSSH 内部跳过表体渲染
    var sshQS = '/api/v1/ssh?limit=50&' + rangeQS();
    if (state.filter && state.filter.type === 'src') { sshQS += '&src_ip=' + state.filter.value; }
    if (state.sshResult !== '') { sshQS += '&result=' + state.sshResult; }
    fetchJSON(sshQS, function (d) {
      state.tables['ssh-table'].rows = d.rows || [];
      renderSSH();
      renderEventStream();
    }, function () { noteFailure(); setTableState('ssh-table', 'error-row', '加载失败，请稍后重试'); });
    // 蜜罐凭据捕获（DEV-HONEY-001；已提取为 fetchHpEvents——hp-table 折叠时整体跳过不拉取）
    fetchHpEvents();
    // 凭据字典聚合（DEV-HONEY-002；与明细卡同一 range/proto 口径；失败置三态错误行）
    var hpdQS = '/api/v1/honeypot/creds?limit=500&' + rangeQS();
    if (state.hp.proto !== '') { hpdQS += '&proto=' + state.hp.proto; }
    fetchJSON(hpdQS, function (d) {
      state.tables['hpd-table'].rows = d.rows || [];
      renderHoneyCredDict();
      // T3：蜜罐新捕获告警——对比总 count（各项求和）与上次值，增长即 toast + 通知
      //（lastCredTotal 为 null 时为口径内首轮，仅记基线不告警）
      var total = 0;
      (d.rows || []).forEach(function (r) { total += (r.count || 0); });
      if (lastCredTotal !== null && total > lastCredTotal) {
        var msg = '蜜罐新捕获：+' + (total - lastCredTotal) + ' 条凭据尝试';
        showToast(msg, 'danger');
        notify('sentry-agent', msg);
      }
      lastCredTotal = total;
    }, function () { noteFailure(); setTableState('hpd-table', 'error-row', '加载失败，请稍后重试'); });
    // 防火墙明细（跟随 range + dst_port/src_ip 联动过滤 + action 下拉）。
    // T-EXPORT：轮询保留（事件流依赖 rows），limit 200→50；折叠时 renderFW 内部跳过表体渲染
    var fwQS = '/api/v1/firewall?limit=50&' + rangeQS();
    if (state.filter && state.filter.type === 'port') { fwQS += '&dst_port=' + state.filter.value; }
    if (state.filter && state.filter.type === 'src') { fwQS += '&src_ip=' + state.filter.value; }
    if (state.fwAction !== '') { fwQS += '&action=' + state.fwAction; }
    fetchJSON(fwQS, function (d) {
      state.tables['fw-table'].rows = d.rows || [];
      renderFW();
      renderEventStream();
    }, function () { noteFailure(); setTableState('fw-table', 'error-row', '加载失败，请稍后重试'); });
  }

  // ===== T2：采集通道健康卡（总览页；/api/v1/channels，独立 30s 轮询，仅总览可见时拉取） =====
  var CHAN_NAMES = {
    connections: '连接事件', ssh_attempts: 'SSH 认证', firewall_events: '防火墙事件',
    ban_events: '封禁记录', cred_events: '蜜罐凭据', resources: '资源采样', system_events: '系统事件'
  };
  // 各通道新鲜度阈值（秒，[绿线, 黄线]）：连接/SSH/防火墙/蜜罐事件随攻击流量持续写入，
  // 300s 内应有新数据；封禁为低频事件（无攻击时长时间无更新属正常）3600s；
  // resources/system_events 为固定周期采样（5s/30s），120s 内必有新数据。
  // 超黄线红显"停更?"仅作提示——低频通道 legitimately 长时间无事件，不一定是故障。
  var CHAN_FRESH = {
    connections: [300, 600], ssh_attempts: [300, 600], firewall_events: [300, 600],
    cred_events: [300, 600], ban_events: [3600, 7200], resources: [120, 600], system_events: [120, 600]
  };
  function chanAgeText(age) { return age < 60 ? age + 's 前' : Math.floor(age / 60) + 'm 前'; }
  // 独立 30s 轮询（数据 30s 粒度足够，不并入 pollOverview 5s 轮询）
  function pollChannels() {
    if (!vis('overview')) { return; }
    fetch('/api/v1/channels').then(function (r) {
      if (!r.ok) { throw new Error('HTTP ' + r.status); }
      return r.json();
    }).then(function (d) {
      renderChannelsData(d || {});
    }).catch(function () {
      // 失败：卡内置灰字（不弹全局横幅，非关键链路）
      var ul = document.getElementById('channels-list');
      if (ul) { ul.innerHTML = '<li style="color:var(--text-dim);cursor:default;">通道状态加载失败</li>'; }
      var sl = document.getElementById('syslog-list');
      if (sl) { sl.innerHTML = ''; }
    });
  }
  function renderChannelsData(d) {
    // 卡头右侧摘要 + 副注保留期数字填充（retention_days<=0 视为永久保留）
    var ret = (typeof d.retention_days === 'number' && d.retention_days > 0) ? d.retention_days : '∞';
    var sum = document.getElementById('channels-summary');
    if (sum) {
      sum.textContent = '库大小 ' + Number(d.db_size_mb || 0).toFixed(1) + ' MB · 溢出 ' +
        Number(d.overrun_total || 0) + ' · 保留 ' + ret + ' 天';
    }
    var note = document.getElementById('channels-note');
    if (note) { note.textContent = '最近事件距此刻；受 ' + ret + ' 天保留期约束'; }
    var now = typeof d.now === 'number' ? d.now : Math.floor(Date.now() / 1000);
    // 7 表状态行（last_ts=0 灰"无数据"；≤绿线绿"Xs 前"；≤黄线黄；>黄线红"停更?"）
    renderMiniList('channels-list', d.tables || [], {
      emptyText: '暂无通道数据',
      rank: function (i) { return i + 1; },
      label: function (t) {
        var nm = CHAN_NAMES[t.name] || t.name;
        var ls = t.last_ts > 0 ? fmtTimeFull(t.last_ts) : '—';
        return '<span class="src-ip">' + escapeHtml(nm) + '</span>' +
          '<span class="port" style="width:auto;color:var(--text-dim);font-weight:400;">' + ls + '</span>';
      },
      hits: function (t) {
        if (!t.last_ts || t.last_ts <= 0) { return '<span class="chan-dot"></span>无数据'; }
        var th = CHAN_FRESH[t.name] || [600, 1800];
        var age = Math.max(0, now - t.last_ts);
        if (age <= th[0]) { return '<span class="chan-dot ok"></span>' + chanAgeText(age); }
        if (age <= th[1]) { return '<span class="chan-dot warn"></span>' + chanAgeText(age); }
        return '<span class="chan-dot err"></span>' + chanAgeText(age) + ' 停更?';
      }
    });
    // 近期告警前 5 条（level=error 红 / warn 黄；空显示"近期无告警"；source/message 全转义）
    var sl = document.getElementById('syslog-list');
    if (sl) {
      var ws = d.recent_warnings || [];
      if (!ws.length) {
        sl.innerHTML = '<li style="color:var(--text-faint);">近期无告警</li>';
      } else {
        sl.innerHTML = ws.slice(0, 5).map(function (w) {
          var cls = w.level === 'error' ? 'err' : (w.level === 'warn' ? 'warn' : '');
          return '<li><span class="syslog-t">' + fmtTimeFull(w.ts) +
            '</span><span class="syslog-src">[' + escapeHtml(w.source || '-') + ']</span>' +
            '<span class="syslog-msg ' + cls + '">' + escapeHtml(w.message || '') + '</span></li>';
        }).join('');
      }
    }
  }

  // 30d 视图 firewall/timeline 聚合估 2-8s（千万行级），5s 轮询会积压超时——
  // 攻击类轮询 30d 降频至 30s（1h/24h/7d 保持 5s）；applyFilter/setRange 直接调 pollAttack 不受节流
  var lastAttackPoll = 0;
  function pollAll() {
    // DEV-EXPORT-001（R-03 reviewer 整改）：导出页为纯交互页——激活期间跳过全局轮询
    // （summary/resources/attack 等拉取全部暂停，避免无意义请求消耗限流桶与带宽）；
    // 切回其他页签后 5s 内恢复（switchPanel 用缓存渲染 + 下轮 pollAll 刷新）。
    if (state.activePanel === 'export') { return; }
    pollOverview();
    var minGap = (state.range === '30d') ? 30000 : 5000;
    var now = Date.now();
    if (now - lastAttackPoll >= minGap) {
      lastAttackPoll = now;
      pollAttack();
    }
  }
  function renderIf() {
    var a = state.attack;
    if (a.ports && a.sources && a.ssh) { renderAttacks(a.ports, a.sources, a.ssh); }
  }


  // ===== 模块 7：交互与联动 =====
  // ===== 明细表折叠组件（T-EXPORT：四明细表默认折叠 + localStorage 记忆 + 按需拉取） =====
  // 设计（用户已拍板）：前端定位"统计+展示"，明细数据走 /api/v1/export/table CSV 离线查看；
  // 四表（ssh/fw/hp/conn）默认折叠、展开预览最近 50 条。snap-table / hpd-table 不参与折叠。
  // localStorage 值约定：'1'=展开（用户选择），'0' 或无记录=折叠（默认态）。
  var FOLD_TABLES = ['ssh-table', 'fw-table', 'hp-table', 'conn-table'];
  function isFolded(id) {
    var v = null;
    try { v = localStorage.getItem('sentry-fold-' + id); } catch (e) {}
    return v !== '1';
  }
  // 折叠态视觉同步：表体容器（.scroll）显隐 + 卡头摘要 + 切换按钮箭头/aria-expanded。
  // 不触碰 state.tables[id]（rows/sort/page）——排序/筛选状态跨折叠保留。
  function setFoldVisual(id, folded) {
    var tb = document.getElementById(id);
    if (!tb) { return; }
    var wrap = tb.parentElement; // index.html 固定结构：.scroll > table#id
    if (wrap) { wrap.style.display = folded ? 'none' : ''; }
    var sum = document.getElementById('fold-sum-' + id);
    if (sum) { sum.style.display = folded ? '' : 'none'; }
    var btn = document.getElementById('fold-toggle-' + id);
    if (btn) {
      btn.textContent = folded ? '▸' : '▾';
      btn.setAttribute('aria-expanded', folded ? 'false' : 'true');
      btn.title = folded ? '展开明细预览' : '折叠明细预览';
    }
  }
  function toggleFold(id) {
    var folded = !isFolded(id); // 旧状态取反 = 新状态
    try { localStorage.setItem('sentry-fold-' + id, folded ? '0' : '1'); } catch (e) {}
    setFoldVisual(id, folded);
    if (!folded) {
      // 展开即强制补拉/补渲染：conn/hp 折叠期间完全不拉取，先渲染占位（rows null → loading 行）再补拉；
      // ssh/fw 轮询常拉，补渲染即可
      if (id === 'conn-table') { renderConns(); fetchConns(); }
      else if (id === 'hp-table') { renderHoneypot(); fetchHpEvents(); }
      else if (id === 'ssh-table') { renderSSH(); }
      else if (id === 'fw-table') { renderFW(); }
    }
  }
  function initFolds() {
    FOLD_TABLES.forEach(function (id) {
      setFoldVisual(id, isFolded(id));
      var btn = document.getElementById('fold-toggle-' + id);
      if (btn) { btn.addEventListener('click', function () { toggleFold(id); }); }
    });
  }
  function filterText() {
    if (!state.filter) return '';
    var src = state.filter.from ? '（来自' + state.filter.from + '）' : '';
    return state.filter.type === 'port' ? '过滤：端口 :' + state.filter.value + ' ✕' + src : '过滤：源 IP ' + ip(state.filter.value) + ' ✕' + src;
  }
  // N-1：filter 变更同样存在旧响应迟到覆盖——与 setRange 共用 state.reqSeq 自增，fetchJSON 统一校验
  function applyFilter(f, from) {
    state.reqSeq++;
    state.filter = f;
    if (f) { f.from = from || ''; } // chip 文案带来源（方案 3.5）
    var chip = document.getElementById('filter-chip');
    if (chip) {
      chip.style.display = f ? 'block' : 'none';
      chip.textContent = f ? filterText() : '';
    }
    resetTablePages();
    lastAttackPoll = Date.now(); // 避免 5s 内 pollAll 再触发一轮重复攻击轮询
    // 联动重查明细（TOP 图保持全局视图；connections 支持 dst_port/src_ip 双过滤，fetchConns 收敛）
    pollAttack();
    fetchConns();
  }

  // 时间范围切换
  function setRange(r) {
    state.range = r;
    document.querySelectorAll('#range-bar .range-btn').forEach(function (b) {
      b.classList.toggle('active', b.dataset.range === r);
    });
    // 统计卡标签跟随范围（近 1 小时/今日/近 7 天/近 30 天）
    var lb1 = document.querySelector('#today-fw') && document.querySelector('#today-fw').parentElement.querySelector('.l');
    var lb2 = document.querySelector('#today-sshfail') && document.querySelector('#today-sshfail').parentElement.querySelector('.l');
    if (lb1) { lb1.textContent = RANGE_LABEL[r] + '外部威胁事件'; }
    if (lb2) { lb2.textContent = RANGE_LABEL[r] + ' SSH 失败'; }
    state.reqSeq++; // RB-01：请求序号自增——旧 range 在途响应全部作废
    // 30d 降频提示（攻击页顶部弱显示；切到 30d 显示，切走隐藏）
    var hint = document.getElementById('rate-hint');
    if (hint) { hint.style.display = (r === '30d') ? 'block' : 'none'; }
    resetTablePages();
    // 重置明细缓存（避免旧范围数据闪回；summary 一并重置，
    // 否则新范围 summary 会与旧范围数据混合渲染态势条/风险评分）
    // 注：snap-table 不随 range 重置（snapshot 固定 20s 采集源，无 range 口径），行为与重构前一致
    state.tables['ssh-table'].rows = state.tables['fw-table'].rows = state.tables['conn-table'].rows = null;
    state.attack = { ports: null, sources: null, ssh: null, bans: null };
    // 范围切换后清空攻击三图——30d 慢响应期间旧 range 图不得残留误导
    ['chart-ports', 'chart-sources', 'chart-ssh'].forEach(function (id) {
      if (charts[id]) { charts[id].clear(); }
    });
    state.fwTimeline = null;
    state.summary = null;
    state.geo.rows = null;   // 地图数据随范围重置（country/min 过滤保持，交互状态不丢）
    state.tables['hp-table'].rows = null;    // 蜜罐凭据随范围重置（proto/revealed 保持，交互状态不丢）
    state.tables['hpd-table'].rows = null;   // 凭据字典聚合随范围重置（DEV-HONEY-002）
    lastCredTotal = null; // T3：字典口径随 range 变化，重置告警基线防误报
    state.topPorts = [];
    state.resourceData = null;
    state.eventExpanded = false; // 范围切换后事件流恢复默认 3 条
    // 范围切换重置失败标志（避免旧范围失败残留到新范围首个成功响应）
    state.attackDataFailed = false;
    state.sshTimelineOk = true;
    state.summaryFailed = false;
    state.failStreak = 0; // R-05：横幅计数随范围重置（旧范围失败不延续到新范围）
    hideErrorBanner();
    // 切 range 强制立即拉取攻击数据（绕过 30d 节流）
    lastAttackPoll = 0;
    pollAll();
  }

  // 封禁跳转攻击页逻辑已随封禁展示移除（DEV-GEO-001）

  // WS system 帧独立浮条（DEV-FE-003 IN-4：右下角 5s 自动消失，不再覆盖连接徽章文字；
  // 连续帧到达重置计时器）
  var sysToastTimer = null;
  function showSysToast(text) {
    var el = document.getElementById('sys-toast');
    if (!el) return;
    el.textContent = text;
    el.style.display = 'block';
    if (sysToastTimer) { clearTimeout(sysToastTimer); }
    sysToastTimer = setTimeout(function () { el.style.display = 'none'; }, 5000);
  }

  // ===== T1：来源 IP 画像弹层（单例覆盖；/api/v1/ip?ip= 点分 IPv4，168h 统计窗口） =====
  // 点分 IPv4 → uint32（applyFilter 的 src 过滤值口径为 uint32，与表格行 src_ip 一致，
  // 后端明细查询参数沿用既有 uint32 拼接方式）
  function ipToUint(s) {
    var p = String(s || '').split('.');
    if (p.length !== 4) { return 0; }
    var v = 0;
    for (var i = 0; i < 4; i++) {
      var n = parseInt(p[i], 10);
      if (isNaN(n) || n < 0 || n > 255) { return 0; }
      v = v * 256 + n;
    }
    return v >>> 0;
  }
  function closeIpProf() {
    var modal = document.getElementById('ip-prof-modal');
    if (modal) { modal.style.display = 'none'; }
    state.ipProf = { ip: null, loading: false };
  }
  // 打开画像（弹层单例重复打开覆盖内容；同 IP 在途请求不重复发，切 IP 重置在途标志）
  function openIpProfile(ipStr) {
    ipStr = String(ipStr || '');
    if (!ipStr || ipStr === '-') { return; }
    var modal = document.getElementById('ip-prof-modal');
    if (!modal) { return; }
    var changed = state.ipProf.ip !== ipStr;
    state.ipProf.ip = ipStr;
    renderIpProfShell(ipStr);
    // 0.0.0.0 为 IPv6 归源占位（功能审计 Minor-1）：前端前置提示，不发无效请求
    // （后端同口径 400）。
    if (ipStr === '0.0.0.0') {
      state.ipProf.loading = false;
      renderIpProfError('0.0.0.0 为 IPv6 归源占位值，不支持画像');
      return;
    }
    renderIpProfBodyLoading();
    if (state.ipProf.loading && !changed) { return; } // 去抖：同 IP 在途不重复发
    state.ipProf.loading = true;
    // 独立 fetch（不走 fetchJSON：画像请求与全局 range/filter 的 reqSeq 竞态校验无关）
    fetch('/api/v1/ip?ip=' + encodeURIComponent(ipStr)).then(function (r) {
      // 非 2xx 时透出后端 error 文案（功能审计 Minor-1：不再一律显示"画像加载失败"）
      return r.json().catch(function () { return null; }).then(function (d) {
        if (!r.ok) { throw new Error((d && d.error) || ('HTTP ' + r.status)); }
        return d;
      });
    }).then(function (d) {
      if (state.ipProf.ip !== ipStr) { return; } // 已切其他 IP：过期响应丢弃（先判再复位，审计 C4：顺序颠倒会使同 IP 去抖失效）
      state.ipProf.loading = false;
      renderIpProfData(d || {});
    }).catch(function (e) {
      if (state.ipProf.ip !== ipStr) { return; } // 同上（C4）
      state.ipProf.loading = false;
      renderIpProfError(e && e.message);
    });
  }
  // 标题行：IP 等宽字体 + 徽章占位（数据到后填充）+ 按钮组（复制/按此 IP 过滤/关闭）
  function renderIpProfShell(ipStr) {
    var head = document.getElementById('ip-prof-head');
    if (!head) { return; }
    head.innerHTML = '<span class="ip-prof-ip">' + escapeHtml(ipStr) + '</span>' +
      '<span class="ip-prof-badge dim" id="ip-prof-b-country">…</span>' +
      '<span class="ip-prof-badge dim" id="ip-prof-b-ban">…</span>';
    var acts = document.createElement('span');
    acts.className = 'ip-prof-acts';
    acts.appendChild(makeCopyBtn(ipStr, '复制失败'));
    var fb = document.createElement('button');
    fb.className = 'ip-prof-btn';
    fb.textContent = '按此 IP 过滤';
    fb.title = '跳转攻击页并按源 IP 过滤';
    fb.addEventListener('click', function () {
      closeIpProf();
      switchPanel('attack');
      applyFilter({ type: 'src', value: ipToUint(ipStr) }, 'IP 画像');
    });
    acts.appendChild(fb);
    var cb = document.createElement('button');
    cb.className = 'ip-prof-btn';
    cb.textContent = '×';
    cb.title = '关闭画像';
    cb.setAttribute('aria-label', '关闭画像');
    cb.addEventListener('click', closeIpProf);
    acts.appendChild(cb);
    head.appendChild(acts);
  }
  function renderIpProfBodyLoading() {
    var el = document.getElementById('ip-prof-body');
    if (el) { el.innerHTML = '<div class="ip-prof-dim">加载中…</div>'; }
    var modal = document.getElementById('ip-prof-modal');
    if (modal) { modal.style.display = 'flex'; }
  }
  function renderIpProfError(msg) {
    var el = document.getElementById('ip-prof-body');
    if (el) { el.innerHTML = '<div class="ip-prof-dim" style="color:var(--danger);">' + escapeHtml(msg || '画像加载失败') + '</div>'; }
  }
  // 区块小标题包裹
  function ipProfSection(title, inner) {
    return '<div class="ip-prof-sec"><div class="ip-prof-sec-t">' + title + '</div>' + inner + '</div>';
  }
  // TOP 条目 chips（t 为调用方已转义/纯数字拼接的安全片段，n 为数字）
  function ipProfChips(pairs) {
    if (!pairs || !pairs.length) { return ''; }
    var h = '<div class="ip-prof-tops">';
    pairs.forEach(function (p) {
      h += '<span class="ip-prof-top-item">' + p.t + ' <span class="num">×' + p.n + '</span></span>';
    });
    return h + '</div>';
  }
  // 数据区渲染：country/banned 徽章 + 五区块（空数据显示 '—'）。
  // XSS 红线：username/action/proto/jail 等后端字符串字段一律 escapeHtml 后拼接；
  // 数字字段经 Number() 重建，时间经 fmtTimeFull 纯数字输出。
  function renderIpProfData(d) {
    var bc = document.getElementById('ip-prof-b-country');
    if (bc) {
      if (d.country && d.country.name) { bc.textContent = d.country.name; bc.className = 'ip-prof-badge'; }
      else { bc.textContent = '未知'; bc.className = 'ip-prof-badge dim'; }
    }
    var bb = document.getElementById('ip-prof-b-ban');
    if (bb) {
      bb.textContent = d.banned_now ? '在封中' : '未在封';
      bb.className = 'ip-prof-badge' + (d.banned_now ? ' danger' : ' dim');
    }
    var el = document.getElementById('ip-prof-body');
    if (!el) { return; }
    var html = '';
    // SSH 认证（总/失败/成功 + top 用户名）
    var ssh = d.ssh || {};
    if (ssh.total) {
      var sh = '<div class="ip-prof-line">总 <b class="num">' + Number(ssh.total || 0) +
        '</b> · 失败 <b class="num">' + Number(ssh.failed || 0) +
        '</b> · 成功 <b class="num">' + Number(ssh.ok || 0) + '</b></div>';
      sh += ipProfChips((ssh.top_usernames || []).slice(0, 5).map(function (u) {
        return { t: escapeHtml(u.username), n: Number(u.count || 0) };
      }));
      html += ipProfSection('SSH 认证', sh);
    } else { html += ipProfSection('SSH 认证', '<div class="ip-prof-dim">—</div>'); }
    // 连接事件（total + top 目的端口）
    var conn = d.connections || {};
    if (conn.total) {
      var ch = '<div class="ip-prof-line">共 <b class="num">' + Number(conn.total || 0) + '</b> 次连接</div>';
      ch += ipProfChips((conn.top_dst_ports || []).slice(0, 5).map(function (p) {
        return { t: ':' + Number(p.dst_port), n: Number(p.count || 0) };
      }));
      html += ipProfSection('连接事件', ch);
    } else { html += ipProfSection('连接事件', '<div class="ip-prof-dim">—</div>'); }
    // 防火墙（total + action 分布）
    var fw = d.firewall || {};
    if (fw.total) {
      var fh = '<div class="ip-prof-line">共 <b class="num">' + Number(fw.total || 0) + '</b> 次事件</div>';
      fh += ipProfChips((fw.top_actions || []).slice(0, 5).map(function (a) {
        return { t: escapeHtml(a.action), n: Number(a.count || 0) };
      }));
      html += ipProfSection('防火墙', fh);
    } else { html += ipProfSection('防火墙', '<div class="ip-prof-dim">—</div>'); }
    // 蜜罐凭据尝试（契约无 password 字段，仅 时间/协议/用户名，勿虚构）
    var creds = d.creds || {};
    if (creds.total && (creds.recent || []).length) {
      var ch2 = '';
      (creds.recent || []).slice(0, 8).forEach(function (c) {
        ch2 += '<div class="ip-prof-ev"><span class="ip-prof-ev-t">' + fmtTimeFull(c.ts) +
          '</span><span class="ip-prof-ev-p">' + escapeHtml(c.proto || '-') +
          '</span><span class="ip-prof-ev-u">' + escapeHtml(c.username || '(空)') + '</span></div>';
      });
      html += ipProfSection('蜜罐凭据尝试（共 ' + Number(creds.total) + ' 条）', ch2);
    } else { html += ipProfSection('蜜罐凭据尝试', '<div class="ip-prof-dim">—</div>'); }
    // 封禁历史（type：ban=封禁 / unban=解封）
    var bans = d.bans || {};
    if (bans.total && (bans.recent || []).length) {
      var bh = '';
      (bans.recent || []).slice(0, 8).forEach(function (b) {
        var t = b.type === 'ban' ? '封禁' : (b.type === 'unban' ? '解封' : escapeHtml(String(b.type || '-')));
        bh += '<div class="ip-prof-ev"><span class="ip-prof-ev-t">' + fmtTimeFull(b.ts) +
          '</span><span class="ip-prof-ev-type">' + t +
          '</span><span class="ip-prof-ev-u">' + escapeHtml(b.jail || '-') + '</span></div>';
      });
      html += ipProfSection('封禁历史（共 ' + Number(bans.total) + ' 条）', bh);
    } else { html += ipProfSection('封禁历史', '<div class="ip-prof-dim">—</div>'); }
    el.innerHTML = html;
  }

  // ===== T3：告警通知（页内 toast + 可选浏览器通知；事件流行内展示不动，toast 为附加通道） =====
  var seenSysEvents = new Set(); // WS system 帧去重（key=ts|source|message；内存集合，页面刷新重置；超 500 条整体清空——审计 C5：去重仅需覆盖近期重复帧，防长期驻留内存缓慢增长）
  function pruneSeenSys() { if (seenSysEvents.size > 500) { seenSysEvents.clear(); } }
  var lastCredTotal = null;      // 蜜罐凭据总捕获数上次值（null=首轮不告警；切 range/proto 重置基线）
  var lastBans = null;           // 封禁名单上次快照（null=首轮不告警；新增 IP 才告警）
  // 页内 toast（右下角 #toast-box，最多同屏 3 个，5s 自动消失；level: info/warn/danger 左边框着色）
  function showToast(text, level) {
    var box = document.getElementById('toast-box');
    if (!box) { return; }
    var t = document.createElement('div');
    t.className = 'toast-item toast-' + (level || 'info');
    t.textContent = String(text || ''); // textContent 写入自动转义，无注入面
    box.appendChild(t);
    while (box.children.length > 3) { box.removeChild(box.firstChild); }
    setTimeout(function () {
      t.classList.add('out');
      setTimeout(function () { if (t.parentNode) { t.parentNode.removeChild(t); } }, 240);
    }, 5000);
  }
  // 浏览器通知统一出口：仅用户开启（localStorage 'sentry-notify'）且授权 granted 时触发；
  // 构造器受限环境 try/catch 兜底
  function notify(title, body) {
    var on = null;
    try { on = localStorage.getItem('sentry-notify'); } catch (e) {}
    if (on !== '1' || !('Notification' in window) || Notification.permission !== 'granted') { return; }
    try { new Notification(title, { body: body }); } catch (e) {}
  }
  // 铃铛按钮：点击请求通知权限；granted → 图标点亮 + 记忆（localStorage，刷新恢复）；
  // denied / 不支持 → toast 提示仅页内提醒
  function initNotifyBtn() {
    var btn = document.getElementById('notify-btn');
    if (!btn) { return; }
    var saved = null;
    try { saved = localStorage.getItem('sentry-notify'); } catch (e) {}
    if (saved === '1' && ('Notification' in window) && Notification.permission === 'granted') { btn.classList.add('lit'); }
    btn.addEventListener('click', function () {
      if (!('Notification' in window) || !Notification.requestPermission) {
        try { localStorage.setItem('sentry-notify', '0'); } catch (e) {}
        showToast('浏览器通知不可用，仅页内提醒', 'warn');
        return;
      }
      var rp = Notification.requestPermission();
      if (!rp || !rp.then) { showToast('浏览器通知不可用，仅页内提醒', 'warn'); return; } // 回调式旧实现不适配
      rp.then(function (p) {
        if (p === 'granted') {
          btn.classList.add('lit');
          try { localStorage.setItem('sentry-notify', '1'); } catch (e) {}
          showToast('浏览器通知已开启', 'info');
        } else {
          try { localStorage.setItem('sentry-notify', '0'); } catch (e) {}
          showToast('浏览器通知不可用，仅页内提醒', 'warn');
        }
      }).catch(function () { showToast('浏览器通知不可用，仅页内提醒', 'warn'); });
    });
  }

  // 表格列头排序（key 为行对象字段名）；DEV-FE-003 IN-6：aria-sort 同步（th 属性，方案 7.5）
  function bindSort(id, keys, render) {
    var head = document.querySelector('#' + id + ' thead');
    if (!head) return;
    head.querySelectorAll('th').forEach(function (th, idx) {
      var key = keys[idx];
      if (!key) return;
      th.classList.add('sortable');
      th.addEventListener('click', function () {
        var cur = state.tables[id].sort;
        var dir = (!cur || cur.key !== key || cur.dir === 'desc') ? 'asc' : 'desc';
        state.tables[id].sort = { key: key, dir: dir };
        head.querySelectorAll('th').forEach(function (t) {
          t.classList.remove('sorted');
          t.removeAttribute('aria-sort');
          var arrow = t.querySelector('.sort-arrow');
          if (arrow) arrow.remove();
        });
        th.classList.add('sorted');
        th.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
        var arrow = document.createElement('span');
        arrow.className = 'sort-arrow';
        arrow.textContent = dir === 'asc' ? '▲' : '▼';
        th.appendChild(arrow);
        render();
      });
    });
  }

  // ===== 模块 8：WS 实时推送 =====
  function connectWS() {
    state.ws = new WebSocket(WS_URL);
    state.ws.onopen = function () { state.wsMode = true; setStatus('WS 实时', true); };
    state.ws.onmessage = function (ev) {
      var f; try { f = JSON.parse(ev.data); } catch (e) { return; }
      touchFreshness(); // WS 帧到达即刷新新鲜度（本地时钟）
      if (f.type === 'resource') {
        // resource 帧实时更新磁盘显示（与 summary 轮询互补，5s 级）
        if (typeof f.disk === 'number' && f.disk >= 0) {
          document.getElementById('disk-pct').textContent = f.disk.toFixed(1) + '%';
        }
      }
      if (f.type === 'conn_stats' && f.active !== undefined) {
        document.getElementById('active-conns').textContent = f.active;
      }
      if (f.type === 'system') {
        // T3：warn/error → 告警 toast + 浏览器通知（key 去重，Set 内存集合刷新重置）；
        // info 级维持 DEV-FE-003 IN-4 既有浮条——两级互斥，避免同帧双弹。
        var lv = f.level === 'error' || f.level === 'warn';
        var ek = f.ts + '|' + f.source + '|' + f.message;
        if (lv) {
          if (!seenSysEvents.has(ek)) {
            seenSysEvents.add(ek);
            pruneSeenSys(); // 审计 C5：超 500 条整体清空（近期重复帧去重不受影响）
            var msg = '[' + f.source + '] ' + f.message;
            showToast(msg, f.level === 'error' ? 'danger' : 'warn');
            notify('sentry-agent', msg);
          }
        } else {
          showSysToast(f.source + ': ' + f.message);
        }
      }
    };
    state.ws.onclose = function () {
      state.wsMode = false;
      setStatusError('WS 断开，轮询兜底');
      touchFreshness(); // 断线立即显示"降级轮询"warn 态（不等下轮成功回调）
      setTimeout(connectWS, 3000);
    };
    state.ws.onerror = function () { try { state.ws.close(); } catch (e) {} };
  }


  // 连接状态徽章（三级语义：ok=低饱和绿 / degraded=琥珀 / error=红；system 帧不覆盖，IN-4）
  function setStatus(text, ok) {
    statusEl.textContent = text;
    statusEl.className = ok ? 'ok' : 'degraded';
  }
  function setStatusError(text) { statusEl.textContent = text; statusEl.className = 'error'; }

  // ===== 模块 8.5：数据导出（DEV-EXPORT-001） =====
  // 纯交互页：不注册轮询/拉取；点击"导出 CSV"时按需 fetch（blob 下载，不经过 WS）。
  // 429（heavy 限流 1 rps / burst 6 下快速重复导出会触发）与空数据均有提示，不做自动退避。
  var exportState = { range: '24h', custom: false };
  function exportMsg(text, cls) {
    var el = document.getElementById('export-msg');
    if (!el) return;
    el.textContent = text;
    el.className = 'export-msg' + (cls ? ' ' + cls : '');
  }
  function exportFileName() {
    var d = new Date();
    return 'sentry_export_' + d.getFullYear() + pad2(d.getMonth() + 1) + pad2(d.getDate()) +
      '_' + pad2(d.getHours()) + pad2(d.getMinutes()) + pad2(d.getSeconds()) + '.csv';
  }
  // 自定义起止默认值：近 24h（加载时设置一次；用户修改后切换自定义模式）
  function initCustomRange() {
    var fromEl = document.getElementById('export-from');
    var toEl = document.getElementById('export-to');
    if (!fromEl || !toEl) return;
    function fmt(dt) {
      return dt.getFullYear() + '-' + pad2(dt.getMonth() + 1) + '-' + pad2(dt.getDate()) +
        'T' + pad2(dt.getHours()) + ':' + pad2(dt.getMinutes());
    }
    if (!fromEl.value) { fromEl.value = fmt(new Date(Date.now() - 86400 * 1000)); }
    if (!toEl.value) { toEl.value = fmt(new Date()); }
  }
  function setCustomMode() {
    exportState.custom = true;
    document.querySelectorAll('.export-range').forEach(function (b) { b.classList.remove('active'); });
    exportMsg('');
  }
  function doExport() {
    var btn = document.getElementById('export-btn');
    var params;
    if (exportState.custom) {
      var fromEl = document.getElementById('export-from');
      var toEl = document.getElementById('export-to');
      var fromV = fromEl.value, toV = toEl.value;
      if (!fromV || !toV) { exportMsg('请选择完整的起止时间', 'err'); return; }
      // datetime-local 值无时区后缀，new Date 按本地时区解释，getTime()/1000 转 Unix 秒
      var fromT = Math.floor(new Date(fromV).getTime() / 1000);
      var toT = Math.floor(new Date(toV).getTime() / 1000);
      if (isNaN(fromT) || isNaN(toT)) { exportMsg('时间格式无效', 'err'); return; }
      if (fromT > toT) { exportMsg('开始时间不能晚于结束时间', 'err'); return; }
      if (toT - fromT > 90 * 86400) { exportMsg('自定义时间跨度不能超过 90 天', 'err'); return; }
      params = 'from=' + fromT + '&to=' + toT;
    } else {
      params = 'range=' + exportState.range;
    }
    exportMsg('');
    btn.disabled = true;
    var oldText = btn.textContent;
    btn.textContent = '导出中…';
    fetch('/api/v1/export/csv?' + params).then(function (r) {
      if (r.status === 429) { throw { code: 429 }; }
      if (!r.ok) {
        return r.json().then(function (d) {
          throw { code: r.status, msg: (d && d.error) ? d.error : '导出失败（HTTP ' + r.status + '）' };
        });
      }
      return r.blob();
    }).then(function (blob) {
      if (blob.size === 0) { exportMsg('该时间段无攻击记录', 'warn'); return; }
      // blob 变体：本地 objectURL 下载（触发段复用 triggerDownload，用后立即 revoke）
      var url = URL.createObjectURL(blob);
      var fname = exportFileName(); // 文件名前端生成（fetch blob 场景 Content-Disposition 不生效）
      triggerDownload(url, fname);
      URL.revokeObjectURL(url);
      exportMsg('导出成功：' + fname + '（' + blob.size + ' 字节）', 'ok');
    }).catch(function (e) {
      if (e && e.code === 429) { exportMsg('导出请求过于频繁，请稍候重试', 'err'); }
      else if (e && e.msg) { exportMsg(e.msg, 'err'); }
      else { exportMsg('导出失败，请稍后重试', 'err'); }
    }).finally(function () {
      btn.disabled = false;
      btn.textContent = oldText;
    });
  }

  // ===== 卡头明细 CSV 导出（T-EXPORT：/api/v1/export/table，heavy 档 1 rps） =====
  // 6 处卡头按钮共用：type 为常量白名单（无用户输入入 URL）；range 跟随全局 state.range
  // （页面全局仅四档 range；导出页自定义起止为该页局部状态，无全局 from/to 口径，不做降级拼接）。
  // 流程：fetch 校验 ok + Content-Type 含 csv → blob 本地命名下载（参考 doExport blob 变体，
  // 文件名 sentry-<type>-<yyyymmdd-hhmmss>.csv 本地生成）；429 → warn toast（文案对齐 doExport）；
  // 其他错误 → danger toast 透传后端 error 字段。按钮 disabled 1.5s 防连点。
  var EXPORT_TYPES = ['ssh', 'fw', 'hp', 'conn', 'bans', 'sys'];
  function exportTableCsv(type, btn) {
    if (EXPORT_TYPES.indexOf(type) < 0) { return; }
    var url = '/api/v1/export/table?type=' + type + '&' + rangeQS();
    if (btn) { btn.disabled = true; }
    fetch(url).then(function (r) {
      if (r.status === 429) { throw { code: 429 }; }
      if (!r.ok) {
        return r.json().then(function (d) {
          throw { code: r.status, msg: (d && d.error) ? d.error : '导出失败（HTTP ' + r.status + '）' };
        });
      }
      var ct = r.headers.get('Content-Type') || '';
      if (ct.indexOf('csv') < 0) { throw { code: r.status, msg: '导出响应格式异常（非 CSV）' }; }
      return r.blob();
    }).then(function (blob) {
      if (!blob || !blob.size) { showToast('导出为空：该范围无记录', 'warn'); return; }
      var objUrl = URL.createObjectURL(blob);
      var d = new Date();
      var fname = 'sentry-' + type + '-' + d.getFullYear() + pad2(d.getMonth() + 1) + pad2(d.getDate()) +
        '-' + pad2(d.getHours()) + pad2(d.getMinutes()) + pad2(d.getSeconds()) + '.csv';
      triggerDownload(objUrl, fname); // blob 场景 Content-Disposition 不生效，文件名本地生成
      URL.revokeObjectURL(objUrl);
      // 审计 A4：后端导出中断时在 CSV 尾部写 "# EXPORT_TRUNCATED" 标记行——
      // 检测到则追加强警告（文件照常交付，已扫描前缀仍可用，但须知情数据不完整）。
      blob.slice(Math.max(0, blob.size - 300)).text().then(function (tail) {
        if (tail.indexOf('# EXPORT_TRUNCATED') >= 0) {
          showToast(fname + ' 导出中断，文件不完整（可尝试缩小时间范围后重导）', 'danger');
        }
      });
      showToast('已开始下载：' + fname, 'info');
    }).catch(function (e) {
      if (e && e.code === 429) { showToast('导出请求过于频繁，请稍候重试', 'warn'); }
      else if (e && e.msg) { showToast(e.msg, 'danger'); }
      else { showToast('导出失败，请稍后重试', 'danger'); }
    }).finally(function () {
      if (btn) { setTimeout(function () { btn.disabled = false; }, 1500); }
    });
  }

  // ===== 模块 9：初始化 =====
  connectWS();
  setInterval(pollAll, POLL_MS);
  // R-08：首载 KPI 骨架（summary 未到先显示骨架块，pollAll 首轮 summary 回调到达后移除）
  if (!state.summary && !state.summaryFailed) { setKpiSkeleton(true); }
  pollAll(); // 首轮立即

  // 页签切换：激活即重渲染（数据缓存于 state，避免隐藏面板暂停渲染后切回白屏）；
  // conn 为页签激活才拉取的低频数据，激活时立即补拉
  // DEV-FE-003 IN-6：切换后焦点移至该页首个卡片标题（tabindex="-1" + focus()）
  function switchPanel(name) {
    document.querySelectorAll('nav button').forEach(function (b) { b.classList.remove('active'); });
    document.querySelectorAll('.panel').forEach(function (p) { p.classList.remove('active'); });
    var btn = document.querySelector('nav button[data-panel="' + name + '"]');
    if (btn) { btn.classList.add('active'); }
    document.getElementById('panel-' + name).classList.add('active');
    state.activePanel = name;
    Object.keys(charts).forEach(function (k) { charts[k].resize(); });
    if (name === 'overview') {
      if (state.summary) { renderKPI(); }
      renderRisk();
      renderAttackTrend();
      if (state.resourceData) { renderResource(state.resourceData); }
      renderMiniTop(state.topPorts || []);
      renderTopSourcesMini();
      renderEventStream();
      pollChannels(); // T2：切回总览补拉通道状态（内部 vis 门控，此时已激活总览）
    } else if (name === 'conn') {
      renderSnap();
      renderConns();
      pollConns(); // 低频档：连接页激活才拉取（方案 7.4）
    } else if (name === 'attack') {
      renderIf();
      renderSSH();
      renderFW();
      renderGeo();
      renderGeoSources();
      renderHoneypot(); // DEV-HONEY-001：蜜罐凭据表（缓存于 state.tables['hp-table']，切回补渲染）
      renderHoneyCredDict(); // DEV-HONEY-002：凭据字典表（缓存于 state.tables['hpd-table']，切回补渲染）
      renderBansActive(); // P3-1：封禁名单榜（缓存于 state.attack.bans，切回补渲染）
    } else if (name === 'export') {
      // DEV-EXPORT-001：导出页为纯交互页——不注册任何轮询/拉取（可见性门控：无数据拉取），
      // 切页激活时不触发任何 render；数据由用户点击"导出 CSV"时按需 fetch。
    }
    var title = document.querySelector('#panel-' + name + ' h3.panel-title');
    if (title) { title.focus(); } // DEV-FE-003 IN-6：焦点管理（读屏位置感）
  }
  // T3：选择器收窄为 [data-panel]——nav 内通知铃铛按钮不参与页签切换
  document.querySelectorAll('nav button[data-panel]').forEach(function (btn) {
    btn.addEventListener('click', function () { switchPanel(btn.dataset.panel); });
  });

  // 时间范围按钮
  document.querySelectorAll('#range-bar .range-btn').forEach(function (b) {
    b.addEventListener('click', function () { setRange(b.dataset.range); });
  });

  // DEV-EXPORT-001：导出页交互绑定（预设按钮 / 自定义起止 / 导出按钮 / 默认值）
  document.querySelectorAll('.export-range').forEach(function (b) {
    b.addEventListener('click', function () {
      exportState.custom = false;
      exportState.range = b.dataset.exportRange;
      document.querySelectorAll('.export-range').forEach(function (x) {
        x.classList.toggle('active', x === b);
      });
      exportMsg('');
    });
  });
  var exportFromEl = document.getElementById('export-from');
  var exportToEl = document.getElementById('export-to');
  if (exportFromEl) { exportFromEl.addEventListener('change', setCustomMode); }
  if (exportToEl) { exportToEl.addEventListener('change', setCustomMode); }
  var exportBtnEl = document.getElementById('export-btn');
  if (exportBtnEl) { exportBtnEl.addEventListener('click', doExport); }
  initCustomRange();

  // DEV-GEO-001：全球攻击地图交互绑定（国家下拉 / 次数阈值 / 导出；地图点击在 renderGeo 内绑定）
  var geoCountrySel = document.getElementById('geo-country-filter');
  if (geoCountrySel) {
    geoCountrySel.addEventListener('change', function () { setGeoCountry(geoCountrySel.value); });
  }
  var geoMinSel = document.getElementById('geo-min-filter');
  if (geoMinSel) {
    geoMinSel.addEventListener('change', function () {
      state.geo.min = parseInt(geoMinSel.value, 10) || 0;
      renderGeo();
      renderGeoSources();
    });
  }
  var geoExportBtn = document.getElementById('geo-export-btn');
  if (geoExportBtn) { geoExportBtn.addEventListener('click', geoExport); }
  // DEV-HONEY-002：凭据字典导出（triggerDownload 统一 a.click 下载；跟随 range + 协议过滤）。
  function honeyCredExport(format) {
    var q = 'range=' + state.range + '&format=' + format;
    if (state.hp.proto !== '') { q += '&proto=' + encodeURIComponent(state.hp.proto); }
    var ext = format === 'csv' ? 'csv' : 'txt';
    triggerDownload('/api/v1/export/creds?' + q,
      'sentry_creds_' + format + '_' + state.range +
      (state.hp.proto !== '' ? '_' + state.hp.proto : '') + '.' + ext);
  }
  var hpdBind = function (id, fmt) {
    var b = document.getElementById(id);
    if (b) { b.addEventListener('click', function () { honeyCredExport(fmt); }); }
  };
  hpdBind('hpd-export-csv', 'csv');
  hpdBind('hpd-export-pairs', 'pairs');
  hpdBind('hpd-export-pass', 'passwords');
  loadWorldMap(function () { if (state.activePanel === 'attack') { renderGeo(); } }); // 后台预载（幂等）

  // A-04（AUDIT-005）：数据保留提示——从 health 读取 retention_days（跟随配置，
  // 默认 7 天；<=0 表示禁用清理=永久保留）。失败保持静态默认文案。
  fetch('/api/v1/health').then(function (r) { return r.json(); }).then(function (d) {
    if (d && typeof d.retention_days === 'number') {
      var el = document.getElementById('retention-note');
      if (el) {
        el.textContent = d.retention_days > 0 ? ('数据保留 ' + d.retention_days + ' 天') : '数据永久保留';
      }
    }
  }).catch(function () {});

  // 态势头折叠（折叠按钮与状态点分离——仅按钮触发；button 原生键盘可达）
  var sitToggle = document.getElementById('sit-toggle');
  if (sitToggle) {
    sitToggle.addEventListener('click', function (ev) {
      ev.stopPropagation();
      state.sitCollapsed = !state.sitCollapsed;
      renderSituation();
    });
  }

  // 过滤 chip 清除（全局位，交互不变）
  var chipEl = document.getElementById('filter-chip');
  if (chipEl) {
    chipEl.addEventListener('click', function () { applyFilter(null); });
  }

  // DEV-047 D1：采样标注——桌面（hover 可用）走 CSS tooltip（::after + data-full），
  // 移除 title 避免浏览器原生 tooltip 与 CSS tooltip 双显；触屏（hover 不可用）保留 title 兜底
  var snEl = document.getElementById('sample-note');
  if (snEl && window.matchMedia && window.matchMedia('(hover: hover)').matches) {
    snEl.removeAttribute('title');
  }

  // 事件流"展开全部/收起"（默认 3 条，点击展开 20 条）
  var evBtn = document.getElementById('event-expand-btn');
  if (evBtn) {
    evBtn.addEventListener('click', function () {
      state.eventExpanded = !state.eventExpanded;
      suppressStreamNew = true; // R-03：展开/收起动作抑制本轮高亮（避免误报事件突增）
      renderEventStream();
    });
  }

  // 折叠区初始状态 = 展开（方案 9.4），用户手动折叠后 sessionStorage 记忆（低成本）
  function initFold(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var saved = null;
    try { saved = sessionStorage.getItem('fold-' + id); } catch (e) {}
    if (saved === '0') { el.open = false; }
    el.addEventListener('toggle', function () {
      try { sessionStorage.setItem('fold-' + id, el.open ? '1' : '0'); } catch (e) {}
    });
  }
  initFold('fold-resources');
  initFold('fold-events');

  // DOM 规模控制：滚动到底加载下一批（每表首屏 TABLE_PAGE 行；行级 diff 下追加批次走复用路径）。
  // T-EXPORT：四明细表（ssh/fw/hp/conn）预览量固定 50 条 < TABLE_PAGE(60)，滚动加载无意义，
  // 已移除绑定（明细走导出离线查看）；snap-table / hpd-table 保留滚动加载不动。
  bindScrollLoad('snap-table', renderSnap);
  bindScrollLoad('hpd-table', renderHoneyCredDict); // DEV-HONEY-002

  // 列头排序绑定（keys 与表头列一一对应；null 列不可排）
  bindSort('snap-table', [null, null, 'src_port', 'dst_port', 'pid'], renderSnap);
  bindSort('conn-table', [null, null, null, null, null, 'packets'], renderConns);
  bindSort('ssh-table', ['ts', null, null, null, null, null, null], renderSSH);
  bindSort('fw-table', ['ts', null, null, null, null, null, null], renderFW);
  bindSort('hp-table', ['ts', null, null, null, null, null], renderHoneypot); // DEV-HONEY-001
  // 凭据字典表列头排序（功能审计 Minor-3：与各明细表交互一致；密码列与 kind 徽标列不可排）
  bindSort('hpd-table', ['proto', 'username', null, 'count', 'first_ts', 'last_ts', 'src_ip_cnt', null], renderHoneyCredDict);

  // 表内过滤下拉：SSH 结果 / 防火墙动作。
  // N-1（reviewer R-01）：下拉变更同样存在旧响应迟到覆盖——与 setRange/applyFilter 共用
  // state.reqSeq 自增（fetchJSON 统一校验）并重置行数分页，杜绝旧 result/action 响应覆盖新状态
  var sshF = document.getElementById('ssh-result-filter');
  if (sshF) {
    sshF.addEventListener('change', function () {
      state.sshResult = sshF.value;
      state.reqSeq++;
      resetTablePages();
      state.tables['ssh-table'].rows = null; // 避免旧结果闪回
      pollAttack();
    });
  }
  var fwF = document.getElementById('fw-action-filter');
  if (fwF) {
    fwF.addEventListener('change', function () {
      state.fwAction = fwF.value;
      state.reqSeq++;
      resetTablePages();
      state.tables['fw-table'].rows = null;
      pollAttack();
    });
  }
  // DEV-HONEY-001：蜜罐协议筛选下拉（与 SSH 结果/防火墙动作下拉同模式：
  // reqSeq 自增防旧响应覆盖 + 重置分页 + 清缓存防闪回）
  var hpF = document.getElementById('hp-proto-filter');
  if (hpF) {
    hpF.addEventListener('change', function () {
      state.hp.proto = hpF.value;
      state.reqSeq++;
      resetTablePages();
      state.tables['hp-table'].rows = null;
      state.tables['hpd-table'].rows = null;
      lastCredTotal = null; // T3：字典口径随 proto 过滤变化，重置告警基线防误报
      pollAttack();
    });
  }

  // 窗口尺寸变化自适应
  window.addEventListener('resize', function () {
    Object.keys(charts).forEach(function (k) { charts[k].resize(); });
  });

  // ===== T1/T2/T3 初始化绑定 =====
  // T1：ip-prof 点击事件委托（document 级单点绑定，覆盖表格单元格与三榜 label 内的 IP 文本；
  // 表格 IP 单元格走 renderTableDiff cell.click（自带 stopPropagation），不冒泡到此处，不会重复触发）
  document.addEventListener('click', function (ev) {
    var t = ev.target;
    if (!t || !t.closest) { return; }
    var el = t.closest('.ip-prof');
    if (!el) { return; }
    var v = el.getAttribute('data-ip');
    if (v) { openIpProfile(v); }
  });
  // ===== T-EXPORT 初始化绑定 =====
  // 四明细表折叠（默认折叠 + localStorage 记忆 + 展开强制补拉）
  initFolds();
  // 6 处卡头导出按钮（type 白名单常量见 exportTableCsv；heavy 档 1 rps，内置 1.5s 防连点）
  var bindTblExport = function (btnId, type) {
    var b = document.getElementById(btnId);
    if (b) { b.addEventListener('click', function () { exportTableCsv(type, b); }); }
  };
  bindTblExport('export-ssh-table', 'ssh');
  bindTblExport('export-fw-table', 'fw');
  bindTblExport('export-hp-table', 'hp');
  bindTblExport('export-conn-table', 'conn');
  bindTblExport('export-bans-history', 'bans');
  bindTblExport('export-sys-events', 'sys');

  // T2：通道健康独立 30s 轮询（vis('overview') 门控；首轮立即；切回总览由 switchPanel 补拉）
  setInterval(pollChannels, 30000);
  pollChannels();
  // T3：通知铃铛（权限请求 + localStorage 记忆 + 图标点亮恢复）
  initNotifyBtn();
})();
