// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Maestra: the "Developer setup" page (`/ui/setup`) and its dashboard call to action.
//!
//! Every URL comes from `server.public_url` (`{BASE}`) and `server.ui_docs_login_url`
//! (`{LOGIN}`); the page text carries placeholders that [`render_setup_page`]
//! substitutes once, HTML-escaped. English and Russian; other languages get English.

use super::components::{html_escape, layout_dark, sanitize_href};
use super::i18n::Lang;

/// What the page needs from the running config.
pub struct SetupInfo<'a> {
    /// `public_base_url()`: scheme + host (+ path), no trailing slash.
    pub base_url: &'a str,
    /// Where people open the UI to sign in and mint a token (Teleport).
    pub login_url: &'a str,
    /// Enforced cooldown per registry label ("NuGet", "npm", "PyPI"), seconds.
    /// Empty when no min-release-age is enforced.
    pub cooldown: Vec<(&'static str, i64)>,
    /// `curation.internal_namespaces`: never delayed, never proxied.
    pub internal_namespaces: &'a [String],
    /// The "Generate token" form; `None` when the viewer cannot mint here
    /// (no token store, or no authenticated identity).
    pub mint: Option<MintOptions>,
    /// A token just minted by the JS-free form post: filled into every slot.
    pub token: Option<&'a str>,
}

/// What the viewer may mint from the setup page (the Tokens page's rule).
pub struct MintOptions {
    /// The caller's own role can write (Teleport role `apps`), so `write` is offered.
    pub can_write: bool,
    pub description: String,
    pub default_ttl_days: u64,
    pub max_ttl_days: u64,
}

/// A command's token placeholder; `data-token-slot` is the hook the page's JS
/// (and the JS-free post) fills with a freshly minted token.
const TOKEN_MARK: &str = r#"<mark class="ds-tok" data-token-slot>&lt;TOKEN&gt;</mark>"#;
/// The same look in prose, never filled.
const TOKEN_LABEL: &str = r#"<mark class="ds-tok">&lt;TOKEN&gt;</mark>"#;

/// A copyable code block; `<TOKEN>` is highlighted. `text` is plain text.
fn code(text: &str) -> String {
    format!(
        r#"<div class="ds-code"><pre><code>{}</code></pre><button type="button" class="ds-copy" onclick="dsCopy(this)">Copy</button></div>"#,
        html_escape(text).replace("&lt;TOKEN&gt;", TOKEN_MARK)
    )
}

/// The macOS and Windows variants of one command; only the selected OS shows.
fn per_os(mac: &str, win: &str) -> String {
    format!(
        r#"<div class="ds-mac">{}</div><div class="ds-win">{}</div>"#,
        code(mac),
        code(win)
    )
}

fn section(id: &str, title: &str, body: &str) -> String {
    section_with(id, "", title, body)
}

/// One tool tab's panel: shown alone once the tool switch is set.
fn tool_section(id: &str, title: &str, body: &str) -> String {
    section_with(
        id,
        &format!(r#" ds-tool" role="tabpanel" aria-labelledby="tab-{id}"#),
        title,
        body,
    )
}

fn section_with(id: &str, extra: &str, title: &str, body: &str) -> String {
    format!(
        r#"<section id="{id}" class="bg-[#1e293b] rounded-lg border border-slate-700 p-4 md:p-6 mb-6 ds-prose{extra}">
    <h2 class="text-lg font-semibold text-slate-200 mb-2">{title}</h2>
    {body}
</section>"#
    )
}

/// Human cooldown: whole days as days, anything else in hours.
fn format_age(secs: i64, ru: bool) -> String {
    match (secs % 86_400 == 0, ru) {
        (true, false) => format!("{} d", secs / 86_400),
        (true, true) => format!("{} дн.", secs / 86_400),
        (false, false) => format!("{} h", secs / 3_600),
        (false, true) => format!("{} ч", secs / 3_600),
    }
}

/// The dashboard card linking to the setup page.
pub fn render_setup_cta(lang: Lang) -> String {
    let (title, text, button) = if lang == Lang::Ru {
        (
            "Настройте свою машину",
            "NuGet, npm и PyPI за пару команд: токен, конфиг, готово.",
            "Открыть инструкцию",
        )
    } else {
        (
            "Set up your machine",
            "NuGet, npm and PyPI in a few commands: token, config, done.",
            "Open the guide",
        )
    };
    format!(
        r##"<a href="/ui/setup" class="block mb-6 rounded-lg border border-blue-800 bg-gradient-to-r from-slate-800 to-slate-900 p-4 md:p-6 hover:border-blue-400 transition-colors">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div class="flex items-center gap-4">
            <div class="p-3 rounded-lg bg-blue-900/30 text-blue-400 flex-shrink-0">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
            </div>
            <div>
                <div class="text-lg font-semibold text-slate-200">{title}</div>
                <div class="text-sm text-slate-400">{text}</div>
            </div>
        </div>
        <span class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium whitespace-nowrap text-center">{button} &rarr;</span>
    </div>
</a>"##
    )
}

const STYLE: &str = r#"<style>
#ds-root[data-os="mac"] .ds-win, #ds-root[data-os="win"] .ds-mac { display: none; }
.ds-tabs { display: inline-flex; gap: .25rem; padding: .25rem; background: #0f172a; border: 1px solid #334155; border-radius: .6rem; }
.ds-tab { padding: .45rem 1.1rem; border-radius: .45rem; font-size: .875rem; font-weight: 600; color: #94a3b8; transition: background .15s, color .15s; }
.ds-tab:hover { color: #e2e8f0; }
.ds-tab[aria-selected="true"] { background: #2563eb; color: #fff; }
#ds-root [hidden] { display: none !important; }
.ds-code { position: relative; margin: .5rem 0 1rem; }
.ds-code pre { background: #0f172a; border: 1px solid #334155; border-radius: .5rem; padding: .75rem 4.75rem .75rem 1rem; font-size: .8125rem; line-height: 1.6; color: #e2e8f0; white-space: pre-wrap; overflow-wrap: anywhere; }
.ds-copy { position: absolute; top: .45rem; right: .45rem; padding: .2rem .6rem; font-size: .75rem; border-radius: .35rem; background: #334155; color: #cbd5e1; }
.ds-copy:hover { background: #475569; color: #fff; }
.ds-tok { background: rgba(250, 204, 21, .16); color: #fde047; border-radius: .25rem; padding: 0 .2rem; outline: 1px dashed rgba(250, 204, 21, .55); }
.ds-prose { color: #cbd5e1; font-size: .9rem; line-height: 1.6; }
.ds-prose p { margin: .5rem 0; }
.ds-prose h3 { color: #e2e8f0; font-weight: 600; font-size: .95rem; margin: 1.1rem 0 .25rem; }
.ds-prose ol { list-style: decimal; padding-left: 1.25rem; }
.ds-prose ul { list-style: disc; padding-left: 1.25rem; }
.ds-prose li { margin: .3rem 0; }
.ds-prose a { color: #60a5fa; }
.ds-prose a:hover { color: #93c5fd; }
.ds-prose :not(pre) > code { background: #0f172a; border: 1px solid #334155; padding: .05rem .35rem; border-radius: .3rem; font-size: .85em; color: #e2e8f0; word-break: break-word; }
.ds-note { border-left: 3px solid #2563eb; background: rgba(30, 58, 138, .25); padding: .6rem .9rem; border-radius: .35rem; margin: .75rem 0; }
.ds-chip { display: inline-block; font-family: ui-monospace, monospace; font-size: .8rem; padding: .1rem .5rem; margin: .15rem .2rem .15rem 0; border-radius: .35rem; background: #0f172a; border: 1px solid #334155; color: #e2e8f0; }
.ds-step { display: flex; gap: .75rem; align-items: flex-start; }
#ds-root[data-tool="nuget"] .ds-tool:not(#nuget), #ds-root[data-tool="npm"] .ds-tool:not(#npm), #ds-root[data-tool="pypi"] .ds-tool:not(#pypi) { display: none; }
#ds-root:not([data-tool]) .ds-tooltabs { display: none; }
.ds-switches { display: flex; flex-wrap: wrap; gap: .75rem; align-items: center; margin-bottom: 1.5rem; }
.ds-tab:focus-visible, .ds-btn:focus-visible { outline: 2px solid #60a5fa; outline-offset: 2px; }
.ds-mint { display: grid; grid-template-columns: 1fr; gap: .75rem; margin: .75rem 0; }
@media (min-width: 768px) { .ds-mint { grid-template-columns: 2fr 1fr 1fr auto; align-items: end; } }
.ds-mint label { display: flex; flex-direction: column; gap: .25rem; font-size: .8rem; color: #94a3b8; }
.ds-mint input, .ds-mint select { background: #0f172a; border: 1px solid #475569; border-radius: .45rem; padding: .45rem .6rem; color: #e2e8f0; font-size: .875rem; width: 100%; }
.ds-btn { background: #2563eb; color: #fff; font-weight: 600; border-radius: .45rem; padding: .5rem 1rem; font-size: .875rem; white-space: nowrap; }
.ds-btn:hover { background: #1d4ed8; }
.ds-btn:disabled { opacity: .6; }
.ds-btn-ghost { background: #334155; color: #e2e8f0; }
.ds-btn-ghost:hover { background: #475569; }
.ds-warn { border-left: 3px solid #eab308; background: rgba(113, 63, 18, .3); padding: .6rem .9rem; border-radius: .35rem; margin: .75rem 0; }
.ds-err { color: #f87171; }
.ds-tok[data-filled] { outline-style: solid; }
#ds-root.ds-masked .ds-tok[data-filled] { filter: blur(5px); }
.ds-num { flex-shrink: 0; width: 1.6rem; height: 1.6rem; border-radius: 9999px; background: #1e3a8a; color: #bfdbfe; font-weight: 700; font-size: .8rem; display: flex; align-items: center; justify-content: center; }
</style>"#;

const SCRIPT: &str = r#"<script>
function dsCopy(b) {
    var text = b.parentElement.querySelector('pre').innerText;
    navigator.clipboard.writeText(text).then(function () {
        var label = b.textContent;
        b.textContent = '✓';
        setTimeout(function () { b.textContent = label; }, 1500);
    });
}
(function () {
    var root = document.getElementById('ds-root');
    function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
    function store(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
    // A tab switch: buttons [data-<attr>-tab] set #ds-root[data-<attr>]; arrow keys move.
    function switcher(attr, key, values, initial) {
        var tabs = Array.prototype.slice.call(root.querySelectorAll('[data-' + attr + '-tab]'));
        function set(v, save) {
            root.setAttribute('data-' + attr, v);
            tabs.forEach(function (t) {
                var on = t.getAttribute('data-' + attr + '-tab') === v;
                t.setAttribute('aria-selected', String(on));
                t.tabIndex = on ? 0 : -1;
            });
            if (save) store(key, v);
        }
        tabs.forEach(function (t, i) {
            t.addEventListener('click', function () {
                var v = t.getAttribute('data-' + attr + '-tab');
                set(v, true);
                if (attr === 'tool') history.replaceState(null, '', '#' + v);
            });
            t.addEventListener('keydown', function (e) {
                var d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
                if (!d) return;
                e.preventDefault();
                var n = tabs[(i + d + tabs.length) % tabs.length];
                n.focus();
                n.click();
            });
        });
        set(values.indexOf(initial) >= 0 ? initial : values[0], false);
        return set;
    }
    switcher('os', 'nora_setup_os', ['mac', 'win'], load('nora_setup_os') || (/Win/.test(navigator.platform) ? 'win' : 'mac'));
    var tools = ['nuget', 'npm', 'pypi'];
    function fromHash() { var h = location.hash.slice(1); return tools.indexOf(h) >= 0 ? h : null; }
    var setTool = switcher('tool', 'nora_setup_tool', tools, fromHash() || load('nora_setup_tool'));
    window.addEventListener('hashchange', function () { var h = fromHash(); if (h) setTool(h, true); });

    // Generate token: the token lives only in this page's DOM (never in a URL or storage).
    var form = document.getElementById('ds-mint');
    var minted = document.getElementById('ds-minted');
    var err = document.getElementById('ds-mint-err');
    function fill(token) {
        root.querySelectorAll('[data-token-slot]').forEach(function (el) {
            el.textContent = token;
            el.setAttribute('data-filled', '');
        });
        if (minted) minted.hidden = false;
    }
    if (form) form.addEventListener('submit', function (e) {
        e.preventDefault();
        var btn = form.querySelector('button[type=submit]');
        btn.disabled = true;
        err.textContent = '';
        fetch(form.action, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'HX-Request': 'true', 'Accept': 'application/json' },
            body: new URLSearchParams(new FormData(form))
        }).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (j) {
                if (!r.ok || !j.token) throw new Error(j.error || ('HTTP ' + r.status));
                return j.token;
            });
        }).then(function (t) {
            fill(t);
            form.hidden = true;
        }).catch(function (x) {
            err.textContent = x.message;
        }).then(function () { btn.disabled = false; });
    });
    root.querySelectorAll('[data-mask-toggle]').forEach(function (b) {
        b.addEventListener('click', function () {
            var masked = root.classList.toggle('ds-masked');
            b.textContent = b.getAttribute(masked ? 'data-show' : 'data-hide');
            b.setAttribute('aria-pressed', String(masked));
        });
    });
})();
</script>"#;

/// The Claude Code shortcut: install the skillz `packages` plugin, then run its
/// setup skill (steps as in the maestra-io/skillz README).
fn claude_note(ru: bool) -> String {
    let t = |en: &'static str, ru_text: &'static str| if ru { ru_text } else { en };
    format!(
        r#"<p>{intro}</p>
<ol>
<li>{s1}{c1}</li>
<li>{s2}{c2}</li>
<li>{s3}</li>
<li>{s4}{c4}</li>
</ol>
<p>{upd}</p>
{c5}
<p>{dep}</p>"#,
        intro = t(
            "Using Claude Code? The <code>packages</code> plugin does every step below for you (token, NuGet, npm, pip, uv, Poetry) and verifies the result:",
            "Работаете в Claude Code? Плагин <code>packages</code> сделает все шаги ниже сам (токен, NuGet, npm, pip, uv, Poetry) и проверит результат:",
        ),
        s1 = t(
            "Add our marketplace, once per machine (needs GitHub SSH access to maestra-io):",
            "Добавьте наш маркетплейс, один раз на машину (нужен SSH-доступ к GitHub maestra-io):",
        ),
        c1 = code("/plugin marketplace add git@github.com:maestra-io/skillz.git"),
        s2 = t("Install the plugin:", "Установите плагин:"),
        c2 = code("/plugin install packages@maestra-plugins"),
        s3 = t("Restart Claude Code.", "Перезапустите Claude Code."),
        s4 = t("Run the setup:", "Запустите настройку:"),
        c4 = code("/packages:packages-dev-setup"),
        upd = t("Update later with:", "Обновление:"),
        c5 = code("/plugin marketplace update maestra-plugins\n/plugin update packages@maestra-plugins"),
        dep = t(
            "The <code>delivery</code> plugin depends on <code>packages</code>: installing <code>delivery@maestra-plugins</code> pulls it in.",
            "Плагин <code>delivery</code> зависит от <code>packages</code>: установка <code>delivery@maestra-plugins</code> подтягивает его автоматически.",
        ),
    )
}

/// The "Generate token" form and the shown-once box it reveals. The form posts to
/// the Tokens page's own endpoint (same auth, same role cap); JS fetches it as
/// JSON and fills the page, without JS the response is this page, filled.
fn mint_block(m: &MintOptions, minted: bool, ru: bool) -> String {
    let t = |en: &'static str, ru_text: &'static str| if ru { ru_text } else { en };
    let write = if m.can_write {
        r#"<option value="write">write</option>"#
    } else {
        ""
    };
    format!(
        r#"<h3>{heading}</h3>
<p>{lead}</p>
<form id="ds-mint" method="post" action="/api/ui/tokens/create" class="ds-mint"{form_hidden}>
    <input type="hidden" name="ui" value="setup">
    <label>{desc}<input type="text" name="description" value="{description}" maxlength="200" required></label>
    <label>{role}<select name="role"><option value="read">read</option>{write}</select></label>
    <label>{ttl}<input type="number" name="ttl_days" value="{ttl_default}" min="1" max="{ttl_max}"></label>
    <button type="submit" class="ds-btn">{button}</button>
</form>
<p id="ds-mint-err" class="ds-err" role="alert"></p>
<div id="ds-minted" class="ds-warn"{box_hidden}>
    <p><b>{done}</b> {warn}</p>
    {slot}
    <button type="button" class="ds-btn ds-btn-ghost" data-mask-toggle data-hide="{hide}" data-show="{show}" aria-pressed="false">{hide}</button>
</div>
<h3>{manual}</h3>"#,
        heading = t("Generate it here", "Выпустите его здесь"),
        lead = t(
            "One click mints a personal token and fills it into every command on this page.",
            "Одна кнопка выпускает личный токен и подставляет его во все команды на этой странице.",
        ),
        form_hidden = if minted { " hidden" } else { "" },
        desc = t("Description", "Описание"),
        description = html_escape(&m.description),
        role = t("Role", "Роль"),
        ttl = t("Expiry (days)", "Срок жизни (дней)"),
        ttl_default = m.default_ttl_days,
        ttl_max = m.max_ttl_days,
        button = t("Generate token", "Выпустить токен"),
        box_hidden = if minted { "" } else { " hidden" },
        done = t("Your token:", "Ваш токен:"),
        warn = t(
            "It is shown once and this page does not store it: a reload brings the placeholders back. It is already filled into the commands below.",
            "Он показывается один раз, страница его не хранит: после перезагрузки вернутся плейсхолдеры. Он уже подставлен в команды ниже.",
        ),
        slot = code("<TOKEN>"),
        hide = t("Hide token", "Скрыть токен"),
        show = t("Show token", "Показать токен"),
        manual = t("Or on the Tokens page", "Или на странице токенов"),
    )
}

/// Renders `/ui/setup`.
pub fn render_setup_page(info: &SetupInfo, lang: Lang, auth_enabled: bool) -> String {
    let ru = lang == Lang::Ru;
    let tr = |en: &'static str, ru_text: &'static str| if ru { ru_text } else { en };
    let tok = TOKEN_LABEL;

    // ── How it works ───────────────────────────────────────────────────
    let intro = format!(
        r#"<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-2">
    <div class="ds-step"><span class="ds-num">1</span><div>{s1}</div></div>
    <div class="ds-step"><span class="ds-num">2</span><div>{s2}</div></div>
    <div class="ds-step"><span class="ds-num">3</span><div>{s3}</div></div>
</div>"#,
        s1 = tr(
            "One registry, <code>{BASE}</code>, serves NuGet, npm and PyPI: our own packages plus a cached proxy of nuget.org, npmjs.com and pypi.org. Point every client at it and nothing else.",
            "Один реестр, <code>{BASE}</code>, обслуживает NuGet, npm и PyPI: наши пакеты плюс кэширующий прокси nuget.org, npmjs.com и pypi.org. Все клиенты смотрят только в него.",
        ),
        s2 = tr(
            "Package clients authenticate with your personal token. You mint it yourself in this UI, which is reachable only through Teleport.",
            "Клиенты пакетов авторизуются вашим личным токеном. Его вы выпускаете сами в этом UI, который открывается только через Teleport.",
        ),
        s3 = if info.cooldown.is_empty() {
            tr(
                "Then install and publish exactly as with the public registries.",
                "Дальше устанавливайте и публикуйте пакеты так же, как с публичными реестрами.",
            )
        } else {
            tr(
                "Brand-new public versions wait out a short cooldown before they are served; our internal packages never wait.",
                "Совсем свежие публичные версии выдерживают короткий карантин, прежде чем станут доступны; наши внутренние пакеты не ждут никогда.",
            )
        },
    );

    // ── 1. Token ───────────────────────────────────────────────────────
    let kc = code("security add-generic-password -U -s {HOSTPATH} -a nora -w <TOKEN>");
    let token_body = if ru {
        format!(
            r#"<ol>
<li>Откройте UI через Teleport: <a href="{{LOGIN_HREF}}" target="_blank" rel="noopener">{{LOGIN}}</a>, вход через GitHub SSO.</li>
<li>Страница <a href="/ui/tokens">Токены</a> &rarr; «Создать токен»: описание (например, имя ноутбука), роль <b>read</b> для установки пакетов, <b>write</b> только если вы публикуете пакеты (доступна с ролью Teleport <code>apps</code>), срок жизни в днях.</li>
<li>Скопируйте токен сразу: он показывается один раз. Токены выглядят как <code>nra_…</code>; ниже везде вместо {tok} подставьте его.</li>
<li class="ds-mac">Сохраните его в связке ключей (login keychain): строки профиля для uv и NuGet ниже читают токен оттуда, и секрет не лежит в профиле шелла:</li>
</ol>
<div class="ds-mac">{kc}</div>
<div class="ds-note">Пароли снаружи не принимаются: клиенты пакетов отправляют только токен (имя пользователя любое, мы пишем <code>token</code>). В GitHub Actions токен не нужен: workflow авторизуются через GitHub OIDC, личный токен в секреты CI не кладите.</div>"#
        )
    } else {
        format!(
            r#"<ol>
<li>Open the UI through Teleport: <a href="{{LOGIN_HREF}}" target="_blank" rel="noopener">{{LOGIN}}</a>, sign in with GitHub SSO.</li>
<li><a href="/ui/tokens">Tokens</a> page &rarr; Create token: a description (e.g. your laptop's name), role <b>read</b> to install packages, <b>write</b> only if you publish (available with the Teleport role <code>apps</code>), expiry in days.</li>
<li>Copy the token right away, it is shown once. Tokens look like <code>nra_…</code>; replace every {tok} below with it.</li>
<li class="ds-mac">Keep it in the login keychain; the uv and NuGet profile lines below read it from there, so no shell profile holds the secret:</li>
</ol>
<div class="ds-mac">{kc}</div>
<div class="ds-note">Passwords are not accepted from outside: package clients send only the token (any username, we use <code>token</code>). GitHub Actions need no token: workflows authenticate with GitHub OIDC, so never put a personal token into CI secrets.</div>"#
        )
    };

    let token_body = match &info.mint {
        Some(m) => format!("{}{token_body}", mint_block(m, info.token.is_some(), ru)),
        None => token_body,
    };

    // ── 2. NuGet ───────────────────────────────────────────────────────
    let nuget_body = format!(
        r#"<p>{p1}</p>
{add}
<p>{p2}</p>
<p>{p_org}</p>
<div class="ds-note">{p3}</div>
{cred}
<h3>{publish}</h3>
{push}"#,
        p1 = tr(
            "Add the feed to your user-level NuGet config once:",
            "Один раз добавьте фид в пользовательский конфиг NuGet:",
        ),
        add = per_os(
            "dotnet nuget add source \"{BASE}/nuget/v3/index.json\" -n maestra -u token -p <TOKEN> --store-password-in-clear-text\ndotnet nuget disable source nuget.org",
            "dotnet nuget add source \"{BASE}/nuget/v3/index.json\" -n maestra -u token -p <TOKEN>\ndotnet nuget disable source nuget.org",
        ),
        p2 = if ru {
            r#"<span class="ds-mac">Пишется в <code>~/.nuget/NuGet/NuGet.Config</code>. На macOS NuGet не умеет шифровать пароли, поэтому флаг <code>--store-password-in-clear-text</code> обязателен, а токен лежит в файле открытым текстом.</span><span class="ds-win">Пишется в <code>%APPDATA%\NuGet\NuGet.Config</code>. На Windows NuGet шифрует пароль (только для вас и этой машины), поэтому флаг <code>--store-password-in-clear-text</code> не нужен.</span>"#
        } else {
            r#"<span class="ds-mac">This writes <code>~/.nuget/NuGet/NuGet.Config</code>. NuGet can encrypt passwords only on Windows, so on macOS <code>--store-password-in-clear-text</code> is required and the token sits in the file as plain text.</span><span class="ds-win">This writes <code>%APPDATA%\NuGet\NuGet.Config</code>. On Windows NuGet encrypts the password (for you on this machine only), so <code>--store-password-in-clear-text</code> is not needed.</span>"#
        },
        p_org = tr(
            "<code>nuget.org</code> is disabled on purpose: the registry proxies it, and a direct source would bypass the cooldown and the dependency-confusion guard. To turn it back on: <code>dotnet nuget enable source nuget.org</code>.",
            "<code>nuget.org</code> отключён намеренно: реестр его проксирует, а прямой источник обходил бы карантин и защиту от dependency confusion. Включить обратно: <code>dotnet nuget enable source nuget.org</code>.",
        ),
        p3 = tr(
            "A repository whose own <code>nuget.config</code> pins the feed with <code>&lt;clear/&gt;</code> under another key (ours use <code>private</code>) gets no credentials from the <code>maestra</code> source: NuGet matches credentials by key. Give that key the token through the environment (new terminals):",
            "Репозиторий, чей <code>nuget.config</code> фиксирует фид с <code>&lt;clear/&gt;</code> под другим ключом (у нас <code>private</code>), не получает учётные данные источника <code>maestra</code>: NuGet сопоставляет их по ключу. Передайте токен этому ключу через окружение (в новых терминалах):",
        ),
        cred = per_os(
            r#"echo 'export NuGetPackageSourceCredentials_private="Username=token;Password=$(security find-generic-password -s {HOSTPATH} -a nora -w 2>/dev/null)"' >> ~/.zshrc"#,
            "[Environment]::SetEnvironmentVariable('NuGetPackageSourceCredentials_private', 'Username=token;Password=<TOKEN>', 'User')",
        ),
        publish = tr("Publish (write token)", "Публикация (токен write)"),
        push = per_os(
            r#"dotnet nuget push bin/Release/MyPackage.1.0.0.nupkg --source "{BASE}/nuget/v3/index.json" --api-key <TOKEN>"#,
            r#"dotnet nuget push bin\Release\MyPackage.1.0.0.nupkg --source "{BASE}/nuget/v3/index.json" --api-key <TOKEN>"#,
        ),
    );

    // ── 3. npm ─────────────────────────────────────────────────────────
    let npm_body = format!(
        r#"<p>{p1}</p>
{set}
<p>{p2}</p>
{file}
<p>{p_scope}</p>
<h3>Yarn &amp; pnpm</h3>
<p>{p3}</p>
{yarn}
<h3>{publish}</h3>
{pub_cmd}"#,
        p1 = tr(
            "Point npm at the registry and store your token for it:",
            "Направьте npm в реестр и сохраните для него токен:",
        ),
        set = code("npm config set \"registry={BASE}/npm/\"\nnpm config set \"//{HOSTPATH}/npm/:_authToken=<TOKEN>\""),
        p2 = if ru {
            r#"Это две строки в <span class="ds-mac"><code>~/.npmrc</code></span><span class="ds-win"><code>%USERPROFILE%\.npmrc</code></span>; можно вписать их и вручную:"#
        } else {
            r#"These are two lines in <span class="ds-mac"><code>~/.npmrc</code></span><span class="ds-win"><code>%USERPROFILE%\.npmrc</code></span>; you can also write them by hand:"#
        },
        file = code("registry={BASE}/npm/\n//{HOSTPATH}/npm/:_authToken=<TOKEN>"),
        p_scope = tr(
            "Delete any <code>@mindbox-cloud:registry=</code> line from that file: a scope pinned elsewhere bypasses the registry.",
            "Удалите из этого файла строку <code>@mindbox-cloud:registry=</code>, если она есть: scope, направленный в другое место, обходит реестр.",
        ),
        p3 = tr(
            "pnpm and Yarn 1 read the same <code>.npmrc</code>, nothing else to do. Yarn 2+ (Berry) keeps its own config:",
            "pnpm и Yarn 1 читают тот же <code>.npmrc</code>, больше ничего не нужно. У Yarn 2+ (Berry) свой конфиг:",
        ),
        yarn = code("yarn config set -H npmRegistryServer \"{BASE}/npm/\"\nyarn config set -H npmAuthToken \"<TOKEN>\"\nyarn config set -H npmAlwaysAuth true"),
        publish = tr("Publish (write token)", "Публикация (токен write)"),
        pub_cmd = code("npm publish --registry \"{BASE}/npm/\""),
    );

    // ── 4. PyPI ────────────────────────────────────────────────────────
    let pypi_body = format!(
        r#"<h3>pip</h3>
{pip}
<p>{p1}</p>
<h3>uv</h3>
<p>{p2}</p>
{uv}
<h3>Poetry</h3>
<p>{p3}</p>
{poetry}
<h3>{publish}</h3>
{twine}
{poetry_pub}"#,
        pip = code(r#"pip config --user set global.index-url "{SCHEME}://token:<TOKEN>@{HOSTPATH}/simple/""#),
        p1 = if ru {
            r#"Пишется в <span class="ds-mac"><code>~/.config/pip/pip.conf</code> (или <code>~/Library/Application Support/pip/pip.conf</code>, если эта папка уже есть)</span><span class="ds-win"><code>%APPDATA%\pip\pip.ini</code></span>, секция <code>[global]</code>, ключ <code>index-url</code>."#
        } else {
            r#"This writes <span class="ds-mac"><code>~/.config/pip/pip.conf</code> (or <code>~/Library/Application Support/pip/pip.conf</code> if that folder already exists)</span><span class="ds-win"><code>%APPDATA%\pip\pip.ini</code></span>, section <code>[global]</code>, key <code>index-url</code>."#
        },
        p2 = tr(
            "uv ignores <code>pip.conf</code>; set its default index in the environment (<code>UV_INDEX_URL</code> is the older, deprecated name of the same setting):",
            "uv не читает <code>pip.conf</code>; задайте индекс по умолчанию через окружение (<code>UV_INDEX_URL</code> — старое, устаревшее имя той же настройки):",
        ),
        uv = per_os(
            r#"echo 'export UV_DEFAULT_INDEX="{SCHEME}://token:$(security find-generic-password -s {HOSTPATH} -a nora -w 2>/dev/null)@{HOSTPATH}/simple/"' >> ~/.zshrc"#,
            "[Environment]::SetEnvironmentVariable('UV_DEFAULT_INDEX', '{SCHEME}://token:<TOKEN>@{HOSTPATH}/simple/', 'User')",
        ),
        p3 = tr(
            "Per project: add the source, then store the credentials once per machine:",
            "В проекте добавьте источник, затем один раз на машине сохраните учётные данные:",
        ),
        poetry = code("poetry source add --priority=primary maestra \"{BASE}/simple/\"\npoetry config http-basic.maestra token <TOKEN>"),
        publish = tr("Publish (write token)", "Публикация (токен write)"),
        twine = code(r#"twine upload --repository-url "{BASE}/simple/" -u token -p <TOKEN> dist/*"#),
        poetry_pub = code("poetry config repositories.maestra \"{BASE}/simple/\"\npoetry publish --build -r maestra"),
    );

    // ── 5. Cooldown ────────────────────────────────────────────────────
    let cooldown_body = if info.cooldown.is_empty() {
        format!(
            "<p>{}</p>",
            tr(
                "No cooldown is enforced on this instance: public versions are served as soon as they are published.",
                "На этом инстансе карантин не включён: публичные версии доступны сразу после публикации.",
            )
        )
    } else {
        let ages: String = info
            .cooldown
            .iter()
            .map(|(label, secs)| {
                format!(
                    r#"<span class="ds-chip">{} &middot; {}</span>"#,
                    label,
                    format_age(*secs, ru)
                )
            })
            .collect();
        let internal: String = info
            .internal_namespaces
            .iter()
            .map(|ns| format!(r#"<span class="ds-chip">{}</span>"#, html_escape(ns)))
            .collect();
        format!(
            r#"<p>{p1}</p><p>{ages}</p>
<p>{p2}</p><p>{internal}</p>
<div class="ds-note">{p3}</div>"#,
            p1 = tr(
                "Public versions younger than the cooldown are hidden from package metadata on purpose, so a freshly published (possibly hijacked) release never reaches us on day one. Your client just resolves the newest version that is old enough.",
                "Публичные версии моложе карантина намеренно скрыты из метаданных пакетов, чтобы только что опубликованный (возможно, угнанный) релиз не попал к нам в первый же день. Клиент просто выбирает самую новую версию, которая уже выдержана.",
            ),
            p2 = tr(
                "Never delayed: everything published here, and these internal names:",
                "Без задержки: всё, что опубликовано здесь, и внутренние имена:",
            ),
            p3 = tr(
                r#"A <b>403</b> with <code>"error": "blocked_by_policy"</code> means you asked for an exact version still inside its cooldown; the body names the package, version and rule. Wait until it ages out or pin the previous version. If you need it now (a security fix), ask the infrastructure team to allow-list <code>name@version</code>."#,
                r#"<b>403</b> с <code>"error": "blocked_by_policy"</code> значит, что запрошена конкретная версия, которая ещё в карантине; в теле ответа указаны пакет, версия и правило. Подождите, пока версия выдержится, или зафиксируйте предыдущую. Если нужна прямо сейчас (фикс уязвимости), попросите команду инфраструктуры добавить <code>name@version</code> в allow-list."#,
            ),
        )
    };

    // ── 6. Troubleshooting ─────────────────────────────────────────────
    let trouble_body = format!(
        r#"<h3>401 Unauthorized</h3>
<p>{p1}</p>
{curl}
<p>{p2}</p>
<h3>403 Forbidden</h3>
<p>{p3}</p>
<h3>{rotate}</h3>
<p>{p4}</p>
{update}
<p>{p5}</p>
{locals}"#,
        p1 = tr(
            "The token is wrong, expired or revoked. Check it directly:",
            "Токен неверный, истёк или отозван. Проверьте его напрямую:",
        ),
        curl = per_os(
            r#"curl -s -o /dev/null -w "%{http_code}\n" -u token:<TOKEN> "{BASE}/nuget/v3/index.json""#,
            r#"curl.exe -s -o NUL -w "%{http_code}\n" -u token:<TOKEN> "{BASE}/nuget/v3/index.json""#,
        ),
        p2 = tr(
            r#"<code>200</code>: the token works, look at the client config. <code>401</code>: open the <a href="/ui/tokens">Tokens</a> page (it lists your tokens with their expiry) and create a new one."#,
            r#"<code>200</code>: токен рабочий, проверьте конфиг клиента. <code>401</code>: откройте страницу <a href="/ui/tokens">Токены</a> (там ваши токены и сроки их жизни) и создайте новый."#,
        ),
        p3 = tr(
            r##"On a push or publish: your token is <b>read</b>, create a <b>write</b> one. With <code>blocked_by_policy</code> in the body: see <a href="#cooldown">Cooldown</a>."##,
            r##"При push или publish: у вас токен <b>read</b>, создайте <b>write</b>. С <code>blocked_by_policy</code> в теле: см. <a href="#cooldown">Карантин</a>."##,
        ),
        rotate = tr("New token or stale metadata", "Новый токен или устаревшие метаданные"),
        p4 = tr(
            "After you mint a new token, rerun the commands above; for NuGet update the existing source:",
            "После выпуска нового токена повторите команды выше; для NuGet обновите существующий источник:",
        ),
        update = per_os(
            "dotnet nuget update source maestra -s \"{BASE}/nuget/v3/index.json\" -u token -p <TOKEN> --store-password-in-clear-text",
            "dotnet nuget update source maestra -s \"{BASE}/nuget/v3/index.json\" -u token -p <TOKEN>",
        ),
        p5 = tr(
            "NuGet caches feed responses for 30 minutes; if a version that just left the cooldown is still not found:",
            "NuGet кэширует ответы фида на 30 минут; если версия, только что вышедшая из карантина, всё ещё не находится:",
        ),
        locals = code("dotnet nuget locals http-cache --clear"),
    );

    let title = tr("Set up your machine", "Настройка машины");
    let content = format!(
        r#"{STYLE}
<div id="ds-root" data-os="mac" class="ds-prose">
    <div class="mb-6">
        <h1 class="text-2xl font-bold text-slate-200 mb-1">{title}</h1>
        <p class="text-slate-400">{subtitle}</p>
    </div>
    <div class="bg-[#1e293b] rounded-lg border border-slate-700 p-4 md:p-6 mb-6">
        <h2 class="text-lg font-semibold text-slate-200">{how}</h2>
        {intro}
        <div class="ds-note">{claude}</div>
    </div>
    {s_token}
    <div class="ds-switches">
        <div class="ds-tabs" role="tablist" aria-label="OS">
            <button type="button" class="ds-tab" role="tab" data-os-tab="mac" aria-selected="true">macOS</button>
            <button type="button" class="ds-tab" role="tab" data-os-tab="win" aria-selected="false">Windows</button>
        </div>
        <div class="ds-tabs ds-tooltabs" role="tablist" aria-label="{tools_label}">
            <button type="button" class="ds-tab" role="tab" id="tab-nuget" aria-controls="nuget" data-tool-tab="nuget" aria-selected="true">NuGet</button>
            <button type="button" class="ds-tab" role="tab" id="tab-npm" aria-controls="npm" data-tool-tab="npm" aria-selected="false">npm</button>
            <button type="button" class="ds-tab" role="tab" id="tab-pypi" aria-controls="pypi" data-tool-tab="pypi" aria-selected="false">PyPI</button>
        </div>
    </div>
    {s_nuget}
    {s_npm}
    {s_pypi}
    {s_cooldown}
    {s_trouble}
</div>"#,
        subtitle = tr(
            "Connect dotnet, npm, pip, uv and Poetry to our package registry. One screen per tool.",
            "Подключите dotnet, npm, pip, uv и Poetry к нашему реестру пакетов. По экрану на инструмент.",
        ),
        how = tr("How it works", "Как это устроено"),
        tools_label = tr("Package manager", "Менеджер пакетов"),
        claude = claude_note(ru),
        s_token = section("token", tr("Get a token", "Получите токен"), &token_body),
        s_nuget = tool_section("nuget", "NuGet (dotnet)", &nuget_body),
        s_npm = tool_section("npm", "npm", &npm_body),
        s_pypi = tool_section("pypi", "PyPI (pip, uv, Poetry)", &pypi_body),
        s_cooldown = section("cooldown", tr("Cooldown for new public versions", "Карантин новых публичных версий"), &cooldown_body),
        s_trouble = section("troubleshooting", tr("Troubleshooting", "Если не работает"), &trouble_body),
    );

    // One substitution pass for every URL on the page, escaped for HTML.
    let base = info.base_url.trim_end_matches('/');
    let (scheme, hostpath) = base.split_once("://").unwrap_or(("https", base));
    let login_href = sanitize_href(info.login_url).unwrap_or("#");
    let content = content
        .replace("{BASE}", &html_escape(base))
        .replace("{SCHEME}", &html_escape(scheme))
        .replace("{HOSTPATH}", &html_escape(hostpath))
        .replace("{LOGIN_HREF}", &html_escape(login_href))
        .replace("{LOGIN}", &html_escape(info.login_url));
    // JS-free mint: the response page carries the token once, in every slot.
    let content = match info.token {
        Some(t) => content.replace(
            TOKEN_MARK,
            &format!(
                r#"<mark class="ds-tok" data-token-slot data-filled>{}</mark>"#,
                html_escape(t)
            ),
        ),
        None => content,
    };

    layout_dark(title, &content, Some("setup"), SCRIPT, lang, auth_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(cooldown: Vec<(&'static str, i64)>) -> SetupInfo<'static> {
        static NS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        SetupInfo {
            base_url: "https://registry.example.test",
            login_url: "https://login.example.test",
            cooldown,
            internal_namespaces: NS.get_or_init(|| vec!["@corp/*".into(), "corp.*".into()]),
            mint: None,
            token: None,
        }
    }

    fn mint(can_write: bool) -> Option<MintOptions> {
        Some(MintOptions {
            can_write,
            description: "dev setup <alice>".into(),
            default_ttl_days: 90,
            max_ttl_days: 3650,
        })
    }

    #[test]
    fn tool_tabs_and_deep_link_ids() {
        for (lang, label) in [
            (Lang::En, "Package manager"),
            (Lang::Ru, "Менеджер пакетов"),
        ] {
            let html = render(lang);
            assert!(html.contains(label));
            for tool in ["nuget", "npm", "pypi"] {
                assert!(
                    html.contains(&format!(r#"data-tool-tab="{tool}""#)),
                    "{tool} tab"
                );
                assert!(html.contains(&format!(r#"aria-controls="{tool}""#)));
                assert!(
                    html.contains(&format!(r#"<section id="{tool}""#)),
                    "#{tool} panel"
                );
                assert!(html.contains(&format!(r#"aria-labelledby="tab-{tool}""#)));
            }
            // Cooldown and Troubleshooting stay plain sections, always visible.
            for id in ["cooldown", "troubleshooting", "token"] {
                let at = html.find(&format!(r#"<section id="{id}""#)).expect(id);
                let tag = &html[at..at + html[at..].find('>').unwrap()];
                assert!(!tag.contains("ds-tool"), "{id} must not be a tab panel");
            }
            assert!(
                html.contains("nora_setup_tool"),
                "tool choice is remembered"
            );
            assert!(html.contains("location.hash"), "deep links select the tab");
        }
    }

    #[test]
    fn token_slots_carry_the_js_hook() {
        let html = render(Lang::En);
        assert!(html.matches("data-token-slot").count() > 10);
        // The prose label ("replace every <TOKEN>") is never filled.
        assert!(html.contains(TOKEN_LABEL));
        assert!(html.contains("querySelectorAll('[data-token-slot]')"));
    }

    #[test]
    fn mint_form_follows_the_callers_role() {
        let mut i = info(vec![]);
        assert!(!render_setup_page(&i, Lang::En, true).contains(r#"id="ds-mint""#));
        i.mint = mint(false);
        let html = render_setup_page(&i, Lang::En, true);
        assert!(html.contains(r#"action="/api/ui/tokens/create""#));
        assert!(html.contains(r#"name="ui" value="setup""#));
        assert!(
            html.contains("dev setup &lt;alice&gt;"),
            "description escaped"
        );
        assert!(!html.contains(r#"<option value="write">"#));
        assert!(html.contains(r#"id="ds-minted" class="ds-warn" hidden"#));
        i.mint = mint(true);
        let html = render_setup_page(&i, Lang::Ru, true);
        assert!(html.contains(r#"<option value="write">"#));
        assert!(html.contains("Выпустить токен"));
        assert!(html.contains("Скрыть токен"));
    }

    #[test]
    fn js_free_post_fills_every_slot_once() {
        let mut i = info(vec![]);
        i.mint = mint(true);
        i.token = Some("nra_abc123");
        let html = render_setup_page(&i, Lang::En, true);
        assert!(!html.contains(TOKEN_MARK), "every slot filled");
        assert!(html.contains(r#"data-token-slot data-filled>nra_abc123</mark>"#));
        assert!(html.contains(r#"-p <mark class="ds-tok" data-token-slot data-filled>nra_abc123"#));
        assert!(
            html.contains(r#"id="ds-minted" class="ds-warn">"#),
            "box shown"
        );
        assert!(html.contains(r#"class="ds-mint" hidden"#), "form hidden");
        assert!(html.contains("shown once"));
    }

    fn render(lang: Lang) -> String {
        render_setup_page(
            &info(vec![("NuGet", 3 * 86_400), ("npm", 7 * 86_400)]),
            lang,
            true,
        )
    }

    #[test]
    fn renders_both_languages() {
        let en = render(Lang::En);
        assert!(en.contains("Set up your machine"));
        assert!(en.contains("How it works"));
        let ru = render(Lang::Ru);
        assert!(ru.contains("Настройка машины"));
        assert!(ru.contains("Как это устроено"));
        assert!(!ru.contains("How it works"));
        // Other languages fall back to English.
        assert!(render(Lang::Zh).contains("How it works"));
    }

    #[test]
    fn has_both_os_tabs_and_variants() {
        let html = render(Lang::En);
        assert!(html.contains(r#"data-os-tab="mac""#));
        assert!(html.contains(r#"data-os-tab="win""#));
        assert!(html.contains("nora_setup_os"), "OS choice is remembered");
        // macOS needs the clear-text flag, Windows encrypts.
        assert!(html.contains("~/.nuget/NuGet/NuGet.Config"));
        assert!(html.contains(r"%APPDATA%\NuGet\NuGet.Config"));
        assert!(html.contains(r"%APPDATA%\pip\pip.ini"));
        assert!(html.contains("curl.exe"));
    }

    #[test]
    fn public_url_substituted_everywhere() {
        let html = render(Lang::En);
        for placeholder in [
            "{BASE}",
            "{SCHEME}",
            "{HOSTPATH}",
            "{LOGIN}",
            "{LOGIN_HREF}",
        ] {
            assert!(
                !html.contains(placeholder),
                "{placeholder} left unsubstituted"
            );
        }
        assert!(html.contains("https://registry.example.test/nuget/v3/index.json"));
        assert!(html.contains("registry=https://registry.example.test/npm/"));
        assert!(html.contains("//registry.example.test/npm/:_authToken="));
        assert!(html.contains("https://token:"));
        assert!(html.contains("@registry.example.test/simple/"));
        assert!(html.contains(r#"href="https://login.example.test""#));
    }

    #[test]
    fn public_url_with_sub_path() {
        let mut i = info(vec![]);
        i.base_url = "http://host.test/nora/";
        let html = render_setup_page(&i, Lang::En, true);
        assert!(html.contains("http://host.test/nora/npm/"));
        assert!(html.contains("//host.test/nora/npm/:_authToken="));
        assert!(html.contains("http://token:"));
    }

    #[test]
    fn no_hardcoded_host() {
        for lang in [Lang::En, Lang::Ru] {
            let html = render(lang);
            assert!(!html.contains("maestra.io"), "hardcoded host in {lang:?}");
        }
    }

    /// Same commands as the skillz `packages` plugin's dev-setup.sh / dev-setup.ps1.
    #[test]
    fn matches_dev_setup_scripts() {
        let html = render(Lang::En);
        assert!(html.contains("-n maestra -u token -p"));
        assert!(html.contains("dotnet nuget disable source nuget.org"));
        assert!(html.contains("dotnet nuget enable source nuget.org"));
        assert!(html.contains("export UV_DEFAULT_INDEX="));
        assert!(html.contains("SetEnvironmentVariable(&#39;UV_DEFAULT_INDEX&#39;"));
        assert!(html.contains("security add-generic-password -U -s registry.example.test -a nora"));
        assert!(html.contains("NuGetPackageSourceCredentials_private"));
        assert!(html.contains("http-basic.maestra"));
        assert!(html.contains("/packages:packages-dev-setup"));
        assert!(html.contains("/plugin marketplace add git@github.com:maestra-io/skillz.git"));
        assert!(html.contains("/plugin install packages@maestra-plugins"));
        assert!(html.contains("/plugin update packages@maestra-plugins"));
        assert!(html.contains("delivery@maestra-plugins"));
        assert!(render(Lang::Ru).contains("Перезапустите Claude Code."));
        assert!(html.contains(r#"href="/ui/tokens""#));
    }

    #[test]
    fn token_placeholder_highlighted() {
        let html = render(Lang::En);
        assert!(html.contains(TOKEN_MARK));
        assert!(
            !html.contains("<TOKEN>"),
            "raw <TOKEN> would be an HTML tag"
        );
    }

    #[test]
    fn cooldown_from_config() {
        let html = render(Lang::En);
        assert!(html.contains("NuGet &middot; 3 d"));
        assert!(html.contains("npm &middot; 7 d"));
        assert!(html.contains("@corp/*"));
        assert!(html.contains("blocked_by_policy"));
        let off = render_setup_page(&info(vec![]), Lang::En, true);
        assert!(off.contains("No cooldown is enforced"));
    }

    #[test]
    fn unsafe_login_url_not_linked() {
        let mut i = info(vec![]);
        i.login_url = "javascript:alert(1)";
        let html = render_setup_page(&i, Lang::En, true);
        assert!(!html.contains(r#"href="javascript:"#));
    }

    #[test]
    fn cta_links_to_setup() {
        assert!(render_setup_cta(Lang::En).contains(r#"href="/ui/setup""#));
        assert!(render_setup_cta(Lang::Ru).contains("Настройте свою машину"));
    }
}
