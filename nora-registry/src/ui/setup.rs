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
}

const TOKEN_MARK: &str = r#"<mark class="ds-tok">&lt;TOKEN&gt;</mark>"#;

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
    format!(
        r#"<section id="{id}" class="bg-[#1e293b] rounded-lg border border-slate-700 p-4 md:p-6 mb-6 ds-prose">
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
.ds-pills { display: flex; flex-wrap: wrap; gap: .5rem; }
.ds-pills a { font-size: .8rem; padding: .3rem .7rem; border-radius: 9999px; border: 1px solid #334155; color: #cbd5e1; }
.ds-pills a:hover { border-color: #60a5fa; color: #fff; }
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
    var tabs = document.querySelectorAll('[data-os-tab]');
    function set(os) {
        root.setAttribute('data-os', os);
        tabs.forEach(function (t) { t.setAttribute('aria-selected', String(t.getAttribute('data-os-tab') === os)); });
        try { localStorage.setItem('nora_setup_os', os); } catch (e) {}
    }
    var saved = null;
    try { saved = localStorage.getItem('nora_setup_os'); } catch (e) {}
    set(saved === 'mac' || saved === 'win' ? saved : (/Win/.test(navigator.platform) ? 'win' : 'mac'));
    tabs.forEach(function (t) { t.addEventListener('click', function () { set(t.getAttribute('data-os-tab')); }); });
})();
</script>"#;

/// Renders `/ui/setup`.
pub fn render_setup_page(info: &SetupInfo, lang: Lang, auth_enabled: bool) -> String {
    let ru = lang == Lang::Ru;
    let tr = |en: &'static str, ru_text: &'static str| if ru { ru_text } else { en };
    let tok = TOKEN_MARK;

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
    let token_body = if ru {
        format!(
            r#"<ol>
<li>Откройте UI через Teleport: <a href="{{LOGIN_HREF}}" target="_blank" rel="noopener">{{LOGIN}}</a>, вход через GitHub SSO.</li>
<li>Страница <a href="/ui/tokens">Токены</a> &rarr; «Создать токен»: описание (например, имя ноутбука), роль <b>read</b> для установки пакетов, <b>write</b> только если вы публикуете пакеты (доступна с ролью Teleport <code>apps</code>), срок жизни в днях.</li>
<li>Скопируйте токен сразу: он показывается один раз. Токены выглядят как <code>nra_…</code>; ниже везде вместо {tok} подставьте его.</li>
</ol>
<div class="ds-note">Пароли снаружи не принимаются: клиенты пакетов отправляют только токен (имя пользователя любое, мы пишем <code>token</code>). В GitHub Actions токен не нужен: workflow авторизуются через GitHub OIDC, личный токен в секреты CI не кладите.</div>"#
        )
    } else {
        format!(
            r#"<ol>
<li>Open the UI through Teleport: <a href="{{LOGIN_HREF}}" target="_blank" rel="noopener">{{LOGIN}}</a>, sign in with GitHub SSO.</li>
<li><a href="/ui/tokens">Tokens</a> page &rarr; Create token: a description (e.g. your laptop's name), role <b>read</b> to install packages, <b>write</b> only if you publish (available with the Teleport role <code>apps</code>), expiry in days.</li>
<li>Copy the token right away, it is shown once. Tokens look like <code>nra_…</code>; replace every {tok} below with it.</li>
</ol>
<div class="ds-note">Passwords are not accepted from outside: package clients send only the token (any username, we use <code>token</code>). GitHub Actions need no token: workflows authenticate with GitHub OIDC, so never put a personal token into CI secrets.</div>"#
        )
    };

    // ── 2. NuGet ───────────────────────────────────────────────────────
    let nuget_body = format!(
        r#"<p>{p1}</p>
{add}
<p>{p2}</p>
<div class="ds-note">{p3}</div>
<h3>{publish}</h3>
{push}"#,
        p1 = tr(
            "Add the feed to your user-level NuGet config once:",
            "Один раз добавьте фид в пользовательский конфиг NuGet:",
        ),
        add = per_os(
            r#"dotnet nuget add source "{BASE}/nuget/v3/index.json" --name private --username token --password <TOKEN> --store-password-in-clear-text"#,
            r#"dotnet nuget add source "{BASE}/nuget/v3/index.json" --name private --username token --password <TOKEN>"#,
        ),
        p2 = if ru {
            r#"<span class="ds-mac">Пишется в <code>~/.nuget/NuGet/NuGet.Config</code>. На macOS NuGet не умеет шифровать пароли, поэтому флаг <code>--store-password-in-clear-text</code> обязателен, а токен лежит в файле открытым текстом.</span><span class="ds-win">Пишется в <code>%APPDATA%\NuGet\NuGet.Config</code>. На Windows NuGet шифрует пароль (только для вас и этой машины), поэтому флаг <code>--store-password-in-clear-text</code> не нужен.</span>"#
        } else {
            r#"<span class="ds-mac">This writes <code>~/.nuget/NuGet/NuGet.Config</code>. NuGet can encrypt passwords only on Windows, so on macOS <code>--store-password-in-clear-text</code> is required and the token sits in the file as plain text.</span><span class="ds-win">This writes <code>%APPDATA%\NuGet\NuGet.Config</code>. On Windows NuGet encrypts the password (for you on this machine only), so <code>--store-password-in-clear-text</code> is not needed.</span>"#
        },
        p3 = tr(
            "Our repositories pin the feed in their own <code>nuget.config</code> with <code>&lt;clear/&gt;</code> under the key <code>private</code>. <code>&lt;clear/&gt;</code> drops your user-level sources, but credentials are matched by source name, so keep the name <code>private</code> exactly.",
            "Наши репозитории фиксируют фид в своём <code>nuget.config</code> с <code>&lt;clear/&gt;</code> под ключом <code>private</code>. <code>&lt;clear/&gt;</code> отбрасывает ваши пользовательские источники, но учётные данные сопоставляются по имени источника, поэтому имя должно быть ровно <code>private</code>.",
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
            r#"echo 'export UV_DEFAULT_INDEX="{SCHEME}://token:<TOKEN>@{HOSTPATH}/simple/"' >> ~/.zshrc"#,
            r#"setx UV_DEFAULT_INDEX "{SCHEME}://token:<TOKEN>@{HOSTPATH}/simple/""#,
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
            "dotnet nuget update source private --username token --password <TOKEN> --store-password-in-clear-text",
            "dotnet nuget update source private --username token --password <TOKEN>",
        ),
        p5 = tr(
            "NuGet caches feed responses for 30 minutes; if a version that just left the cooldown is still not found:",
            "NuGet кэширует ответы фида на 30 минут; если версия, только что вышедшая из карантина, всё ещё не находится:",
        ),
        locals = code("dotnet nuget locals http-cache --clear"),
    );

    let nav = [
        ("token", tr("Token", "Токен")),
        ("nuget", "NuGet"),
        ("npm", "npm"),
        ("pypi", "PyPI"),
        ("cooldown", tr("Cooldown", "Карантин")),
        ("troubleshooting", tr("Troubleshooting", "Если не работает")),
    ]
    .iter()
    .map(|(id, label)| format!(r##"<a href="#{id}">{label}</a>"##))
    .collect::<String>();

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
    </div>
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
        <div class="ds-tabs" role="tablist" aria-label="OS">
            <button type="button" class="ds-tab" role="tab" data-os-tab="mac" aria-selected="true">macOS</button>
            <button type="button" class="ds-tab" role="tab" data-os-tab="win" aria-selected="false">Windows</button>
        </div>
        <nav class="ds-pills">{nav}</nav>
    </div>
    {s_token}
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
        s_token = section("token", tr("1. Get a token", "1. Получите токен"), &token_body),
        s_nuget = section("nuget", "2. NuGet (dotnet)", &nuget_body),
        s_npm = section("npm", "3. npm", &npm_body),
        s_pypi = section("pypi", "4. PyPI (pip, uv, Poetry)", &pypi_body),
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
        }
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
