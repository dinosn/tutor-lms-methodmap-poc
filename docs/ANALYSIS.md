# Analysis — Tutor LMS ≤ 4.0.5 `method_map` unauthenticated function execution

Deep walk-through of the vulnerability, the two reachable routes, the execution-scope asymmetry that
governs the account-creation escalation, and the general pattern for reuse.

## 1. The sink

`templates/single-content-loader.php` builds a hard-coded dispatch table, then `extract()`s an
attacker-controlled array over it, then calls the selected entry with no arguments:

```php
$method_map = array(
    'lesson'     => 'tutor_lesson_content',
    'assignment' => 'tutor_assignment_content',
);
// ...
extract( $data );   // $data is attacker-controlled -> overwrites $method_map and sets $context
// ...
( isset( $method_map[ $context ] ) && is_callable( $method_map[ $context ] ) ) ? $method_map[ $context ]() : 0;
```

Send `data[method_map][X] = <callable>` and `data[context] = X`, and `$method_map[$context]()`
becomes `<callable>()`. The only gate is `is_callable()`. The return value is discarded, so only
callables that **print** or **side-effect via superglobals** are observable/useful.

## 2. Reaching the sink — `extract()` clobbering the template name

`single-content-loader.php` is normally included only for real lessons/quizzes. It is reachable with an
arbitrary `$data` because `tutor_load_template()` `extract()`s its variables **before** it resolves the
template name:

```php
function tutor_load_template( $template = null, $variables = array(), $tutor_pro = false ) {
    $variables = (array) $variables;
    $variables = apply_filters( 'get_tutor_load_template_variables', $variables );
    extract( $variables );                       // (:118) attacker 'template' key overwrites $template
    // ...
    $template_file = tutor_get_template( $template );  // (:126) now 'single-content-loader'
    include $template_file;                      // (:128) includes the sink template, $data in scope
}
```

So any caller that forwards a request-derived array (containing `template` and `data` keys) as
`$variables` yields full control of both the template *and* `$data`.

## 3. The two unauthenticated callers

### 3a. Front-end course archive — `templates/archive-course.php`

```php
$get = isset($_GET['course_filter']) ? Input::sanitize_array($_GET) : array();   // keeps 'template','data'
if ( isset($get['course_filter']) ) {
    $filter = ( new \Tutor\Course_Filter(false) )->load_listing($get, true);      // $return_filter=true => nonce SKIPPED
    query_posts($filter);
}
tutor_load_template(
    'archive-course-init',
    array_merge( $get, array('course_filter'=>..., 'supported_filters'=>..., 'loop_content_only'=>false) )
);
```

`array_merge($get, [...])` lists `$get` first, and the fixed keys don't collide with `template` / `data`,
so those survive into `extract()`. Reached by `GET /courses/?course_filter=1&...`. **No nonce** —
`load_listing($get, true)` is called with `$return_filter = true`, which skips `checking_nonce()`.
The archive page is selected by `Template::load_course_archive_template()` (a `template_include` filter)
for the public course post-type archive.

This route runs as a **normal front-end page** — `WP_ADMIN` is not defined, so `wp-admin/includes` is
not loaded.

### 3b. admin-ajax — `Course_Filter::load_listing()`

```php
add_action('wp_ajax_nopriv_tutor_course_filter_ajax', array($this, 'load_listing'), 10, 0);   // :58
// ...
public function load_listing($filters = null, $return_filter = false) {
    ! $return_filter ? tutils()->checking_nonce() : 0;                    // nonce required on this path
    $sanitized_post = tutor_sanitize_data($_POST);                       // keeps 'template','data'
    // ...
    tutor_load_template('archive-course-init', array_merge(['loop_content_only'=>true], $sanitized_post));  // :224
}
```

Reached by `POST /wp-admin/admin-ajax.php` with `action=tutor_course_filter_ajax`. The nonce is real but
**self-serve**: Tutor localizes `_tutor_nonce` into `_tutorobject` for every logged-out visitor
(`Assets.php`), so an attacker just scrapes it from any page and replays it in the same anonymous
session. It is CSRF decoration, not authorization.

This route runs under `/wp-admin/admin-ajax.php`, which:

```php
if ( ! defined('WP_ADMIN') ) define('WP_ADMIN', true);         // admin-ajax.php:17-18
require_once ABSPATH . 'wp-admin/includes/admin.php';          // admin-ajax.php:36
```

and `wp-admin/includes/admin.php` `require_once`s `template.php` (`wp_dropdown_roles`) and `user.php`
(`edit_user`, `wp_create_user`, `add_new_user_to_blog`). **This is the only reachable scope where those
functions exist.** (Verified in the lab: WP 6.6.2 `admin-ajax.php` loads `admin.php` → `user.php:85`.)

### 3c. Everything else is safe

The other `wp_ajax_nopriv_*` handlers do **not** reach the sink: `load_filtered_instructor`,
`show_more`, `tutor_render_lesson_content`, review `load_more`, etc. all pass a **fixed-key** variable
array (or a hard-coded template name), so no `template`/`data` key reaches `extract()`. The
`[tutor_course]` shortcode path likewise passes an explicit allowlist. The archive and the
`tutor_course_filter_ajax` handler are the only two routes that spread the request into the template
variables.

## 4. Impact ceiling and the `edit_user` escalation

The dispatch passes **no arguments**, so this is not shell RCE:

- Arg-taking functions raise `ArgumentCountError` (PHP 8) → nothing happens.
- Class-method callables are broken by WordPress magic-quotes backslash-doubling.

Useful gadgets are therefore **zero-argument functions that either print or read superglobals**:

| Gadget | Scope | Effect |
|--------|-------|--------|
| `phpinfo`, `phpcredits`, `debug_print_backtrace`, `get_defined_vars` | front-end + ajax | configuration / path / state disclosure |
| bad `template` name | front-end + ajax | absolute-path disclosure via the not-found notice |
| `retrieve_password` | front-end + ajax | reads `$_POST['user_login']` → triggers a password-reset email (unauth) |
| **`edit_user`** | **ajax only** | `edit_user($user_id = 0)` → *create* branch, reads `user_login`/`pass1`/`pass2`/`email` from `$_POST` → **creates a persistent subscriber, no nonce, no capability check** |

### Why subscriber, not administrator

`edit_user()` only assigns a role from `$_POST['role']` when
`current_user_can('promote_users' / 'edit_users')`. An anonymous caller (user 0) has no capabilities, so
that branch is skipped and the new user falls back to `get_option('default_role')` — `subscriber` on a
stock install. Sending `role=administrator` is ignored. The result is still an unauthenticated,
persistent, authenticated foothold — a pivot for any authentication-gated vulnerability — created even
when `users_can_register = 0`.

### Deployment dependence

Account creation needs both (a) the sink reached in (b) admin-ajax scope. On a default install both
hold, and the lab proves the create end to end (login returns a `wordpress_logged_in` cookie, confirmed
by an independent `wp user list`). Some hardened deployments neutralize the injection specifically on the
`tutor_course_filter_ajax` action (edge WAF / mu-plugin) while leaving the front-end `/courses/` route
open — there, only disclosure-grade impact is reachable, because the front-end scope lacks `edit_user`.
The PoC's `--scope-probe` distinguishes the two.

## 5. The general pattern (for variant hunting)

The bug is an instance of: **`extract()` of a request-controlled array into a template that then uses a
request-controlled key to select a callable.** When auditing any plugin/theme for the same class:

1. Find `extract(` calls whose argument derives from `$_GET`/`$_POST`/`$_REQUEST` (directly or via a
   sanitizer that preserves keys).
2. From each, check whether a following `include`/`require` uses a variable filename, or whether a
   later template does a second `extract(` + `$callable[$key]()` / `call_user_func` / variable-function
   dispatch.
3. Tie gadget availability to execution scope: functions in `wp-admin/includes/*` exist only under
   `WP_ADMIN` (admin-ajax, admin-post, admin pages), not on front-end requests.

The PoC's parameter flags (`--template-param`, `--data-param`, `--methodmap-key`, `--context-key`,
`--ajax-action`, `--archive-path`) let it drive any such dispatch without code changes.
