#!/usr/bin/env bash
# Idempotent wp-cli provisioner for the Tutor LMS method_map lab.
# Installs WordPress, pins Tutor LMS 4.0.4, seeds a published course, and enables
# pretty permalinks so the /courses/ archive (the front-end exploit route) resolves.
set -euo pipefail

PORT="${WP_PORT:-8099}"
URL="http://localhost:${PORT}"
TITLE="Tutor method_map lab"
ADMIN_USER="admin"
ADMIN_PASS="admin-lab-pass"
ADMIN_EMAIL="admin@example.com"
TUTOR_VERSION="4.0.4"

cd /var/www/html

echo "[*] waiting for wp core files to appear (wp container unpacks them)..."
for i in $(seq 1 60); do [ -f wp-load.php ] && break; sleep 2; done

wpx() { wp --allow-root --path=/var/www/html "$@"; }

if ! wpx core is-installed 2>/dev/null; then
  echo "[*] installing WordPress core..."
  wpx core install --url="$URL" --title="$TITLE" \
      --admin_user="$ADMIN_USER" --admin_password="$ADMIN_PASS" --admin_email="$ADMIN_EMAIL" \
      --skip-email
else
  echo "[*] WordPress already installed."
fi

# Pretty permalinks — required for the /courses/ CPT archive route.
wpx option update permalink_structure '/%postname%/' >/dev/null
wpx option update blogname "$TITLE" >/dev/null
# keep a real default_role so the edit_user escalation lands a 'subscriber'
wpx option update default_role 'subscriber' >/dev/null
wpx option update users_can_register 0 >/dev/null   # prove the bug bypasses closed registration

# Pin Tutor LMS to the vulnerable 4.0.4.
if ! wpx plugin is-installed tutor 2>/dev/null; then
  echo "[*] installing Tutor LMS ${TUTOR_VERSION}..."
  wpx plugin install "https://downloads.wordpress.org/plugin/tutor.${TUTOR_VERSION}.zip" --activate
else
  wpx plugin activate tutor >/dev/null 2>&1 || true
fi
INSTALLED_VER="$(wpx plugin get tutor --field=version 2>/dev/null || echo '?')"
echo "[*] Tutor LMS version: ${INSTALLED_VER}"

# Seed one published course so the archive is non-empty (not required for the bug,
# but makes the lab render like a real site).
if ! wpx post list --post_type=courses --field=ID 2>/dev/null | grep -q .; then
  echo "[*] seeding a sample course..."
  wpx post create --post_type=courses --post_status=publish \
      --post_title="Sample Course" --post_content="Lab course." >/dev/null 2>&1 || \
    echo "[!] course seed skipped (post type may register on next request)"
fi

wpx rewrite flush --hard >/dev/null 2>&1 || true

echo
echo "=========================================================================="
echo " Lab ready:  ${URL}"
echo "   wp-admin: ${URL}/wp-admin/   (${ADMIN_USER} / ${ADMIN_PASS})"
echo "   Tutor LMS ${INSTALLED_VER}  (vulnerable: <= 4.0.5)"
echo
echo " Reproduce (read-only):"
echo "   python3 ../poc/tutor_methodmap_poc.py ${URL}"
echo " Escalation (creates a subscriber via edit_user, admin-ajax route):"
echo "   python3 ../poc/tutor_methodmap_poc.py ${URL} --create-user --i-understand-this-creates-a-user"
echo "=========================================================================="
