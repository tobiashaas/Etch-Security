<?php
/**
 * Plugin Name: Etch Security
 * Plugin URI:  https://github.com/tobiashaas/Etch-Security
 * Description: Two protection layers in one file: (1) User Guard — only allowed
 *              email domains get an account, foreign accounts are immediately
 *              neutralized (also for programmatic creation / privilege escalation);
 *              (2) Audit Log — self-hosted, persistent security log (actor, IP,
 *              request) independent of premium plugins. Keeps itself up to date
 *              via GitHub releases. View: Tools → Etch Security.
 * Version:     1.1.1
 * Author:      Tobias Haas
 *
 * 1.1.1: Self-updater switched from api.github.com (60 req/h per IP → 403
 *        "rate limit exceeded" on shared hosting) to raw.githubusercontent.com
 *        (CDN, no API limit). Source of truth = the file on `main`; version is
 *        read directly from it.
 * 1.1.0: Module "Core Updates" — forces WordPress minor/security auto-updates
 *        even when a management tool (e.g. Installatron) has disabled them via
 *        filter. Only point releases of the same X.Y branch; major updates are
 *        left untouched. Reason: a blocked forced security update left the site
 *        on an unauthenticated-RCE-vulnerable core version for 3 days.
 * Author URI:  https://github.com/tobiashaas
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Update URI:  https://github.com/tobiashaas/Etch-Security
 *
 * Designed as an mu-plugin (wp-content/mu-plugins/etch-security.php): a
 * compromised admin cannot deactivate it — the guard stays active. It works
 * equally well as a regular plugin (the update notice then appears on the
 * Plugins screen; as an mu-plugin the update runs silently via cron).
 *
 * CONFIGURATION (all optional, safe defaults):
 *   define('ETCH_SECURITY_ALLOWED_DOMAINS', 'example.com,partner.com'); // in wp-config.php
 *   — OR — manage in the backend under Tools → Etch Security.
 *   The domain of the site admin address is ALWAYS allowed (no self-lockout).
 *   Enforcement is OFF as long as no domain is configured: the audit log runs
 *   immediately (read-only, harmless), the guard only activates after configuration.
 */

if (!defined('ABSPATH')) exit;

if (!defined('ETCH_SECURITY_VERSION')) define('ETCH_SECURITY_VERSION', '1.1.1');
if (!defined('ETCH_SECURITY_REPO'))    define('ETCH_SECURITY_REPO', 'tobiashaas/Etch-Security');
if (!defined('ETCH_SECURITY_FILE'))    define('ETCH_SECURITY_FILE', __FILE__);


/* =============================================================================
 * 0) Shared Configuration
 * ========================================================================== */

final class EtchSecurity_Config
{
    const OPT_DOMAINS = 'etch_security_allowed_domains';   // array of domains
    const OPT_ENFORCE = 'etch_security_enforce';           // '1' | '0'
    const OPT_CORE_UPDATES = 'etch_security_force_core_updates'; // '1' | '0' (default on)

    /** Configured domains (option, plus constant as initial default). */
    public static function configured_domains()
    {
        $opt = get_option(self::OPT_DOMAINS, null);
        if ($opt === null && defined('ETCH_SECURITY_ALLOWED_DOMAINS')) {
            $opt = self::parse(ETCH_SECURITY_ALLOWED_DOMAINS);
        }
        return is_array($opt) ? $opt : array();
    }

    /**
     * Effective allowlist: configured domains + the domain of the site admin
     * address (always, to prevent self-lockout) + filter for programmatic use.
     */
    public static function allowed_domains()
    {
        $domains = self::configured_domains();

        $admin = strtolower((string) get_option('admin_email'));
        $at = strrpos($admin, '@');
        if ($at !== false) $domains[] = substr($admin, $at + 1);

        /** @return string[] List of allowed domains (lowercased). */
        $domains = apply_filters('etch_security_allowed_domains', $domains);

        return array_values(array_unique(array_filter(array_map('strtolower', (array) $domains))));
    }

    /** Enforcement only when enabled AND at least one domain is configured. */
    public static function enforcing()
    {
        if (get_option(self::OPT_ENFORCE, '0') !== '1') return false;
        return count(self::configured_domains()) > 0;
    }

    /** Force core security auto-updates (default on). */
    public static function force_core_updates()
    {
        return get_option(self::OPT_CORE_UPDATES, '1') === '1';
    }

    public static function is_allowed($email)
    {
        $email = strtolower(trim((string) $email));
        if ($email === '') return false;
        $at = strrpos($email, '@');
        if ($at === false) return false;
        return in_array(substr($email, $at + 1), self::allowed_domains(), true);
    }

    /** "a.com, b.de\nc.org" -> ['a.com','b.de','c.org'] */
    public static function parse($raw)
    {
        $parts = preg_split('/[\s,;]+/', (string) $raw, -1, PREG_SPLIT_NO_EMPTY);
        $out = array();
        foreach ($parts as $p) {
            $p = strtolower(ltrim(trim($p), '@'));
            if ($p !== '') $out[] = $p;
        }
        return array_values(array_unique($out));
    }
}


/* =============================================================================
 * 1) User Guard — Domain Allowlist + Backstop
 * ========================================================================== */

final class EtchSecurity_User_Guard
{
    const FLAG_META = 'etch_security_neutralized';
    private static $busy = false;

    public static function boot()
    {
        // Layer 1 — Prevention on the regular paths.
        add_filter('rest_pre_insert_user',       array(__CLASS__, 'guard_rest'), 10, 2);
        add_action('user_profile_update_errors', array(__CLASS__, 'guard_profile'), 10, 3);
        add_filter('registration_errors',        array(__CLASS__, 'guard_registration'), 10, 3);

        // Layer 2 — Backstop, also catches wp_insert_user() + escalation.
        add_action('user_register', array(__CLASS__, 'backstop'), PHP_INT_MAX, 1);
        add_action('set_user_role', array(__CLASS__, 'watch_role'), PHP_INT_MAX, 3);
    }

    private static function refusal()
    {
        $list = EtchSecurity_Config::allowed_domains();
        return sprintf(
            /* translators: %s = list of allowed domains */
            __('This email address is not allowed. Accounts are restricted to %s.', 'etch-security'),
            '@' . implode(', @', $list)
        );
    }

    // ---------------------------------------------------------------- Layer 1

    public static function guard_rest($prepared_user, $request)
    {
        if (!EtchSecurity_Config::enforcing()) return $prepared_user;
        $email = isset($prepared_user->user_email) ? $prepared_user->user_email : '';
        if ($email !== '' && !EtchSecurity_Config::is_allowed($email)) {
            EtchSecurity_Audit_Log::log('guard_blocked', array('login' => $email),
                array('path' => 'rest', 'email' => $email));
            return new WP_Error('etch_security_user_guard', self::refusal(), array('status' => 403));
        }
        return $prepared_user;
    }

    public static function guard_profile($errors, $update, $user)
    {
        if (!EtchSecurity_Config::enforcing()) return;
        $email = isset($user->user_email) ? $user->user_email : '';
        if ($email === '') return;

        if ($update && !empty($user->ID)) {
            $current = get_userdata($user->ID);
            if ($current && strtolower($current->user_email) === strtolower($email)) return; // unchanged
        }
        if (!EtchSecurity_Config::is_allowed($email)) {
            $errors->add('etch_security_user_guard', self::refusal());
            EtchSecurity_Audit_Log::log('guard_blocked',
                array('id' => isset($user->ID) ? (int) $user->ID : 0, 'login' => $email),
                array('path' => 'profile', 'email' => $email));
        }
    }

    public static function guard_registration($errors, $login, $email)
    {
        if (!EtchSecurity_Config::enforcing()) return $errors;
        if ($email !== '' && !EtchSecurity_Config::is_allowed($email)) {
            $errors->add('etch_security_user_guard', self::refusal());
            EtchSecurity_Audit_Log::log('guard_blocked', array('login' => $email),
                array('path' => 'registration', 'email' => $email));
        }
        return $errors;
    }

    // ---------------------------------------------------------------- Layer 2

    public static function backstop($user_id)
    {
        if (self::$busy || !EtchSecurity_Config::enforcing()) return;
        $user = get_userdata($user_id);
        if (!$user || EtchSecurity_Config::is_allowed($user->user_email)) return;
        self::neutralize($user, 'user_register');
    }

    public static function watch_role($user_id, $role, $old_roles)
    {
        if (self::$busy || !EtchSecurity_Config::enforcing()) return;
        $user = get_userdata($user_id);
        if (!$user) return;
        if (!EtchSecurity_Config::is_allowed($user->user_email)) {
            self::neutralize($user, 'set_user_role:' . $role);
        }
    }

    /** Disable account without deleting it (preserved as evidence). */
    private static function neutralize($user, $trigger)
    {
        self::$busy = true;

        $wp_user = new WP_User($user->ID);
        $wp_user->set_role('');
        wp_set_password(wp_generate_password(64, true, true), $user->ID);
        $tokens = WP_Session_Tokens::get_instance($user->ID);
        if ($tokens) $tokens->destroy_all();
        update_user_meta($user->ID, self::FLAG_META, current_time('mysql'));

        self::$busy = false;

        EtchSecurity_Audit_Log::log('guard_neutralized',
            array('id' => $user->ID, 'login' => $user->user_login),
            array('trigger' => $trigger, 'email' => $user->user_email));

        self::notify($user, $trigger);
    }

    private static function notify($user, $trigger)
    {
        $to = get_option('admin_email');
        if (!$to) return;
        $brand = get_bloginfo('name') ?: 'Etch Security';
        $body = sprintf(
            "An account with a disallowed domain was created and immediately neutralized.\n\n"
            . "User:        %s\nEmail:       %s\nID:          %d\nTriggered by: %s\nTime:        %s\nIP:          %s\n\n"
            . "Status: role stripped, password invalidated, sessions terminated.\n"
            . "The account was NOT deleted — it is preserved as evidence.\n"
            . "Details: Tools → Etch Security.",
            $user->user_login, $user->user_email, $user->ID, $trigger,
            current_time('mysql'), EtchSecurity_Util::ip()
        );
        wp_mail($to, '[' . $brand . '] ' . __('Foreign user blocked', 'etch-security') . ': ' . $user->user_login, $body);
    }
}


/* =============================================================================
 * 2) Audit Log — persistent, self-hosted security log
 * ========================================================================== */

final class EtchSecurity_Audit_Log
{
    const TABLE       = 'etch_security_audit';
    const DB_VERSION  = '1';
    const DB_OPTION   = 'etch_security_audit_db_version';
    const RETAIN_DAYS = 180;
    const CRON_HOOK   = 'etch_security_audit_prune';

    public static function boot()
    {
        add_action('plugins_loaded', array(__CLASS__, 'maybe_install'));

        // Accounts
        add_action('user_register',   array(__CLASS__, 'on_user_register'), 5, 1);
        add_action('profile_update',  array(__CLASS__, 'on_profile_update'), 5, 2);
        add_action('set_user_role',   array(__CLASS__, 'on_set_role'), 5, 3);
        add_action('deleted_user',    array(__CLASS__, 'on_deleted_user'), 5, 3);
        add_action('wp_create_application_password', array(__CLASS__, 'on_app_password'), 5, 2);
        // Authentication
        add_action('wp_login',        array(__CLASS__, 'on_login'), 5, 2);
        add_action('wp_login_failed', array(__CLASS__, 'on_login_failed'), 5, 1);
        add_action('after_password_reset', array(__CLASS__, 'on_password_reset'), 5, 1);
        // Code changes (persistence vectors)
        add_action('activated_plugin',   array(__CLASS__, 'on_plugin_activated'), 5, 1);
        add_action('deactivated_plugin', array(__CLASS__, 'on_plugin_deactivated'), 5, 1);
        add_action('switch_theme',       array(__CLASS__, 'on_switch_theme'), 5, 1);
        // Retention
        add_action(self::CRON_HOOK, array(__CLASS__, 'prune'));
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 3600, 'daily', self::CRON_HOOK);
        }
    }

    public static function table()
    {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    public static function maybe_install()
    {
        if (get_option(self::DB_OPTION) === self::DB_VERSION) return;
        global $wpdb;
        $table   = self::table();
        $charset = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta("CREATE TABLE $table (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            event_time DATETIME NOT NULL,
            event_time_gmt DATETIME NOT NULL,
            event VARCHAR(64) NOT NULL,
            actor_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            actor_login VARCHAR(191) NOT NULL DEFAULT '',
            target_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            target_login VARCHAR(191) NOT NULL DEFAULT '',
            detail TEXT NULL,
            ip VARCHAR(64) NOT NULL DEFAULT '',
            ua VARCHAR(255) NOT NULL DEFAULT '',
            uri VARCHAR(255) NOT NULL DEFAULT '',
            context VARCHAR(16) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            KEY event_time_gmt (event_time_gmt),
            KEY event (event),
            KEY actor_id (actor_id),
            KEY target_id (target_id)
        ) $charset;");
        update_option(self::DB_OPTION, self::DB_VERSION, false);
    }

    /** Central write function. $target = [id, login]; $detail = array. */
    public static function log($event, $target = array(), $detail = array())
    {
        global $wpdb;
        $actor = function_exists('wp_get_current_user') ? wp_get_current_user() : null;
        $wpdb->insert(self::table(), array(
            'event_time'     => current_time('mysql'),
            'event_time_gmt' => current_time('mysql', true),
            'event'          => substr($event, 0, 64),
            'actor_id'       => $actor ? (int) $actor->ID : 0,
            'actor_login'    => $actor ? substr($actor->user_login, 0, 191) : '',
            'target_id'      => isset($target['id']) ? (int) $target['id'] : 0,
            'target_login'   => isset($target['login']) ? substr((string) $target['login'], 0, 191) : '',
            'detail'         => $detail ? wp_json_encode($detail) : null,
            'ip'             => EtchSecurity_Util::ip(),
            'ua'             => substr(EtchSecurity_Util::server('HTTP_USER_AGENT'), 0, 255),
            'uri'            => substr(EtchSecurity_Util::server('REQUEST_URI'), 0, 255),
            'context'        => EtchSecurity_Util::context(),
        ));
    }

    // Handlers
    public static function on_user_register($user_id)
    {
        $u = get_userdata($user_id);
        self::log('user_register', array('id' => $user_id, 'login' => $u ? $u->user_login : ''),
            array('email' => $u ? $u->user_email : '', 'roles' => $u ? $u->roles : array()));
    }
    public static function on_profile_update($user_id, $old)
    {
        $u = get_userdata($user_id);
        if (!$u) return;
        if (!$old || strtolower($old->user_email) === strtolower($u->user_email)) return;
        self::log('profile_update', array('id' => $user_id, 'login' => $u->user_login),
            array('email' => array('from' => $old->user_email, 'to' => $u->user_email)));
    }
    public static function on_set_role($user_id, $role, $old_roles)
    {
        $u = get_userdata($user_id);
        self::log('set_user_role', array('id' => $user_id, 'login' => $u ? $u->user_login : ''),
            array('new' => $role ?: '(none)', 'previous' => $old_roles ?: array()));
    }
    public static function on_deleted_user($id, $reassign, $user)
    {
        self::log('deleted_user', array('id' => $id, 'login' => $user ? $user->user_login : ''),
            array('email' => $user ? $user->user_email : '', 'reassign_to' => $reassign ? (int) $reassign : null));
    }
    public static function on_app_password($user_id, $item)
    {
        $u = get_userdata($user_id);
        self::log('application_password_created', array('id' => $user_id, 'login' => $u ? $u->user_login : ''),
            array('name' => isset($item['name']) ? $item['name'] : ''));
    }
    public static function on_login($login, $user)
    {
        self::log('login_success', array('id' => $user ? $user->ID : 0, 'login' => $login),
            array('roles' => $user ? $user->roles : array()));
    }
    public static function on_login_failed($username)   { self::log('login_failed', array('login' => $username)); }
    public static function on_password_reset($user)      { self::log('password_reset', array('id' => $user ? $user->ID : 0, 'login' => $user ? $user->user_login : '')); }
    public static function on_plugin_activated($plugin)  { self::log('plugin_activated',   array(), array('plugin' => $plugin)); }
    public static function on_plugin_deactivated($plugin){ self::log('plugin_deactivated', array(), array('plugin' => $plugin)); }
    public static function on_switch_theme($name)        { self::log('switch_theme',       array(), array('theme' => $name)); }

    public static function prune()
    {
        global $wpdb;
        $table = self::table();
        $wpdb->query($wpdb->prepare(
            "DELETE FROM $table WHERE event_time_gmt < (UTC_TIMESTAMP() - INTERVAL %d DAY)",
            self::RETAIN_DAYS
        ));
    }
}


/* =============================================================================
 * 3) Utility functions (IP / context)
 * ========================================================================== */

final class EtchSecurity_Util
{
    public static function server($key)
    {
        return isset($_SERVER[$key]) ? sanitize_text_field(wp_unslash($_SERVER[$key])) : '';
    }

    /**
     * Source IP. Deliberately REMOTE_ADDR: proxy headers (X-Forwarded-For etc.)
     * are client-spoofable and are not suitable as evidence. If a trusted
     * reverse proxy/CDN is in front, supplement via filter.
     */
    public static function ip()
    {
        $ip = substr(self::server('REMOTE_ADDR'), 0, 64);
        return (string) apply_filters('etch_security_client_ip', $ip);
    }

    public static function context()
    {
        if (defined('WP_CLI') && WP_CLI) return 'cli';
        if (function_exists('wp_doing_cron') && wp_doing_cron()) return 'cron';
        if (defined('REST_REQUEST') && REST_REQUEST) return 'rest';
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) return 'xmlrpc';
        if (is_admin()) return 'admin';
        return 'web';
    }
}


/* =============================================================================
 * 4) Self-Updater (GitHub releases)
 * ========================================================================== */

final class EtchSecurity_Updater
{
    const CRON_HOOK  = 'etch_security_update_check';
    const OPT_STATUS = 'etch_security_update_status';

    public static function boot()
    {
        add_action(self::CRON_HOOK, array(__CLASS__, 'run'));
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 1800, 'twicedaily', self::CRON_HOOK);
        }
    }

    /**
     * Fetch latest version + code directly from the file on `main`.
     * Deliberately raw.githubusercontent instead of api.github.com: the GitHub
     * API is rate-limited to 60 requests/hour per (shared) IP and then returns
     * 403 — raw is a CDN without this limit. Contract: `main` always carries the
     * latest published version (version bump = release).
     */
    private static function fetch_main()
    {
        $raw = wp_remote_get(
            'https://raw.githubusercontent.com/' . ETCH_SECURITY_REPO . '/main/etch-security.php',
            array('timeout' => 20, 'headers' => array('User-Agent' => 'etch-security-updater'))
        );
        if (is_wp_error($raw) || wp_remote_retrieve_response_code($raw) !== 200) return null;
        $code = wp_remote_retrieve_body($raw);
        if (!preg_match('/ETCH_SECURITY_VERSION\',\s*\'([0-9][0-9.]*)\'/', $code, $m)) return null;
        return array('version' => $m[1], 'code' => $code);
    }

    /**
     * Update run. Returns status array. One request (raw main) covers both
     * version check AND download.
     */
    public static function run($force = false)
    {
        $status = array('checked' => current_time('mysql'), 'installed' => ETCH_SECURITY_VERSION,
                        'latest' => null, 'action' => 'none', 'error' => null);

        $main = self::fetch_main();
        if (!$main) { $status['error'] = 'raw.githubusercontent not reachable / version not readable'; return self::save($status); }

        $latest = $main['version'];
        $status['latest'] = $latest;

        if (version_compare($latest, ETCH_SECURITY_VERSION, '<=')) {
            $status['action'] = 'up-to-date';
            return self::save($status);
        }

        $code = $main['code'];

        // Plausibility: real PHP file of this plugin with matching version.
        if (strpos($code, '<?php') !== 0
            || strpos($code, 'Plugin Name: Etch Security') === false
            || strpos($code, "ETCH_SECURITY_VERSION', '" . $latest . "'") === false) {
            $status['error'] = 'Release file implausible — nothing written'; return self::save($status);
        }

        $target = ETCH_SECURITY_FILE;
        if (!is_writable($target)) { $status['error'] = 'File not writable: ' . $target; return self::save($status); }

        // Write atomically: temp + rename.
        $tmp = $target . '.tmp-' . wp_generate_password(6, false);
        if (file_put_contents($tmp, $code) === false || !@rename($tmp, $target)) {
            @unlink($tmp);
            $status['error'] = 'Write failed'; return self::save($status);
        }

        $status['action'] = 'updated';
        $status['updated_to'] = $latest;
        return self::save($status);
    }

    private static function save($status)
    {
        update_option(self::OPT_STATUS, $status, false);
        return $status;
    }

    public static function status()
    {
        return get_option(self::OPT_STATUS, array());
    }
}


/* =============================================================================
 * 5) Admin — one page: Tools → Etch Security
 * ========================================================================== */

final class EtchSecurity_Admin
{
    const SLUG = 'etch-security';

    public static function boot()
    {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_post_etch_security_save',   array(__CLASS__, 'save_settings'));
        add_action('admin_post_etch_security_update', array(__CLASS__, 'manual_update'));
        add_action('admin_post_etch_security_csv',    array(__CLASS__, 'export_csv'));
    }

    public static function menu()
    {
        add_management_page('Etch Security', 'Etch Security', 'manage_options', self::SLUG, array(__CLASS__, 'render'));
    }

    private static function tab_url($tab)
    {
        return admin_url('tools.php?page=' . self::SLUG . '&tab=' . $tab);
    }

    public static function render()
    {
        if (!current_user_can('manage_options')) return;
        $tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'status';

        echo '<div class="wrap"><h1>Etch Security</h1>';
        echo '<h2 class="nav-tab-wrapper">';
        foreach (array('status' => 'Status & Settings', 'log' => 'Security Log') as $k => $label) {
            printf('<a href="%s" class="nav-tab%s">%s</a>',
                esc_url(self::tab_url($k)), $tab === $k ? ' nav-tab-active' : '', esc_html($label));
        }
        echo '</h2>';

        if (isset($_GET['msg'])) {
            printf('<div class="notice notice-success is-dismissible"><p>%s</p></div>',
                esc_html(sanitize_text_field(wp_unslash($_GET['msg']))));
        }

        $tab === 'log' ? self::render_log() : self::render_status();
        echo '</div>';
    }

    // ------------------------------------------------------------ Tab: Status

    private static function render_status()
    {
        $domains  = EtchSecurity_Config::configured_domains();
        $enforce  = get_option(EtchSecurity_Config::OPT_ENFORCE, '0') === '1';
        $eff      = EtchSecurity_Config::allowed_domains();
        $enforcing = EtchSecurity_Config::enforcing();
        $st       = EtchSecurity_Updater::status();

        echo '<h3>WordPress Core</h3>';
        echo '<table class="widefat" style="max-width:820px"><tbody>';
        self::row('Core Version', '<code>' . esc_html(get_bloginfo('version')) . '</code>');
        self::row('Security Auto-Updates', EtchSecurity_Config::force_core_updates()
            ? '<strong style="color:#1a7f37">enforced</strong> — minor/security releases run through, even against a blocker (e.g. Installatron)'
            : '<span style="color:#996800">not enforced</span> — site policy applies');
        echo '</tbody></table>';

        echo '<h3>User Guard</h3>';
        echo '<table class="widefat" style="max-width:820px"><tbody>';
        self::row('Enforcement', $enforcing
            ? '<strong style="color:#1a7f37">active</strong> — foreign domains will be neutralized'
            : '<strong style="color:#996800">inactive</strong> — only audit log runs (no domain configured or switch off)');
        self::row('Allowed Domains (effective)', $eff ? '<code>' . esc_html(implode(', ', $eff)) . '</code>' : '—');
        echo '</tbody></table>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:1.5em 0;max-width:820px">';
        wp_nonce_field('etch_security_save');
        echo '<input type="hidden" name="action" value="etch_security_save">';
        echo '<p><label><strong>Allowed Domains</strong> (one per line or comma-separated; without @):</label><br>';
        echo '<textarea name="domains" rows="4" style="width:100%;max-width:520px" placeholder="example.com">'
            . esc_textarea(implode("\n", $domains)) . '</textarea></p>';
        echo '<p><label><input type="checkbox" name="enforce" value="1"' . checked($enforce, true, false) . '> '
            . 'Enable enforcement (immediately neutralize foreign accounts)</label></p>';
        echo '<p class="description">The domain of the site admin address (' . esc_html(get_option('admin_email'))
            . ') is always allowed. Without a configured domain, enforcement stays off for safety.</p>';
        echo '<p style="margin-top:1.5em"><label><input type="checkbox" name="force_core" value="1"'
            . checked(EtchSecurity_Config::force_core_updates(), true, false) . '> '
            . '<strong>Force WordPress core security updates</strong> — lets minor/security point releases run automatically, '
            . 'even if a management tool (e.g. Installatron) has disabled them. '
            . 'Major version jumps are left untouched.</label></p>';
        submit_button('Save');
        echo '</form>';

        echo '<hr><h3>Version & Self-Update</h3>';
        echo '<table class="widefat" style="max-width:820px"><tbody>';
        self::row('Installed Version', '<code>' . esc_html(ETCH_SECURITY_VERSION) . '</code>');
        $latest = isset($st['latest']) ? $st['latest'] : null;
        $vtxt = $latest ? esc_html($latest) : '—';
        if ($latest && version_compare($latest, ETCH_SECURITY_VERSION, '>')) {
            $vtxt .= ' <strong style="color:#996800">(update available — on the next cron run)</strong>';
        } elseif ($latest) {
            $vtxt .= ' <span style="color:#1a7f37">(up to date)</span>';
        }
        self::row('Latest Release', $vtxt);
        self::row('Last Check', isset($st['checked']) ? esc_html($st['checked'])
            . (isset($st['action']) ? ' · ' . esc_html($st['action']) : '') : 'never');
        if (!empty($st['error'])) self::row('Last Error', '<span style="color:#b32d2e">' . esc_html($st['error']) . '</span>');
        self::row('Source', '<a href="https://github.com/' . esc_attr(ETCH_SECURITY_REPO)
            . '/releases" target="_blank" rel="noopener">github.com/' . esc_html(ETCH_SECURITY_REPO) . '</a> · automatic 2×/day');
        echo '</tbody></table>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:1em">';
        wp_nonce_field('etch_security_update');
        echo '<input type="hidden" name="action" value="etch_security_update">';
        submit_button('Check for Updates Now', 'secondary');
        echo '</form>';
    }

    private static function row($k, $v)
    {
        printf('<tr><th style="width:230px;text-align:left">%s</th><td>%s</td></tr>', esc_html($k), $v);
    }

    // --------------------------------------------------------------- Tab: Log

    private static function render_log()
    {
        global $wpdb;
        $table = EtchSecurity_Audit_Log::table();
        $per   = 50;
        $paged = max(1, isset($_GET['paged']) ? (int) $_GET['paged'] : 1);
        $ev    = isset($_GET['ev']) ? sanitize_text_field(wp_unslash($_GET['ev'])) : '';

        $where = $ev !== '' ? $wpdb->prepare('WHERE event = %s', $ev) : '';
        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table $where");
        $rows  = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table $where ORDER BY id DESC LIMIT %d OFFSET %d",
            $per, ($paged - 1) * $per));
        $events = $wpdb->get_col("SELECT DISTINCT event FROM $table ORDER BY event");
        $csv = wp_nonce_url(admin_url('admin-post.php?action=etch_security_csv'), 'etch_security_csv');

        echo '<p>' . esc_html((string) $total) . ' entries · retention '
            . esc_html((string) EtchSecurity_Audit_Log::RETAIN_DAYS) . ' days · times in site timezone.</p>';

        echo '<form method="get" style="margin:1em 0"><input type="hidden" name="page" value="' . esc_attr(self::SLUG) . '">';
        echo '<input type="hidden" name="tab" value="log"><select name="ev"><option value="">— all events —</option>';
        foreach ($events as $e) {
            printf('<option value="%s"%s>%s</option>', esc_attr($e), selected($ev, $e, false), esc_html($e));
        }
        echo '</select> <button class="button">Filter</button> <a class="button" href="' . esc_url($csv) . '">CSV Export</a></form>';

        echo '<table class="widefat striped"><thead><tr><th>Time</th><th>Event</th><th>Actor</th>'
            . '<th>Target</th><th>IP</th><th>Context</th><th>Details</th></tr></thead><tbody>';
        if (!$rows) echo '<tr><td colspan="7">No entries yet.</td></tr>';
        foreach ($rows as $r) {
            $actor  = $r->actor_id ? $r->actor_login . ' (#' . $r->actor_id . ')' : ($r->actor_login ?: '—');
            $target = $r->target_login ? $r->target_login . ($r->target_id ? ' (#' . $r->target_id . ')' : '') : '—';
            printf('<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                 . '<td><code style="font-size:11px">%s</code></td></tr>',
                esc_html($r->event_time), esc_html($r->event), esc_html($actor), esc_html($target),
                esc_html($r->ip), esc_html($r->context), esc_html($r->detail ? substr($r->detail, 0, 300) : ''));
        }
        echo '</tbody></table>';

        $pages = (int) ceil($total / $per);
        if ($pages > 1) {
            echo '<div class="tablenav"><div class="tablenav-pages">';
            for ($i = 1; $i <= $pages; $i++) {
                $url = add_query_arg(array('page' => self::SLUG, 'tab' => 'log', 'ev' => $ev, 'paged' => $i), admin_url('tools.php'));
                printf(' %s ', $i === $paged ? '<strong>' . $i . '</strong>' : '<a href="' . esc_url($url) . '">' . $i . '</a>');
            }
            echo '</div></div>';
        }
    }

    // ------------------------------------------------------------- Actions

    public static function save_settings()
    {
        if (!current_user_can('manage_options')) wp_die('Insufficient permissions.');
        check_admin_referer('etch_security_save');
        $domains = EtchSecurity_Config::parse(isset($_POST['domains']) ? wp_unslash($_POST['domains']) : '');
        update_option(EtchSecurity_Config::OPT_DOMAINS, $domains, false);
        update_option(EtchSecurity_Config::OPT_ENFORCE, empty($_POST['enforce']) ? '0' : '1', false);
        update_option(EtchSecurity_Config::OPT_CORE_UPDATES, empty($_POST['force_core']) ? '0' : '1', false);
        $msg = $domains ? 'Saved.' : 'Saved (no domain configured → enforcement stays off).';
        wp_safe_redirect(add_query_arg('msg', rawurlencode($msg), self::tab_url('status')));
        exit;
    }

    public static function manual_update()
    {
        if (!current_user_can('manage_options')) wp_die('Insufficient permissions.');
        check_admin_referer('etch_security_update');
        $st = EtchSecurity_Updater::run(true);
        $msg = !empty($st['error']) ? 'Update check: ' . $st['error']
             : ($st['action'] === 'updated' ? 'Updated to ' . $st['updated_to'] . '.'
             : 'Version is up to date (' . ETCH_SECURITY_VERSION . ').');
        wp_safe_redirect(add_query_arg('msg', rawurlencode($msg), self::tab_url('status')));
        exit;
    }

    public static function export_csv()
    {
        if (!current_user_can('manage_options')) wp_die('Insufficient permissions.');
        check_admin_referer('etch_security_csv');
        global $wpdb;
        $rows = $wpdb->get_results("SELECT * FROM " . EtchSecurity_Audit_Log::table() . " ORDER BY id DESC", ARRAY_A);
        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=etch-security-audit-' . gmdate('Ymd-His') . '.csv');
        $out = fopen('php://output', 'w');
        fputcsv($out, array('id','event_time','event_time_gmt','event','actor_id','actor_login',
                            'target_id','target_login','detail','ip','ua','uri','context'));
        foreach ($rows as $r) fputcsv($out, $r);
        fclose($out);
        exit;
    }
}


/* =============================================================================
 * 6) Core Updates — force minor/security auto-updates
 * ========================================================================== */

final class EtchSecurity_Core_Updates
{
    public static function boot()
    {
        if (!EtchSecurity_Config::force_core_updates()) return;

        // Overrides blockers like Installatron (which disable via __return_false):
        // later priority wins, PHP_INT_MAX runs last.
        add_filter('allow_minor_auto_core_updates', '__return_true', PHP_INT_MAX);
        add_filter('auto_update_core', array(__CLASS__, 'allow_security'), PHP_INT_MAX, 2);

        // Log the result of an auto-update to the audit log.
        add_action('automatic_updates_complete', array(__CLASS__, 'log_result'), 10, 1);
    }

    /**
     * Forces auto-update ONLY for minor/security point releases (same X.Y branch,
     * e.g. 7.0.1 → 7.0.2). Major updates keep the existing decision — those remain
     * with Installatron/manual.
     */
    public static function allow_security($update, $item)
    {
        if (!is_object($item) || empty($item->current)) return $update;
        $installed = isset($GLOBALS['wp_version']) ? $GLOBALS['wp_version'] : get_bloginfo('version');
        if (self::same_branch($installed, $item->current)) return true;
        return $update;
    }

    /** Same major.minor branch? Dev suffixes (-beta/-RC) are ignored. */
    private static function same_branch($a, $b)
    {
        $pa = explode('.', preg_replace('/[^0-9.].*$/', '', (string) $a));
        $pb = explode('.', preg_replace('/[^0-9.].*$/', '', (string) $b));
        return isset($pa[0], $pa[1], $pb[0], $pb[1]) && $pa[0] === $pb[0] && $pa[1] === $pb[1];
    }

    public static function log_result($results)
    {
        if (empty($results['core']) || !is_array($results['core'])) return;
        foreach ($results['core'] as $r) {
            $ver = (isset($r->item) && isset($r->item->current)) ? $r->item->current : '?';
            $ok  = !empty($r->result) && !is_wp_error($r->result);
            EtchSecurity_Audit_Log::log('core_auto_update',
                array('login' => 'WordPress'),
                array('version' => $ver, 'success' => $ok ? 'yes' : 'no'));
        }
    }
}


/* =============================================================================
 * 7) Bootstrap
 * ========================================================================== */

EtchSecurity_Audit_Log::boot();   // first — other modules log through this
EtchSecurity_User_Guard::boot();
EtchSecurity_Core_Updates::boot();
EtchSecurity_Updater::boot();
if (is_admin()) EtchSecurity_Admin::boot();
