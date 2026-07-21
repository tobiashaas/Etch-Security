<?php
/**
 * Plugin Name: Etch Security
 * Plugin URI:  https://github.com/tobiashaas/Etch-Security
 * Description: Zwei Schutzschichten in einer Datei: (1) User Guard — nur erlaubte
 *              E-Mail-Domains bekommen ein Konto, fremde werden sofort entschärft
 *              (auch bei programmatischer Anlage / Rechte-Eskalation); (2) Audit
 *              Log — selbst gehostetes, dauerhaftes Sicherheits-Log (Actor, IP,
 *              Request) unabhängig von Premium-Plugins. Hält sich per
 *              GitHub-Releases selbst aktuell. Ansicht: Werkzeuge → Etch Security.
 * Version:     1.0.0
 * Author:      Tobias Haas
 * Author URI:  https://github.com/tobiashaas
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Update URI:  https://github.com/tobiashaas/Etch-Security
 *
 * Als mu-plugin gedacht (wp-content/mu-plugins/etch-security.php): dann kann ein
 * kompromittierter Admin es nicht deaktivieren — der Guard bleibt aktiv. Als
 * reguläres Plugin funktioniert es ebenso (die Update-Notice erscheint dann im
 * Plugins-Screen; als mu-plugin läuft das Update still per Cron).
 *
 * KONFIGURATION (alles optional, sichere Defaults):
 *   define('ETCH_SECURITY_ALLOWED_DOMAINS', 'example.com,partner.de'); // in wp-config.php
 *   — ODER — im Backend unter Werkzeuge → Etch Security pflegen.
 *   Die Domain der Site-Admin-Adresse ist IMMER erlaubt (kein Selbst-Aussperren).
 *   Enforcement ist AUS, solange keine Domain gesetzt ist: das Audit-Log läuft
 *   sofort (rein lesend, ungefährlich), der Guard greift erst nach Konfiguration.
 */

if (!defined('ABSPATH')) exit;

if (!defined('ETCH_SECURITY_VERSION')) define('ETCH_SECURITY_VERSION', '1.0.0');
if (!defined('ETCH_SECURITY_REPO'))    define('ETCH_SECURITY_REPO', 'tobiashaas/Etch-Security');
if (!defined('ETCH_SECURITY_FILE'))    define('ETCH_SECURITY_FILE', __FILE__);


/* =============================================================================
 * 0) Gemeinsame Konfiguration
 * ========================================================================== */

final class EtchSecurity_Config
{
    const OPT_DOMAINS = 'etch_security_allowed_domains';   // array von Domains
    const OPT_ENFORCE = 'etch_security_enforce';           // '1' | '0'

    /** Konfigurierte Domains (Option, plus Konstante als Erst-Default). */
    public static function configured_domains()
    {
        $opt = get_option(self::OPT_DOMAINS, null);
        if ($opt === null && defined('ETCH_SECURITY_ALLOWED_DOMAINS')) {
            $opt = self::parse(ETCH_SECURITY_ALLOWED_DOMAINS);
        }
        return is_array($opt) ? $opt : array();
    }

    /**
     * Effektive Allowlist: konfigurierte Domains + die Domain der Site-Admin-
     * Adresse (immer, gegen Selbst-Aussperren) + Filter fuer Programmatik.
     */
    public static function allowed_domains()
    {
        $domains = self::configured_domains();

        $admin = strtolower((string) get_option('admin_email'));
        $at = strrpos($admin, '@');
        if ($at !== false) $domains[] = substr($admin, $at + 1);

        /** @return string[] Liste erlaubter Domains (klein geschrieben). */
        $domains = apply_filters('etch_security_allowed_domains', $domains);

        return array_values(array_unique(array_filter(array_map('strtolower', (array) $domains))));
    }

    /** Enforcement nur, wenn eingeschaltet UND mindestens eine Domain konfiguriert. */
    public static function enforcing()
    {
        if (get_option(self::OPT_ENFORCE, '0') !== '1') return false;
        return count(self::configured_domains()) > 0;
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
 * 1) User Guard — Domain-Allowlist + Backstop
 * ========================================================================== */

final class EtchSecurity_User_Guard
{
    const FLAG_META = 'etch_security_neutralized';
    private static $busy = false;

    public static function boot()
    {
        // Schicht 1 — Praevention auf den regulaeren Wegen.
        add_filter('rest_pre_insert_user',       array(__CLASS__, 'guard_rest'), 10, 2);
        add_action('user_profile_update_errors', array(__CLASS__, 'guard_profile'), 10, 3);
        add_filter('registration_errors',        array(__CLASS__, 'guard_registration'), 10, 3);

        // Schicht 2 — Backstop, faengt auch wp_insert_user() + Eskalation.
        add_action('user_register', array(__CLASS__, 'backstop'), PHP_INT_MAX, 1);
        add_action('set_user_role', array(__CLASS__, 'watch_role'), PHP_INT_MAX, 3);
    }

    private static function refusal()
    {
        $list = EtchSecurity_Config::allowed_domains();
        return sprintf(
            /* translators: %s = Liste der erlaubten Domains */
            __('Diese E-Mail-Adresse ist nicht zugelassen. Konten sind auf %s beschränkt.', 'etch-security'),
            '@' . implode(', @', $list)
        );
    }

    // ---------------------------------------------------------------- Schicht 1

    public static function guard_rest($prepared_user, $request)
    {
        if (!EtchSecurity_Config::enforcing()) return $prepared_user;
        $email = isset($prepared_user->user_email) ? $prepared_user->user_email : '';
        if ($email !== '' && !EtchSecurity_Config::is_allowed($email)) {
            EtchSecurity_Audit_Log::log('guard_blocked', array('login' => $email),
                array('weg' => 'rest', 'email' => $email));
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
            if ($current && strtolower($current->user_email) === strtolower($email)) return; // unveraendert
        }
        if (!EtchSecurity_Config::is_allowed($email)) {
            $errors->add('etch_security_user_guard', self::refusal());
            EtchSecurity_Audit_Log::log('guard_blocked',
                array('id' => isset($user->ID) ? (int) $user->ID : 0, 'login' => $email),
                array('weg' => 'profile', 'email' => $email));
        }
    }

    public static function guard_registration($errors, $login, $email)
    {
        if (!EtchSecurity_Config::enforcing()) return $errors;
        if ($email !== '' && !EtchSecurity_Config::is_allowed($email)) {
            $errors->add('etch_security_user_guard', self::refusal());
            EtchSecurity_Audit_Log::log('guard_blocked', array('login' => $email),
                array('weg' => 'registration', 'email' => $email));
        }
        return $errors;
    }

    // ---------------------------------------------------------------- Schicht 2

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

    /** Konto unbrauchbar machen, ohne es zu loeschen (Beweismittel). */
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
            "Es wurde ein Konto mit nicht zugelassener Domain angelegt und sofort entschärft.\n\n"
            . "Benutzer:  %s\nE-Mail:    %s\nID:        %d\nAusgelöst durch: %s\nZeit:      %s\nIP:        %s\n\n"
            . "Status: Rolle entzogen, Passwort invalidiert, Sessions beendet.\n"
            . "Das Konto wurde NICHT gelöscht — es ist Beweismittel.\n"
            . "Details: Werkzeuge → Etch Security.",
            $user->user_login, $user->user_email, $user->ID, $trigger,
            current_time('mysql'), EtchSecurity_Util::ip()
        );
        wp_mail($to, '[' . $brand . '] ' . __('Fremder Benutzer blockiert', 'etch-security') . ': ' . $user->user_login, $body);
    }
}


/* =============================================================================
 * 2) Audit Log — dauerhaftes, selbst gehostetes Sicherheits-Log
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

        // Konten
        add_action('user_register',   array(__CLASS__, 'on_user_register'), 5, 1);
        add_action('profile_update',  array(__CLASS__, 'on_profile_update'), 5, 2);
        add_action('set_user_role',   array(__CLASS__, 'on_set_role'), 5, 3);
        add_action('deleted_user',    array(__CLASS__, 'on_deleted_user'), 5, 3);
        add_action('wp_create_application_password', array(__CLASS__, 'on_app_password'), 5, 2);
        // Authentifizierung
        add_action('wp_login',        array(__CLASS__, 'on_login'), 5, 2);
        add_action('wp_login_failed', array(__CLASS__, 'on_login_failed'), 5, 1);
        add_action('after_password_reset', array(__CLASS__, 'on_password_reset'), 5, 1);
        // Code-Aenderungen (Persistenz-Vektoren)
        add_action('activated_plugin',   array(__CLASS__, 'on_plugin_activated'), 5, 1);
        add_action('deactivated_plugin', array(__CLASS__, 'on_plugin_deactivated'), 5, 1);
        add_action('switch_theme',       array(__CLASS__, 'on_switch_theme'), 5, 1);
        // Aufbewahrung
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

    /** Zentrale Schreibfunktion. $target = [id, login]; $detail = Array. */
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
            array('email' => array('von' => $old->user_email, 'nach' => $u->user_email)));
    }
    public static function on_set_role($user_id, $role, $old_roles)
    {
        $u = get_userdata($user_id);
        self::log('set_user_role', array('id' => $user_id, 'login' => $u ? $u->user_login : ''),
            array('neu' => $role ?: '(keine)', 'vorher' => $old_roles ?: array()));
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
 * 3) Hilfsfunktionen (IP / Kontext)
 * ========================================================================== */

final class EtchSecurity_Util
{
    public static function server($key)
    {
        return isset($_SERVER[$key]) ? sanitize_text_field(wp_unslash($_SERVER[$key])) : '';
    }

    /**
     * Quell-IP. Bewusst REMOTE_ADDR: Proxy-Header (X-Forwarded-For etc.) sind
     * client-seitig faelschbar und taugen nicht als Beweismittel. Sitzt ein
     * vertrauenswuerdiger Reverse-Proxy/CDN davor, per Filter ergaenzen.
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
 * 4) Self-Updater (GitHub-Releases) — mirror des WebAudits-Musters
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

    /** Neueste Release-Version ermitteln (Tag ohne fuehrendes v). */
    private static function latest_tag()
    {
        $api = wp_remote_get('https://api.github.com/repos/' . ETCH_SECURITY_REPO . '/releases/latest', array(
            'timeout' => 15,
            'headers' => array('Accept' => 'application/vnd.github+json', 'User-Agent' => 'etch-security-updater'),
        ));
        if (is_wp_error($api) || wp_remote_retrieve_response_code($api) !== 200) return null;
        $body = json_decode(wp_remote_retrieve_body($api), true);
        return isset($body['tag_name']) ? $body['tag_name'] : null;
    }

    /**
     * Update-Lauf. $force ignoriert den 6h-Cache. Gibt Status-Array zurueck.
     */
    public static function run($force = false)
    {
        $status = array('checked' => current_time('mysql'), 'installed' => ETCH_SECURITY_VERSION,
                        'latest' => null, 'action' => 'none', 'error' => null);

        $tag = self::latest_tag();
        if (!$tag) { $status['error'] = 'GitHub-API nicht erreichbar'; return self::save($status); }

        $latest = ltrim($tag, 'vV');
        $status['latest'] = $latest;

        if (version_compare($latest, ETCH_SECURITY_VERSION, '<=')) {
            $status['action'] = 'up-to-date';
            return self::save($status);
        }

        // Datei am Release-Tag ziehen.
        $raw = wp_remote_get(
            'https://raw.githubusercontent.com/' . ETCH_SECURITY_REPO . '/' . rawurlencode($tag) . '/etch-security.php',
            array('timeout' => 20, 'headers' => array('User-Agent' => 'etch-security-updater'))
        );
        if (is_wp_error($raw) || wp_remote_retrieve_response_code($raw) !== 200) {
            $status['error'] = 'Release-Datei nicht abrufbar'; return self::save($status);
        }
        $code = wp_remote_retrieve_body($raw);

        // Plausibilitaet: echte PHP-Datei dieses Plugins mit passender Version.
        if (strpos($code, '<?php') !== 0
            || strpos($code, 'Plugin Name: Etch Security') === false
            || strpos($code, "ETCH_SECURITY_VERSION', '" . $latest . "'") === false) {
            $status['error'] = 'Release-Datei unplausibel — nichts geschrieben'; return self::save($status);
        }

        $target = ETCH_SECURITY_FILE;
        if (!is_writable($target)) { $status['error'] = 'Datei nicht schreibbar: ' . $target; return self::save($status); }

        // Atomar schreiben: temp + rename.
        $tmp = $target . '.tmp-' . wp_generate_password(6, false);
        if (file_put_contents($tmp, $code) === false || !@rename($tmp, $target)) {
            @unlink($tmp);
            $status['error'] = 'Schreiben fehlgeschlagen'; return self::save($status);
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
 * 5) Admin — eine Seite: Werkzeuge → Etch Security
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
        foreach (array('status' => 'Status & Einstellungen', 'log' => 'Sicherheits-Log') as $k => $label) {
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

        echo '<h3>User Guard</h3>';
        echo '<table class="widefat" style="max-width:820px"><tbody>';
        self::row('Enforcement', $enforcing
            ? '<strong style="color:#1a7f37">aktiv</strong> — fremde Domains werden entschärft'
            : '<strong style="color:#996800">inaktiv</strong> — nur Audit-Log läuft (keine Domain gesetzt oder Schalter aus)');
        self::row('Erlaubte Domains (effektiv)', $eff ? '<code>' . esc_html(implode(', ', $eff)) . '</code>' : '—');
        echo '</tbody></table>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:1.5em 0;max-width:820px">';
        wp_nonce_field('etch_security_save');
        echo '<input type="hidden" name="action" value="etch_security_save">';
        echo '<p><label><strong>Erlaubte Domains</strong> (eine pro Zeile oder komma­getrennt; ohne @):</label><br>';
        echo '<textarea name="domains" rows="4" style="width:100%;max-width:520px" placeholder="kunze-ritter.de">'
            . esc_textarea(implode("\n", $domains)) . '</textarea></p>';
        echo '<p><label><input type="checkbox" name="enforce" value="1"' . checked($enforce, true, false) . '> '
            . 'Enforcement einschalten (fremde Konten sofort entschärfen)</label></p>';
        echo '<p class="description">Die Domain der Site-Admin-Adresse (' . esc_html(get_option('admin_email'))
            . ') ist immer erlaubt. Ohne konfigurierte Domain bleibt Enforcement aus Sicherheitsgründen aus.</p>';
        submit_button('Speichern');
        echo '</form>';

        echo '<hr><h3>Version & Self-Update</h3>';
        echo '<table class="widefat" style="max-width:820px"><tbody>';
        self::row('Installierte Version', '<code>' . esc_html(ETCH_SECURITY_VERSION) . '</code>');
        $latest = isset($st['latest']) ? $st['latest'] : null;
        $vtxt = $latest ? esc_html($latest) : '—';
        if ($latest && version_compare($latest, ETCH_SECURITY_VERSION, '>')) {
            $vtxt .= ' <strong style="color:#996800">(Update verfügbar — beim nächsten Cron-Lauf)</strong>';
        } elseif ($latest) {
            $vtxt .= ' <span style="color:#1a7f37">(aktuell)</span>';
        }
        self::row('Neueste Release', $vtxt);
        self::row('Letzte Prüfung', isset($st['checked']) ? esc_html($st['checked'])
            . (isset($st['action']) ? ' · ' . esc_html($st['action']) : '') : 'noch keine');
        if (!empty($st['error'])) self::row('Letzter Fehler', '<span style="color:#b32d2e">' . esc_html($st['error']) . '</span>');
        self::row('Quelle', '<a href="https://github.com/' . esc_attr(ETCH_SECURITY_REPO)
            . '/releases" target="_blank" rel="noopener">github.com/' . esc_html(ETCH_SECURITY_REPO) . '</a> · automatisch 2×/Tag');
        echo '</tbody></table>';

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:1em">';
        wp_nonce_field('etch_security_update');
        echo '<input type="hidden" name="action" value="etch_security_update">';
        submit_button('Jetzt auf Updates prüfen', 'secondary');
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

        echo '<p>' . esc_html((string) $total) . ' Einträge · Aufbewahrung '
            . esc_html((string) EtchSecurity_Audit_Log::RETAIN_DAYS) . ' Tage · Zeiten in Website-Zeitzone.</p>';

        echo '<form method="get" style="margin:1em 0"><input type="hidden" name="page" value="' . esc_attr(self::SLUG) . '">';
        echo '<input type="hidden" name="tab" value="log"><select name="ev"><option value="">— alle Ereignisse —</option>';
        foreach ($events as $e) {
            printf('<option value="%s"%s>%s</option>', esc_attr($e), selected($ev, $e, false), esc_html($e));
        }
        echo '</select> <button class="button">Filtern</button> <a class="button" href="' . esc_url($csv) . '">CSV-Export</a></form>';

        echo '<table class="widefat striped"><thead><tr><th>Zeit</th><th>Ereignis</th><th>Actor</th>'
            . '<th>Ziel</th><th>IP</th><th>Kontext</th><th>Details</th></tr></thead><tbody>';
        if (!$rows) echo '<tr><td colspan="7">Noch keine Einträge.</td></tr>';
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

    // ------------------------------------------------------------- Aktionen

    public static function save_settings()
    {
        if (!current_user_can('manage_options')) wp_die('Keine Berechtigung.');
        check_admin_referer('etch_security_save');
        $domains = EtchSecurity_Config::parse(isset($_POST['domains']) ? wp_unslash($_POST['domains']) : '');
        update_option(EtchSecurity_Config::OPT_DOMAINS, $domains, false);
        update_option(EtchSecurity_Config::OPT_ENFORCE, empty($_POST['enforce']) ? '0' : '1', false);
        $msg = $domains ? 'Gespeichert.' : 'Gespeichert (keine Domain → Enforcement bleibt aus).';
        wp_safe_redirect(add_query_arg('msg', rawurlencode($msg), self::tab_url('status')));
        exit;
    }

    public static function manual_update()
    {
        if (!current_user_can('manage_options')) wp_die('Keine Berechtigung.');
        check_admin_referer('etch_security_update');
        $st = EtchSecurity_Updater::run(true);
        $msg = !empty($st['error']) ? 'Update-Prüfung: ' . $st['error']
             : ($st['action'] === 'updated' ? 'Aktualisiert auf ' . $st['updated_to'] . '.'
             : 'Version ist aktuell (' . ETCH_SECURITY_VERSION . ').');
        wp_safe_redirect(add_query_arg('msg', rawurlencode($msg), self::tab_url('status')));
        exit;
    }

    public static function export_csv()
    {
        if (!current_user_can('manage_options')) wp_die('Keine Berechtigung.');
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
 * 6) Bootstrap
 * ========================================================================== */

EtchSecurity_Audit_Log::boot();   // zuerst — andere Module loggen hierüber
EtchSecurity_User_Guard::boot();
EtchSecurity_Updater::boot();
if (is_admin()) EtchSecurity_Admin::boot();
