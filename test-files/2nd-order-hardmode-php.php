<?php
/**
 * HARD MODE: 2nd-Order SQL Injection Test Cases for PHP
 * Tests: JSON poisoning, Table name injection, Calculation sinks
 * These patterns break most scanners because taint is lost through transformations
 */

class HardModeVulnerableController {

    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    // ========================================
    // HARD MODE 1: JSON Nested Object Poisoning
    // Most scanners lose taint through json_decode()
    // ========================================

    public function saveUserConfig($userId, $config) {
        // Phase 1: Safe storage of JSON config
        // Payload: {"theme": "dark", "order_col": "price) OR 1=1; -- "}
        $stmt = $this->db->prepare("UPDATE settings SET config = ? WHERE user_id = ?");
        $stmt->execute([json_encode($config), $userId]);
    }

    public function calculateStats($userId) {
        // Phase 2: Load JSON config from DB
        $row = $this->db->query("SELECT config FROM settings WHERE user_id = $userId")->fetch_assoc();

        // JSON decode - THIS IS WHERE MOST SCANNERS LOSE THE TAINT
        $config = json_decode($row['config'], true);

        // HARD MODE VULN: JSON key used in SUM calculation
        $col = $config['order_col'];
        $this->db->query("SELECT SUM($col) FROM orders");
        // Payload creates: SELECT SUM(price) OR 1=1; -- ) FROM orders
    }

    public function reportByUserPreference($settingId) {
        // Fetch and decode JSON from DB
        $jsonData = $this->db->query("SELECT preferences FROM user_settings")->fetch_column();
        $prefs = json_decode($jsonData, true);

        // HARD MODE VULN: JSON key in GROUP BY
        $groupField = $prefs['group_by'];
        $this->db->query("SELECT COUNT(*) FROM sales GROUP BY $groupField");
    }

    public function sortedReport($configId) {
        // Chain: DB -> JSON decode -> use in ORDER BY
        $result = $this->db->query("SELECT json_config FROM reports WHERE id = $configId");
        $row = $result->fetch_assoc();
        $settings = json_decode($row['json_config'], true);

        // HARD MODE VULN: ORDER BY from nested JSON
        $sortCol = $settings['display']['sort_column'];
        $this->db->query("SELECT * FROM products ORDER BY $sortCol");
    }

    // ========================================
    // HARD MODE 2: Multi-Tenant Table Name Injection
    // The "Bunker Buster" attack
    // ========================================

    public function saveTenantConfig($tenantId, $tableName) {
        // Phase 1: Store tenant's table name
        // Payload: "users --" or "admin_users; DROP TABLE customers;--"
        $stmt = $this->db->prepare("UPDATE tenant_config SET table_name = ? WHERE tenant_id = ?");
        $stmt->execute([$tableName, $tenantId]);
    }

    public function cleanupTenantData($tenantId) {
        // Phase 2: Load table name from config
        $config = $this->db->query("SELECT table_name FROM tenant_config WHERE tenant_id = $tenantId")->fetch_assoc();
        $table = $config['table_name'];

        // HARD MODE VULN: Table name injection
        // Attacker stored "users --", query becomes: DELETE FROM users -- WHERE ...
        $this->db->query("DELETE FROM $table WHERE created_at < NOW() - INTERVAL 30 DAY");
    }

    public function insertIntoTenantTable($tenantId, $data) {
        // Load table from tenant config
        $row = $this->db->query("SELECT tbl FROM tenants WHERE id = $tenantId")->fetch_object();
        $tableName = $row->tbl;

        // HARD MODE VULN: INSERT with poisoned table name
        $this->db->query("INSERT INTO $tableName (col1, col2) VALUES ('a', 'b')");
    }

    public function updateTenantEntity($configId) {
        // Table name from JSON config
        $config = json_decode($this->db->query("SELECT config FROM tenant_config")->fetch_column(), true);
        $entity = $config['entity'];

        // HARD MODE VULN: UPDATE with JSON-sourced table name
        $this->db->query("UPDATE $entity SET status = 'archived'");
    }

    // ========================================
    // HARD MODE 3: Calculation Sinks (No SELECT for exfil)
    // ========================================

    public function aggregateByStoredColumn($prefId) {
        // Load column preference from DB
        $pref = $this->db->query("SELECT agg_column FROM preferences WHERE id = $prefId")->fetch_assoc();
        $column = $pref['agg_column'];

        // HARD MODE VULN: AVG with db-sourced column
        $this->db->query("SELECT AVG($column) FROM metrics");
    }

    public function minMaxFromConfig($configId) {
        // Chain through fetch_object
        $obj = $this->db->query("SELECT * FROM calc_config WHERE id = $configId")->fetch_object();
        $minCol = $obj->min_column;
        $maxCol = $obj->max_column;

        // HARD MODE VULN: MIN/MAX with db-sourced columns
        $this->db->query("SELECT MIN($minCol), MAX($maxCol) FROM analytics");
    }

    // ========================================
    // COMBINED: JSON + Table + Calculation
    // The Ultimate Test
    // ========================================

    public function ultimateVuln($tenantId) {
        // Load JSON config from tenant table
        $row = $this->db->query("SELECT config FROM multi_tenant WHERE id = $tenantId")->fetch_assoc();
        $config = json_decode($row['config'], true);

        // ALL FROM JSON:
        $table = $config['target_table'];    // Table name
        $sumCol = $config['sum_column'];     // Calculation column
        $orderCol = $config['order_column']; // Structural column

        // TRIPLE WHAMMY: Table + SUM + ORDER BY all from JSON
        $this->db->query("SELECT SUM($sumCol) FROM $table ORDER BY $orderCol");
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================

    public function safeJsonUsage($userId) {
        $row = $this->db->query("SELECT config FROM settings WHERE user_id = $userId")->fetch_assoc();
        $config = json_decode($row['config'], true);

        // Safe: Using JSON value as data, not as SQL structure
        $theme = $config['theme'];
        $stmt = $this->db->prepare("UPDATE users SET theme = ? WHERE id = ?");
        $stmt->execute([$theme, $userId]);
    }

    public function safeTableWithWhitelist($tenantId) {
        $config = $this->db->query("SELECT table_name FROM config WHERE id = $tenantId")->fetch_assoc();
        $table = $config['table_name'];

        // Safe: Whitelist validation
        $allowed = ['logs', 'events', 'metrics'];
        if (!in_array($table, $allowed)) {
            throw new Exception("Invalid table");
        }
        $this->db->query("SELECT * FROM $table");
    }
}
