<?php
/**
 * 2nd-Order SQLi Test Cases - PHP Double-Unserialize Pattern
 * Attack chain: Serialized payload stored in DB -> unserialize() -> property used in SQL
 *
 * Payload example: O:8:"stdClass":1:{s:5:"theme";s:25:"1' OR '1'='1' -- ";}
 */

class DashboardService {

    private $pdo;
    private $mysqli;

    // ==================================================
    // VULNERABLE PATTERNS (Should detect)
    // ==================================================

    /**
     * Pattern 1: Unserialized object property in mysqli_query
     */
    public function vuln_mysqli_query($userId) {
        // Phase 1: Load serialized preferences from database
        $result = mysqli_query($this->mysqli, "SELECT prefs FROM user_prefs WHERE user_id = $userId");
        $row = mysqli_fetch_assoc($result);
        $data = $row['prefs'];  // Serialized blob from DB

        // Phase 2: Unserialize and use property
        $prefs = unserialize($data);  // Now $prefs is tainted object

        // Phase 3: Use property in SQL - VULN!
        // Payload in $prefs->theme: "1' UNION SELECT password FROM users--"
        $query = "SELECT * FROM themes WHERE id = '" . $prefs->theme . "'";
        return mysqli_query($this->mysqli, $query);
    }

    /**
     * Pattern 2: PDO query with unserialized value
     */
    public function vuln_pdo_query($configId) {
        // Phase 1: Fetch serialized config
        $stmt = $this->pdo->query("SELECT config_data FROM configs WHERE id = $configId");
        $serialized = $stmt->fetchColumn();

        // Phase 2: Unserialize
        $config = unserialize($serialized);
        $tableName = $config->target_table;  // Tainted!

        // Phase 3: Use in raw query - VULN!
        // Payload: "users; DROP TABLE users;--"
        return $this->pdo->query("SELECT COUNT(*) FROM " . $tableName);
    }

    /**
     * Pattern 3: sprintf SQL with unserialized property
     */
    public function vuln_sprintf_sql($userId) {
        // Load and unserialize user settings
        $row = $this->pdo->query("SELECT settings FROM users WHERE id = $userId")->fetch();
        $settings = unserialize($row['settings']);

        // VULN: sprintf doesn't sanitize!
        // Payload in $settings->sort_column: "id; UPDATE users SET is_admin=1 WHERE id=1;--"
        $sql = sprintf("SELECT * FROM posts ORDER BY %s", $settings->sort_column);
        return $this->pdo->query($sql);
    }

    /**
     * Pattern 4: String concat SQL with unserialized value
     */
    public function vuln_concat_sql($dashboardId) {
        $data = $this->fetchSerializedData($dashboardId);
        $dashboard = unserialize($data);

        // VULN: Direct concatenation of unserialized property
        $query = "SELECT * FROM widgets WHERE dashboard_id = " . $dashboard->id
               . " AND status = '" . $dashboard->filter_status . "'";
        return mysql_query($query);
    }

    /**
     * Pattern 5: Laravel/Eloquent raw query with unserialized value
     */
    public function vuln_laravel_raw($reportId) {
        // Fetch serialized report config
        $report = DB::table('reports')->where('id', $reportId)->first();
        $config = unserialize($report->config_blob);

        // VULN: DB::raw with unserialized property
        return DB::select("SELECT * FROM data WHERE category = '" . $config->category . "'");
    }

    /**
     * Pattern 6: Chained property access after unserialize
     */
    public function vuln_chained_properties($userId) {
        $row = pg_fetch_assoc(pg_query("SELECT prefs FROM users WHERE id = $userId"));
        $prefs = unserialize($row['prefs']);

        // Access nested property
        $filterValue = $prefs->display->filter;

        // VULN: Nested property in SQL
        $sql = "SELECT * FROM items WHERE type = '" . $filterValue . "'";
        return pg_query($sql);
    }

    /**
     * Pattern 7: whereRaw with unserialized value
     */
    public function vuln_where_raw($sessionId) {
        // Load session data (often serialized)
        $session = $this->pdo->query("SELECT data FROM sessions WHERE id = '$sessionId'")->fetch();
        $sessionData = unserialize($session['data']);

        // VULN: whereRaw doesn't escape
        return DB::table('logs')
            ->whereRaw("user_id = " . $sessionData->user_id)
            ->get();
    }

    // ==================================================
    // SAFE PATTERNS (Should NOT detect)
    // ==================================================

    /**
     * Safe: Parameterized query after unserialize
     */
    public function safe_parameterized($userId) {
        $row = $this->pdo->query("SELECT prefs FROM users WHERE id = $userId")->fetch();
        $prefs = unserialize($row['prefs']);

        // Safe: Using prepared statement with bound parameter
        $stmt = $this->pdo->prepare("SELECT * FROM themes WHERE id = ?");
        $stmt->execute([$prefs->theme]);
        return $stmt->fetchAll();
    }

    /**
     * Safe: PDO prepared statement with named parameter
     */
    public function safe_named_param($configId) {
        $config = unserialize($this->fetchConfig($configId));

        // Safe: Named parameter binding
        $stmt = $this->pdo->prepare("SELECT * FROM items WHERE category = :cat");
        $stmt->bindParam(':cat', $config->category);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    /**
     * Safe: Type casting before use
     */
    public function safe_type_cast($userId) {
        $prefs = unserialize($this->fetchPrefs($userId));

        // Safe: Integer cast prevents SQL injection
        $themeId = (int)$prefs->theme_id;
        return $this->pdo->query("SELECT * FROM themes WHERE id = $themeId");
    }

    /**
     * Safe: Whitelist validation
     */
    public function safe_whitelist($userId) {
        $prefs = unserialize($this->fetchPrefs($userId));
        $allowedColumns = ['id', 'name', 'created_at'];

        // Safe: Whitelist check
        if (!in_array($prefs->sort_column, $allowedColumns)) {
            $prefs->sort_column = 'id';
        }

        return $this->pdo->query("SELECT * FROM items ORDER BY " . $prefs->sort_column);
    }

    private function fetchSerializedData($id) {
        return $this->pdo->query("SELECT data FROM configs WHERE id = $id")->fetchColumn();
    }

    private function fetchPrefs($userId) {
        return $this->pdo->query("SELECT prefs FROM users WHERE id = $userId")->fetchColumn();
    }

    private function fetchConfig($id) {
        return $this->pdo->query("SELECT config FROM configs WHERE id = $id")->fetchColumn();
    }
}
