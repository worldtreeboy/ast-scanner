<?php
/**
 * 2nd-Order SQL Injection Test Cases for PHP
 * Tests: UPDATE/DELETE with database-sourced values
 */

class VulnerableAuditController {

    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    // ========================================
    // PHASE 1: Safe storage (no vuln here)
    // ========================================
    public function saveDisplayName($userId, $name) {
        // Safe: Parameterized storage
        $stmt = $this->db->prepare("UPDATE users SET display_name = ? WHERE id = ?");
        $stmt->execute([$name, $userId]);
        // Payload stored: "admin' --"
    }

    // ========================================
    // 2ND-ORDER: UPDATE with db-sourced value
    // ========================================
    public function auditPasswordReset($targetId) {
        // Phase 2 trigger: Load the poisoned display_name
        $res = $this->db->query("SELECT display_name FROM users WHERE id = $targetId");
        $user = $res->fetch_assoc();
        $displayName = $user['display_name'];

        // VULNERABLE: 2nd-order UPDATE injection
        // Stored payload: "admin' --"
        // Result: Updates admin's session instead of target
        $this->db->query("UPDATE sessions SET status = 'revoked' WHERE username = '" . $displayName . "'");
    }

    public function updateUserStatus($userId) {
        // Fetch row from database
        $result = mysqli_fetch_assoc($this->db->query("SELECT status FROM temp_data WHERE uid = $userId"));
        $storedStatus = $result['status'];

        // VULNERABLE: mysqli_query with db value in UPDATE
        mysqli_query($this->db, "UPDATE users SET flag = 1 WHERE status = '" . $storedStatus . "'");
    }

    // ========================================
    // 2ND-ORDER: DELETE with db-sourced value
    // ========================================
    public function cleanupByCategory($categoryId) {
        // Fetch category name from DB
        $cat = $this->db->query("SELECT name FROM categories WHERE id = $categoryId")->fetch_assoc();
        $categoryName = $cat['name'];

        // VULNERABLE: 2nd-order DELETE
        // Payload: "test' OR 1=1 --" deletes everything
        $this->db->query("DELETE FROM items WHERE category = '" . $categoryName . "'");
    }

    public function purgeMessages($configId) {
        // Load purge condition from config table
        $row = $this->db->query("SELECT purge_filter FROM config WHERE id = $configId")->fetch_object();
        $filter = $row->purge_filter;

        // VULNERABLE: PDO exec with db-sourced value
        $this->db->exec("DELETE FROM messages WHERE " . $filter);
    }

    // ========================================
    // 2ND-ORDER: Structural (ORDER BY / GROUP BY)
    // ========================================
    public function generateReport($userId) {
        // Load sort preference from user profile
        $pref = $this->db->query("SELECT sort_column FROM preferences WHERE user_id = $userId")->fetch_assoc();
        $sortCol = $pref['sort_column'];

        // VULNERABLE: 2nd-order ORDER BY injection
        // Enables boolean-based exfiltration via CASE WHEN
        $this->db->query("SELECT * FROM reports ORDER BY " . $sortCol);
    }

    public function statsGrouped($settingId) {
        // Fetch grouping from settings
        $setting = mysqli_fetch_array($this->db->query("SELECT group_by FROM settings WHERE id = $settingId"));
        $groupField = $setting['group_by'];

        // VULNERABLE: 2nd-order GROUP BY
        $this->db->query("SELECT COUNT(*) FROM sales GROUP BY " . $groupField);
    }

    // ========================================
    // 1ST-ORDER (Direct) for comparison
    // ========================================
    public function directUpdate() {
        // 1st-order: Direct $_GET in query
        $name = $_GET['name'];
        $this->db->query("UPDATE users SET status = 'active' WHERE name = '" . $name . "'");
    }

    public function directDelete() {
        // 1st-order: Direct $_POST in DELETE
        $id = $_POST['id'];
        mysqli_query($this->db, "DELETE FROM records WHERE id = " . $id);
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================
    public function safeUpdate($userId, $status) {
        // Prepared statement - safe
        $stmt = $this->db->prepare("UPDATE users SET status = ? WHERE id = ?");
        $stmt->execute([$status, $userId]);
    }

    public function safeDelete($id) {
        // Prepared statement - safe
        $stmt = $this->db->prepare("DELETE FROM messages WHERE id = ?");
        $stmt->execute([$id]);
    }
}
