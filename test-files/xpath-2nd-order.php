<?php
/**
 * 2nd-Order XPath Injection Test Cases - PHP
 *
 * PHP XPath Sinks:
 * - DOMXPath->query($expr)
 * - DOMXPath->evaluate($expr)
 * - SimpleXMLElement->xpath($expr)
 *
 * Attack Payloads:
 * - Breakout: "' or 1=1 or 'a'='a"
 * - Enumerate: "//user" or "/*"
 * - Brute force: "user[password='admin']"
 */

class AclService {
    private $pdo;

    // ========================================
    // CRITICAL: DOMXPath->query() with DB value
    // ========================================

    public function hasPermission($userId, $featureId) {
        // Phase 1: Load department from database
        $row = $this->pdo->query("SELECT dept FROM users WHERE id = $userId")->fetch();
        $dept = $row['dept'];  // DB-sourced!

        // Phase 2: Query ACL XML
        $doc = new DOMDocument();
        $doc->load('permissions.xml');
        $xpath = new DOMXPath($doc);

        // CRITICAL VULN: DB value in XPath query
        // Payload in $dept: "Engineering' or 1=1 or 'a'='a"
        $nodes = $xpath->query("//dept[@name='" . $dept . "']/feature[@id='$featureId']");
        return $nodes->length > 0;
    }

    // ========================================
    // CRITICAL: DOMXPath->evaluate() with DB value
    // ========================================

    public function countUserNodes($configId) {
        // Phase 1: Load XPath filter from config table
        $stmt = $this->pdo->query("SELECT filter FROM configs WHERE id = $configId");
        $config = $stmt->fetch();
        $filter = $config['filter'];  // DB-sourced!

        $doc = new DOMDocument();
        $doc->loadXML(file_get_contents('data.xml'));
        $xpath = new DOMXPath($doc);

        // CRITICAL VULN: DB value in evaluate()
        // Payload: "//user" returns all users
        return $xpath->evaluate("count(" . $filter . ")");
    }

    // ========================================
    // CRITICAL: SimpleXML->xpath() with DB value
    // ========================================

    public function findProducts($userId) {
        // Phase 1: Load category preference from user
        $row = $this->pdo->query("SELECT category FROM user_prefs WHERE user_id = $userId")->fetch();
        $category = $row['category'];  // DB-sourced!

        $xml = simplexml_load_file('products.xml');

        // CRITICAL VULN: SimpleXML xpath with DB value
        // Payload in $category: "books' or 1=1 or 'a'='a"
        return $xml->xpath("//product[@category='" . $category . "']");
    }

    // ========================================
    // CRITICAL: JSON-decoded value in XPath
    // ========================================

    public function searchByJsonConfig($userId) {
        // Phase 1: Load JSON config from database
        $row = $this->pdo->query("SELECT json_config FROM settings WHERE user_id = $userId")->fetch();
        $config = json_decode($row['json_config'], true);
        $searchPath = $config['xpath_filter'];  // JSON-poisoned!

        $doc = new DOMDocument();
        $doc->load('data.xml');
        $xpath = new DOMXPath($doc);

        // CRITICAL VULN: JSON-decoded value in XPath
        return $xpath->query($searchPath);
    }

    // ========================================
    // CRITICAL: Unserialized value in XPath
    // ========================================

    public function searchByPrefs($userId) {
        // Phase 1: Load serialized preferences
        $row = $this->pdo->query("SELECT prefs FROM users WHERE id = $userId")->fetch();
        $prefs = unserialize($row['prefs']);  // Unserialized!
        $filterPath = $prefs->xpath_filter;  // Property access

        $doc = new DOMDocument();
        $doc->load('data.xml');
        $xpath = new DOMXPath($doc);

        // CRITICAL VULN: Unserialized property in XPath
        return $xpath->query($filterPath);
    }

    // ========================================
    // CRITICAL: Direct taint in XPath
    // ========================================

    public function searchByUserInput() {
        // Direct user input
        $searchExpr = $_GET['xpath'];  // Tainted!

        $xml = simplexml_load_file('data.xml');

        // CRITICAL VULN: Direct user input in xpath()
        return $xml->xpath($searchExpr);
    }

    // ========================================
    // SAFE PATTERNS (Should NOT flag)
    // ========================================

    public function safeHardcodedXPath() {
        $xml = simplexml_load_file('data.xml');
        // Safe: Hardcoded XPath
        return $xml->xpath("//products/product[@active='true']");
    }

    public function safeWhitelistXPath($userId) {
        $row = $this->pdo->query("SELECT category FROM prefs WHERE id = $userId")->fetch();
        $category = $row['category'];

        // Safe: Whitelist validation
        $allowed = ['books', 'electronics', 'clothing'];
        if (!in_array($category, $allowed)) {
            $category = 'books';
        }

        $xml = simplexml_load_file('products.xml');
        // Safe after whitelist check
        return $xml->xpath("//product[@category='" . $category . "']");
    }
}
