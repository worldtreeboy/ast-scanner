<?php
/**
 * PHP XSS Test File - INTENTIONALLY VULNERABLE
 * Tests Reflected XSS patterns in PHP
 */

// ==================== DIRECT SUPERGLOBAL OUTPUT ====================

// Direct echo of GET parameter (CRITICAL)
echo $_GET['name'];

// Direct print of POST parameter
print $_POST['comment'];

// Short echo tag with superglobal
?>
<div><?= $_REQUEST['data'] ?></div>
<?php

// Echo with concatenation
echo "Hello, " . $_GET['username'] . "!";

// ==================== TAINTED VARIABLE OUTPUT ====================

$userInput = $_GET['search'];
echo $userInput;  // Tainted variable output

$name = $_POST['name'];
print "Welcome, " . $name;

// ==================== HTML CONTEXT XSS ====================

// Variable in form value
?>
<input type="text" value="<?= $userInput ?>">

<!-- Variable in href -->
<a href="<?php echo $_GET['url']; ?>">Click here</a>

<!-- Variable in src -->
<img src="<?= $_GET['image'] ?>">
<?php

// ==================== SAFE PATTERNS (should NOT trigger) ====================

// Properly encoded output
echo htmlspecialchars($_GET['safe']);
echo htmlentities($_POST['encoded']);
print strip_tags($_REQUEST['clean']);

// WordPress escaping
echo esc_html($_GET['wp_safe']);
echo esc_attr($_POST['wp_attr']);
?>
