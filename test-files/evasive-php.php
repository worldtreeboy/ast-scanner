<?php
/**
 * Test file for PHP strrev and variable variable evasion detection
 * These patterns should be detected as potential code injection
 */

// Pattern 1: strrev to hide 'passthru'
$func = strrev("urhtssap");  // DETECT: strrev hides 'passthru'
$cmd = $_GET['cmd'];
$func($cmd);  // DETECT: Variable function call with tainted args

// Pattern 2: strrev to hide 'system'
$executor = strrev("metsys");  // DETECT: strrev hides 'system'
$input = $_POST['input'];
$executor($input);  // DETECT: Variable function call with tainted args

// Pattern 3: strrev to hide 'shell_exec'
$shell = strrev("cexe_llehs");  // DETECT: strrev hides 'shell_exec'
$command = $_REQUEST['command'];
$shell($command);  // DETECT: Variable function call with tainted args

// Pattern 4: strrev to hide 'exec'
$run = strrev("cexe");  // DETECT: strrev hides 'exec'
$output = [];
$run($_GET['exec_cmd'], $output);  // DETECT: Variable function call

// Pattern 5: strrev to hide 'eval' (code injection)
$evil = strrev("lave");  // DETECT: strrev hides 'eval'
$code = base64_decode($_POST['code']);
$evil($code);  // DETECT: Variable function with tainted args

// Pattern 6: Multiple levels of obfuscation
$fn = strrev("nepop");  // DETECT: strrev hides 'popen'
$handle = $fn($_GET['cmd'], 'r');  // DETECT: Variable function call

// Safe patterns (should NOT be flagged or lower severity)
$safe_reversed = strrev("olleh");  // "hello" - not dangerous
echo $safe_reversed;

// Still flaggable: variable function but not from strrev
$callback = $_GET['callback'];  // User controlled function name
$callback();  // Should be flagged by existing detection

?>
