<?php
/**
 * search.php - Secure Patient & Medical Record Search Proxy
 * * DESIGN PRINCIPLES:
 * 1. Strict separation of data-plane and command-plane via PDO Parameterization.
 * 2. Least Privilege Principle: Utilizes a read-only database service account.
 * 3. Context-Aware Output Defense: HTML-encodes dynamic data streams prior to browser rendering.
 */

// Import database configuration (assumed to instantiate a secure $pdo handle)
// The $pdo handle MUST be configured with:
// $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
// $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
require_once 'db_config.php';

// 1. INPUT ACQUISITION & SANITY FILTERING
// Retrieve user query parameter; default to an empty string if not provided.
$keyword = $_GET['keyword'] ?? '';

try {
    // 2. PARALLEL STATEMENT PRECOMPILATION (Command-Plane Protection)
    // We prepare the SQL template string containing an explicit named placeholder (:keyword).
    // This allows the database query parser to build and freeze the Abstract Syntax Tree (AST)
    // BEFORE the user's data payload ever arrives.
    $sql = "SELECT id, name, illness_history 
            FROM patient_records 
            WHERE name LIKE :keyword";

    $stmt = $pdo->prepare($sql);

    // 3. SECURE BINDING & EXECUTION (Data-Plane Isolation)
    // The query execution maps the raw search term strictly to the leaf node of the AST.
    // The wildcard characters (%) are concatenated programmatically to avoid syntax leakage.
    $stmt->execute([
        'keyword' => '%' . $keyword . '%'
    ]);

    // Retrieve all matched rows securely as an associative array
    $records = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // 4. CONTEXT-AWARE RENDERING (XSS Protection)
    // Encodes the raw input and output strings before emitting them to the HTML DOM.
    // ENT_QUOTES ensures both single and double quotes are escaped.
    // Specifying UTF-8 prevents encoding-bypass tricks.
    $safeKeyword = htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');

    if (count($records) > 0) {
        foreach ($records as $row) {
            // Encode patient-specific records retrieved from the database to handle stored threats
            $safeName = htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8');
            $safeHistory = htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8');

            echo "<div class='record'>";
            echo "Result found for keyword: <strong>" . $safeKeyword . "</strong><br>";
            echo "Patient: " . $safeName . " | History: " . $safeHistory;
            echo "</div><hr>";
        }
    } else {
        // Enforce the same rigorous output boundary in the error/fallback condition
        echo "<div class='info'>No records found for: " . $safeKeyword . "</div>";
    }

} catch (PDOException $e) {
    // Fail closed: Log internal system error details securely, and emit a generic error message
    error_log("Database Execution Failure in search.php: " . $e->getMessage());
    http_response_code(500);
    echo "<div class='error'>A system error occurred. Please contact your system administrator.</div>";
}
?>