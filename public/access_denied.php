<?php http_response_code(403); ?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Access denied — Server Manager</title>
    <link rel="stylesheet" href="/assets/css/app.css">
</head>
<body class="denied-page">
    <div class="denied-card">
        <div class="denied-icon">&#9888;</div>
        <h1>Access denied</h1>
        <p>Your account does not have a role permitted to use Server Manager.</p>
        <p class="muted">Contact an administrator if you believe this is a mistake.</p>
        <a class="btn" href="/logout.php">Sign out</a>
    </div>
</body>
</html>
