<?php
/**
 * SSO callback endpoint. The login service redirects here with payload/sig.
 */
require_once __DIR__ . '/../client_helper/auth.php';
handle_sso_callback();

// If we reach here it was not a callback; send the user home.
header('Location: /');
exit;
