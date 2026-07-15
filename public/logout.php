<?php
/**
 * Logout endpoint — revokes the session centrally and redirects.
 */
require_once __DIR__ . '/../client_helper/auth.php';
handle_logout_request();
