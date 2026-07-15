<?php
/**
 * Server Manager — SPA shell. SSO-guarded; renders the dashboard skeleton
 * which app.js hydrates via the REST API.
 */
require_once __DIR__ . '/../app/bootstrap.php';

use App\Auth;

$user = Auth::requireWeb();
$name = htmlspecialchars($user['name'] ?? 'operator', ENT_QUOTES);
$roles = htmlspecialchars(implode(', ', $user['roles'] ?? []), ENT_QUOTES);
$appName = htmlspecialchars((string) \App\config('app.name', 'Server Manager'), ENT_QUOTES);
$isAdmin = (bool) array_intersect($user['roles'] ?? [], \App\config('auth.admin_roles', []));
?><!doctype html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $appName ?></title>
    <meta name="csrf" content="<?= htmlspecialchars(bin2hex(random_bytes(16))) ?>">
    <link rel="preconnect" href="https://cdnjs.cloudflare.com">
    <link rel="stylesheet" href="/assets/css/app.css?v=1">
</head>
<body data-admin="<?= $isAdmin ? '1' : '0' ?>">
<div id="app">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="brand">
            <span class="brand-mark">SM</span>
            <div class="brand-text">
                <strong>Server Manager</strong>
                <small>mcnutt.cloud</small>
            </div>
        </div>
        <nav class="nav">
            <a href="#overview"  class="nav-item active" data-view="overview"><span class="ico">&#9632;</span> Overview</a>
            <a href="#services"  class="nav-item" data-view="services"><span class="ico">&#9881;</span> Services</a>
            <a href="#firewall"  class="nav-item" data-view="firewall"><span class="ico">&#128737;</span> Firewall</a>
            <a href="#nids"      class="nav-item" data-view="nids"><span class="ico">&#128680;</span> NIDS / Blocks</a>
            <a href="#apps"      class="nav-item" data-view="apps"><span class="ico">&#128230;</span> Applications</a>
            <a href="#logs"      class="nav-item" data-view="logs"><span class="ico">&#128196;</span> Logs &amp; Usage</a>
            <a href="#runner"    class="nav-item" data-view="runner"><span class="ico">&#9002;_</span> CLI Runner</a>
            <a href="#audit"     class="nav-item" data-view="audit"><span class="ico">&#128220;</span> Audit</a>
        </nav>
        <div class="sidebar-foot">
            <div class="user">
                <div class="avatar"><?= strtoupper(substr($name, 0, 1)) ?></div>
                <div class="user-meta">
                    <span class="user-name"><?= $name ?></span>
                    <span class="user-role"><?= $roles ?: 'user' ?></span>
                </div>
            </div>
            <a class="logout" href="/logout.php" title="Sign out">&#9099;</a>
        </div>
    </aside>

    <!-- Main -->
    <main class="main">
        <header class="topbar">
            <div class="topbar-title">
                <button class="btn ghost menu-toggle" id="menuToggle" aria-label="Menu">&#9776;</button>
                <h1 id="viewTitle">Overview</h1>
                <span class="host-pill" id="hostPill">&hellip;</span>
            </div>
            <div class="topbar-actions">
                <span class="health-badge" id="healthBadge">&mdash;</span>
                <button class="btn ghost" id="refreshBtn" title="Refresh">&#8635; Refresh</button>
                <label class="auto-toggle"><input type="checkbox" id="autoRefresh" checked> Auto</label>
            </div>
        </header>

        <div class="toast-wrap" id="toasts"></div>

        <section class="content" id="content">
            <!-- Views injected by app.js -->
            <div class="view" id="view-overview"></div>
            <div class="view hidden" id="view-services"></div>
            <div class="view hidden" id="view-firewall"></div>
            <div class="view hidden" id="view-nids"></div>
            <div class="view hidden" id="view-apps"></div>
            <div class="view hidden" id="view-logs"></div>
            <div class="view hidden" id="view-runner"></div>
            <div class="view hidden" id="view-audit"></div>
        </section>
    </main>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>window.SM = { admin: <?= $isAdmin ? 'true' : 'false' ?>, user: <?= json_encode($name) ?> };</script>
<script src="/assets/js/app.js?v=1"></script>
</body>
</html>
