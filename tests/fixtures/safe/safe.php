<?php
$password = getenv("DB_PASSWORD");
$stmt = $pdo->prepare("SELECT * FROM orders WHERE id = ?");
$stmt->execute([$_GET['id']]);
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
system("uptime");
$data = json_decode($_COOKIE['prefs'], true);
$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
include __DIR__ . "/header.php";
