<?php
// Sample - intentionally vulnerable PHP page (for scanner demos)
$db_password = "MyS3cretPhp!";
$mysqli = new mysqli("localhost", "app", $db_password, "shop");

$id = $_GET['id'];
$result = mysqli_query($mysqli, "SELECT * FROM orders WHERE id = " . $id);

$output = shell_exec("ping -c 1 " . $_GET['host']);
system("convert " . $_POST['file'] . " out.pdf");

eval($_POST['code']);

$prefs = unserialize($_COOKIE['prefs']);

include $_GET['page'];

echo "Hello " . $_GET['name'];

$ch = curl_init("https://api.example.com");
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

$hash = md5($_POST['password']);
