<?php
// Devuelve un sello de tiempo firmado que el formulario envía junto a la solicitud.
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
$config = require __DIR__ . '/privado/config.php';
$t = (string) time();
echo json_encode(['t' => $t, 's' => hash_hmac('sha256', $t, $config['secret'])]);
