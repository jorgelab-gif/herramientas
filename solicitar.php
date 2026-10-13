<?php
// Recibe las solicitudes de acceso de cada herramienta y las envía por email.
declare(strict_types=1);
date_default_timezone_set('Europe/Madrid');
mb_internal_encoding('UTF-8');

$config = require __DIR__ . '/privado/config.php';
$tools  = require __DIR__ . '/privado/herramientas.php';

const SOURCES = ['Google u otro buscador', 'LinkedIn', 'Podcast', 'Blog de jorgelaborda.es',
                 'Recomendación de alguien', 'Ya soy cliente', 'Otro'];
const MIN_SECONDS = 4;        // un humano tarda más en rellenarlo
const MAX_SECONDS = 4 * 3600; // el sello caduca

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: /', true, 303);
    exit;
}

function field(string $name, int $max = 200): string
{
    $v = trim((string) ($_POST[$name] ?? ''));
    $v = str_replace(["\r\n", "\r"], "\n", $v);
    return mb_substr($v, 0, $max);
}

function one_line(string $v): string
{
    return trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $v));
}

function fail(array $errors): void
{
    http_response_code(422);
    $items = '<ul>' . implode('', array_map(fn($e) => '<li>' . htmlspecialchars($e) . '</li>', $errors)) . '</ul>';
    $tpl = file_get_contents(__DIR__ . '/privado/plantilla-error.html');
    echo str_replace('{ERRORES}', $items, $tpl);
    exit;
}

$slug = field('herramienta', 40);
if (!isset($tools[$slug])) {
    fail(['La herramienta indicada no existe.']);
}
$toolName = $tools[$slug];
$thanks   = '/' . $slug . '/gracias/';

// Trampa 1: campo oculto que solo rellenan los bots. Se finge éxito para no darles pistas.
if (field('empresa_web') !== '') {
    header('Location: ' . $thanks, true, 303);
    exit;
}

// Trampa 2: el envío debe venir de esta web.
$origin = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
if ($origin !== '' && parse_url($origin, PHP_URL_HOST) !== $config['host']) {
    fail(['El formulario debe enviarse desde ' . $config['host'] . '.']);
}

// Trampa 3: sello de tiempo firmado que la página pide con JavaScript.
$t = field('t', 20);
$s = field('s', 80);
if ($t === '' || !ctype_digit($t) || !hash_equals(hash_hmac('sha256', $t, $config['secret']), $s)) {
    fail(['No se ha podido verificar el formulario. Recarga la página con JavaScript activado y vuelve a enviarlo.']);
}
$elapsed = time() - (int) $t;
if ($elapsed < MIN_SECONDS) {
    fail(['Has enviado el formulario demasiado rápido. Espera unos segundos y vuelve a intentarlo.']);
}
if ($elapsed > MAX_SECONDS) {
    fail(['El formulario ha caducado. Recarga la página y vuelve a enviarlo.']);
}

// Límite de envíos por IP (se guarda un hash, no la IP).
$ipHash = hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '') . $config['secret']);
$limitFile = __DIR__ . '/privado/limites/' . substr($ipHash, 0, 32);
$recent = [];
if (is_file($limitFile)) {
    $recent = array_filter(array_map('intval', explode("\n", (string) file_get_contents($limitFile))),
        fn($ts) => $ts > time() - 3600);
}
if (count($recent) >= (int) $config['max_per_hour']) {
    fail(['Has enviado demasiadas solicitudes en poco tiempo. Inténtalo dentro de una hora.']);
}

$data = [
    'Nombre'              => one_line(field('nombre', 120)),
    'Email'               => one_line(field('email', 160)),
    'Teléfono'            => one_line(field('telefono', 30)),
    'Razón social'        => one_line(field('razon_social', 160)),
    'NIF / CIF'           => strtoupper(one_line(field('nif', 20))),
    'Dirección'           => one_line(field('direccion', 200)),
    'Código postal'       => one_line(field('cp', 10)),
    'Población'           => one_line(field('ciudad', 80)),
    'Provincia'           => one_line(field('provincia', 80)),
    'País'                => one_line(field('pais', 80)),
    'Web donde usarla'    => one_line(field('web', 200)),
    'Cómo me ha conocido' => one_line(field('origen', 60)),
];
$motivo = field('motivo', 3000);

$errors = [];
foreach ($data as $label => $value) {
    if ($value === '') {
        $errors[] = "Falta: $label.";
    }
}
if ($data['Email'] !== '' && !filter_var($data['Email'], FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'El email no es válido.';
}
if ($data['Teléfono'] !== '' && strlen(preg_replace('/\D/', '', $data['Teléfono'])) < 9) {
    $errors[] = 'El teléfono debe tener al menos 9 cifras.';
}
if ($data['Web donde usarla'] !== '') {
    if (!preg_match('#^https?://#i', $data['Web donde usarla'])) {
        $data['Web donde usarla'] = 'https://' . $data['Web donde usarla'];
    }
    if (!filter_var($data['Web donde usarla'], FILTER_VALIDATE_URL)) {
        $errors[] = 'La web no es una dirección válida.';
    }
}
if ($data['Cómo me ha conocido'] !== '' && !in_array($data['Cómo me ha conocido'], SOURCES, true)) {
    $errors[] = 'Elige cómo me has conocido.';
}
if (mb_strlen($motivo) < 20) {
    $errors[] = 'Cuéntame un poco más para qué quieres usar la herramienta (mínimo 20 caracteres).';
}
// Trampa 4: los mensajes de spam suelen llevar muchos enlaces.
if (preg_match_all('#https?://|www\.#i', $motivo) > 2) {
    $errors[] = 'El motivo no puede llevar más de dos enlaces.';
}
if (($_POST['privacidad'] ?? '') !== '1') {
    $errors[] = 'Debes aceptar la política de privacidad.';
}
if ($errors) {
    fail($errors);
}

$recent[] = time();
@file_put_contents($limitFile, implode("\n", $recent), LOCK_EX);

$lines = ["Nueva solicitud de acceso a $toolName", str_repeat('=', 40), ''];
foreach ($data as $label => $value) {
    $lines[] = $label . ':' . str_repeat(' ', max(1, 21 - mb_strlen($label))) . $value;
}
$lines[] = '';
$lines[] = 'Motivo:';
$lines[] = $motivo;
$lines[] = '';
$lines[] = '--';
$lines[] = 'Enviado desde https://' . $config['host'] . '/' . $slug . '/ el ' . date('d/m/Y H:i');
$lines[] = 'Acepta la política de privacidad: sí';

$subject = "Solicitud de acceso a $toolName: " . $data['Nombre'];
$headers = [
    'From: Herramientas Jorge Laborda <' . $config['from'] . '>',
    'Reply-To: ' . $data['Email'],
    'Bcc: ' . $config['bcc'],
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
];

$sent = mail(
    $config['to'],
    mb_encode_mimeheader($subject, 'UTF-8', 'B'),
    implode("\n", $lines),
    implode("\r\n", $headers),
    '-f' . $config['from']
);

if (!$sent) {
    fail(['El servidor no ha podido enviar el correo. Inténtalo más tarde o escribe a ' . $config['to'] . '.']);
}

header('Location: ' . $thanks, true, 303);
