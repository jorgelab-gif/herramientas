<?php
// Copia este archivo como config.php y rellena los valores.
return [
    // A quién llegan las solicitudes
    'to'     => 'herramientas@jorgelaborda.es',
    // Copia oculta
    'bcc'    => 'jorgelabordat@gmail.com',
    // Remitente: debe ser un buzón del propio dominio en Banahosting
    'from'   => 'herramientas@jorgelaborda.es',
    // Cadena aleatoria larga para firmar el formulario (no la compartas)
    'secret' => 'CAMBIA-ESTO-POR-UNA-CADENA-ALEATORIA-LARGA',
    // Dominio desde el que se aceptan envíos
    'host'   => 'herramientas.jorgelaborda.es',
    // Máximo de solicitudes por IP y hora
    'max_per_hour' => 5,
];
