<?php
// NIC przed tym znakiem! (zero spacji/BOM/nowej linii)

// Na czas diagnozy: widzimy tylko poważne błędy, bez deprecated/notice/warning
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);

// jeśli phpqrcode jest w /var/www/html/ksef/lib/phpqrcode.php:
require_once __DIR__ . '/../lib/phpqrcode.php';

// CORS (opcjonalnie zawęź do swojej domeny)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Tylko POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Dozwolona jest tylko metoda POST.'], JSON_UNESCAPED_UNICODE);
    exit;
}

// Wczytaj JSON z body
$rawInput = file_get_contents('php://input');
$data = json_decode($rawInput, true);

if (!is_array($data)) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Nieprawidłowy JSON w treści żądania.'], JSON_UNESCAPED_UNICODE);
    exit;
}

/*
 * Oczekiwane dane wejściowe:
 * {
 *   "data_wystawienia": "01-02-2026",
 *   "nip_sprzedawcy": "1111111111",
 *   "skrot_sha256": "UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE",
 *   "ulr_api": "https://ksef-test.mf.gov.pl/"
 * }
 */

$dataWystawienia = $data['data_wystawienia'] ?? null;
$nipSprzedawcy   = $data['nip_sprzedawcy']   ?? null;
$skrotSha256     = $data['skrot_sha256']     ?? null;

// Uwaga: używam dokładnie klucza "ulr_api", tak jak podałeś
$ulrApi          = $data['ulr_api']          ?? 'https://ksef-test.mf.gov.pl/';

$errors = [];

// Walidacja
if (empty($dataWystawienia)) {
    $errors[] = 'Brak pola data_wystawienia.';
}

if (empty($nipSprzedawcy)) {
    $errors[] = 'Brak pola nip_sprzedawcy.';
} elseif (!preg_match('/^[0-9]{10}$/', $nipSprzedawcy)) {
    $errors[] = 'nip_sprzedawcy musi mieć dokładnie 10 cyfr.';
}

if (empty($skrotSha256)) {
    $errors[] = 'Brak pola skrot_sha256.';
}

if (!empty($errors)) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => $errors], JSON_UNESCAPED_UNICODE);
    exit;
}

// Normalizacja daty do DD-MM-RRRR
$dataNorm = normalizeDateToDdMmYyyy($dataWystawienia);
if ($dataNorm === null) {
    http_response_code(400);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(
        ['error' => 'Nieprawidłowy format daty. Dozwolone: DD-MM-RRRR lub RRRR-MM-DD.'],
        JSON_UNESCAPED_UNICODE
    );
    exit;
}

// Budowa base URL:
// ulr_api = "https://ksef-test.mf.gov.pl/"
// końcowy base do faktury = "https://ksef-test.mf.gov.pl/client-app/invoice"
$ulrApi         = rtrim($ulrApi, '/');
$invoiceBaseUrl = $ulrApi . '/client-app/invoice';

// Budowa pełnego URL do faktury
$linkKsef = $invoiceBaseUrl
    . '/' . $nipSprzedawcy
    . '/' . $dataNorm
    . '/' . $skrotSha256;

// Nazwa pliku dla Content-Disposition
$safeDate = preg_replace('/[^0-9\-]/', '_', $dataNorm);
$fileName = 'ksef_qr_' . $nipSprzedawcy . '_' . $safeDate . '.png';

// Zwracamy od razu PNG
header('Content-Type: image/png');
header('Content-Disposition: attachment; filename="' . $fileName . '"');

// Parametry QR
$errorCorrectionLevel = QR_ECLEVEL_M; // M – średnia korekcja
$matrixPointSize      = 5;            // rozmiar modułów QR

// Generowanie QR bezpośrednio do odpowiedzi HTTP
QRcode::png($linkKsef, null, $errorCorrectionLevel, $matrixPointSize, 1);
exit;


// ------- FUNKCJA POMOCNICZA -------

/**
 * Zwraca datę w formacie DD-MM-RRRR lub null, jeśli format niepoprawny.
 * Akceptuje:
 *  - "DD-MM-YYYY"
 *  - "YYYY-MM-DD"
 */
function normalizeDateToDdMmYyyy(string $date): ?string
{
    $date = trim($date);

    // DD-MM-YYYY
    $dt = DateTime::createFromFormat('d-m-Y', $date);
    if ($dt instanceof DateTime) {
        return $dt->format('d-m-Y');
    }

    // YYYY-MM-DD
    $dt = DateTime::createFromFormat('Y-m-d', $date);
    if ($dt instanceof DateTime) {
        return $dt->format('d-m-Y');
    }

    return null;
}
