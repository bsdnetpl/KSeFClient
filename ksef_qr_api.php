<?php
// --- PROSTE ZABEZPIECZENIE API (KLUCZ W URL) ---
$apiSecretKey = "T474Y0aY2yMApEkn";

if (!isset($_GET['key']) || $_GET['key'] !== $apiSecretKey) {
    http_response_code(403);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Brak dostępu. Niepoprawny klucz API.'], JSON_UNESCAPED_UNICODE);
    exit;
}

// NIC przed tym znakiem! (zero spacji/BOM)

// Produkcyjnie: nie wypluwamy warningów/deprecated, żeby nie psuć PNG
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(E_ERROR | E_PARSE);

// Ścieżka do biblioteki PHP QR Code
require_once __DIR__ . '/lib/phpqrcode.php';

// CORS (opcjonalnie zawęź do swojej domeny)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Dozwolona jest tylko metoda POST.'], JSON_UNESCAPED_UNICODE);
    exit;
}

// ------------------------------
// ZMIENNE WSPÓLNE
// ------------------------------
$dataWystawienia = null;
$nipSprzedawcy   = null;
$skrotSha256     = null;
$ulrApi          = null;

// ------------------------------
// TRYB 1: PLIK XML (multipart/form-data) – PRIORYTET
// ------------------------------
if (isset($_FILES['xml_file'])) {

    $fileError = $_FILES['xml_file']['error'];

    if ($fileError !== UPLOAD_ERR_OK) {
        $msg = 'Błąd uploadu pliku XML. Kod: ' . $fileError;

        switch ($fileError) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $msg = 'Plik XML jest większy niż dopuszcza konfiguracja serwera (upload_max_filesize / post_max_size).';
                break;
            case UPLOAD_ERR_PARTIAL:
                $msg = 'Plik XML został wgrany tylko częściowo.';
                break;
            case UPLOAD_ERR_NO_FILE:
                $msg = 'Nie przesłano pliku XML (pole xml_file).';
                break;
            case UPLOAD_ERR_NO_TMP_DIR:
                $msg = 'Brak katalogu tymczasowego na serwerze (upload_tmp_dir).';
                break;
            case UPLOAD_ERR_CANT_WRITE:
                $msg = 'Nie można zapisać pliku XML na dysk (uprawnienia).';
                break;
            case UPLOAD_ERR_EXTENSION:
                $msg = 'Rozszerzenie PHP przerwało upload pliku XML.';
                break;
        }

        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => $msg], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Wymagane pola z POST (z formularza / cURL -F)
    $dataWystawienia = $_POST['data_wystawienia'] ?? null;
    $nipSprzedawcy   = $_POST['nip_sprzedawcy']   ?? null;
    $ulrApi          = $_POST['ulr_api']          ?? 'https://ksef-test.mf.gov.pl/';

    $errors = [];

    if (empty($dataWystawienia)) {
        $errors[] = 'Brak pola data_wystawienia.';
    }

    if (empty($nipSprzedawcy)) {
        $errors[] = 'Brak pola nip_sprzedawcy.';
    } elseif (!preg_match('/^[0-9]{10}$/', $nipSprzedawcy)) {
        $errors[] = 'nip_sprzedawcy musi mieć dokładnie 10 cyfr.';
    }

    if (!empty($errors)) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => $errors], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $xmlContent = file_get_contents($_FILES['xml_file']['tmp_name']);
    if ($xmlContent === false || $xmlContent === '') {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Nie udało się odczytać przesłanego pliku XML.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // SHA-256 z surowej treści XML (binarnie)
    $hashBin = hash('sha256', $xmlContent, true);
    // Base64 klasyczne
    $hashB64 = base64_encode($hashBin);
    // Base64URL (zgodnie ze specyfikacją KSeF)
    $skrotSha256 = rtrim(strtr($hashB64, '+/', '-_'), '=');

} else {

    // ------------------------------
    // TRYB 2: JSON (fallback / zgodność wsteczna)
    // ------------------------------
    $rawInput = file_get_contents('php://input');
    $data = json_decode($rawInput, true);

    if (!is_array($data)) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Nieprawidłowy JSON w treści żądania.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $dataWystawienia = $data['data_wystawienia'] ?? null;
    $nipSprzedawcy   = $data['nip_sprzedawcy']   ?? null;
    $skrotSha256     = $data['skrot_sha256']     ?? null;   // opcjonalne
    $xmlBase64       = $data['xml_base64']       ?? null;
    $xmlRaw          = $data['xml_raw']          ?? null;
    $ulrApi          = $data['ulr_api']          ?? 'https://ksef-test.mf.gov.pl/';

    $errors = [];

    if (empty($dataWystawienia)) {
        $errors[] = 'Brak pola data_wystawienia.';
    }

    if (empty($nipSprzedawcy)) {
        $errors[] = 'Brak pola nip_sprzedawcy.';
    } elseif (!preg_match('/^[0-9]{10}$/', $nipSprzedawcy)) {
        $errors[] = 'nip_sprzedawcy musi mieć dokładnie 10 cyfr.';
    }

    if (empty($skrotSha256) && empty($xmlBase64) && empty($xmlRaw)) {
        $errors[] = 'Podaj skrot_sha256 lub xml_base64 albo xml_raw.';
    }

    if (!empty($errors)) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => $errors], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Jeśli nie mamy gotowego skrótu – liczymy go z XML-a
    if (empty($skrotSha256)) {
        $xmlContent = null;

        if (!empty($xmlBase64)) {
            $xmlContent = base64_decode($xmlBase64, true);
            if ($xmlContent === false) {
                http_response_code(400);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode(['error' => 'Nie udało się zdekodować xml_base64.'], JSON_UNESCAPED_UNICODE);
                exit;
            }
        } elseif (!empty($xmlRaw)) {
            $xmlContent = $xmlRaw;
        }

        if ($xmlContent === null) {
            http_response_code(400);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'Brak poprawnej treści XML (xml_base64/xml_raw).'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $hashBin = hash('sha256', $xmlContent, true);
        $hashB64 = base64_encode($hashBin);
        $skrotSha256 = rtrim(strtr($hashB64, '+/', '-_'), '=');
    }
}

// ------------------------------
// WSPÓLNA CZĘŚĆ DLA OBU TRYBÓW
// ------------------------------

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

// 🔹 Wymuszenie formatu Base64URL (niezależnie od źródła)
$skrotSha256 = toBase64Url($skrotSha256);

// Budowa URL KSeF
$ulrApi         = rtrim($ulrApi, '/');
$invoiceBaseUrl = $ulrApi . '/client-app/invoice';

$linkKsef = $invoiceBaseUrl
    . '/' . $nipSprzedawcy
    . '/' . $dataNorm
    . '/' . $skrotSha256;

// Nazwa pliku – GUID.png
$guid     = generateGuid();
$fileName = $guid . '.png';

// Nagłówki i generowanie PNG
header('Content-Type: image/png');
header('Content-Disposition: attachment; filename="' . $fileName . '"');

$errorCorrectionLevel = QR_ECLEVEL_M;
$matrixPointSize      = 5;

QRcode::png($linkKsef, null, $errorCorrectionLevel, $matrixPointSize, 1);
exit;


// ------- FUNKCJE POMOCNICZE -------

function normalizeDateToDdMmYyyy(string $date): ?string
{
    $date = trim($date);

    $dt = DateTime::createFromFormat('d-m-Y', $date);
    if ($dt instanceof DateTime) {
        return $dt->format('d-m-Y');
    }

    $dt = DateTime::createFromFormat('Y-m-d', $date);
    if ($dt instanceof DateTime) {
        return $dt->format('d-m-Y');
    }

    return null;
}

function generateGuid(): string
{
    return sprintf(
        '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

function toBase64Url(string $hash): string
{
    $hash = trim($hash);
    $hash = rtrim($hash, '=');        // usuń padding
    $hash = strtr($hash, '+/', '-_'); // zamień na URL-safe
    return $hash;
}
