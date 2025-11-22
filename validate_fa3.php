<?php
// validate_fa3.php
declare(strict_types=1);

// Konfiguracja domyślnego XSD:
const DEFAULT_XSD_URL = 'https://audev.pl/ksef/schemat-fa3.xsd';

// Upewnij się, że błędy libxml nie wylecą na ekran w surowej formie
libxml_use_internal_errors(true);

function validateXmlAgainstXsd(string $xmlContent, string $xsdUrl): array {
    $dom = new DOMDocument();
    // Wczytanie XML z opcjami zwiększającymi precyzję numerów linii
    $loaded = $dom->loadXML($xmlContent, LIBXML_BIGLINES | LIBXML_NOCDATA | LIBXML_NONET);
    if (!$loaded) {
        return ['ok' => false, 'errors' => formatLibxmlErrors(libxml_get_errors(), 'Błąd wczytywania XML')];
    }

    // Walidacja względem XSD (zdalny URL). LIBXML_NONET blokuje ładowanie sieciowe bytów, ale schemaValidate
    // pobiera XSD niezależnie — jeśli chcesz całkowicie odciąć sieć, zapisz XSD lokalnie i wskaż ścieżkę pliku.
    $isValid = @$dom->schemaValidate($xsdUrl);
    if ($isValid) {
        return ['ok' => true, 'errors' => []];
    }
    return ['ok' => false, 'errors' => formatLibxmlErrors(libxml_get_errors(), 'Błąd walidacji XSD')];
}

function formatLibxmlErrors(array $errors, string $title = 'Błędy'): array {
    $out = [];
    foreach ($errors as $err) {
        switch ($err->level) {
            case LIBXML_ERR_WARNING:
                $level = 'Ostrzeżenie';
                break;
            case LIBXML_ERR_ERROR:
                $level = 'Błąd';
                break;
            case LIBXML_ERR_FATAL:
                $level = 'Błąd krytyczny';
                break;
            default:
                $level = 'Info';
        }
        $out[] = [
            'level'   => $level,
            'code'    => $err->code,
            'line'    => $err->line,
            'column'  => $err->column,
            'message' => trim($err->message),
            'file'    => $err->file ?: null,
        ];
    }
    libxml_clear_errors();
    return $out;
}

function getPostedXml(): ?string {
    // 1) Priorytet: upload pliku
    if (!empty($_FILES['xml_file']['tmp_name']) && is_uploaded_file($_FILES['xml_file']['tmp_name'])) {
        $content = file_get_contents($_FILES['xml_file']['tmp_name']);
        return is_string($content) && $content !== '' ? $content : null;
    }
    // 2) Alternatywnie: wklejona treść
    if (!empty($_POST['xml_text'])) {
        return (string)$_POST['xml_text'];
    }
    return null;
}

// Obsługa POST
$result = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xsdUrl = trim($_POST['xsd_url'] ?? DEFAULT_XSD_URL);
    $xml    = getPostedXml();

    if (!$xml) {
        $result = ['ok' => false, 'errors' => [['level' => 'Błąd', 'message' => 'Nie dostarczono pliku XML ani treści XML.']]];
    } elseif (!filter_var($xsdUrl, FILTER_VALIDATE_URL)) {
        $result = ['ok' => false, 'errors' => [['level' => 'Błąd', 'message' => 'Nieprawidłowy URL schematu XSD.']]];
    } else {
        $result = validateXmlAgainstXsd($xml, $xsdUrl);
    }
}

?>
<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Walidacja XML względem FA(3) XSD</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
    body { padding: 2rem 0; }
    .code { white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }
</style>
</head>
<body>
<div class="container">
    <h1 class="mb-3">Walidacja XML względem schematu FA(3)</h1>
    <p class="text-muted">Wgraj plik XML lub wklej treść. Domyślnie używany jest schemat: <code><?= htmlspecialchars(DEFAULT_XSD_URL, ENT_QUOTES) ?></code>.</p>

    <form method="post" enctype="multipart/form-data" class="row g-3">
        <div class="col-12">
            <label for="xsd_url" class="form-label">URL schematu XSD</label>
            <input type="url" class="form-control" id="xsd_url" name="xsd_url"
                   value="<?= htmlspecialchars($_POST['xsd_url'] ?? DEFAULT_XSD_URL, ENT_QUOTES) ?>" required>
            <div class="form-text">Możesz podać własny URL XSD (HTTPS zalecany).</div>
        </div>

        <div class="col-md-6">
            <label for="xml_file" class="form-label">Plik XML</label>
            <input class="form-control" type="file" id="xml_file" name="xml_file" accept=".xml,text/xml">
            <div class="form-text">Opcjonalnie — zamiast wklejać treść.</div>
        </div>

        <div class="col-md-6">
            <label for="xml_text" class="form-label">Treść XML (wklej)</label>
            <textarea class="form-control" id="xml_text" name="xml_text" rows="8" placeholder="&lt;?xml version=&quot;1.0&quot;?&gt;&#10;&lt;Faktura ...&gt;...&lt;/Faktura&gt;"><?= isset($_POST['xml_text']) ? htmlspecialchars($_POST['xml_text'], ENT_QUOTES) : '' ?></textarea>
            <div class="form-text">Jeśli wgrasz plik i wkleisz treść, priorytet ma plik.</div>
        </div>

        <div class="col-12">
            <button class="btn btn-primary" type="submit">Waliduj</button>
        </div>
    </form>

    <?php if ($result !== null): ?>
        <hr class="my-4">
        <?php if ($result['ok']): ?>
            <div class="alert alert-success">
                ✅ XML jest <strong>poprawny</strong> względem podanego schematu XSD.
            </div>
        <?php else: ?>
            <div class="alert alert-danger">
                ❌ XML <strong>nie przeszedł</strong> walidacji. Szczegóły poniżej.
            </div>
            <?php if (!empty($result['errors'])): ?>
                <div class="table-responsive">
                    <table class="table table-bordered table-striped align-middle">
                        <thead class="table-light">
                        <tr>
                            <th>#</th>
                            <th>Poziom</th>
                            <th>Kod</th>
                            <th>Linia</th>
                            <th>Kolumna</th>
                            <th>Komunikat</th>
                        </tr>
                        </thead>
                        <tbody>
                        <?php foreach ($result['errors'] as $i => $e): ?>
                            <tr>
                                <td><?= $i + 1 ?></td>
                                <td><?= htmlspecialchars($e['level'] ?? '', ENT_QUOTES) ?></td>
                                <td><?= htmlspecialchars((string)($e['code'] ?? ''), ENT_QUOTES) ?></td>
                                <td><?= htmlspecialchars((string)($e['line'] ?? ''), ENT_QUOTES) ?></td>
                                <td><?= htmlspecialchars((string)($e['column'] ?? ''), ENT_QUOTES) ?></td>
                                <td class="code"><?= htmlspecialchars($e['message'] ?? '', ENT_QUOTES) ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <p class="text-muted">Brak dodatkowych informacji o błędach (sprawdź, czy libxml jest włączony).</p>
            <?php endif; ?>
        <?php endif; ?>
    <?php endif; ?>

    <hr class="my-4">
    <details>
        <summary class="h6 mb-3">Wskazówki i bezpieczeństwo</summary>
        <ul>
            <li>Jeśli serwer produkcyjny nie ma dostępu do internetu, pobierz XSD lokalnie i podaj ścieżkę pliku (np. <code>/var/www/html/ksef/schemat-fa3.xsd</code>).</li>
            <li>Dla pełnej izolacji sieci ustaw lokalną ścieżkę XSD — <code>LIBXML_NONET</code> blokuje zewnętrzne encje, ale sama walidacja i tak pobierze XSD z URL.</li>
            <li>Gdy walidacja zgłasza błędy przestrzeni nazw, upewnij się, że root XML ma prawidłowe <code>xmlns</code> i ewentualne prefiksy.</li>
            <li>Walidacja XSD sprawdza zgodność struktury/typów, nie poprawność biznesową (np. sumy). Do reguł biznesowych dodaj własne testy po przejściu XSD.</li>
        </ul>
    </details>
</div>
</body>
</html>



