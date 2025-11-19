<?php
declare(strict_types=1);

ini_set('display_errors','1');
error_reporting(E_ALL);
header('Content-Type: text/html; charset=utf-8');

session_start();

require __DIR__ . '/KSeFAuth.php';

// ===================== KONFIG =====================
$nip      = '1111111111';
$crtPath  = __DIR__ . '/main_nip.crt';                                                          // Dla wyjaśnienia: projekt testowy pobiera te dane z plików niezakodowanych. W środowisku
$keyPath  = __DIR__ . '/main_nip.key';                                                          // produkcyjnym jest to niedopuszczalne — dane powinny być przechowywane np. w bazie, w formie
$keyPass  = trim(@file_get_contents(__DIR__ . '/pass.txt')) ?: null; // null jeśli bez hasła    // zaszyfrowanej. Dopiero podczas użycia powinny być odszyfrowywane i wykorzystywane, i to wyłącznie po stronie serwera.
$baseUrl  = 'https://ksef-test.mf.gov.pl';

// Stała ścieżka do pliku faktury FA(3), bez uploadu
$invoiceXmlPath = __DIR__ . '/fa3.xml';

// Wyczyść wszystko (ręcznie)
if (isset($_GET['reset'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: '.$_SERVER['PHP_SELF']);
    exit;
}

// Pomocnicze: bezpieczny stringify do <pre>
$toString = function($v): string {
    if (is_string($v)) return $v;
    if (is_array($v) || is_object($v)) {
        return json_encode($v, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    }
    return (string)$v;
};

$authError = $openError = $sendError = $closeError = $statusError = null;
$sendResp = null;
$closeOk = false;
$statusData = null;
$statusDesc = null;

// UPO
$upoError = null;
$upoXml   = null;

// ===================== AKCJE POST =====================

// Wysyłka faktury w aktywnej sesji – plik z dysku ($invoiceXmlPath)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'send') {
    try {
        $ksef = new KSeFXAdESClient($nip, $crtPath, $keyPath, $keyPass, $baseUrl);

        $accessToken = (string)($_SESSION['accessToken']      ?? '');
        $sessionRef  = (string)($_SESSION['sessionReference'] ?? '');
        $aesKeyB64   = (string)($_SESSION['aesKeyB64']        ?? '');
        $ivB64       = (string)($_SESSION['ivB64']            ?? '');

        if ($accessToken === '' || $sessionRef === '' || $aesKeyB64 === '' || $ivB64 === '') {
            throw new RuntimeException('Brak parametrów sesji (accessToken / sessionRef / aesKeyB64 / ivB64). Otwórz lub odśwież sesję.');
        }

        if (!is_file($invoiceXmlPath)) {
            throw new RuntimeException('Brak pliku faktury FA(3) pod ścieżką: ' . $invoiceXmlPath);
        }

        $xml = file_get_contents($invoiceXmlPath);
        if ($xml === false || $xml === '') {
            throw new RuntimeException('Plik faktury FA(3) jest pusty lub nieczytelny: ' . $invoiceXmlPath);
        }

        // Szyfruj fakturę (AES-256-CBC + PKCS#7)
        $enc  = $ksef->encryptInvoiceAesCbc($aesKeyB64, $ivB64, $xml);

        // Metadane — hash i size zaszyfrowanej liczone z bajtów cipherText (CBC)
        $meta = $ksef->computeInvoiceMeta($xml, $enc['cipherRaw']);

        $payload = [
            'invoiceHash'             => $meta['invoiceHash'],          // SHA256(plain XML) Base64
            'invoiceSize'             => $meta['invoiceSize'],          // strlen(plain XML)
            'encryptedInvoiceHash'    => $meta['encryptedInvoiceHash'], // SHA256(cipher) Base64
            'encryptedInvoiceSize'    => $meta['encryptedInvoiceSize'], // strlen(cipher)
            'encryptedInvoiceContent' => $enc['cipherB64'],             // Base64(cipherText)
            'offlineMode'             => false,
        ];

        $sendResp = $ksef->sendEncryptedInvoice($accessToken, $sessionRef, $payload);
        $_SESSION['lastSendRef'] = $sendResp['referenceNumber'] ?? null;
    } catch (Throwable $e) {
        $sendError = $e->getMessage();
    }
}

// Zamknięcie sesji
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'close_session') {
    try {
        $ksef = new KSeFXAdESClient($nip, $crtPath, $keyPath, $keyPass, $baseUrl);
        $accessToken = (string)($_SESSION['accessToken']      ?? '');
        $sessionRef  = (string)($_SESSION['sessionReference'] ?? '');

        if ($accessToken === '' || $sessionRef === '') {
            throw new RuntimeException('Brak accessToken lub sessionReference. Nie można zamknąć sesji.');
        }

        $ok = $ksef->closeInteractiveSession($accessToken, $sessionRef);
        if ($ok) {
            $closeOk = true;
            // Po zamknięciu — wyczyść dane sesji (klucze i referencje)
            $_SESSION['sessionReference'] = '';
            $_SESSION['sessionValidTo']   = '';
            $_SESSION['aesKeyB64']        = '';
            $_SESSION['ivB64']            = '';
            $_SESSION['encKeyB64']        = '';
        }
    } catch (Throwable $e) {
        $closeError = $e->getMessage();
    }
}

// Sprawdzenie statusu ostatniej faktury w sesji
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'check_status') {
    try {
        $ksef = new KSeFXAdESClient($nip, $crtPath, $keyPath, $keyPass, $baseUrl);

        $accessToken = (string)($_SESSION['accessToken']      ?? '');
        $sessionRef  = (string)($_SESSION['sessionReference'] ?? '');
        $invoiceRef  = (string)($_SESSION['lastSendRef']      ?? '');

        if ($accessToken === '' || $sessionRef === '') {
            throw new RuntimeException('Brak accessToken lub sessionReference. Nie można pobrać statusu.');
        }
        if ($invoiceRef === '') {
            throw new RuntimeException('Brak numeru referencyjnego faktury (lastSendRef). Wyślij najpierw fakturę.');
        }

        $statusData = $ksef->getInvoiceStatusFromSession($accessToken, $sessionRef, $invoiceRef);
        $code       = (int)($statusData['status']['code'] ?? 0);
        $statusDesc = $ksef->describeInvoiceStatus($code);

        // *** próba wyciągnięcia numeru KSeF z odpowiedzi ***
        $ksefNumber = '';
        if (isset($statusData['ksefNumber'])) {
            $ksefNumber = (string)$statusData['ksefNumber'];
        } elseif (isset($statusData['ksefReferenceNumber'])) {
            $ksefNumber = (string)$statusData['ksefReferenceNumber'];
        } elseif (isset($statusData['numberInKSeF'])) {
            $ksefNumber = (string)$statusData['numberInKSeF'];
        }

        if ($ksefNumber !== '') {
            $_SESSION['lastKsefNumber'] = $ksefNumber;
        }

    } catch (Throwable $e) {
        $statusError = $e->getMessage();
    }
}

// Pobranie UPO dla ostatniej faktury (po numerze KSeF)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'get_upo') {
    try {
        $ksef = new KSeFXAdESClient($nip, $crtPath, $keyPath, $keyPass, $baseUrl);

        $accessToken = (string)($_SESSION['accessToken']      ?? '');
        $sessionRef  = (string)($_SESSION['sessionReference'] ?? '');
        // można podać ręcznie w formularzu albo użyć z sesji
        $ksefNumber  = trim((string)($_POST['ksefNumber'] ?? ''));
        if ($ksefNumber === '') {
            $ksefNumber = (string)($_SESSION['lastKsefNumber'] ?? '');
        }

        if ($accessToken === '' || $sessionRef === '') {
            throw new RuntimeException('Brak accessToken lub sessionReference. Nie można pobrać UPO.');
        }
        if ($ksefNumber === '') {
            throw new RuntimeException('Brak numeru KSeF. Najpierw pobierz status faktury (kod 200), aby pozyskać numer KSeF, lub wpisz go ręcznie.');
        }

        $upoXml = $ksef->getInvoiceUpoFromSession($accessToken, $sessionRef, $ksefNumber);

        // zapamiętaj ostatnio użyty numer KSeF
        $_SESSION['lastKsefNumber'] = $ksefNumber;

    } catch (Throwable $e) {
        $upoError = $e->getMessage();
    }
}

// ===================== FLOW GET (autoryzacja i otwarcie sesji jeśli brak) =====================
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    try {
        $ksef = new KSeFXAdESClient($nip, $crtPath, $keyPath, $keyPass, $baseUrl);

        // 1) Access token w sesji?
        $haveAccess = isset($_SESSION['accessToken']) && is_string($_SESSION['accessToken']) && $_SESSION['accessToken'] !== '';
        if (!$haveAccess) {
            $auth = $ksef->authenticate();
            $_SESSION['authToken']    = $toString($auth['authToken']    ?? '');
            $_SESSION['accessToken']  = $toString($auth['accessToken']  ?? '');
            $_SESSION['refreshToken'] = $toString($auth['refreshToken'] ?? '');
            $_SESSION['validUntil']   = $toString($auth['validUntil']   ?? '');
        }

        // 2) Jeżeli nie ma aktywnej sesji — otwórz z IV=16 bajtów (AES-256-CBC)
        $haveSession = isset($_SESSION['sessionReference']) && $_SESSION['sessionReference'] !== '';
        if (!$haveSession) {
            try {
                // IV = 16 bajtów dla AES-256-CBC
                $encPrep = $ksef->prepareInteractiveEncryption(16);
                $session = $ksef->openInteractiveSessionFA3(
                    $_SESSION['accessToken'],
                    $encPrep['encKeyB64'],
                    $encPrep['ivB64'],
                    '1-0E'
                );

                $_SESSION['sessionReference'] = $session['referenceNumber'] ?? '';
                $_SESSION['sessionValidTo']   = $session['validUntil'] ?? '';
                $_SESSION['aesKeyB64']        = $encPrep['aesKeyB64'] ?? '';
                $_SESSION['ivB64']            = $encPrep['ivB64'] ?? '';
                $_SESSION['encKeyB64']        = $encPrep['encKeyB64'] ?? '';
            } catch (Throwable $eOpen) {
                $openError = $eOpen->getMessage();
            }
        }
    } catch (Throwable $e) {
        $authError = $e->getMessage();
    }
}

// ===================== DANE DO WIDOKU =====================
$authToken       = (string)($_SESSION['authToken']       ?? '');
$accessToken     = (string)($_SESSION['accessToken']     ?? '');
$refreshToken    = (string)($_SESSION['refreshToken']    ?? '');
$validUntilStr   = (string)($_SESSION['validUntil']      ?? '');
$lastSendRef     = (string)($_SESSION['lastSendRef']     ?? '');
$lastKsefNumber  = (string)($_SESSION['lastKsefNumber']  ?? '');

$validUtc = $validPl = '';
if ($validUntilStr !== '') {
    try {
        $dtUtc = new DateTime($validUntilStr);
        $validUtc = $dtUtc->setTimezone(new DateTimeZone('UTC'))->format(DateTime::ATOM);
        $dtPl  = new DateTime($validUntilStr);
        $dtPl->setTimezone(new DateTimeZone('Europe/Warsaw'));
        $validPl = $dtPl->format('Y-m-d H:i:s T');
    } catch (\Throwable $e) { /* ignore */ }
}

// JWT podgląd (opcjonalnie)
$jwtInfo = [];
if ($authToken !== '') {
    $parts = explode('.', $authToken);
    $dec = function(string $b64url) {
        if ($b64url === '') return null;
        $b64 = strtr($b64url, '-_', '+/');
        $pad = strlen($b64) % 4 ? 4 - strlen($b64) % 4 : 0;
        $b64 .= str_repeat('=', $pad);
        $raw = base64_decode($b64, true);
        return $raw === false ? null : json_decode($raw, true);
    };
    $jwtInfo = ['header' => $dec($parts[0] ?? ''), 'payload' => $dec($parts[1] ?? '')];
}

$haveSession = isset($_SESSION['sessionReference']) && $_SESSION['sessionReference'] !== '';
?>
<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <title>KSeF — Tokeny, sesja interaktywna i wysyłka faktury</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    pre{white-space:pre-wrap;word-break:break-all}
    .copy-btn{white-space:nowrap}
  </style>
</head>
<body class="bg-light">
<div class="container py-4">
  <h1 class="h4 mb-4">KSeF — Tokeny, sesja interaktywna i wysyłka faktury</h1>

  <!-- TOKENY -->
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      <h2 class="h6">Tokeny</h2>
      <?php if ($authError): ?>
        <div class="alert alert-danger"><strong>Błąd autoryzacji:</strong><br><?= htmlspecialchars($authError) ?></div>
      <?php else: ?>
        <div class="row g-3">
          <div class="col-lg-6">
            <div class="border rounded p-3 h-100">
              <h3 class="h6 text-success">Authentication Token (JWT)</h3>
              <pre><?= htmlspecialchars($authToken) ?></pre>
              <?php if ($validUntilStr): ?>
                <div class="small text-muted mb-2">VALID_UNTIL (KSeF): <strong><?= htmlspecialchars($validUntilStr) ?></strong></div>
                <div class="row row-cols-1 row-cols-md-2 g-2">
                  <div class="col"><div class="small text-muted">UTC</div><div><?= htmlspecialchars($validUtc) ?></div></div>
                  <div class="col"><div class="small text-muted">Europe/Warsaw</div><div><?= htmlspecialchars($validPl) ?></div></div>
                </div>
              <?php endif; ?>
              <?php if (!empty($jwtInfo)): ?>
                <details class="mt-2">
                  <summary>Podgląd JWT (bez weryfikacji)</summary>
                  <pre><?= htmlspecialchars(json_encode($jwtInfo, JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE)) ?></pre>
                </details>
              <?php endif; ?>
            </div>
          </div>
          <div class="col-lg-6">
            <div class="border rounded p-3 h-100">
              <h3 class="h6 text-primary">Access Token (Bearer do API)</h3>
              <pre><?= htmlspecialchars($accessToken) ?></pre>
              <?php if (!empty($refreshToken)): ?>
                <div class="mt-2">
                  <div class="small text-muted">Refresh Token</div>
                  <pre class="mb-0"><?= htmlspecialchars($refreshToken) ?></pre>
                </div>
              <?php endif; ?>
              <div class="alert alert-info mt-3 mb-0">
                Używaj: <strong>Authorization: Bearer &lt;accessToken&gt;</strong>
              </div>
            </div>
          </div>
        </div>
      <?php endif; ?>
    </div>
  </div>

  <!-- SESJA -->
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      <h2 class="h6 d-flex align-items-center justify-content-between">
        <span>Sesja interaktywna (FA 3)</span>
        <span class="d-flex gap-2">
          <a class="btn btn-outline-danger btn-sm" href="?reset=1">Wyczyść sesję</a>
          <?php if ($haveSession && $accessToken): ?>
            <form method="post" class="d-inline">
              <input type="hidden" name="action" value="close_session">
              <button class="btn btn-warning btn-sm" onclick="return confirm('Zamknąć sesję i rozpocząć generowanie zbiorczego UPO?');">
                Zamknij sesję
              </button>
            </form>
          <?php endif; ?>
        </span>
      </h2>

      <?php if ($closeOk): ?>
        <div class="alert alert-success">Sesja została zamknięta — rozpoczęto generowanie zbiorczego UPO.</div>
      <?php elseif ($closeError): ?>
        <div class="alert alert-danger"><strong>Błąd zamykania:</strong><br><pre class="mb-0"><?= htmlspecialchars($closeError) ?></pre></div>
      <?php endif; ?>

      <?php if ($haveSession): ?>
        <div class="alert alert-success mb-3">
          <div><strong>referenceNumber:</strong> <?= htmlspecialchars($_SESSION['sessionReference']) ?></div>
          <div><strong>validUntil:</strong> <?= htmlspecialchars($_SESSION['sessionValidTo'] ?? '') ?></div>
        </div>

        <!-- Pokazuj IV/keys zawsze + przyciski kopiuj -->
        <div class="mt-2">
          <label class="form-label fw-semibold">initializationVector (Base64)</label>
          <div class="input-group">
            <input type="text" class="form-control" id="ivB64" value="<?= htmlspecialchars((string)($_SESSION['ivB64'] ?? '')) ?>" readonly>
            <button type="button" class="btn btn-outline-secondary copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('ivB64').value)">Kopiuj</button>
          </div>
        </div>

        <div class="mt-2">
          <label class="form-label fw-semibold">encryptedSymmetricKey (Base64)</label>
          <textarea class="form-control" id="encKeyB64" rows="3" readonly><?= htmlspecialchars((string)($_SESSION['encKeyB64'] ?? '')) ?></textarea>
          <button type="button" class="btn btn-outline-secondary mt-2 copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('encKeyB64').value)">Kopiuj</button>
        </div>

        <div class="mt-2">
          <label class="form-label fw-semibold">aesKey (Base64, jawny do szyfrowania)</label>
          <textarea class="form-control" id="aesKeyB64" rows="2" readonly><?= htmlspecialchars((string)($_SESSION['aesKeyB64'] ?? '')) ?></textarea>
          <button type="button" class="btn btn-outline-secondary mt-2 copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('aesKeyB64').value)">Kopiuj</button>
        </div>

      <?php elseif ($openError): ?>
        <div class="alert alert-danger">
          <strong>Błąd otwierania sesji:</strong>
          <pre class="mb-0"><?= htmlspecialchars($openError) ?></pre>
        </div>
      <?php else: ?>
        <div class="text-muted">Sesja nie została otwarta.</div>
      <?php endif; ?>
    </div>
  </div>

  <!-- WYSYŁKA FAKTURY + STATUS + UPO -->
  <div class="card shadow-sm mb-4">
    <div class="card-body">
      <h2 class="h6">Wyślij fakturę FA(3) w bieżącej sesji</h2>

      <?php if ($sendError): ?>
        <div class="alert alert-danger">
          <strong>Błąd wysyłki:</strong>
          <pre class="mb-0"><?= htmlspecialchars($sendError) ?></pre>
        </div>
      <?php elseif ($sendResp): ?>
        <div class="alert alert-success">
          <div><strong>referenceNumber:</strong> <?= htmlspecialchars($sendResp['referenceNumber'] ?? '') ?></div>
        </div>
      <?php elseif (!empty($lastSendRef)): ?>
        <div class="alert alert-success">
          <div><strong>Ostatnia wysyłka (202):</strong> <?= htmlspecialchars($lastSendRef) ?></div>
        </div>
      <?php endif; ?>

      <?php if ($statusError): ?>
        <div class="alert alert-danger mt-3">
          <strong>Błąd pobierania statusu:</strong>
          <pre class="mb-0"><?= htmlspecialchars($statusError) ?></pre>
        </div>
      <?php elseif ($statusData && $statusDesc): ?>
        <div class="card mt-3">
          <div class="card-body">
            <h3 class="h6">Status ostatniej faktury</h3>
            <p>
              <span class="badge bg-<?= htmlspecialchars($statusDesc['bootstrap']) ?>">
                <?= htmlspecialchars($statusDesc['code'] . ' ' . $statusDesc['name']) ?>
              </span>
            </p>
            <p class="mb-1"><?= htmlspecialchars($statusDesc['description']) ?></p>
            <p class="small text-muted mb-2">
              Numer referencyjny faktury (EE): <code><?= htmlspecialchars($statusData['referenceNumber'] ?? '') ?></code><br>
              Lp. w sesji: <code><?= htmlspecialchars((string)($statusData['ordinalNumber'] ?? '')) ?></code><br>
              Data wystawienia (invoicingDate): <code><?= htmlspecialchars($statusData['invoicingDate'] ?? '') ?></code><br>
              <?php
                // Próba odczytania numeru KSeF z sesji lub z $statusData
                $ksefNumberView = $lastKsefNumber;
                if ($ksefNumberView === '') {
                    if (isset($statusData['ksefNumber'])) {
                        $ksefNumberView = (string)$statusData['ksefNumber'];
                    } elseif (isset($statusData['ksefReferenceNumber'])) {
                        $ksefNumberView = (string)$statusData['ksefReferenceNumber'];
                    } elseif (isset($statusData['numberInKSeF'])) {
                        $ksefNumberView = (string)$statusData['numberInKSeF'];
                    }
                }
              ?>
              <?php if ($ksefNumberView !== ''): ?>
                Numer KSeF: <code><?= htmlspecialchars($ksefNumberView) ?></code>
              <?php endif; ?>
            </p>

            <?php if (!empty($statusData['status']['details'])): ?>
              <details class="mt-2">
                <summary>Szczegóły (status.details)</summary>
                <ul class="mt-2">
                  <?php foreach ($statusData['status']['details'] as $d): ?>
                    <li><?= htmlspecialchars($d) ?></li>
                  <?php endforeach; ?>
                </ul>
              </details>
            <?php endif; ?>

            <?php if (!empty($ksefNumberView)): ?>
              <hr>
              <form method="post" class="d-flex flex-column flex-md-row gap-2 align-items-start">
                <input type="hidden" name="action" value="get_upo">
                <div class="flex-grow-1">
                  <label class="form-label small mb-1">Numer KSeF (możesz zmienić ręcznie):</label>
                  <input type="text" name="ksefNumber" class="form-control form-control-sm"
                         value="<?= htmlspecialchars($ksefNumberView) ?>">
                </div>
                <div class="pt-2 pt-md-4">
                  <button class="btn btn-sm btn-outline-primary">Pobierz UPO</button>
                </div>
              </form>
            <?php endif; ?>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($upoError): ?>
        <div class="alert alert-danger mt-3">
          <strong>Błąd pobierania UPO:</strong>
          <pre class="mb-0"><?= htmlspecialchars($upoError) ?></pre>
        </div>
      <?php elseif ($upoXml !== null): ?>
        <div class="card mt-3">
          <div class="card-body">
            <h3 class="h6">UPO ostatniej faktury (XML)</h3>
            <pre class="small mb-0"><?= htmlspecialchars($upoXml) ?></pre>
          </div>
        </div>
      <?php endif; ?>

      <?php if ($haveSession && $accessToken): ?>
        <div class="mb-3 mt-3">
          <div class="small text-muted">Bieżący plik FA(3):</div>
          <code><?= htmlspecialchars($invoiceXmlPath) ?></code>
          <?php if (!is_file($invoiceXmlPath)): ?>
            <div class="text-danger mt-1 small">Uwaga: plik nie istnieje — wysyłka zwróci błąd.</div>
          <?php endif; ?>
        </div>

        <div class="row gy-3">
          <div class="col-12 d-flex gap-2 flex-wrap">
            <form method="post">
              <input type="hidden" name="action" value="send">
              <button class="btn btn-primary">Wyślij fakturę z pliku</button>
            </form>

            <?php if (!empty($lastSendRef)): ?>
              <form method="post">
                <input type="hidden" name="action" value="check_status">
                <button class="btn btn-outline-secondary">Sprawdź status ostatniej faktury</button>
              </form>
            <?php endif; ?>
          </div>
          <div class="col-12 small text-muted">
            Treść faktury jest odczytywana z powyższego pliku i szyfrowana
            algorytmem <strong>AES-256-CBC z dopełnianiem PKCS#7</strong>,
            kluczem i IV zadeklarowanymi przy otwarciu sesji.
          </div>
        </div>
      <?php else: ?>
        <div class="text-muted">Brak aktywnej sesji — odśwież stronę, aby spróbować ponownie.</div>
      <?php endif; ?>
    </div>
  </div>

  <hr>
  <p class="text-muted small mb-0">NIP: <?= htmlspecialchars($nip) ?> · Środowisko: <?= htmlspecialchars($baseUrl) ?></p>
</div>
</body>
</html>
