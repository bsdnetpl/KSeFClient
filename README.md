# KSeFXAdESClient – KSeF 2.0, FA(3), XAdES + AES

`KSeFXAdESClient` to lekka klasa PHP obsługująca **KSeF v2 (2.0)** z użyciem:

- podpisu **XAdES** (narzędzie `xmlsec1` + Twój certyfikat KSeF),
- pełnego flow uwierzytelnienia (`/api/v2/auth/...`),
- **interaktywnej sesji online** (`/api/v2/sessions/online`),
- szyfrowania faktur **FA(3)** algorytmem **AES-256-CBC**,
- wysyłki zaszyfrowanej faktury do KSeF.

Klasa jest samodzielna, nie wymaga frameworka – opiera się na `cURL`, `openssl`, `xmlsec1` i standardowych funkcjach PHP.

---

## Funkcjonalności

- 🔐 **Uwierzytelnienie XAdES** z użyciem certyfikatu KSeF:
  - `POST /api/v2/auth/challenge`
  - podpis XAdES żądania przez `xmlsec1`
  - `POST /api/v2/auth/xades-signature` → `authenticationToken` (krótkożyjący JWT)
  - `POST /api/v2/auth/access-token` → `accessToken` + `refreshToken`

- 🔑 **Pobranie kluczy publicznych KSeF**:
  - `GET /api/v2/security/public-key-certificates`
  - filtrowanie po `usage = SymmetricKeyEncryption`
  - wybór ważnego certyfikatu i przygotowanie RSA-OAEP

- 🧬 **Przygotowanie szyfrowania sesji interaktywnej**:
  - generowanie klucza **AES-256** i **IV**,
  - szyfrowanie klucza AES algorytmem **RSA-OAEP** kluczem publicznym KSeF,
  - zwrot: `encKeyB64`, `aesKeyB64`, `ivB64`.

- 💬 **Sesja interaktywna online (FA(3))**:
  - `POST /api/v2/sessions/online`
  - deklaracja formy FA(3) (`systemCode: "FA (3)", schemaVersion: "1-0E"`)
  - przekazanie zaszyfrowanego klucza symetrycznego + IV

- 📄 **Szyfrowanie i wysyłka faktury FA(3)**:
  - szyfrowanie XML algorytmem **AES-256-CBC** (PKCS#7),
  - liczenie hashy i rozmiarów (plain i encrypted),
  - `POST /api/v2/sessions/online/{ref}/invoices`.

- ℹ️ **Pomocnicze narzędzia**:
  - mapowanie kodów statusu faktury → opis + „bootstrap class”,
  - formatowanie wyjątków z KSeF,
  - prosty HTTP debug (logowanie odpowiedzi).

---

## Wymagania

- **PHP**: `>= 8.1` (typowane własności, `strict_types`)
- Rozszerzenia PHP:
  - `curl`
  - `openssl`
- Systemowe binarki:
  - `xmlsec1` – do podpisu XAdES,
  - `openssl` – do operacji na certyfikatach / RSA / SHA-256,
  - powłoka `bash` (używana przy wywołaniach CLI).

Certyfikat:

- certyfikat / łańcuch certyfikatów w formacie **PEM** (`$certPath`),
- klucz prywatny w formacie **PEM/PKCS#8** (`$keyPath`),
- opcjonalne hasło do klucza (`$keyPass` lub `null`).

---

## Instalacja

Skopiuj plik `KSeFAuth.php` do projektu (np. do `src/KSeF/KSeFXAdESClient.php`) i włącz go:

```php
require_once __DIR__ . '/KSeFAuth.php';
Szybki start – wysyłka FA(3) do KSeF testowego

Przykładowy minimalny flow (uwierzytelnienie + sesja interaktywna + wysyłka zaszyfrowanej faktury FA(3)):
<?php

declare(strict_types=1);

require_once __DIR__ . '/KSeFAuth.php';

// 1. Inicjalizacja klienta
$client = new KSeFXAdESClient(
    nip:      '1234567890',                         // NIP podmiotu
    certPath: __DIR__ . '/certs/ksef-cert.pem',     // certyfikat (PEM)
    keyPath:  __DIR__ . '/certs/ksef-key.pem',      // klucz prywatny (PEM/PKCS#8)
    keyPass:  'haslo-do-klucza',                    // lub null, jeśli bez hasła
    baseUrl:  'https://ksef-test.mf.gov.pl'         // test / produkcja
);

// (opcjonalnie) włącz prosty debug HTTP
//$client->withHttpDebug(true);

// 2. Uwierzytelnienie XAdES → accessToken
$auth        = $client->authenticate();
$accessToken = $auth['accessToken'];

// 3. Przygotowanie klucza AES i IV oraz zaszyfrowanego klucza (RSA-OAEP)
$enc = $client->prepareInteractiveEncryption();
// $enc['aesKeyB64']  – klucz AES-256 (Base64)
// $enc['ivB64']      – IV (Base64)
// $enc['encKeyB64']  – zaszyfrowany klucz AES (RSA-OAEP, Base64)

// 4. Sesja interaktywna online dla FA(3)
$session = $client->openInteractiveSessionFA3(
    $accessToken,
    $enc['encKeyB64'],
    $enc['ivB64'],
    '1-0E'                           // wersja schematu FA(3) w KSeF 2.0
);

$sessionRef = $session['referenceNumber'];

// 5. Wczytanie faktury FA(3) (surowy XML zgodny ze schematem FA(3))
$invoiceXml = file_get_contents(__DIR__ . '/invoices/example-fa3.xml');

// 6. Szyfrowanie faktury AES-256-CBC
$encrypted = $client->encryptInvoiceAesCbc(
    $enc['aesKeyB64'],
    $enc['ivB64'],
    $invoiceXml
);

// 7. Metadane: hash i rozmiary (plain + encrypted)
$meta = $client->computeInvoiceMeta(
    $invoiceXml,
    $encrypted['cipherRaw']
);

// 8. Złożenie payloadu do KSeF
$payload = array_merge($meta, [
    'encryptedInvoiceContent' => base64_encode($encrypted['cipherRaw']),
    'offlineMode'             => false, // tryb online
]);

// 9. Wysyłka zaszyfrowanej faktury do sesji interaktywnej
$sendResp = $client->sendEncryptedInvoice(
    $accessToken,
    $sessionRef,
    $payload
);

// 10. (Opcjonalnie) zamknięcie sesji po zakończeniu pracy
// $client->closeInteractiveSession($accessToken, $sessionRef);
```
API udostępnia endpoint, który przyjmuje dane faktury (data wystawienia, NIP sprzedawcy, skrót SHA-256, adres API KSeF), a następnie generuje kod QR z linkiem do podglądu faktury w KSeF.

API zwraca binarny plik PNG — gotowy kod QR do pobrania.

Dane wejściowe (JSON)
{
  "data_wystawienia": "01-02-2026",
  "nip_sprzedawcy": "1111111111",
  "skrot_sha256": "UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE",
  "ulr_api": "https://ksef-test.mf.gov.pl/"
}
Opis parametrów:
| Pole                 | Opis                                                       |
| -------------------- | ---------------------------------------------------------- |
| **data_wystawienia** | Data faktury, format `DD-MM-RRRR` lub `RRRR-MM-DD`         |
| **nip_sprzedawcy**   | 10-cyfrowy NIP sprzedawcy                                  |
| **skrot_sha256**     | Skrót faktury SHA-256 zakodowany Base64URL                 |
| **ulr_api**          | Adres API KSeF (domyślnie: `https://ksef-test.mf.gov.pl/`) |

CURL – przykład wywołania: 

curl "https://serwer.pl/ksef/ksef_qr_api.php" \
  -H "Content-Type: application/json" \
  --output ksef_qr.png \
  -d '{
    "data_wystawienia": "01-02-2026",
    "nip_sprzedawcy": "1111111111",
    "skrot_sha256": "UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE",
    "ulr_api": "https://ksef-test.mf.gov.pl/"
  }'
Po wykonaniu komendy w katalogu pojawi się: ksef_qr.png
