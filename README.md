KSeFXAdESClient – KSeF 2.0, FA(3), XAdES + AES

☕ Jeśli chcesz mi podziękować za tę klasę / bibliotekę, możesz postawić mi wirtualną kawę:
👉 https://suppi.pl/audev

### W sprawie integracji, wsparcia technicznego lub wdrożenia biblioteki w Twoim systemie, proszę o kontakt:
📧 adrian@bsd-net.pl

Możliwe integracje: 
- C++ (np. aplikacje desktopowe lub serwisowe),
- PHP (sklepy internetowe, panele administracyjne, systemy ERP),
- C# / .NET (aplikacje biznesowe, API REST, usługi serwerowe),
- frontendy w React lub Angular (integracja poprzez REST API).

**Uwaga: pomoc techniczna, integracja i wdrożenia są usługami odpłatnymi.
Wsparcie udzielane jest wyłącznie po wcześniejszym kontakcie mailowym.**

Opis

KSeFXAdESClient to lekka klasa PHP obsługująca KSeF v2 (2.0) z wykorzystaniem:

- podpisu XAdES (xmlsec1 + Twój certyfikat KSeF),

- pełnego procesu uwierzytelnienia (/api/v2/auth/...),

- interaktywnej sesji online (/api/v2/sessions/online),

- szyfrowania faktur FA(3) algorytmem AES-256-CBC,

- wysyłki zaszyfrowanej faktury do KSeF.

Klasa jest samodzielna – nie wymaga frameworka.
Opiera się na cURL, openssl, xmlsec1 i standardowych funkcjach PHP.

Przeznaczenie biblioteki

Biblioteka została zaprojektowana jako warstwa pomocnicza dla API KSeF opartego o PHP.
Jej głównym zadaniem jest obsługa pełnego procesu komunikacji z KSeF, tak aby z warstwy biznesowej (np. aplikacji w C++ Builder XE) wystarczyło wywołanie prostych endpointów HTTP/JSON.

Typowy scenariusz użycia
# Tryb online (interaktywny)

Podczas wystawiania faktury VAT aplikacja wywołuje API w PHP.
Biblioteka realizuje wówczas następujące kroki:

- uwierzytelnienie w systemie KSeF,

- przygotowanie i wysyłkę faktury w formacie FA(3),

- odbiór numeru referencyjnego lub statusu przetwarzania,

- zapisanie informacji o wysłanej fakturze oraz statusu w bazie danych.

# Tryb wsadowy / offline (niedostępność systemu KSeF)

-Jeżeli w momencie wystawiania faktury serwery KSeF są niedostępne, dane faktury są jedynie zapisywane w bazie ze statusem „oczekuje na wysyłkę”.

- Zadanie CRON (uruchamiane o określonej godzinie) automatycznie:

- pobiera z bazy faktury w statusie „oczekujące”,

- wysyła je do KSeF metodą wsadową,

- aktualizuje statusy i zapisuje dane zwrotne (np. numer KSeF, błędy walidacji).

🕓 Wymagania prawne:
W przypadku trybu offline (niedostępność systemu) fakturę należy dosłać do KSeF nie później niż w następnym dniu roboczym po dniu zakończenia okresu niedostępności.
W przypadku trybu awaryjnego fakturę należy przesłać do KSeF nie później niż w ciągu 7 dni roboczych od zakończenia awarii systemu KSeF.

# Kod QR

Dla każdej faktury generowany jest kod QR zgodny z wymaganiami KSeF.
Wygenerowany obraz QR jest zapisywany w bazie danych lub w strukturze projektu, tak aby mógł być później użyty przy generowaniu plików PDF, podglądzie dokumentu lub wydruku.

Integracja z C++ Builder XE

Klasy zostały zaprojektowane z myślą o integracji ze starszym środowiskiem Embarcadero C++ Builder XE.
Aplikacja w C++ nie komunikuje się bezpośrednio z KSeF — zamiast tego korzysta z prostych endpointów HTTP/JSON wystawionych przez warstwę PHP, np.:
```
POST /api/invoice/send
GET  /api/invoice/status/{id}
```
Cała logika KSeF (uwierzytelnienie, podpis XAdES, szyfrowanie AES, walidacja FA(3), obsługa błędów) jest realizowana po stronie PHP.

# Funkcjonalności

🔐 Uwierzytelnienie XAdES z użyciem certyfikatu KSeF:

POST /api/v2/auth/challenge

- podpis XAdES żądania przez xmlsec1

POST /api/v2/auth/xades-signature → authenticationToken (krótkożyjący JWT)

POST /api/v2/auth/access-token → accessToken + refreshToken

🔑 Pobranie kluczy publicznych KSeF:

GET /api/v2/security/public-key-certificates

filtrowanie po usage = SymmetricKeyEncryption

wybór ważnego certyfikatu i przygotowanie RSA-OAEP

🧬 Przygotowanie szyfrowania sesji interaktywnej:

generowanie klucza AES-256 i IV,

szyfrowanie klucza AES algorytmem RSA-OAEP kluczem publicznym KSeF,

zwrot: encKeyB64, aesKeyB64, ivB64.

💬 Sesja interaktywna online (FA(3)):

POST /api/v2/sessions/online

deklaracja formy FA(3):
systemCode: "FA (3)", schemaVersion: "1-0E"

przekazanie zaszyfrowanego klucza symetrycznego + IV

📄 Szyfrowanie i wysyłka faktury FA(3):

szyfrowanie XML algorytmem AES-256-CBC (PKCS#7),

obliczanie hashy i rozmiarów (plain i encrypted),

POST /api/v2/sessions/online/{ref}/invoices

ℹ️ Narzędzia pomocnicze:

mapowanie kodów statusu faktury → opis + klasa CSS (Bootstrap),

formatowanie wyjątków i błędów KSeF,

prosty HTTP debug (logowanie zapytań i odpowiedzi).

Wymagania

PHP: >= 8.1 (strict_types, typowane własności)

Rozszerzenia PHP: curl, openssl

Narzędzia systemowe:

xmlsec1 – podpis XAdES,

openssl – RSA / SHA-256 / certyfikaty,

bash – wywołania CLI.

Certyfikaty:

certyfikat / łańcuch certyfikatów w formacie PEM ($certPath),

klucz prywatny w formacie PEM/PKCS#8 ($keyPath),

opcjonalne hasło ($keyPass lub null).
Instalacja

Skopiuj plik KSeFAuth.php do projektu (np. src/KSeF/KSeFXAdESClient.php) i załaduj go:
```php
require_once __DIR__ . '/KSeFClient.php';
```
Szybki start – wysyłka FA(3) do środowiska testowego KSeF

Przykładowy minimalny flow: uwierzytelnienie → sesja interaktywna → szyfrowanie → wysyłka faktury FA(3):
```php
<?php
declare(strict_types=1);

require_once __DIR__ . '/KSeFClient.php';

// 1. Inicjalizacja klienta
$client = new KSeFXAdESClient(
    nip:      '1234567890',
    certPath: __DIR__ . '/certs/ksef-cert.pem',
    keyPath:  __DIR__ . '/certs/ksef-key.pem',
    keyPass:  'haslo-do-klucza',
    baseUrl:  'https://ksef-test.mf.gov.pl'
);

// $client->withHttpDebug(true); // debug opcjonalny

// 2. Uwierzytelnienie
$auth = $client->authenticate();
$accessToken = $auth['accessToken'];

// 3. Przygotowanie szyfrowania
$enc = $client->prepareInteractiveEncryption();

// 4. Otwarcie sesji interaktywnej
$session = $client->openInteractiveSessionFA3(
    $accessToken,
    $enc['encKeyB64'],
    $enc['ivB64'],
    '1-0E'
);
$sessionRef = $session['referenceNumber'];

// 5. Wczytanie faktury
$invoiceXml = file_get_contents(__DIR__ . '/invoices/example-fa3.xml');

// 6. Szyfrowanie
$encrypted = $client->encryptInvoiceAesCbc(
    $enc['aesKeyB64'],
    $enc['ivB64'],
    $invoiceXml
);

// 7. Metadane faktury
$meta = $client->computeInvoiceMeta($invoiceXml, $encrypted['cipherRaw']);

// 8. Payload do KSeF
$payload = array_merge($meta, [
    'encryptedInvoiceContent' => base64_encode($encrypted['cipherRaw']),
    'offlineMode'             => false,
]);

// 9. Wysyłka faktury
$sendResp = $client->sendEncryptedInvoice($accessToken, $sessionRef, $payload);

// 10. (opcjonalnie) zamknięcie sesji
// $client->closeInteractiveSession($accessToken, $sessionRef);

```
API – generowanie kodu QR

Endpoint API przyjmuje dane faktury i generuje kod QR z linkiem do podglądu w KSeF.
Zwraca binarny plik PNG.

Dane wejściowe (JSON)
```json
{
  "data_wystawienia": "01-02-2026",
  "nip_sprzedawcy": "1111111111",
  "skrot_sha256": "UtQp9Gpc51y-u3xApZjIjgkpZ01js-J8KflSPW8WzIE",
  "ulr_api": "https://ksef-test.mf.gov.pl/"
}

```
| Pole                 | Opis                                                      |
| -------------------- | --------------------------------------------------------- |
| **data_wystawienia** | Data faktury (`DD-MM-RRRR` lub `RRRR-MM-DD`)              |
| **nip_sprzedawcy**   | 10-cyfrowy NIP sprzedawcy                                 |
| **skrot_sha256**     | Skrót SHA-256 faktury w Base64URL                         |
| **ulr_api**          | Adres API KSeF (domyślnie `https://ksef-test.mf.gov.pl/`) |

CURL – przykład
```bash
curl -X POST "https://serwer.pl/ksef/ksef_qr_api.php?key=xxx" \
  -F "xml_file=@fa3.xml" \
  -F "data_wystawienia=14-11-2025" \
  -F "nip_sprzedawcy=1111111111" \
  -F "ulr_api=https://ksef-test.mf.gov.pl/" \
  --remote-header-name \
  --remote-name
```
Po wykonaniu komendy w katalogu pojawi się plik:
guid.png
# Bezpieczeństwo

Wszystkie dane wrażliwe, takie jak ścieżki do certyfikatów, klucze prywatne i hasła, powinny być przechowywane wyłącznie w bazie danych w formie zakodowanej (np. z użyciem AES-256 lub OpenSSL).

Odszyfrowanie tych danych powinno następować po stronie serwera i tylko na czas wykonywania konkretnej operacji, np. podczas uwierzytelnienia, podpisu XAdES lub szyfrowania faktury.
W żadnym momencie klucz ani hasło nie powinny być przechowywane w postaci jawnej w plikach projektu, logach czy zmiennych środowiskowych.

Zaleca się:

- użycie dedykowanej klasy do szyfrowania i deszyfrowania danych (np. CryptoStorage),

- oddzielenie danych konfiguracyjnych od logiki aplikacji,

- regularne rotowanie kluczy i haseł dostępowych,

- ograniczenie dostępu do katalogu z certyfikatami (chmod, chown).

  # Monitoring ważności certyfikatów

Z uwagi na to, że certyfikaty używane do komunikacji z KSeF mają ograniczoną ważność (zwykle 2 lata), zaleca się przygotowanie skryptu kontrolnego, który będzie cyklicznie sprawdzał datę wygaśnięcia certyfikatu i odpowiednio wcześnie informował o konieczności jego odnowienia.

Rekomendowany mechanizm:

- uruchamiany z CRON-a (np. raz dziennie lub raz w tygodniu),

- odczytuje datę ważności certyfikatu (pole NotAfter),

- porównuje ją z aktualną datą,

jeśli do wygaśnięcia pozostaje mniej niż np. 30 / 14 / 7 dni, wysyła komunikat ostrzegawczy (np. e-mail, wpis w logach, webhook do systemu monitoringu).

Dzięki temu minimalizuje się ryzyko sytuacji, w której:

- certyfikat straci ważność,

- biblioteka nie będzie mogła poprawnie uwierzytelnić się w KSeF,

a wystawianie i wysyłka faktur zostaną zablokowane aż do ręcznej interwencji.
