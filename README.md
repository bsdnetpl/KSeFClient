# KSeFClient

`KSeFClient` to klasa PHP do integracji z Krajowym Systemem e-Faktur (KSeF). Umożliwia zarządzanie sesjami, przesyłanie faktur oraz sprawdzanie statusu sesji w systemie KSeF.

## Funkcjonalności

- Tworzenie tokenu sesji na podstawie tokenu API i czasu wyzwania.
- Wysyłanie faktur do KSeF.
- Zamykanie aktywnej sesji.
- Sprawdzanie statusu sesji na podstawie numeru referencyjnego.
- Obsługa szyfrowania przy użyciu klucza publicznego (RSA).
- Automatyczne obsługiwanie błędów HTTP i cURL.

## Wymagania

- PHP 7.4 lub nowszy.
- Rozszerzenie `curl` w PHP.
- Rozszerzenie `openssl` w PHP.
- Klucz publiczny systemu KSeF w formacie PEM.

## Instalacja

1. Sklonuj repozytorium:

   ```bash
   git clone https://github.com/<username>/ksef-client.git
   cd ksef-client

    Upewnij się, że Twój serwer PHP ma włączone rozszerzenia curl i openssl.

    Umieść klucz publiczny w odpowiedniej lokalizacji na serwerze i podaj jego ścieżkę w parametrze $publicKeyPath.

Użycie
Inicjalizacja klasy

require 'KSeFClient.php';

$apiUrl = "https://ksef-demo.mf.gov.pl/api";
$nip = "1234567890";
$apiKey = "your-api-key";
$publicKeyPath = "/path/to/publicKey.pem";

$client = new KSeFClient($apiUrl, $nip, $apiKey, $publicKeyPath);

Uzyskanie tokenu sesji

$challengeData = $client->getChallengeAndTimestamp();
$encryptedToken = $client->encryptToken($apiKey, $challengeData['challengeTime']);
$sessionToken = $client->getKSeFSessionToken($encryptedToken, $challengeData['challenge']);

Wysyłanie faktury

$response = $client->sendInvoice('/path/to/invoice.xml');
if ($response) {
    echo "Faktura została przesłana pomyślnie.";
}

Sprawdzanie statusu sesji

$referenceNumber = "your-reference-number";
$status = $client->getSessionStatus($referenceNumber, 10, 0, true);

if ($status) {
    print_r($status);
}

Zamykanie sesji

$client->terminateSession();

Struktura metody getSessionStatus

Metoda getSessionStatus umożliwia sprawdzanie statusu sesji na podstawie numeru referencyjnego. Przyjmuje następujące parametry:

    referenceNumber (string) - Numer referencyjny sesji.
    pageSize (int) - Rozmiar strony wyników (domyślnie: 10).
    pageOffset (int) - Przesunięcie stron wyników (domyślnie: 0).
    includeDetails (bool) - Czy uwzględniać szczegóły w odpowiedzi (domyślnie: true).

Obsługa błędów

Klasa automatycznie obsługuje błędy cURL i HTTP, wypisując je w konsoli. Jeśli wymagane, możesz dostosować logikę obsługi błędów wewnątrz metody sendRequest.
Licencja

Projekt jest dostępny na licencji MIT. Szczegóły znajdują się w pliku LICENSE.
Wsparcie

W razie pytań lub problemów, otwórz zgłoszenie w sekcji Issues.
