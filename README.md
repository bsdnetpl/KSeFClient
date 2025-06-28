KSeFClient

KSeFClient to klasa PHP do integracji z Krajowym Systemem e-Faktur (KSeF). Umożliwia zarządzanie sesjami, przesyłanie faktur oraz sprawdzanie statusu sesji w systemie KSeF zgodnie ze specyfikacją FA(3).
✅ Funkcjonalności

    Tworzenie tokenu sesji na podstawie tokenu API i czasu wyzwania (ChallengeTime)

    Wysyłanie faktur XML do systemu KSeF

    Zamykanie aktywnej sesji KSeF

    Sprawdzanie statusu sesji po numerze referencyjnym

    Szyfrowanie tokenu z użyciem klucza publicznego RSA (PEM)

    Obsługa błędów HTTP i cURL z komunikatami diagnostycznymi

📦 Wymagania

    PHP 7.4 lub nowszy

    Rozszerzenia PHP: curl, openssl

    Klucz publiczny systemu KSeF w formacie .pem

🚀 Instalacja

    Sklonuj repozytorium:

git clone https://github.com/<username>/ksef-client.git
cd ksef-client

    Upewnij się, że Twój serwer PHP ma włączone rozszerzenia curl i openssl.

    Umieść publiczny klucz KSeF (publicKey.pem) w odpowiednim katalogu i podaj jego ścieżkę w konstruktorze klasy.

🧩 Użycie
Inicjalizacja klasy

require 'KSeFClient.php';

$apiUrl = "https://ksef-demo.mf.gov.pl/api";
$nip = "1234567890";
$apiKey = "twoj-token-api";
$publicKeyPath = "/ścieżka/do/publicKey.pem";

$client = new KSeFClient($apiUrl, $nip, $apiKey, $publicKeyPath);

Uzyskanie tokenu sesji FA(3)

$challengeData = $client->getChallengeAndTimestamp();
$encryptedToken = $client->encryptToken($apiKey, $challengeData['challengeTime']);
$sessionToken = $client->getKSeFSessionToken($encryptedToken, $challengeData['challenge']);

Wysyłanie faktury XML

$response = $client->sendInvoice('/ścieżka/do/faktury.xml');

if ($response) {
    echo "Faktura została przesłana pomyślnie.\n";
}

Sprawdzanie statusu sesji

$referenceNumber = "numer-referencyjny";
$status = $client->getSessionStatus($referenceNumber);

if ($status) {
    print_r($status);
}

Zamykanie sesji

$client->terminateSession();

📘 Szczegóły: getSessionStatus()

getSessionStatus(string $referenceNumber, int $pageSize = 10, int $pageOffset = 0, bool $includeDetails = true)

Parametry:

    referenceNumber – numer referencyjny sesji

    pageSize – liczba wyników na stronę (domyślnie 10)

    pageOffset – przesunięcie wyników (domyślnie 0)

    includeDetails – czy dołączyć szczegóły faktur (domyślnie true)

🛠 Obsługa błędów

Klasa automatycznie obsługuje:

    błędy cURL (np. brak połączenia, błąd SSL)

    błędy HTTP (np. 400, 401, 500)

    błędy odpowiedzi KSeF (np. brak tokenu)

Komunikaty są wypisywane na standardowe wyjście. Możesz rozbudować logikę błędów w metodzie sendRequest().
📄 Licencja

Projekt dostępny na licencji MIT.
🧑‍💻 Wsparcie

W razie pytań, problemów lub sugestii – otwórz zgłoszenie (Issue) w repozytorium GitHub.
