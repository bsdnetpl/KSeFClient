<?php
declare(strict_types=1);

/**
 * KSeFBatchClient.php
 *
 * Klient do obsługi sesji WSADOWYCH KSeF v2:
 *  - /api/v2/sessions/batch
 *  - /api/v2/sessions/batch/{referenceNumber}/close
 *
 * Autoryzacja:
 *  - używa accessToken uzyskanego z KSeFXAdESClient::authenticate()
 */
final class KSeFBatchClient
{
    /** Bazowy URL KSeF, np. https://ksef-test.mf.gov.pl */
    private string $baseUrl;

    /** Włącza/wyłącza tryb debugowania cURL (nagłówki, itp.) */
    private bool $httpDebug = false;

    /**
     * @param string $baseUrl Bazowy adres KSeF (domyślnie środowisko testowe).
     */
    public function __construct(string $baseUrl = 'https://ksef-test.mf.gov.pl')
    {
        // ...
    }

    /**
     * Włącza/wyłącza debug HTTP (nagłówki, raw odpowiedzi).
     *
     * @param bool $on true = debug włączony.
     * @return self
     */
    public function withHttpDebug(bool $on = true): self
    {
        // ...
    }

    // ========================================================================
    // 1) METADANE PACZKI Z PLIKU
    // ========================================================================

    /**
     * Oblicza metadane paczki wsadowej z pliku:
     *  - hash całego pliku (SHA-256 Base64),
     *  - rozmiar całego pliku,
     *  - podział na części (fileParts) z hashami i długościami,
     *  - dodatkowo wewnętrzne pola _offset i _length do późniejszego uploadu.
     *
     * Typowy input: ścieżka do spakowanej paczki (ZIP/GZ) i rozmiar części w bajtach.
     *
     * @param string $filePath  Ścieżka do pliku paczki.
     * @param int    $partSize  Rozmiar jednej części (np. 5_000_000 bajtów).
     *
     * @return array {
     *   fileSize:int,
     *   fileHash:string,
     *   fileParts:array<int,array{
     *      ordinalNumber:int,
     *      fileSize:int,
     *      fileHash:string,
     *      _offset:int,
     *      _length:int
     *   }>
     * }
     *
     * @throws InvalidArgumentException Przy błędnych parametrach/plikach.
     * @throws RuntimeException         Przy błędach odczytu.
     */
    public function computeBatchMetaFromFile(string $filePath, int $partSize = 5_000_000): array
    {
        // ...
    }

    // ========================================================================
    // 2) OTWARCIE SESJI WSADOWEJ
    // ========================================================================

    /**
     * Otwiera sesję wsadową do wysyłki paczki faktur.
     *
     * Wysyła żądanie:
     *   POST /api/v2/sessions/batch
     * z JSON-em zawierającym:
     *   - formCode (systemCode, schemaVersion, value),
     *   - batchFile (fileSize, fileHash, fileParts),
     *   - encryption (encryptedSymmetricKey, initializationVector),
     *   - offlineMode.
     *
     * Typowe użycie:
     *   - batchMeta – wynik computeBatchMetaFromFile()
     *   - encryptedSymmetricKeyB64, ivB64 – jak w sesji interaktywnej
     *     (przygotowane np. metodą prepareInteractiveEncryption z innej klasy).
     *
     * Zwraca m.in.:
     *   - referenceNumber          – numer sesji wsadowej,
     *   - partUploadRequests[]     – instrukcje wysyłki poszczególnych części (URL, method, headers).
     *
     * @param string $accessToken              AccessToken (Bearer) z KSeFXAdESClient.
     * @param array  $batchMeta                Metadane paczki (z computeBatchMetaFromFile).
     * @param string $encryptedSymmetricKeyB64 Klucz symetryczny zaszyfrowany kluczem MF (Base64).
     * @param string $ivB64                    IV dla AES (Base64, 16 bajtów po dekodowaniu).
     * @param string $systemCode               Domyślnie 'FA (2)' lub 'FA (3)'.
     * @param string $schemaVersion            Domyślnie '1-0E'.
     * @param string $value                    Domyślnie 'FA'.
     * @param bool   $offlineMode              Deklaracja trybu offline (domyślnie false).
     *
     * @return array Odpowiedź JSON z KSeF (referenceNumber, partUploadRequests, itp.).
     *
     * @throws InvalidArgumentException Przy brakujących danych wejściowych.
     * @throws RuntimeException         Przy błędach HTTP/cURL/KSeF.
     */
    public function openBatchSessionFA(
        string $accessToken,
        array $batchMeta,
        string $encryptedSymmetricKeyB64,
        string $ivB64,
        string $systemCode = 'FA (2)',
        string $schemaVersion = '1-0E',
        string $value = 'FA',
        bool   $offlineMode = false
    ): array {
        // ...
    }

    // ========================================================================
    // 3) WYSYŁANIE CZĘŚCI PLIKU PACZKI
    // ========================================================================

    /**
     * Wysyła fizyczne bajty części pliku paczki na adresy z partUploadRequests.
     *
     * Bardzo ważne:
     *  - ZGODNIE Z DOKUMENTACJĄ – NIE dodajemy nagłówka Authorization.
     *  - Każda część jest wysyłana jako osobne żądanie HTTP (np. PUT/POST).
     *
     * Wejście:
     *  - partUploadRequests – bezpośrednio z odpowiedzi /sessions/batch:
     *      [
     *        [
     *          'ordinalNumber' => 1,
     *          'method'        => 'PUT',
     *          'url'           => 'https://...',
     *          'headers'       => [ 'Header-Name' => 'Value', ... ] lub ['Header: Value', ...]
     *        ],
     *        ...
     *      ]
     *  - filePath           – ścieżka do pliku paczki (tego samego, z którego liczono batchMeta).
     *  - batchMeta          – wynik computeBatchMetaFromFile(), zawiera _offset/_length dla każdej części.
     *
     * Wyjście:
     *  - tablica z rezultatami wysyłki dla każdej części:
     *      [
     *        [
     *          'ordinalNumber' => 1,
     *          'httpCode'      => 201,
     *          'rawResponse'   => '...'
     *        ],
     *        ...
     *      ]
     *
     * @param array  $partUploadRequests Instrukcje wysyłki części z KSeF.
     * @param string $filePath           Ścieżka do pliku-paczki.
     * @param array  $batchMeta          Metadane z computeBatchMetaFromFile().
     *
     * @return array Lista wyników uploadu części.
     *
     * @throws InvalidArgumentException Przy brakujących danych/metadanych.
     * @throws RuntimeException         Przy błędach cURL/HTTP lub niezgodnościach długości danych.
     */
    public function uploadBatchParts(
        array $partUploadRequests,
        string $filePath,
        array $batchMeta
    ): array {
        // ...
    }

    // ========================================================================
    // 4) ZAMKNIĘCIE SESJI WSADOWEJ
    // ========================================================================

    /**
     * Zamyka sesję wsadową i inicjuje przetwarzanie paczki.
     *
     * Endpoint:
     *   POST /api/v2/sessions/batch/{referenceNumber}/close
     *
     * Oczekiwany sukces:
     *   - HTTP 204 (No Content).
     *
     * W razie błędu:
     *   - dla HTTP 400 i odpowiedzi z węzłem "Exception" – komunikat z formatKsefException(),
     *   - dla innych kodów – RuntimeException z treścią odpowiedzi.
     *
     * @param string $accessToken    AccessToken (Bearer) z KSeFXAdESClient.
     * @param string $referenceNumber Numer referencyjny sesji wsadowej (36 znaków).
     *
     * @return bool true, jeśli sesja została poprawnie zamknięta (HTTP 204).
     *
     * @throws RuntimeException Przy błędach HTTP/cURL/KSeF.
     */
    public function closeBatchSession(string $accessToken, string $referenceNumber): bool
    {
        // ...
    }

    // ========================================================================
    // 5) WSPÓLNE NARZĘDZIA HTTP (wewnętrzne)
    // ========================================================================

    /**
     * Wspólna metoda do wywołań endpointów chronionych Bearer-em,
     * zwracających JSON.
     *
     * Ustawia:
     *  - Authorization: Bearer <accessToken>
     *  - Accept: application/json
     *  - Content-Type: application/json (gdy body != null)
     *
     * Waliduje:
     *  - JSON,
     *  - kody HTTP (>=400 -> wyjątek),
     *  - specjalnie obsługuje węzeł "Exception" z odpowiedzi KSeF.
     *
     * @param string            $path        Ścieżka względna lub pełny URL.
     * @param string            $accessToken AccessToken (Bearer).
     * @param array|string|null $body        Dane do wysłania (tablica -> json_encode()).
     * @param string            $method      Metoda HTTP (POST, GET, itp.).
     *
     * @return array Zdekodowany JSON jako tablica asocjacyjna.
     *
     * @throws RuntimeException Przy błędach cURL/HTTP/JSON/KSeF.
     */
    private function callProtectedJson(
        string $path,
        string $accessToken,
        $body = null,
        string $method = 'POST'
    ): array {
        // ...
    }

    /**
     * Ustawia wspólne opcje cURL (timeout, metoda, nagłówki, debug).
     *
     * @param resource $ch       Uchwyt cURL.
     * @param array    $headers  Lista nagłówków (np. ["Header: value", ...]).
     * @param string   $method   Metoda HTTP.
     * @param int      $timeout  Timeout w sekundach.
     *
     * @return void
     */
    private function applyCommonCurl($ch, array $headers, string $method = 'GET', int $timeout = 30): void
    {
        // ...
    }

    /**
     * Składa pełny URL na podstawie ścieżki:
     *  - jeśli $path zaczyna się od http/https – zwraca bez zmian,
     *  - w przeciwnym razie dokleja do $baseUrl.
     *
     * @param string $path Ścieżka względna lub pełny URL.
     *
     * @return string Pełny URL.
     */
    private function absoluteUrl(string $path): string
    {
        // ...
    }

    // ========================================================================
    // 6) FORMATOWANIE BŁĘDÓW KSeF (wewnętrzne)
    // ========================================================================

    /**
     * Buduje czytelny opis błędu z węzła "Exception" odpowiedzi KSeF.
     *
     * Wejście:
     *  [
     *    'ReferenceNumber'     => '...',
     *    'ServiceCode'         => '...',
     *    'ServiceName'         => '...',
     *    'Timestamp'           => '...',
     *    'ExceptionDetailList' => [
     *      [
     *        'ExceptionCode'        => '...',
     *        'ExceptionDescription' => '...',
     *        'Details'              => ['...', ...]
     *      ],
     *      ...
     *    ]
     *  ]
     *
     * Wyjście (string):
     *  "#KOD: opis [Details...] | #KOD2: ... (Ref=... Svc=... Name=... Ts=...)"
     *
     * @param array $ex Węzeł Exception z JSON-a KSeF.
     *
     * @return string Gotowy opis do wyrzucenia w RuntimeException.
     */
    private function formatKsefException(array $ex): string
    {
        // ...
    }
}
