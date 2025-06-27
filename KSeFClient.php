<?php

class KSeFClient {
    private $apiUrl;
    private $nip;
    private $apiKey;
    private $publicKeyPath;
    private $sessionToken;

    public function __construct($apiUrl, $nip, $apiKey, $publicKeyPath) {
        $this->apiUrl = $apiUrl;
        $this->nip = $nip;
        $this->apiKey = $apiKey;
        $this->publicKeyPath = $publicKeyPath;
    }

    private function sendRequest($url, $data, $headers, $method = 'POST') {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method); 
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        if ($data) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        }

        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $curlError = curl_error($curl);
        curl_close($curl);

        if ($curlError) {
            echo "Błąd cURL: " . $curlError . "\n";
        }

        return ['response' => $response, 'httpCode' => $httpCode];
    }

    public function getChallengeAndTimestamp() {
        $url = "{$this->apiUrl}/online/Session/AuthorisationChallenge";
        $data = json_encode([
            "contextIdentifier" => [
                "type" => "onip",
                "identifier" => $this->nip
            ]
        ]);
        $headers = ["Content-Type: application/json", "Accept: application/json"];

        $response = $this->sendRequest($url, $data, $headers);
        if ($response['httpCode'] === 201) {
            return json_decode($response['response'], true);
        } else {
            die("Błąd w uzyskiwaniu challenge: " . $response['response']);
        }
    }

    private function encryptToken($token, $challengeTimeMillis) {
        $dataToEncrypt = "$token|$challengeTimeMillis";
        $encryptedToken = '';
        $publicKey = file_get_contents($this->publicKeyPath);
        if (openssl_public_encrypt($dataToEncrypt, $encryptedToken, $publicKey, OPENSSL_PKCS1_PADDING)) {
            return base64_encode($encryptedToken);
        } else {
            echo "Nie udało się zaszyfrować tokenu.\n";
            return false;
        }
    }
public function getKSeFSessionTokenFA3($encryptedToken, $challenge) {
    $dom = new DOMDocument('1.0', 'UTF-8');
    $dom->formatOutput = true;

    $ns = 'http://e-dokument.mf.gov.pl/InitSessionTokenRequest';

    $root = $dom->createElementNS($ns, 'InitSessionTokenRequest');
    $dom->appendChild($root);

    $context = $dom->createElement('Context');
    $tokenElement = $dom->createElement('Token', trim($encryptedToken));
    $challengeElement = $dom->createElement('Challenge', $challenge);

    $context->appendChild($tokenElement);
    $root->appendChild($context);
    $root->appendChild($challengeElement);

    $url = "{$this->apiUrl}/online/Session/InitToken";
    $headers = ["Content-Type: application/xml; charset=UTF-8", "Accept: application/json"];

    $response = $this->sendRequest($url, $dom->saveXML(), $headers);
    if ($response['httpCode'] === 200 || $response['httpCode'] === 201) {
        $this->sessionToken = json_decode($response['response'], true)['sessionToken']['token'];
        return $this->sessionToken;
    } else {
        echo "Błąd w uzyskiwaniu tokenu sesji (FA3).\n";
        echo $response['response'];
        return false;
    }
}


    public function sendInvoice($invoiceFile) {
        if (!file_exists($invoiceFile) || !is_readable($invoiceFile)) {
            die("Plik faktury nie istnieje lub nie można go odczytać: $invoiceFile\n");
        }

        $invoiceData = file_get_contents($invoiceFile);
        $hashSHA = base64_encode(hash('sha256', $invoiceData, true));
        $invoiceBody = base64_encode($invoiceData);
        $fSize = filesize($invoiceFile);

        $body = json_encode([
            "invoiceHash" => [
                "fileSize" => $fSize,
                "hashSHA" => ["algorithm" => "SHA-256", "encoding" => "Base64", "value" => $hashSHA]
            ],
            "invoicePayload" => ["type" => "plain", "invoiceBody" => $invoiceBody]
        ]);

        $headers = [
            'Accept: application/json',
            'SessionToken: ' . $this->sessionToken,
            'Content-Type: application/json'
        ];

        $response = $this->sendRequest("{$this->apiUrl}/online/Invoice/Send", $body, $headers, 'PUT');
        $httpCode = $response['httpCode'];

        if ($httpCode === 200 || $httpCode === 201) {
            return json_decode($response['response'], true);
        } elseif ($httpCode === 202) {
            echo "Żądanie zaakceptowane do przetwarzania.\n";
            return json_decode($response['response'], true);
        } else {
            echo "Błąd w wysyłaniu faktury.\n";
            return false;
        }
    }

    public function terminateSession() {
        $url = "{$this->apiUrl}/online/Session/Terminate";
        $headers = ['Accept: application/json', 'SessionToken: ' . $this->sessionToken];
        $response = $this->sendRequest($url, null, $headers, 'GET');

        if ($response['httpCode'] === 200) {
            echo "Sesja została zakończona pomyślnie.\n";
            return json_decode($response['response'], true);
        } else {
            echo "Błąd zamknięcia sesji.\n";
            return false;
        }
    }

    public function getSessionStatus($referenceNumber, $pageSize = 10, $pageOffset = 0, $includeDetails = true) {
        // Budowanie URL z parametrami zapytania
        $statusUrl = "{$this->apiUrl}/online/Session/Status/$referenceNumber";
        $queryParams = http_build_query([
            'PageSize' => $pageSize,
            'PageOffset' => $pageOffset,
            'IncludeDetails' => $includeDetails ? 'true' : 'false'
        ]);
        $statusUrl .= '?' . $queryParams;

        // Nagłówki żądania
        $headers = [
            'Accept: application/json',
            'SessionToken: ' . $this->sessionToken
        ];

        // Wysłanie żądania
        $statusResponse = $this->sendRequest($statusUrl, null, $headers, 'GET');
        $httpCode = $statusResponse['httpCode'];

        if ($httpCode === 200) {
            // Parsowanie odpowiedzi JSON
            return json_decode($statusResponse['response'], true);
        } else {
            // Obsługa błędów
            echo "Błąd w sprawdzaniu statusu sesji. Kod odpowiedzi HTTP: $httpCode\n";
            echo "Treść odpowiedzi: " . $statusResponse['response'] . "\n";
            return false;
        }
    }
}
