<?php
declare(strict_types=1);

/**
 * KSeFXAdESClient — KSeF v2:
 *  1) POST /api/v2/auth/challenge
 *  2) XAdES (xmlsec1) -> POST /api/v2/auth/xades-signature => authenticationToken (JWT, krótkożyjący)
 *  3) POST /api/v2/auth/access-token                      => accessToken + refreshToken (jednorazowo)
 *  4) GET  /api/v2/security/public-key-certificates
 *  5) POST /api/v2/sessions/online                        => sesja interaktywna (deklaracja RSA-OAEP klucza AES + IV)
 *  6) POST /api/v2/sessions/online/{ref}/invoices         => wysyłka zaszyfrowanej faktury FA(3)
 */
final class KSeFXAdESClient
{
    private string $nip;
    private string $certPath; // Twoje .crt (PEM)
    private string $keyPath;  // Twój .key (PEM/PKCS#8)
    private ?string $keyPass;
    private string $baseUrl;
    private bool $httpDebug = false;

    public function __construct(
        string $nip,
        string $certPath,
        string $keyPath,
        ?string $keyPass,
        string $baseUrl = 'https://ksef-test.mf.gov.pl'
    ) {
        $this->nip      = $nip;
        $this->certPath = $certPath;
        $this->keyPath  = $keyPath;
        $this->keyPass  = $keyPass;
        $this->baseUrl  = rtrim($baseUrl, '/');
        $this->preChecks();
    }

    public function withHttpDebug(bool $on = true): self
    {
        $this->httpDebug = $on;
        return $this;
    }

    /**
     * Pełna autoryzacja: challenge -> XAdES -> authToken -> accessToken (+refreshToken).
     * Robi jeden retry, gdy /access-token zwróci 401 (typowo „token już użyty” / zegar).
     *
     * @return array{
     *   authToken:string, accessToken:string, refreshToken?:string,
     *   validUntil?:string, rawAuth?:array, rawAccess?:array
     * }
     */
    public function authenticate(): array
    {
        $auth = $this->authenticateOnce();
        if (($auth['status'] ?? '') === 'redeem_401_retry') {
            $auth = $this->authenticateOnce();
        }
        if (empty($auth['accessToken'])) {
            throw new RuntimeException('Nie uzyskano accessToken: ' . json_encode($auth, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        }
        return $auth;
    }

    private function authenticateOnce(): array
    {
        $challenge   = $this->getChallenge();
        $xmlUnsigned = $this->buildAuthXml($challenge);
        $xmlSigned   = $this->signXmlWithXmlSec1($xmlUnsigned);

        $authResp   = $this->postXmlForToken($xmlSigned);
        $authToken  = $authResp['authenticationToken']['token']      ?? null;
        $validUntil = $authResp['authenticationToken']['validUntil'] ?? null;
        if (!$authToken) {
            throw new RuntimeException('Brak authenticationToken.token: ' . json_encode($authResp, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        }

        try {
            $accessResp   = $this->redeemAccessToken($authToken);
            $accessToken  = $this->normalizeTokenField($accessResp['accessToken']  ?? null);
            $refreshToken = $this->normalizeTokenField($accessResp['refreshToken'] ?? null);

            return [
                'authToken'    => (string)$authToken,
                'accessToken'  => (string)$accessToken,
                'refreshToken' => $refreshToken ? (string)$refreshToken : null,
                'validUntil'   => $validUntil ?: null,
                'rawAuth'      => $authResp,
                'rawAccess'    => $accessResp,
            ];
        } catch (RuntimeException $e) {
            if (str_contains($e->getMessage(), 'HTTP 401')) {
                return [
                    'authToken'   => (string)$authToken,
                    'validUntil'  => $validUntil ?: null,
                    'status'      => 'redeem_401_retry',
                    'redeemError' => $e->getMessage(),
                ];
            }
            throw $e;
        }
    }

    /** Normalizuje pole tokena (bywa, że serwer zwróci strukturę typu ["token"=>"..."]). */
    private function normalizeTokenField($v)
    {
        if (is_string($v)) {
            return $v;
        }
        if (is_array($v) && isset($v['token']) && is_string($v['token'])) {
            return $v['token'];
        }
        return $v;
    }

    /** Wywołanie chronionego endpointu z Bearer. */
    public function callProtected(string $path, string $accessToken, $body = null, string $method = 'POST'): array
    {
        $url = $this->absoluteUrl($path);
        $payload = is_array($body) ? json_encode($body, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) : $body;

        $ch = curl_init($url);
        $headers = ['Authorization: Bearer ' . $accessToken, 'Accept: application/json'];
        if ($payload !== null) {
            $headers[] = 'Content-Type: application/json';
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        }
        $this->applyCommonCurl($ch, $headers, strtoupper($method));

        $raw = curl_exec($ch);
        $info = curl_getinfo($ch);
        if ($raw === false) {
            $e = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error: ' . $e);
        }
        curl_close($ch);

        $code = (int)($info['http_code'] ?? 0);
        $decoded = json_decode($raw, true);
        if ($decoded === null && $raw !== '' && $raw !== 'null') {
            throw new RuntimeException("Niepoprawny JSON z {$url} (HTTP {$code}): " . $raw);
        }
        if ($code >= 400) {
            throw new RuntimeException("Błąd HTTP {$code}: " . ($decoded ? json_encode($decoded, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) : $raw));
        }
        return $decoded ?? [];
    }

    // ===== KROK 1: challenge =====
    private function getChallenge(): string
    {
        $url = $this->absoluteUrl('/api/v2/auth/challenge');
        $payload = json_encode(['contextIdentifier' => ['nip' => $this->nip]], JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);

        $ch = curl_init($url);
        $this->applyCommonCurl($ch, ['Content-Type: application/json', 'Accept: application/json'], 'POST', 30);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);

        $raw = curl_exec($ch);
        $info = curl_getinfo($ch);
        if ($raw === false) {
            $e = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error: ' . $e);
        }
        curl_close($ch);

        $code = (int)($info['http_code'] ?? 0);
        $decoded = json_decode($raw, true);
        if ($decoded === null) {
            throw new RuntimeException("Niepoprawny JSON z challenge (HTTP {$code}): " . $raw);
        }
        $challenge = $decoded['challenge'] ?? null;
        if (!$challenge) {
            throw new RuntimeException('Brak pola "challenge": ' . json_encode($decoded, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        }
        return $challenge;
    }

    // ===== KROK 2: XML XAdES =====
    private function buildAuthXml(string $challenge): string
    {
        $sigMethod     = $this->detectSignatureMethod(); // ecdsa-sha256 / rsa-sha256
        $certDigestB64 = $this->getCertSha256DigestBase64();
        $issuerDN      = $this->getIssuerDnString();
        $serialDec     = $this->getSerialAsDecimal();
        $signingTime   = gmdate('Y-m-d\TH:i:s\Z');
        $certBodyB64   = $this->getCertBodyBase64();

        $xml = <<<XML
<?xml version="1.0" encoding="utf-8"?>
<AuthTokenRequest xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                  xmlns="http://ksef.mf.gov.pl/auth/token/2.0"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">
  <Challenge>{$this->xml($challenge)}</Challenge>
  <ContextIdentifier><Nip>{$this->xml($this->nip)}</Nip></ContextIdentifier>
  <SubjectIdentifierType>certificateSubject</SubjectIdentifierType>

  <ds:Signature Id="Sig-1">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#{$sigMethod}"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
      <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#SignedProperties-1">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>
{$certBodyB64}
        </ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>

    <ds:Object>
      <xades:QualifyingProperties Target="#Sig-1">
        <xades:SignedProperties Id="SignedProperties-1">
          <xades:SignedSignatureProperties>
            <xades:SigningTime>{$signingTime}</xades:SigningTime>
            <xades:SigningCertificate>
              <xades:Cert>
                <xades:CertDigest>
                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <ds:DigestValue>{$certDigestB64}</ds:DigestValue>
                </xades:CertDigest>
                <xades:IssuerSerial>
                  <ds:X509IssuerName>{$this->xml($issuerDN)}</ds:X509IssuerName>
                  <ds:X509SerialNumber>{$serialDec}</ds:X509SerialNumber>
                </xades:IssuerSerial>
              </xades:Cert>
            </xades:SigningCertificate>
          </xades:SignedSignatureProperties>
        </xades:SignedProperties>
      </xades:QualifyingProperties>
    </ds:Object>
  </ds:Signature>
</AuthTokenRequest>
XML;
        return $xml;
    }

    // ===== KROK 3: podpis xmlsec1 =====
    private function signXmlWithXmlSec1(string $xmlUnsigned): string
    {
        // tworzymy pliki tymczasowe przez helper
        $inPath  = $this->createTempFile('ksef-auth-unsigned-');
        $outPath = $this->createTempFile('ksef-auth-signed-');

        if (file_put_contents($inPath, $xmlUnsigned) === false) {
            @unlink($inPath);
            @unlink($outPath);
            throw new RuntimeException('Nie mogę zapisać pliku wejściowego: ' . $inPath);
        }

        $keyForXmlsec = $this->keyPath;
        $tmpKey = null;

        try {
            if ($this->keyPass !== null && $this->keyPass !== '') {
                $tmpKey = $this->createTempFile('ksef-key-');

                $cmd = [
                    'bash','-lc',
                    'openssl pkey -in ' . escapeshellarg($this->keyPath) .
                    ' -passin ' . escapeshellarg('pass:' . $this->keyPass) .
                    ' -out ' . escapeshellarg($tmpKey)
                ];
                $this->run($cmd, $ret);
                if ($ret !== 0 || !is_file($tmpKey) || filesize($tmpKey) === 0) {
                    throw new RuntimeException('Nie udało się zdjąć hasła z klucza (openssl pkey).');
                }
                $keyForXmlsec = $tmpKey;
            }

            $cmdSign = [
                'xmlsec1','--sign',
                '--privkey-pem', $keyForXmlsec . ',' . $this->certPath,
                '--X509-skip-strict-checks',
                '--id-attr:Id','ds:Signature',
                '--output',$outPath,
                $inPath,
            ];
            $out = $this->run($cmdSign, $retSign);
            if ($retSign !== 0 || !is_file($outPath) || filesize($outPath) === 0) {
                throw new RuntimeException("Podpis xmlsec1 nie powiódł się (exit={$retSign}). Wyjście:\n".$out);
            }

            $signed = file_get_contents($outPath);
            if ($signed === false || $signed === '') {
                throw new RuntimeException('Plik podpisany jest pusty.');
            }

            // opcjonalna walidacja
            try {
                $this->run(
                    ['xmlsec1','--verify','--pubkey-cert-pem',$this->certPath,'--id-attr:Id','ds:Signature',$outPath],
                    $rv
                );
            } catch (\Throwable $e) {
                // tylko pomocniczo, bez wyjątku
            }

            return $signed;
        } finally {
            @unlink($inPath);
            @unlink($outPath);
            if ($tmpKey && is_file($tmpKey)) {
                @unlink($tmpKey);
            }
        }
    }


    // ===== KROK 4: xades-signature -> authenticationToken =====
    private function postXmlForToken(string $signedXml): array
    {
        $url = $this->absoluteUrl('/api/v2/auth/xades-signature?verifyCertificateChain=false');

        $ch = curl_init($url);
        $this->applyCommonCurl($ch, ['Content-Type: application/xml', 'Accept: application/json'], 'POST', 60);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $signedXml);

        $raw = curl_exec($ch);
        $info = curl_getinfo($ch);
        if ($raw === false) {
            $e = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error: ' . $e);
        }
        curl_close($ch);

        $code = (int)($info['http_code'] ?? 0);
        $decoded = json_decode($raw, true);
        if ($decoded === null) {
            throw new RuntimeException("Niepoprawny JSON (HTTP {$code}): ".$raw);
        }
        if ($code >= 400) {
            throw new RuntimeException("Błąd HTTP {$code} przy xades-signature: ".json_encode($decoded, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE));
        }
        return $decoded;
    }

    // ===== KROK 5: redeem authToken -> accessToken =====
    private function redeemAccessToken(string $authenticationToken): array
    {
        $urlPrimary = $this->absoluteUrl('/api/v2/auth/access-token');

        $ch = curl_init($urlPrimary);
        $this->applyCommonCurl($ch, ['Authorization: Bearer ' . $authenticationToken, 'Accept: application/json'], 'POST', 30);
        $raw = curl_exec($ch);
        $info = curl_getinfo($ch);
        $code = (int)($info['http_code'] ?? 0);
        $err  = $raw === false ? curl_error($ch) : null;
        curl_close($ch);

        if ($raw === false) {
            throw new RuntimeException('cURL error (access-token): ' . $err);
        }

        if ($code === 405) { // fallback GET (historyczne zachowanie)
            $ch = curl_init($urlPrimary);
            $this->applyCommonCurl($ch, ['Authorization: Bearer ' . $authenticationToken, 'Accept: application/json'], 'GET', 30);
            $raw = curl_exec($ch);
            $info= curl_getinfo($ch);
            $code= (int)($info['http_code'] ?? 0);
            $err = $raw === false ? curl_error($ch) : null;
            curl_close($ch);
            if ($raw === false) {
                throw new RuntimeException('cURL error (access-token GET): ' . $err);
            }
        }

        if ($code === 401) {
            $urlAlt = $this->absoluteUrl('/api/v2/auth/token/redeem');
            $ch = curl_init($urlAlt);
            $this->applyCommonCurl($ch, ['Authorization: Bearer ' . $authenticationToken, 'Accept: application/json'], 'POST', 30);
            $rawAlt = curl_exec($ch);
            $infoAlt= curl_getinfo($ch);
            $codeAlt= (int)($infoAlt['http_code'] ?? 0);
            $errAlt = $rawAlt === false ? curl_error($ch) : null;
            curl_close($ch);

            if ($rawAlt !== false) {
                $decAlt = json_decode($rawAlt, true);
                if ($codeAlt < 400 && is_array($decAlt)) {
                    return $decAlt;
                }
            }

            throw new RuntimeException(
                "Błąd HTTP 401 przy access-token.\n" .
                "- Token auth jest jednorazowy – jeśli już był wymieniony, drugi raz się nie uda.\n" .
                "- Sprawdź czy nie ma podwójnego reloadu oraz czy zegar (NTP) jest poprawny.\n" .
                "Odpowiedź: " . ($raw ?: '(brak treści)')
            );
        }

        $decoded = json_decode($raw, true);
        if ($decoded === null) {
            throw new RuntimeException("Niepoprawny JSON z access-token (HTTP {$code}): " . $raw);
        }
        if ($code >= 400) {
            throw new RuntimeException("Błąd HTTP {$code} przy access-token: " . json_encode($decoded, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES));
        }
        return $decoded;
    }

    // ===== Sesja interaktywna =====
    public function openInteractiveSessionFA3(string $accessToken, string $encryptedSymmetricKeyB64, string $ivB64, string $schemaVersion = '1-0E'): array
    {
        $formCode   = ['systemCode' => 'FA (3)', 'schemaVersion' => $schemaVersion, 'value' => 'FA'];
        $encryption = ['encryptedSymmetricKey' => $encryptedSymmetricKeyB64, 'initializationVector' => $ivB64];
        return $this->openInteractiveSession($accessToken, $formCode, $encryption);
    }

    public function openInteractiveSession(string $accessToken, array $formCode, array $encryption): array
    {
        foreach (['systemCode','schemaVersion','value'] as $k) {
            if (!isset($formCode[$k]) || !is_string($formCode[$k]) || $formCode[$k] === '') {
                throw new InvalidArgumentException("Brak/niepoprawne formCode['{$k}'].");
            }
        }
        foreach (['encryptedSymmetricKey','initializationVector'] as $k) {
            if (!isset($encryption[$k]) || !is_string($encryption[$k]) || $encryption[$k] === '') {
                throw new InvalidArgumentException("Brak/niepoprawne encryption['{$k}'].");
            }
        }
        $body = ['formCode' => $formCode, 'encryption' => $encryption];
        return $this->callProtected('/api/v2/sessions/online', $accessToken, $body, 'POST');
    }

    // ===== Publiczne certyfikaty KSeF =====
    public function getPublicKeyCertificates(): array
    {
        $url = $this->absoluteUrl('/api/v2/security/public-key-certificates');
        $ch = curl_init($url);
        $this->applyCommonCurl($ch, ['Accept: application/json'], 'GET', 30);

        $raw = curl_exec($ch);
        $info = curl_getinfo($ch);
        if ($raw === false) {
            $e = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error: ' . $e);
        }
        curl_close($ch);

        $code = (int)($info['http_code'] ?? 0);
        if ($code === 200) {
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                throw new RuntimeException('Niepoprawny JSON (200): ' . $raw);
            }
            return $decoded;
        }
        if ($code === 400) {
            $err = json_decode($raw, true);
            if (isset($err['Exception'])) {
                $msg = $this->formatKsefException($err['Exception']);
                throw new RuntimeException("KSeF 400: {$msg}");
            }
            throw new RuntimeException("KSeF 400: " . $raw);
        }
        throw new RuntimeException("Błąd HTTP {$code}: " . $raw);
    }

    public function getPublicKeyCertificatesPem(?string $usageFilter = null): array
    {
        $items = $this->getPublicKeyCertificates();
        if ($usageFilter !== null) {
            $items = $this->pickCertificatesByUsage($items, $usageFilter);
        }

        $out = [];
        foreach ($items as $it) {
            $derB64 = $it['certificate'] ?? null;
            if (!is_string($derB64) || $derB64 === '') {
                continue;
            }
            $pem = $this->derBase64ToPem($derB64);
            $out[] = [
                'pem'       => $pem,
                'validFrom' => $it['validFrom'] ?? null,
                'validTo'   => $it['validTo'] ?? null,
                'usage'     => $it['usage'] ?? [],
            ];
        }
        return $out;
    }

    public function pickCertificatesByUsage(array $items, string $usage): array
    {
        return array_values(array_filter($items, fn($it) => isset($it['usage']) && is_array($it['usage']) && in_array($usage, $it['usage'], true)));
    }

    public function derBase64ToPem(string $derBase64): string
    {
        $derBase64 = preg_replace('~\s+~', '', $derBase64 ?? '');
        $body = chunk_split($derBase64, 64, "\n");
        return "-----BEGIN CERTIFICATE-----\n{$body}-----END CERTIFICATE-----\n";
    }

    private function formatKsefException(array $ex): string
    {
        $ref  = $ex['ReferenceNumber'] ?? '';
        $svc  = $ex['ServiceCode']     ?? '';
        $name = $ex['ServiceName']     ?? '';
        $ts   = $ex['Timestamp']       ?? '';
        $list = $ex['ExceptionDetailList'] ?? [];

        $parts = [];
        foreach ($list as $d) {
            $code = $d['ExceptionCode']        ?? '';
            $desc = $d['ExceptionDescription'] ?? '';
            $det  = (isset($d['Details']) && is_array($d['Details'])) ? (' [' . implode('; ', $d['Details']) . ']') : '';
            $parts[] = "#{$code}: {$desc}{$det}";
        }
        $msg = implode(' | ', $parts);
        $meta = trim("Ref={$ref} Svc={$svc} Name={$name} Ts={$ts}");
        return $msg . ($meta ? " ({$meta})" : '');
    }

    /**
     * Przygotowuje klucz AES-256 i IV, szyfruje klucz publicznym certyfikatem KSeF (RSA-OAEP),
     * zwraca: encKeyB64, ivB64, a **także jawny klucz** aesKeyB64 (do szyfrowania treści faktur).
     *
     * @return array{encKeyB64:string, ivB64:string, aesKeyB64:string, usedCertPem:string, validTo:?string}
     */
    public function prepareInteractiveEncryption(int $ivLen = 16): array
    {
        if ($ivLen !== 16) {
            throw new InvalidArgumentException('Dla AES-256-CBC IV musi mieć 16 bajtów.');
        }

        $candidates = $this->getPublicKeyCertificatesPem('SymmetricKeyEncryption');
        if (empty($candidates)) {
            throw new RuntimeException('Brak certyfikatów usage=SymmetricKeyEncryption.');
        }

        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $chosen = null;
        foreach ($candidates as $c) {
            $vt = isset($c['validTo']) ? new \DateTimeImmutable($c['validTo']) : null;
            if ($vt && $vt > $now) {
                $chosen = $c;
                break;
            }
        }
        if ($chosen === null) {
            $chosen = $candidates[0];
        }

        $pem = $chosen['pem'];
        if (!$this->isRsaPublicKeyPem($pem)) {
            throw new RuntimeException('Wybrany certyfikat KSeF nie jest RSA (wymagany dla RSA-OAEP).');
        }

        $aesKey = random_bytes(32);        // AES-256
        $iv     = random_bytes(16);        // 16 bajtów dla CBC

        $ivB64     = base64_encode($iv);
        $aesKeyB64 = base64_encode($aesKey);

        $encKey    = $this->rsaOaepEncryptWithCertPem($pem, $aesKey);
        $encKeyB64 = base64_encode($encKey);

        return [
            'encKeyB64'   => $encKeyB64,
            'ivB64'       => $ivB64,
            'aesKeyB64'   => $aesKeyB64,
            'usedCertPem' => $pem,
            'validTo'     => $chosen['validTo'] ?? null,
        ];
    }

    private function isRsaPublicKeyPem(string $pem): bool
    {
        $res = @openssl_x509_read($pem);
        if ($res === false) {
            return false;
        }
        $pub = openssl_pkey_get_public($res);
        if ($pub === false) {
            return false;
        }
        $det = openssl_pkey_get_details($pub);
        return is_array($det) && ($det['type'] ?? null) === OPENSSL_KEYTYPE_RSA;
    }

    private function rsaOaepEncryptWithCertPem(string $certPem, string $plaintext): string
    {
        $certFile = $this->createTempFile('ksef-cert-');
        $inFile   = $this->createTempFile('ksef-plain-');
        $outFile  = $this->createTempFile('ksef-enc-');

        file_put_contents($certFile, $certPem);
        file_put_contents($inFile, $plaintext);

        try {
            $cmd = [
                'bash','-lc',
                'openssl pkeyutl -encrypt -certin -inkey ' . escapeshellarg($certFile) .
                ' -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256' .
                ' -in ' . escapeshellarg($inFile) . ' -out ' . escapeshellarg($outFile)
            ];
            $out = $this->run($cmd, $ret);
            if ($ret !== 0 || !is_file($outFile) || filesize($outFile) === 0) {
                // fallback (bez jawnego mgf1_md — starsze OpenSSL)
                $cmd2 = [
                    'bash','-lc',
                    'openssl pkeyutl -encrypt -certin -inkey ' . escapeshellarg($certFile) .
                    ' -pkeyopt rsa_padding_mode:oaep' .
                    ' -in ' . escapeshellarg($inFile) . ' -out ' . escapeshellarg($outFile)
                ];
                $out2 = $this->run($cmd2, $ret2);
                if ($ret2 !== 0 || !is_file($outFile) || filesize($outFile) === 0) {
                    throw new RuntimeException("RSA-OAEP szyfrowanie nie powiodło się.\n1) {$out}\n2) {$out2}");
                }
            }

            $cipher = file_get_contents($outFile);
            if ($cipher === false || $cipher === '') {
                throw new RuntimeException('Pusty wynik szyfrowania klucza.');
            }
            return $cipher;
        } finally {
            @unlink($certFile);
            @unlink($inFile);
            @unlink($outFile);
        }
    }

    // ===== Wysyłka zaszyfrowanej faktury =====

    /**
     * POST /api/v2/sessions/online/{referenceNumber}/invoices
     * Payload: invoiceHash, invoiceSize, encryptedInvoiceHash, encryptedInvoiceSize, encryptedInvoiceContent, offlineMode
     * Zwraca (202): ["referenceNumber" => "..."]
     */
    public function sendEncryptedInvoice(string $accessToken, string $sessionReferenceNumber, array $payload): array
    {
        foreach (['invoiceHash','invoiceSize','encryptedInvoiceHash','encryptedInvoiceSize','encryptedInvoiceContent','offlineMode'] as $k) {
            if (!array_key_exists($k, $payload)) {
                throw new InvalidArgumentException("Brak wymaganego pola payload['{$k}'].");
            }
        }
        $path = "/api/v2/sessions/online/" . rawurlencode($sessionReferenceNumber) . "/invoices";
        return $this->callProtected($path, $accessToken, $payload, 'POST');
    }

    /** Liczy metadane do payloadu wysyłki. */
    public function computeInvoiceMeta(string $invoicePlainXml, string $encryptedBytes): array
    {
        return [
            'invoiceHash'          => base64_encode(hash('sha256', $invoicePlainXml, true)),
            'invoiceSize'          => strlen($invoicePlainXml),
            'encryptedInvoiceHash' => base64_encode(hash('sha256', $encryptedBytes, true)),
            'encryptedInvoiceSize' => strlen($encryptedBytes),
        ];
    }

    /**
     * Szyfrowanie faktury algorytmem AES-256-CBC z dopełnianiem PKCS#7.
     *
     * KSeF oczekuje:
     *  - encryptedInvoiceContent = Base64(cipherText)
     *  - encryptedInvoiceHash    = SHA256(cipherText) w Base64
     *  - encryptedInvoiceSize    = długość cipherText w bajtach
     *
     * @param string $aesKeyB64 Klucz AES (Base64, 32 bajty po dekodowaniu)
     * @param string $ivB64     Wektor IV (Base64, 16 bajtów po dekodowaniu)
     * @param string $plaintext Treść faktury (XML)
     *
     * @return array{
     *   cipherB64: string,
     *   cipherRaw: string
     * }
     */
    public function encryptInvoiceAesCbc(
        string $aesKeyB64,
        string $ivB64,
        string $plaintext
    ): array {
        $key = base64_decode($aesKeyB64, true);
        $iv  = base64_decode($ivB64, true);

        if ($key === false || $iv === false) {
            throw new InvalidArgumentException('Nieprawidłowe Base64 dla klucza lub IV.');
        }
        if (strlen($key) !== 32) {
            throw new InvalidArgumentException('Klucz AES musi mieć 32 bajty (AES-256).');
        }
        if (strlen($iv) !== 16) {
            throw new InvalidArgumentException('IV dla AES-256-CBC musi mieć 16 bajtów.');
        }

        $cipher = openssl_encrypt(
            $plaintext,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($cipher === false) {
            throw new RuntimeException('Błąd AES-256-CBC (openssl_encrypt).');
        }

        return [
            'cipherB64' => base64_encode($cipher),
            'cipherRaw' => $cipher,
        ];
    }

    // ===== narzędzia =====
    private function preChecks(): void
    {
        foreach (['xmlsec1', 'openssl'] as $bin) {
            $this->assertBinary($bin);
        }
        if (!is_file($this->certPath)) {
            throw new InvalidArgumentException('Brak pliku certyfikatu: ' . $this->certPath);
        }
        if (!is_file($this->keyPath)) {
            throw new InvalidArgumentException('Brak pliku klucza: ' . $this->keyPath);
        }
    }

    private function absoluteUrl(string $path): string
    {
        if (str_starts_with($path, 'http://') || str_starts_with($path, 'https://')) {
            return $path;
        }
        return $this->baseUrl . '/' . ltrim($path, '/');
    }

    private function xml(string $s): string
    {
        return htmlspecialchars($s, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }

    private function assertBinary(string $bin): void
    {
        $this->run(['bash','-lc', "command -v " . escapeshellarg($bin)], $ret);
        if ($ret !== 0) {
            throw new RuntimeException("Brak programu w PATH: {$bin}");
        }
    }

    private function run(array $cmd, ?int &$exitCode = null): string
    {
        $desc = [1 => ['pipe','w'], 2 => ['pipe','w']];
        $p = proc_open($cmd, $desc, $pipes);
        if (!\is_resource($p)) {
            throw new RuntimeException('Nie udało się uruchomić procesu: ' . implode(' ', $cmd));
        }
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        foreach ($pipes as $h) {
            if (\is_resource($h)) {
                fclose($h);
            }
        }
        $exitCode = proc_close($p);
        return trim(($out ?? '') . ($err ? ("\n".$err) : ''));
    }

    /**
     * Zwraca katalog tymczasowy, gwarantując, że jest zapisywalny.
     * Najpierw próbuje sys_get_temp_dir(), jeśli nie – używa __DIR__.'/tmp'.
     */
    private function getTmpDir(): string
    {
        $dir = sys_get_temp_dir();
        if (is_dir($dir) && is_writable($dir)) {
            return rtrim($dir, DIRECTORY_SEPARATOR);
        }

        $fallback = __DIR__ . DIRECTORY_SEPARATOR . 'tmp';
        if (!is_dir($fallback)) {
            if (!mkdir($fallback, 0770, true) && !is_dir($fallback)) {
                throw new RuntimeException('Nie mogę utworzyć katalogu tymczasowego: ' . $fallback);
            }
        }
        if (!is_writable($fallback)) {
            throw new RuntimeException('Katalog tymczasowy nie jest zapisywalny: ' . $fallback);
        }

        return rtrim($fallback, DIRECTORY_SEPARATOR);
    }

    private function detectSignatureMethod(): string
    {
        $out = $this->run(['bash','-lc', 'openssl x509 -in ' . escapeshellarg($this->certPath) . ' -noout -text | grep -Eo "Public Key Algorithm: .*" | sed "s/^ Public Key Algorithm: //; s/^Public Key Algorithm: //"'], $ret);
        $alg = trim($out);
        if (stripos($alg, 'id-ecPublicKey') !== false || stripos($alg, 'EC') !== false) {
            return 'ecdsa-sha256';
        }
        return 'rsa-sha256';
    }

    private function getCertSha256DigestBase64(): string
    {
        $out = $this->run(['bash','-lc', 'openssl x509 -in ' . escapeshellarg($this->certPath) . ' -outform der | openssl dgst -sha256 -binary | base64 -w0'], $ret);
        if ($ret !== 0 || $out === '') {
            throw new RuntimeException('Nie udało się policzyć digestu SHA256 certyfikatu.');
        }
        return trim($out);
    }

    private function getIssuerDnString(): string
    {
        $out = $this->run(['bash','-lc', 'openssl x509 -in ' . escapeshellarg($this->certPath) . ' -noout -issuer | sed "s/^issuer=//"'], $ret);
        if ($ret !== 0 || $out === '') {
            throw new RuntimeException('Nie udało się odczytać issuer DN z certyfikatu.');
        }
        return trim($out);
    }

    private function getSerialAsDecimal(): string
    {
        $hex = strtoupper(trim($this->run(['bash','-lc', 'openssl x509 -in ' . escapeshellarg($this->certPath) . ' -noout -serial | sed "s/^serial=//; s/://g"'], $ret)));
        if ($ret !== 0 || $hex === '') {
            throw new RuntimeException('Nie udało się odczytać numeru seryjnego z certyfikatu.');
        }
        return $this->hexToDecBig($hex);
    }

    private function getCertBodyBase64(): string
    {
        $pem = file_get_contents($this->certPath);
        if ($pem === false) {
            throw new RuntimeException('Nie mogę wczytać certyfikatu.');
        }
        if (preg_match('~-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----~s', $pem, $m)) {
            return trim($m[1]);
        }
        return chunk_split(base64_encode($pem), 64, "\n");
    }

    private function hexToDecBig(string $hex): string
    {
        $hex = ltrim($hex, "0");
        if ($hex === '') {
            return '0';
        }
        $dec = '0';
        for ($i=0,$len=strlen($hex); $i<$len; $i++) {
            $digit = hexdec($hex[$i]);
            $dec = $this->strMul($dec, 16);
            $dec = $this->strAdd($dec, (string)$digit);
        }
        return $dec;
    }
    private function strAdd(string $a, string $b): string
    {
        $a=strrev($a);
        $b=strrev($b);
        $carry=0;
        $out='';
        $len=max(strlen($a), strlen($b));
        for ($i=0; $i<$len; $i++) {
            $da=$i<strlen($a)?(int)$a[$i]:0;
            $db=$i<strlen($b)?(int)$b[$i]:0;
            $s=$da+$db+$carry;
            $out.=(string)($s%10);
            $carry=intdiv($s, 10);
        }
        if ($carry) {
            $out.=(string)$carry;
        }
        return strrev($out);
    }
    private function strMul(string $a, int $m): string
    {
        $a=strrev($a);
        $carry=0;
        $out='';
        for ($i=0; $i<strlen($a); $i++) {
            $da=(int)$a[$i];
            $p=$da*$m+$carry;
            $out.=(string)($p%10);
            $carry=intdiv($p, 10);
        }
        while ($carry>0) {
            $out.=(string)($carry%10);
            $carry=intdiv($carry, 10);
        }
        $res=strrev($out);
        return ltrim($res, '0')==='' ? '0' : ltrim($res, '0');
    }

    private function applyCommonCurl($ch, array $headers, string $method = 'GET', int $timeout = 30): void
    {
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => $timeout,
        ]);
        if ($this->httpDebug) {
            curl_setopt($ch, CURLINFO_HEADER_OUT, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
        }
    }
    
        /**
     * Tworzy tymczasowy plik, próbuje najpierw w sys_get_temp_dir(),
     * potem w __DIR__/tmp. Zwraca pełną ścieżkę.
     */
    private function createTempFile(string $prefix): string
    {
        // 1) systemowy katalog tymczasowy
        $dir = sys_get_temp_dir();
        if (is_dir($dir) && is_writable($dir)) {
            $path = @tempnam($dir, $prefix);
            if ($path !== false) {
                return $path;
            }
        }

        // 2) fallback: ./tmp obok pliku klasy
        $fallback = __DIR__ . DIRECTORY_SEPARATOR . 'tmp';
        if (!is_dir($fallback)) {
            @mkdir($fallback, 0770, true);
        }
        if (!is_dir($fallback) || !is_writable($fallback)) {
            throw new RuntimeException('Brak zapisywalnego katalogu tymczasowego (sys_get_temp_dir ani ' . $fallback . ').');
        }

        $path = @tempnam($fallback, $prefix);
        if ($path === false) {
            throw new RuntimeException('tempnam() nie udało się ani w sys_get_temp_dir(), ani w ' . $fallback);
        }

        return $path;
    }
    

    /**
     * Zamknięcie sesji interaktywnej i start generowania zbiorczego UPO.
     * Endpoint: POST /api/v2/sessions/online/{referenceNumber}/close
     *
     * Sukces: 204 (No Content)
     * Błąd  : 400 (JSON z "Exception"…) -> rzuca RuntimeException z opisem.
     *
     * @return true Zwraca true przy 204.
     * @throws RuntimeException przy kodach >= 400 lub problemach transportowych.
     */
    public function closeInteractiveSession(string $accessToken, string $sessionReferenceNumber): bool
    {
        $url = $this->absoluteUrl('/api/v2/sessions/online/' . rawurlencode($sessionReferenceNumber) . '/close');

        $ch = curl_init($url);
        $headers = [
            'Authorization: Bearer ' . $accessToken,
            'Accept: application/json',
        ];
        $this->applyCommonCurl($ch, $headers, 'POST', 30);

        $raw  = curl_exec($ch);
        $info = curl_getinfo($ch);
        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error przy zamykaniu sesji: ' . $err);
        }
        $code = (int)($info['http_code'] ?? 0);
        curl_close($ch);

        if ($code === 204) {
            return true;
        }

        if ($code === 400) {
            $err = json_decode($raw, true);
            if (is_array($err) && isset($err['Exception'])) {
                $msg = $this->formatKsefException($err['Exception']);
                throw new RuntimeException("KSeF 400 (close session): {$msg}");
            }
            throw new RuntimeException("KSeF 400 (close session): " . $raw);
        }

        if ($raw === '' || $raw === null) {
            throw new RuntimeException("Błąd HTTP {$code} przy zamykaniu sesji (pusta odpowiedź).");
        }
        $maybe = json_decode($raw, true);
        if (is_array($maybe) && isset($maybe['Exception'])) {
            $msg = $this->formatKsefException($maybe['Exception']);
            throw new RuntimeException("Błąd HTTP {$code} (close session): {$msg}");
        }
        throw new RuntimeException("Błąd HTTP {$code} (close session): " . $raw);
    }

    /**
     * Pobranie statusu faktury z sesji interaktywnej.
     *
     * Endpoint:
     *   GET /api/v2/sessions/{referenceNumber}/invoices/{invoiceReferenceNumber}
     *
     * @throws RuntimeException
     */
    public function getInvoiceStatusFromSession(
        string $accessToken,
        string $sessionReference,
        string $invoiceReference
    ): array {
        $url = $this->absoluteUrl(
            '/api/v2/sessions/' . rawurlencode($sessionReference)
            . '/invoices/' . rawurlencode($invoiceReference)
        );

        $ch = curl_init($url);

        $headers = [
            'Authorization: Bearer ' . $accessToken,
            'Accept: application/json',
        ];

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 30,
        ]);

        $raw = curl_exec($ch);
        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error przy pobieraniu statusu faktury: ' . $err);
        }

        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code === 200) {
            $decoded = json_decode($raw, true);
            if (!is_array($decoded)) {
                throw new RuntimeException('Niepoprawny JSON (200) przy pobieraniu statusu faktury: ' . $raw);
            }
            return $decoded;
        }

        if ($code === 400) {
            $err = json_decode($raw, true);
            if (is_array($err) && isset($err['Exception'])) {
                $msg = $this->formatKsefException($err['Exception']);
                throw new RuntimeException("KSeF 400 (status faktury): {$msg}");
            }
            throw new RuntimeException("KSeF 400 (status faktury): " . $raw);
        }

        $maybe = json_decode($raw, true);
        if (is_array($maybe) && isset($maybe['Exception'])) {
            $msg = $this->formatKsefException($maybe['Exception']);
            throw new RuntimeException("Błąd HTTP {$code} (status faktury): {$msg}");
        }

        if ($raw === '' || $raw === null) {
            throw new RuntimeException("Błąd HTTP {$code} przy pobieraniu statusu faktury (pusta odpowiedź).");
        }

        throw new RuntimeException("Błąd HTTP {$code} (status faktury): " . $raw);
    }

    /**
     * Pobranie UPO faktury z sesji na podstawie numeru KSeF.
     *
     * Endpoint:
     *   GET /api/v2/sessions/{referenceNumber}/invoices/ksef/{ksefNumber}/upo
     *
     * @throws RuntimeException
     */
    public function getInvoiceUpoFromSession(
        string $accessToken,
        string $sessionReference,
        string $ksefNumber
    ): string {
        $url = $this->absoluteUrl(
            '/api/v2/sessions/' . rawurlencode($sessionReference) .
            '/invoices/ksef/' . rawurlencode($ksefNumber) .
            '/upo'
        );

        $ch = curl_init($url);
        $headers = [
            'Authorization: Bearer ' . $accessToken,
            'Accept: application/xml',
        ];

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 30,
        ]);

        $raw = curl_exec($ch);
        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('cURL error przy pobieraniu UPO: ' . $err);
        }

        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code === 200) {
            return $raw;
        }

        if ($code === 400) {
            $err = json_decode($raw, true);
            if (is_array($err) && (isset($err['Exception']) || isset($err['exception']))) {
                $exNode = $err['Exception'] ?? $err['exception'];
                if (is_array($exNode)) {
                    $msg = $this->formatKsefException($exNode);
                    throw new RuntimeException("KSeF 400 (UPO): {$msg}");
                }
            }
            throw new RuntimeException("KSeF 400 (UPO): " . $raw);
        }

        $maybe = json_decode($raw, true);
        if (is_array($maybe) && (isset($maybe['Exception']) || isset($maybe['exception']))) {
            $exNode = $maybe['Exception'] ?? $maybe['exception'];
            if (is_array($exNode)) {
                $msg = $this->formatKsefException($exNode);
                throw new RuntimeException("Błąd HTTP {$code} (UPO): {$msg}");
            }
        }

        if ($raw === '' || $raw === null) {
            throw new RuntimeException("Błąd HTTP {$code} przy pobieraniu UPO (pusta odpowiedź).");
        }

        throw new RuntimeException("Błąd HTTP {$code} (UPO): " . $raw);
    }

    /**
     * Interpretacja statusu faktury z KSeF (pole "status").
     */
    public function describeInvoiceStatus(int $code): array
    {
        $map = [
            100 => [
                'name'        => 'Faktura przyjęta do dalszego przetwarzania',
                'description' => 'Plik został poprawnie przyjęty w systemie i oczekuje na dalsze przetwarzanie.',
                'bootstrap'   => 'info',
            ],
            150 => [
                'name'        => 'Trwa przetwarzanie',
                'description' => 'Faktura jest w trakcie przetwarzania w systemie KSeF.',
                'bootstrap'   => 'info',
            ],
            200 => [
                'name'        => 'Sukces',
                'description' => 'Faktura została poprawnie przetworzona.',
                'bootstrap'   => 'success',
            ],
            405 => [
                'name'        => 'Przetwarzanie anulowane',
                'description' => 'Przetwarzanie faktury zostało anulowane.',
                'bootstrap'   => 'secondary',
            ],
            410 => [
                'name'        => 'Nieprawidłowy zakres uprawnień',
                'description' => 'Użyty token nie ma odpowiedniego zakresu uprawnień (np. brak InvoiceWrite / Introspection / PefInvoiceWrite).',
                'bootstrap'   => 'danger',
            ],
            415 => [
                'name'        => 'Brak możliwości wysyłania faktury z załącznikiem',
                'description' => 'System nie pozwala na wysyłkę faktury z załącznikami w tej konfiguracji.',
                'bootstrap'   => 'warning',
            ],
            430 => [
                'name'        => 'Błąd weryfikacji pliku faktury',
                'description' => 'Plik faktury nie przeszedł weryfikacji (np. struktura / XSD).',
                'bootstrap'   => 'danger',
            ],
            435 => [
                'name'        => 'Błąd odszyfrowania pliku',
                'description' => 'System KSeF nie był w stanie odszyfrować treści faktury.',
                'bootstrap'   => 'danger',
            ],
            440 => [
                'name'        => 'Duplikat faktury',
                'description' => 'Faktura jest duplikatem już poprawnie przesłanego dokumentu.',
                'bootstrap'   => 'warning',
            ],
            450 => [
                'name'        => 'Błąd weryfikacji semantyki dokumentu faktury',
                'description' => 'Weryfikacja semantyczna dokumentu nie powiodła się (np. niespójne dane).',
                'bootstrap'   => 'danger',
            ],
            500 => [
                'name'        => 'Nieznany błąd (500)',
                'description' => 'Nieznany błąd po stronie systemu KSeF.',
                'bootstrap'   => 'danger',
            ],
            550 => [
                'name'        => 'Operacja została anulowana przez system',
                'description' => 'Przetwarzanie zostało przerwane z przyczyn wewnętrznych systemu. Spróbuj ponownie.',
                'bootstrap'   => 'warning',
            ],
        ];

        if (!isset($map[$code])) {
            return [
                'code'        => $code,
                'name'        => "Nieznany status ({$code})",
                'description' => 'Kod statusu nieudokumentowany w lokalnej mapie. Sprawdź status.details w odpowiedzi z KSeF.',
                'detailsHint' => 'Sprawdź pole status.details z odpowiedzi KSeF.',
                'bootstrap'   => 'secondary',
            ];
        }

        $base = $map[$code];
        return [
            'code'        => $code,
            'name'        => $base['name'],
            'description' => $base['description'],
            'detailsHint' => 'Sprawdź pole status.details z odpowiedzi KSeF (jeśli występuje).',
            'bootstrap'   => $base['bootstrap'],
        ];
    }
}
