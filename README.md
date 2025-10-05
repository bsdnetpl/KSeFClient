Status projektu / Project Status
🇵🇱 Polska wersja

Obecnie prace nad klasą KSeFClient są wstrzymane do czasu wprowadzenia przez Ministerstwo Finansów nowych certyfikatów autoryzacyjnych KSeF.
Integracja zostanie wznowiona, gdy system zacznie obsługiwać nowy mechanizm uwierzytelniania oparty na certyfikatach.

🔐 Charakterystyka nowych certyfikatów KSeF

Nowe certyfikaty KSeF będą pełnić wyłącznie funkcję uwierzytelniającą.
Ich zadaniem będzie jedynie potwierdzenie tożsamości użytkownika lub systemu łączącego się z KSeF.
Nie będą zawierały informacji o uprawnieniach, dzięki czemu ich przypisanie będzie możliwe bezpośrednio w systemie.

To rozwiązanie zwiększa bezpieczeństwo, ponieważ:

certyfikaty będą oparte na kryptografii asymetrycznej,

utrudni to ich nieautoryzowane użycie,

nowy model uwierzytelniania umożliwi pracę w trybie offline („offline24”).

📚 Więcej informacji:
👉 Nowe zasady uwierzytelniania w KSeF – certyfikaty zastąpią tokeny
W listopadzie: MCU i testowanie Aplikacji Podatnika

Od 1 listopada 2025 r. zostanie uruchomiony Moduł Certyfikatów i Uprawnień (MCU), który umożliwi nadawanie uprawnień użytkownikom systemu.
Uprawnienia te będą niezbędne do korzystania z Krajowego Systemu e-Faktur od 1 lutego 2026 r.
Moduł pozwoli również na składanie wniosków o certyfikaty oraz ich pobieranie.

Od 3 listopada 2025 r. użytkownicy będą mogli rozpocząć testowanie Aplikacji Podatnika KSeF 2.0 w środowisku testowym.
Następnie, 15 listopada 2025 r., Ministerstwo Finansów udostępni aplikację w środowisku przedprodukcyjnym.

EN:-------------------------------------------------------------------------------------------------------------------------------------------------------
Currently, the development of the KSeFClient class is on hold until the Polish Ministry of Finance introduces new KSeF authorization certificates.
The integration will be resumed once the system supports the new authentication mechanism based on certificates.

🔐 Characteristics of the new KSeF certificates

The new KSeF certificates will serve authentication purposes only.
Their main role will be to confirm the identity of the user or system connecting to KSeF.
They will not contain authorization data, which will now be assigned directly within the KSeF system.

This approach improves security because:

certificates are based on asymmetric cryptography,

unauthorized use becomes much more difficult,

the new authentication model will allow operation in offline mode (“offline24”).

📚 Learn more (Polish source):
👉 New KSeF authentication rules – certificates will replace tokens
In November: MCU and Taxpayer Application testing

Starting from November 1, 2025, the Module of Certificates and Authorizations (MCU) will be launched.
It will allow users to assign permissions necessary to use the National e-Invoice System (KSeF) from February 1, 2026.
The module will also enable users to apply for certificates and download them.

From November 3, 2025, users will be able to start testing the Taxpayer Application KSeF 2.0 in the test environment.
Then, on November 15, 2025, the Ministry of Finance will release the application in the pre-production environment.
