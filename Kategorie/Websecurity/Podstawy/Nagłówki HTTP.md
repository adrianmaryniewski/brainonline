# Nagłówki HTTP

>Luźne notatki z książki "Bezpieczeństwo Aplikacji Webowych (Praca zbiorowa pod redakcją Michała Sajdaka)"

## Nagłówki HTTP w kontekście bezpieczeństwa

W tym rozdziale poznamy interesujące nagłówki HTTP, które mogą pomóc w zwiększeniu bezpieczeństwa aplikacji. Dowiedzieliśmy się również, jak napastnicy mogą próbować je obejść. Nagłówki definiowane są poprzez podanie nazwy i wartości oddzielone znakiem dwukropka. Istnieje wiele różnych nagłówków, których zastosowanie zależy od kreatywności twórcy aplikacji. Najpopularniejsze z nich to te odpowiadające za uwierzytelnianie, pamięć tymczasową, bezpieczeństwo, kodowanie, zakres, pobieranie zasobów, przekierowania, akcje po stronie serwera, WebSockety i zarządzanie połączeniem.

- HTTP Strict Transport Security (HSTS) 
- Content-Security-Policy 
- X-Frame-Options 
- X-Content-Type-Options 
- Referrer-Policy 
- Feature-Policy 
- Access-Control-Allow-Origin 

to najpopularniejsze nagłówki związane z bezpieczeństwem. Autorzy aplikacji i właściciele serwerów mogą dodawać własne, dowolne nagłówki, co oznacza, że ich liczba jest potencjalnie nieograniczona. Należy pamiętać, że nagłówki są bardzo wartościowym źródłem informacji o wykorzystywanych technologiach, oprogramowaniu i elementach konfiguracji. Aby sprawdzić aktualne nagłówki dla konkretnej strony, można skorzystać z narzędzia Developer Tools dostępnego w wielu przeglądarkach. Uruchomienie i korzystanie z tego narzędzia jest bardzo proste - wystarczy uruchomić przeglądarkę, wejść na stronę, której nagłówki chcemy zobaczyć i nacisnąć klawisz F12 (cmd shift i na Macu) lub wybrać narzędzie z poziomu menu VIEW › DEVELOPER › DEVELOPER TOOLS.

![konsola-naglowki-1](https://dsc.cloud/f62499/pb-MFjkUT4Imj.png)

Przechodzimy do zakładki NETWORK, tu ponownie należy przeładować stronę (odświeżyć), np. naciskając klawisz F5.

![konsola-naglowki](https://dsc.cloud/f62499/pb-IWBN9qin0z.png)

W tym momencie zobaczymy wiele różnych wywołań i ładowanych zasobów. Wybierzmy to, co nas interesuje - poprzez zaznaczenie danego elementu.

Zakładka HEADERS w narzędziu do weryfikacji nagłówków HTTP jest najbardziej przydatna do celów weryfikacji. Zawiera ona ogólne informacje o 
- zapytaniu, 
- wykorzystywanej metodzie HTTP, 
- kodzie zwrotnym serwera, 
- adresie IP wraz z portem oraz 
- podsumowanie nagłówków, które zostały dołączone do odpowiedzi HTTP. 

Ponadto, narzędzie posiada również zakładki PREVIEW, RESPONSE, COOKIES i TIMING, które prezentują odpowiednio podgląd witryny, pełny kod źródłowy strony, podsumowanie cookies powiązanych z witryną wraz z obecnymi flagami oraz wydajność i szybkość działania strony.




## Wybrane nagłówki HTTP a ich wpływ na bezpieczeństwo
### HTTP Strict-Transport-Security (HSTS)

Następstwem wdrożenia mechanizmu HSTS jest wymuszenie na użytkowniku korzystania z szyfrowanego połączenia HTTPS, co zapewnia bezpieczeństwo danych. Dodatkowo, w przypadku błędu certyfikatu, użytkownik nie ma możliwości ominięcia ostrzeżenia (Click-Through Insecurity). Jednakże mechanizm ten nie chroni użytkownika przy pierwszym dostępie do strony, jeśli ta nie wykorzystuje opcji bycia na liście preload.

Nagłówek HSTS pozwala stronom internetowym na wskazanie przeglądarkom, aby zawsze ładowały je za pośrednictwem protokołu HTTPS. Parametry max-age, includeSubDomains i preload określają, jak długo przeglądarka ma zapamiętać, że strona jest dostępna tylko po HTTPS, czy też czy regula dotyczy również subdomen oraz czy strona ma zostać dodana do listy HSTS Pre-Loaded List. Użycie dyrektywy preload wiąże się z trwałymi konsekwencjami, dlatego jeśli właściciel strony zdecyduje się na zrezygnowanie z HTTPS, może to zrobić za pośrednictwem strony https://hstspreload.org/removal/.

Nagłówek HSTS pozwala stronom internetowym na wskazanie przeglądarkom, aby zawsze ładowały je za pośrednictwem protokołu HTTPS. 

Parametry: 
- max-age, 
- includeSubDomains, 
- preload 

określają, jak długo przeglądarka powinna zapamiętać, że strona jest dostępna tylko po HTTPS, czy też czy regula dotyczy również subdomen oraz czy strona może zostać dodana do listy HSTS Pre-Loaded List. Użycie dyrektywy preload wiąże się z trwałymi konsekwencjami i jeśli właściciel strony zdecyduje się na jej zaniechanie, może to zrobić za pośrednictwem strony https://hstspreload.org/removal/.

Wartości dla poszczególnych dyrektyw możemy przedstawić w prostej tabeli:

| NAZWA DYREKTYWY | OPIS WARTOŚCI | REKOMENDOWANA WARTOŚĆ | TYP DYREKTYWY |
|----------------|---------------|----------------------|---------------|
| max-age        | czas ważności  | 31536000             | WYMAGANA      |
| includeSubDomains | nd.          | nd.                  | OPCJONALNA    |
| preload        | nd.           | nd.                  | OPCJONALNA    |

nd. oznacza, że dana dyrektywa nie wymaga żadnej wartości.

Dyrektywa includeSubDomains jest ważnym elementem zapewniającym ochronę przed wyciekiem ciasteczek. Jeśli nie jest ustawiona, istnieje ryzyko, że atakujący będzie miał dostęp do ciasteczek, nawet jeśli mają one atrybut Secure. Aby zapewnić pełną ochronę, dyrektywa includeSubDomains musi być aktywna. W przeciwnym razie istnieje ryzyko, że ciasteczka będą wystawiane nawet po wyświetleniu ostrzeżenia o nieprawidłowym certyfikacie. Dlatego ważne jest, aby upewnić się, że dyrektywa includeSubDomains jest ustawiona, aby zapewnić pełną ochronę przed wyciekiem ciasteczek.

Przykład nagłówka HSTS z rekomendowanymi wartościami:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Aby zweryfikować aktualne ustawienia lub obecność HSTS dla danej witryny, możemy skorzystać z narzędzia net-internals w przeglądarce Google Chrome, wpisując w pasek adresu chrome://net-internals/#hsts. Aby zapewnić poprawne działanie witryny, należy uniemożliwić działanie po stronie serwera za pośrednictwem HTTP. Gdy użytkownik wejdzie przez nieszyfrowany kanał komunikacji, powinien nastąpić automatyczne przekierowanie do HTTPS bez inicjowania jakiejkolwiek komunikacji HTTP.

![pb-Xnoyj6SRpO.png](https://dsc.cloud/f62499/pb-Xnoyj6SRpO.png)

Strict-Transport-Security (STS) to mechanizm, który pozwala na zwiększenie bezpieczeństwa połączeń HTTPS. Aby go wdrożyć, należy dodać odpowiednie reguły dla popularnych serwerów webowych. 

- W przypadku Apache, należy ustawić nagłówek Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload".

```
<filter>
	<filter-name›httpHeaderSecurity‹/filter-name›
	<filter-class›org.apache.catalina.filters.HttpHeaderSecurityFilter
</filter-class>
	<async-supported>true</async-supported>
	<init-param>
		<param-name›hstsEnabled</param-name›
		<param-value›true</param-value>
	</init-param>
<init-param>
	<param-name>hstsMaxAgeSeconds</param-name>
	<param-value›31536000</param-value>
</init-param>
<init-param>
	<param-name>hstsIncludeSubDomains</param-name›
	<param-value›true‹/param-value>
</init-param>
<init-param>
	<param-name›hstsPreload‹/param-name>
	<param-value›true‹/param-value>
</init-param>
</filter>
```

- W przypadku Nginx, należy dodać nagłówek add header Strict -Transport-Security "max-age=31536000; includeSub-Domains; preload" always. 
- W przypadku IIS:

```
‹?xmi version="1.0" encoding="UTF-8"?>
‹configuration>
	<system.webServer›
		‹httpProtocol>
			‹customHeaders>
				‹add name="Strict-Transport-Security",
value=" max-age=31536000; includeSubDomains; preload" />
			</customHeaders>
		</httpProtocol>
	</ system.webServer›
</configuration>
```



### Referrer-Policy

Określa, jakie informacje lub ich części powinny być wysyłane w nagłówku Referer w zapytaniu dotyczącym adresu, z którego nastąpiło przekierowanie. Nagłówek Referer może być przyczyną wycieku istotnych informacji, gdy użytkownik przechodzi na zewnętrzną stronę. Przykładowy scenariusz pokazuje, jak może to wyglądać w praktyce. Użytkownik znajduje się na wewnętrznym portalu firmy, gdzie znajdują się informacje o klientach i projektach. Gdy kliknie na link do konkurencyjnej firmy, wycieknie informacja o adresie, z którego został przekierowany. Referrer-Policy określa, jakie informacje powinny być wysyłane w nagłówku Referer, aby zapobiec wyciekom danych.

Zobaczmy na początek przykładowe żądanie HTTP z zaznaczonym nagłówkiem Referer:

```
GET /manager HTTP/1.1
Host: internal.sekurak.pl
Referer: http://sekurak.pl/teksty/
```

Nagłówek Referer jest często wykorzystywany do wielu celów, takich jak analiza i statystyki, aby zobaczyć, skąd pochodzą użytkownicy, lub jako dodatkowa forma ochrony przed atakami Cross-Site Request Forgery (CSRF). Istnieją różne parametry dostępne dla nagłówka Referrer-Policy, takie jak 'no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin', 'strict-origin' i 'strict-origin-when-cross-origin'. Każdy z nich ma swoje własne zastosowanie i zalety.

a. no-referrer-when-downgrade -  jest domyślnym ustawieniem, jeśli polityka nie zostanie zdefiniowana. Oznacza to, że adres strony, z której użytkownik zostanie przekierowany, będzie przesłany tylko wtedy, gdy będzie taki sam typ protokołu.

b. no-referrer - oznacza, że nagłówek Referer nie będzie wysyłany.

c. origin - oznacza wysyłanie tylko wartości origin, czyli adresu strony bez dokładnej ścieżki (np. tylko adres https://sekurak.pl).

d. origin-when-cross-origin - oznacza wysyłanie pełnej ścieżki (https://sekurak.pl/teksty/) w przypadku tego samego originu, a w innych przypadkach tylko wartości origin (https://sekurak.pl).

e. same-origin -  oznacza wysyłanie pełnej ścieżki w przypadku tego samego originu, a w innych przypadkach żadnych danych nie będzie przekazywanych w nagłówku Referer.

f. strict-origin - oznacza wysyłanie tylko wartości origin w przypadku komunikacji tym samym protokołem, a w przypadku przejścia do mniej bezpiecznej komunikacji nie będzie wysyłanego nagłówka.

g. strict-origin-when-cross-origin - oznacza wysyłanie pełnej ścieżki w nagłówku Referer tylko w zapytaniach wychodzących do tego samego originu, a w pozostałych przypadkach zachowanie jest takie samo jak dla wartości strict-origin.

h. unsafe-url - jest ustawieniem polityki, które pozwala na wyświetlenie pełnej wartości adresu strony, z którego został przekierowany użytkownik, gdy zapytanie następuje z dowolnych typów protokołów. To ustawienie może spowodować ujawnienie wartości Referer w momencie przejścia do mniej bezpiecznej komunikacji (HTTPS -> HTTP).


### X-Content-Type-Options

Informuje przeglądarkę, aby nie próbowała interpretować określonych zasobów jako inny typ niż ten zadeklarowany w nagłówku Content-Type. Brak tego nagłówka może spowodować, że przeglądarka będzie próbowała samodzielnie określić format danego pliku, co może prowadzić do nieoczekiwanych i potencjalnie niebezpiecznych skutków. Przykładem może być sytuacja, w której możliwe jest wysłanie pliku na serwer, ale po jego wysłaniu rozszerzenie jest usuwane z nazwy pliku. Dodanie kodu HTML może spowodować, że przeglądarka samodzielnie ustali format pliku, co może umożliwić wykonanie ataku XSS.

Jego rekomendowana wartość to "nosniff", która oznacza, że przeglądarka powinna interpretować pliki zgodnie z wartością nagłówka Content-Type. Użycie tego nagłówka może pomóc w zapobieganiu atakom typu MIME-sniffing, które mogą być wykorzystywane do wykonania ataków typu cross-site scripting. Użycie tego nagłówka może pomóc w zapewnieniu bezpieczeństwa witryny i chronić użytkowników przed potencjalnymi atakami.


### Feature-Policy

Nagłówek bezpieczeństwa feature-policy pozwala na kontrolowanie dostępu do funkcji przeglądarki, takich jak np. wybieranie lokalizacji, wykorzystywanie mikrofonu, wyświetlanie powiadomień itp. Umożliwia to ograniczenie dostępu do tych funkcji do określonych witryn, co zwiększa bezpieczeństwo i prywatność użytkowników.


### X-Frame-Options

Nagłówek X-Frame-Options pozwala na określenie, czy możliwe jest wczytanie strony w ramce. Jego wdrożenie zwiększa ochronę przed atakami typu Clickjacking. Do dyspozycji są trzy parametry:

- deny, 
- sameorigin, 
- allow-from URI. 

Przykładem nagłówka X-Frame-Options z rekomendowanymi wartościami jest X-Frame-Options: SAMEORIGIN. Obecnie coraz częściej w celu ograniczenia wczytywania strony w ramce wykorzystywany jest nagłówek Content-Security-Policy z dyrektywą frame-ancestors, co oznacza, że X-Frame-Options zostanie prawdopodobnie przez niego zastąpiony.


W celu zabezpieczenia dostępu do danych zasobów, wykorzystywana jest prosta weryfikacja adresu IP. Implementacja tej filtracji odbywa się poprzez sprawdzenie wartości różnych nagłówków, takich jak X-Forwarded-For, X-Forwarded-Host, X-Forwarded-IP, X-Remote-IP, X-Remote-Addr, X-Real-IP, Client-IP, X-Client-IP, X-InternalIP, x-Originating-IP, X-Originated-IP, X-Backend, X-Backend-Name, X-Backend-Host, X-Backend-Addr, X-Backend-IP, X-Backend-Server. Aby podjąć próbę ominięcia nakładonych filtrów, wystarczy wysłać proste zapytanie do danej lokalizacji z dodaniem jednego lub kilku z wyżej wymienionych nagłówków.

```
GET /manager HTTP/1.1
Host: internal.sekurak.pl
X-Forwarded-For: 127.0.0.1
```

Omijanie zabezpieczeñ z wykorzystaniem nagłówków HTTP to technika, która pozwala na podszycie się pod inny adres IP lub URL, wykonanie ataku Open Redirect, odkrycie typów serwerów, ominięcie CAPTCHY, uruchomienie trybu deweloperskiego oraz zatruwanie logów dostępowych. Jest to szczególnie niebezpieczne, ponieważ pozwala na ominięcie ograniczeń nakładanych w kontekście dostępu z konkretnego adresu IP, a także wysłanie ofierze ataku e-mail z podmienionym linkiem.

---

