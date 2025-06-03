# IPK_proj1

## Obsah
- [Úvod](#úvod)
- [Základní teorie](#základní-teorie)
  - [TCP protokol](#tcp-protokol)
  - [UDP protokol](#udp-protokol)
- [Použití](#použití)
- [Struktura projektu](#struktura-projektu)
- [Testování](#testování)
- [Bibliografie](#bibliografie)

## Úvod
Řešením projektu je jednoduchý skener síťové vrstvy L4 implementovaný v C++. Umožňuje skenovat vybrané jednotlivé porty vybraného cíle a to pomocí TCP nebo UDP protokolu. Umožňuje skenovat jak cílové adresy typu IPv4 tak i adresy typu IPV6. Výstupem programu je výpis stavu jednotlivých skenovaných portů. Řešení je nepřenositelné a funguje pouze pro Linux.

## Základní teorie

### TCP protokol
Transmission Control Protocol (TCP) je internetový protokol založený na spojení, zajišťuje spolehlivý přenos dat mezi dvěma systémy. Jako spolehlivý se dá označit, protože garantuje přenesení dat do cíle beze ztrát. Každá TCP komunikace musí začít tzv. "3-way handshakem":
1. Klient odešle SYN paket na cílový port.
2. Server odpovídá SYN-ACK paketem, pokud je port otevřen nebo RST paketem pokud není.
3. Klient potvrzuje připojení odesláním ACK paketu.

Při TCP skenování se provedou jen první 2 části. Pošleme SYN paket na cílovou adresu a podle odpovědi rozhodneme, jestli je daný port dostupný nebo ne. Nedokončujeme celý handshake, takže úplné spojení nikdy nevznikne.

Možné odpovědi:
- **SYN-ACK** paket - znamená, že port je otevřený
- **RST** paket - znamená, že port je zavřený
- Pokud nepřijde žádná odpověď, může to znamenat, že port je filtrován firewallem, nebo i teoreticky, že se naše původní zpráva nebo odpověď někde po cestě ztratily.

Po navázání spojení, při samotné komunikaci se očekává na každý odeslaný paket odpověď, že přišel nebo nepřišel, a pokud přijde negativní odpověď nebo případně nepřijde žádná odpověď, daný paket se odešle znovu.
Tenhle druh komunikace se využivá například pro webové stránky, přenosy emailů, souborů, apod. 

### UDP protokol
User Datagram Protocol (UDP) je bezspojový internetový protokol, což znamená, že zprávy jsou posílány bez předchozího navázání spojení. Oproti TCP nezaručuje přenos dat, ale je jednodušší.  
UDP skenování je složitější než TCP, protože otevřený UDP port neposkytuje žádnou odpověď.

Proto při UDP skenování nastane jedna z možností:
- Nepřijde žádná odpověď, což znamená otevřený nebo filtrováný port
- Přijde ICMP zpráva "Port Unreachable", což znamená zavřený port

Tento protokol se využívá například u streamování nebo u online her.

## Použití
Program slouží k analýze dostupnosti portů na specifikovaných hostech pomocí TCP a UDP protokolu.  
Podporuje IPv4 i IPv6 a umožňuje nastavit rozsahy portů, timeout a zvolit zdrojové síťové rozhraní.  
Pro správné fungování musí být program spuštěn s právy správce (Linux s příkazem 'sudo') a samozřejmě zařízení, na kterém je spuštěn, musí být připojeno k internetu.

**Syntaxe spuštění:**
```sh
./ipk-l4-scan {--help | -h} [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout | --wait timeout} [hostname | ip-address]
```
kde:
- **--help** zobrazí nápovědu a informace o používání

- **--interface** specifikuje, které rozhraní chceme použít jako výchozí při skenování  
Pokud není specifikováno konkrétní rozhraní nebo není vůbec specifikovaný tento parametr, tak vypíše list dostupných rozhraní.

- **--pu** specifikuje, které porty chceme skenovat pomocí UDP

- **--pt** specifikuje, které porty chceme skenovat pomocí TCP  
Umožnuje specifikování --pt i --pu zároveň i jen jednoho z nich.  
Umožňuje zvolit jakékoliv platné porty v rozsahu 0-65535.

- **--wait** čas v milisekundách, specifikuje, jak maximálně dlouho se má čekat na odpověď skenování jednoho portu

- **hostname/ip-address** adresa skenovaného zařízení, může být typu IPv4 i IPv6  
Při poskytnutí 'hostname' se provede DNS dotaz a poté skenování na všechny odpovídjící IP adresy

**Příklady použití:**
```sh
./ipk_l4-scan -i
```
Vypíše seznam dostupných rozhraní

```sh
./ipk_l4-scan -i eth0 -t 20-80 -u 22,80 -w 5000 scanme.nmap.org
```
Spustí TCP sken na porty 20-80 a UDP sken na porty 22 a 80 na hostu scanme.nmap.org.

```sh
./ipk_l4-scan -i lo -t 21345 -u 11223 localhost -w 4000
```
Spustí TCP sken portu 21345 a UDP sken portu 11223 na lokální síti.

## Struktura projektu
Základní struktura se skládá ze 3 částí: zpracování argumentů příkazové řádky, skenování zvolených TCP portů a skenování zvolených UDP portů.
Skládá se ze dvou hlavních tříd, představující TCP a UDP skenery, jejich metod a pár pomocných funkcí v modulu utils.cpp a scanner-utils.cpp.

1. **Zpracování argumentů příkazové řádky**  
Pro zpracování argumentů je využita knihovna 'argparser', pomocí které se zpracují argumenty a získají potřebné hodnoty.

2. **TCP skenování**  
Provádí se paralelně pomocí vláken a to zavoláním metody 'scanV4' nebo 'scanV6' (podle typu adresy cíle) pro vytvořený objekt ze třídy TCPScanner, pro každé vlákno s jiným přiděleným číslem paketu. Ten vytvoří 'raw' soket pro odeslání ručně vytvořeného paketu. Poté proběhne nastavení soketu, vytvoření IP hlavičky a TCP hlavičky paketu. Následuje vytvoření pseudo-hlavičky, která se použije k vypočítání kontrolního součtu a paket se odešle na zvolenou cílovou adresu a port. Odpovědi se zachytávají pomocí funkcí s knihovny 'libpcap'. Ještě před odesláním paketu se otevře kanál pro zachytávání komunikace pomocí 'pcap_open_live()', nastaví se filtr na konkrétní pakety, které se snažíme zachytit a podle výsledku se vypíše na standardní výstup stav portu.

3. **UDP skenování**  
Podobně jako u TCP skenování se UDP skenování provádí paralelně pomocí vláken a to zavoláním metody 'scanV4' nebo 'scanV6' pro vytvořený objekt ze třídy UDPScanner, pro každé vlákno s jiným přiděleným číslem paketu. Každé vlákno poté vytvoří soket, z kterého odešle paket na cílovou adresu a zvolený port. Poté pomocí funkce 'epoll' zachytává odpověď a podle výsledku vytiskne stav portu.


## Testování
Testování bylo provedeno na poskytnutém virtuálním stroji hostovaném ve VirtualBoxu.  
Pro testování byly použity následující nástroje, uvedené včetně jejich použité verze:
- **Wireshark** (verze 4.4.3.) - především pro analýzu, testování a kontrolu během vývoje programu
- **Netcat** (verze 1.226) - pro vytvoření otevřených portů
- **Nmap** (verze 7.94SV) - pro porovnání výsledků s výstupem mého programu

**Test TCP skenu pro IPv4 adresy:**  
Pomocí nástroje netcat jsem vytvořil nový otevřený lokální port:
```sh
sudo nc -l -p 11111
```
Spustil můj program pomocí:
```sh
sudo ./ipk-l4-scan -i lo -t 11111 localhost
```
Výstup:
```sh
127.0.0.1 11111 tcp open
```
Podle očekávání vypsal můj program, že je daný port otevřený.  
Ověřil jsem správnost pomocí nástroje Nmap:
``` sh
sudo nmap -sS -p 11111 localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 11:54 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000055s latency).

PORT      STATE SERVICE
11111/tcp open  vce

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```

Sken lokálního portu, který by měl být zavřený pomocí:
```sh
sudo ./ipk-l4-scan -i lo -t 11112 localhost
```
Výstup:
```sh
127.0.0.1 11112 tcp closed
```
Nmap:
``` sh
sudo nmap -sS -p 11112 localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 12:00 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000082s latency).

PORT      STATE  SERVICE
11112/tcp closed dicom

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```
Pro testování veřejné adresy jsem využil scanme.nmap.org, který umožňuje legální testování skenování portů:
```sh
sudo ./ipk-l4-scan -i enp0s3 -t 22,23,75-81  scanme.nmap.org
```
Výstup:
```sh
2600:3c01::f03c:91ff:fe18:bb2f 75 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 22 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 77 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 76 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 78 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 79 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 81 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 23 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 80 tcp closed
45.33.32.156 80 tcp open
45.33.32.156 22 tcp open
45.33.32.156 76 tcp filtered
45.33.32.156 78 tcp filtered
45.33.32.156 77 tcp filtered
45.33.32.156 81 tcp filtered
45.33.32.156 79 tcp filtered
45.33.32.156 23 tcp filtered
45.33.32.156 75 tcp filtered
```
Na výstupu se objevili dvě různé IP adresy, protože DNS dotaz na scanme.nmap.org vrátil jednu IPv4 adresu a jednu IPv6.  
Nmap:
``` sh
sudo nmap -sS -p 22,21,75-81 scanme.nmap.org
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-18 15:34 CET
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.035s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f

PORT   STATE    SERVICE
21/tcp filtered ftp
22/tcp open     ssh
75/tcp filtered priv-dial
76/tcp filtered deos
77/tcp filtered priv-rje
78/tcp filtered vettcp
79/tcp filtered finger
80/tcp open     http
81/tcp filtered hosts2-ns

Nmap done: 1 IP address (1 host up) scanned in 1.57 seconds
```
Stavy portů odpovídají výstupu mého programu. S jediným rozdílem, že nmap neskenoval IPv6 adresu jako můj program, ale na testování IPv6 adres se zaměřuje pozdější část.  

**Test UDP skenu pro IPv4 adresy:**  
Vytvoření nového otevřeného lokální portu (perzistentní, aby se neuzavřel po obdržení prvního paketu):
```sh
while true; do sudo nc -lu -p 12345; done
```
Spuštění:
```sh
sudo ./ipk-l4-scan -i lo -u 11111,11112 localhost
```
Výstup:
```sh
127.0.0.1 11112 udp closed
127.0.0.1 11111 udp open
```
Nmap:
``` sh
sudo nmap -sU -p 11111,11112 localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 12:41 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000025s latency).

PORT      STATE         SERVICE
11111/udp open|filtered vce
11112/udp closed        dicom

Nmap done: 1 IP address (1 host up) scanned in 1.31 seconds
```

Pro testování veřejné adresy jsem využil opět scanme.nmap.org:
```sh
sudo ./ipk-l4-scan -i enp0s3 -u 22,23,75-81  scanme.nmap.org
```
Výstup:
```sh
2600:3c01::f03c:91ff:fe18:bb2f 80 udp open
2600:3c01::f03c:91ff:fe18:bb2f 23 udp open
2600:3c01::f03c:91ff:fe18:bb2f 78 udp open
2600:3c01::f03c:91ff:fe18:bb2f 76 udp open
2600:3c01::f03c:91ff:fe18:bb2f 75 udp open
2600:3c01::f03c:91ff:fe18:bb2f 77 udp open
2600:3c01::f03c:91ff:fe18:bb2f 79 udp open
2600:3c01::f03c:91ff:fe18:bb2f 22 udp open
2600:3c01::f03c:91ff:fe18:bb2f 81 udp open
45.33.32.156 23 udp open
45.33.32.156 75 udp open
45.33.32.156 77 udp open
45.33.32.156 76 udp open
45.33.32.156 22 udp open
45.33.32.156 80 udp open
45.33.32.156 79 udp open
45.33.32.156 78 udp open
45.33.32.156 81 udp open
```
Nmap:
``` sh
sudo nmap -sU -p 22,23,75-81 scanme.nmap.org
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-18 15:39 CET
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.0013s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f

PORT   STATE         SERVICE
22/udp open|filtered ssh
23/udp open|filtered telnet
75/udp open|filtered priv-dial
76/udp open|filtered deos
77/udp open|filtered priv-rje
78/udp open|filtered vettcp
79/udp open|filtered finger
80/udp open|filtered http
81/udp open|filtered hosts2-ns

Nmap done: 1 IP address (1 host up) scanned in 1.53 seconds
```
Výstupy programu Nmap odpovídají výstupům mého programu.  
Porty, které byly u TCP testování označené mým skenerem jako filtered jsou u UDP skenu označeny open, protože u UDP se nedá rozlišit mezi otevřeným a vyfiltrovaným portem.  

**Test TCP skenu pro IPv6 adresy:**  
Vytvoření nového otevřeného lokální portu:
```sh
sudo nc -l -p 11111 -6
```
Spuštění:
```sh
sudo ./ipk-l4-scan -i lo -t 11111,11112  ::1
```
Výstup:
```sh
::1 11111 tcp open
::1 11112 tcp closed
```
Nmap:
``` sh
sudo nmap -6 -p 11111,11112 ::1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 12:49 CET
Nmap scan report for ip6-localhost (::1)
Host is up (0.000076s latency).

PORT      STATE  SERVICE
11111/tcp open   vce
11112/tcp closed dicom

Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds
```

Pro testování veřejné adresy jsem využil veřejnou IPv6 adresu Googlu:
```sh
sudo ./ipk-l4-scan -i enp0s3 -t 22,80 ipv6.google.com
```
Výstup:
```sh
2a00:1450:4014:80a::200e 22 tcp closed
2a00:1450:4014:80a::200e 80 tcp closed
```
Nmap:
``` sh
sudo nmap -6 -sS -p 22,80 ipv6.google.com
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 13:06 CET
Nmap scan report for ipv6.google.com (2a00:1450:4014:80a::200e)
Host is up (0.0028s latency).
rDNS record for 2a00:1450:4014:80a::200e: prg03s10-in-x0e.1e100.net

PORT   STATE  SERVICE
22/tcp closed ssh
80/tcp closed http

Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
```
Výstupy programu Nmap odpovídají opět výstupům mého programu.  


**Test UDP skenu pro IPv6 adresy:**  
Vytvoření nového otevřeného lokální portu:
```sh
while true; do sudo nc -lu -p 11111 -6; done
```
Spuštění:
```sh
sudo ./ipk-l4-scan -i lo -u 11111,11112  ::1
```
Výstup:
```sh
::1 11112 udp closed
::1 11111 udp open
```
Nmap:
``` sh
sudo nmap -6 -sU -p 11111,11112 ::1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 12:56 CET
Nmap scan report for ip6-localhost (::1)
Host is up (0.000028s latency).

PORT      STATE         SERVICE
11111/udp open|filtered vce
11112/udp closed        dicom

Nmap done: 1 IP address (1 host up) scanned in 1.35 seconds
```
Pro testování veřejné adresy jsem využil veřejnou IPv6 adresu Googlu:
```sh
sudo ./ipk-l4-scan -i enp0s3 -u 22,80 ipv6.google.com
```
Výstup:
```sh
2a00:1450:4014:80b::200e 22 udp open
2a00:1450:4014:80b::200e 80 udp open
```
Nmap:
``` sh
sudo nmap -6 -sU -p 22,80 ipv6.google.com
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 13:08 CET
Nmap scan report for ipv6.google.com (2a00:1450:4014:80b::200e)
Host is up (0.00019s latency).
rDNS record for 2a00:1450:4014:80b::200e: prg03s11-in-x0e.1e100.net

PORT   STATE    SERVICE
22/udp filtered ssh
80/udp filtered http

Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
```
Výstupy programu Nmap odpovídají výstupům mého programu. Jediný sporný případ můžeme vidět v posledním případě, kdy ale můj program při UDP skenování označuje jak vyfiltrované tak otevřené porty jako 'open', což odpovídá výstupu Nmap.  

Total points: 6.52/10  
(Timeout timer starts before sending packet, so it doesn't reliably work for timeouts <3000ms. Can be easily "fixed" with fix.diff)

## Bibliografie
- Transmission Control Protocol, 2024. Wikipedia. Online. Available from: https://en.wikipedia.org/wiki/Transmission_Control_Protocol [Accessed 22 March 2025].
- User Datagram Protocol, 2024. Wikipedia. Online. Available from: https://en.wikipedia.org/wiki/User_Datagram_Protocol [Accessed 22 March 2025].
- RFC 793: Transmission Control Protocol, 1981. Online. Internet Engineering Task Force. Available from: https://datatracker.ietf.org/doc/html/rfc793 [Accessed 22 March 2025].
- RFC 768: User Datagram Protocol, 1980. Online. Internet Engineering Task Force. Available from: https://datatracker.ietf.org/doc/html/rfc768 [Accessed 22 March 2025].
- Nmap: The Art of Port Scanning. Online. Available from: https://nmap.org/nmap_doc.html#port_unreach [Accessed 22 March 2025].
- Port scanner, 2024. Wikipedia. Online. Available from: https://en.wikipedia.org/w/index.php?title=Port_scanner&oldid=1225200572 [Accessed 22 March 2025].
- RFC 1071: Computing the internet checksum, 1988. Online. Internet Engineering Task Force. Available from: https://datatracker.ietf.org/doc/html/rfc1071 [Accessed 22 March 2025].
