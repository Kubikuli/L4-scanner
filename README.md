# IPK_proj1

## Obsah
- [Úvod](#úvod)
- [Základní teorie](#základní-teorie)
  - [TCP protokol](#tcp-protokol)
  - [UDP protokol](#udp-protokol)
- [Příklady použití](#příklady-použití)
- [Struktura projektu](#struktura-projektu)
- [Testování](#testování)
- [Bibliografie](#bibliografie)

## Úvod
Řešením projektu je jednoduchý skener síťové vrstvy L4 implementovaný v C++. Umožňuje skenovat vybrané jednotlivé porty vybraného cíle a to pomocí TCP nebo UDP protokolu. Umožňuje skenovat jak cílové adresy typu IPv4 tak i adresy typu IPV6. Jeho výstupem je výpis stavu jednotlivých skenovaných portů.

## Základní teorie

### TCP protokol
Transmission Control Protocol (TCP) je internetový protokol založený na spojení, zajišťuje spolehlivý přenos dat mezi dvěma systémy. Jako spolehlivý se dá označit, protože garantuje přenesení dat do cíle beze ztrát. Každá TCP komunikace musí začít tzv. "3-way handshakem":
1. Klient odešle SYN paket na cílový port.
2. Server odpovídá SYN-ACK paketem, pokud je port otevřen nebo RST packetem pokud není.
3. Klient potvrzuje připojení odesláním ACK paketu.

Při TCP skenování se provedou jen první 2 části. Pošleme SYN paket na cílovou adresu a podle odpovědi rozhodneme, jestli je daný port dostupný nebo ne. Nedokončujeme celý handshake, takže úplné spojení nikdy nevznikne.

Možné odpovědi:
- **SYN-ACK** paket - znamená, že port je otevřený
- **RST** znamená, že port je zavřený
- Pokud nepřijde žádná odpověď, může to znamenat, že port je filtrován firewallem, nebo teoreticky i že se naše původní zpráva nebo odpověď někde po cestě ztratily.

Poté při samotné komunikaci se očekává na každý odeslaný paket odpověď, že přišel a pokud nepřije žádná odpověď nebo negativní odpověď, daný paket se odešle znovu.
Tenhle druh komunikace se využivá například pro webové stránky, přenosy emailů, souborů, apod. 

### UDP protokol
User Datagram Protocol (UDP) je bezspojový internetový protokol, což znamená že zprávy jsou posílány bez předchozího navázání spojení. Oproti TPC nezaručuje přenos dat, ale je o to jednudušší.  
UDP scanning je složitější než TCP, protože otevřený UDP port neposkytuje žádnou odpověď.

Proto při UDP skenování nastane jedna z možností:
- Nepřijde žádná odpověď, což znamená otevřený nebo filtrováný port
- Přijde ICMP zpráva "Port Unreachable", což znamená zavřený port


## Příklady použití
Program slouží k analýze dostupnosti portů na specifikovaných hostech pomocí TCP a UDP protokolu.  
Podporuje IPv4 i IPv6 a umožňuje nastavit rozsahy portů, timeout a zvolit zdrojové síťové rozhraní.  
Pro správné fungování musí být program spuštěn s právy správce (s příkazem 'sudo').

**Syntaxe spuštění:**
```sh
./ipk-l4-scan {--help | -h} [-i interface | --interface interface] [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] {-w timeout | --wait timeout} [hostname | ip-address]
```
kde:
- **--help** zobrazí nápovědu a informací o použití

- **--interface** specifikuje, které rozhraní chceme použít jako výchozí při skenování  
Pokud není specifikované konkrétní rozhraní nebo není vůbec specifikovaný tento parametr, tak vypíše list dostupných rozhraní.

- **--pu** specifikuje, které porty chceme skenovat pomocí UDP

- **--pt** specifikuje, které porty chceme skenovat pomocí TPC  
Umožnuje specifikování --pt i --pu zároveň i jen jednoho z nich  
Umožňuje zvolit jakékoliv platné porty v rozsahu 0-65535

- **--wait** čas v milisekundách, specifikuje, jak maximálně dlouho se má čekat na odpověď skenování jednoho portu

- **hostname/ip-address** adresa skenovaného zařízení, můžu být typu IPv4 i IPv6 

**Příklady použití:**
```sh
./ipk_l4-scan -i
```

```sh
./ipk_l4-scan -i eth0 -t 20-80 -u 22,80 -w 5000 scanme.nmap.org
```

```sh
./ipk_l4-scan -i lo -t 21345 -u 11223 localhost -w 4000
```


## Struktura projektu
Základní struktura se skládá ze 3 částí: zpracování argumentů příkazové řádky, skenování zvolených TCP portů a skenování zvolených UDP portů.
Skládá se ze dvou hlavních tříd, představujích konkrétní TCP a UDP skenery, jejich metod a pár pomocných funkcí.

1. **Zpracování argumentů příkazové řádky**  
Pro zpracování argumentů je využita knihovna 'argparser', pomocí které se zpracují argumenty a získají potřebné hodnoty.

2. **TCP skenování**  
Provádí se paralelně pomocí vláken a to zavoláním metody 'scanV4' nebo 'scanV6' (podle typu adresy cíle) pro vytvořený objekt ze třídy TCPScanner, pro každé vlákno s jiným přidělených číslem paketu. Ten vytvoří 'raw' soket pro odeslání ručně vytvořeného paketu. Poté proběhne nastavení soketu, vytvoření IP hlavičky a TCP hlavičky paketu. Poté se vytvoří pseudo-hlavička, která se využije k vypočítání kontrolního součtu a paket se odešle na zvolenou cílovou adresu a port. Odpovědi se zachytávají pomocí funkcí s knihovny 'libpcap'. Kdy se otevře kanál pro zachytávání komunikace pomocí 'pcap_open_live()', nastaví se filtr na zachytávané pakety a podle výsledku se vypíše na standardní výstup stav portu.

3. **UDP skenování**  
Podobně jako u TCP skenování se UDP skenování provádí paralelně pomocí vláken a to zavoláním metody 'scanV4' nebo 'scanV6' pro vytvořený objekt ze třídy UDPScanner, pro každé vlákno s jiným přidělených číslem paketu. Každé vlákno poté vytvoří soket, z kterého odešle paket na cílovou adresu a zvolený port. Poté pomocí funkce 'epoll' zachytává odpověď a podle výsledku vytiskne stav portu.


## Testování
Testování bylo provedeno na poskytnutém virtuálním stroji hostovaném ve VirtualBoxu.  
Pro testování byly použity následující nástroje, uvedené včetně jejich použité verze:
- **Wireshark** (verze 4.4.3.) - především pro analýzu, testování a kontrolu během vývoje programu
- **Netcat** (verze 1.226) - pro vytvoření otevřených portů
- **Nmap** (verze 7.94SV) - pro porovnání výsledků s výstupem mého programu

**Test TCP skenu IPv4 adresy:**
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
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-17 11:54 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000055s latency).

PORT      STATE SERVICE
11111/tcp open  vce

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
```

**Příklad testu lokálního hostitele:**
```sh
sudo nc -lu -p 11111  # Otevřený UDP port
./ipk-l4-scan -i lo -u 11111 localhost
```

## Bibliografie
- Transmission Control Protocol, 2024. Wikipedia. Online. Available from: https://en.wikipedia.org/wiki/Transmission_Control_Protocol [Accessed 17 March 2025].
- User Datagram Protocol, 2024. Wikipedia. Online. Available from: https://en.wikipedia.org/wiki/User_Datagram_Protocol [Accessed 17 March 2025].
- RFC 793: Transmission Control Protocol, 1981. Online. Request for Comments. Internet Engineering Task Force. [Accessed 17 March 2025].
- RFC 768: User Datagram Protocol, 1980. Online. Request for Comments. Internet Engineering Task Force. [Accessed 17 March 2025].
- Nmap: The Art of Port Scanning. Online. Available from: https://nmap.org/nmap_doc.html#port_unreach [Accessed 17 March 2025].
- Port scanner, 2024. Wikipedia. Online. Available from: https://en.wikipedia.org/w/index.php?title=Port_scanner&oldid=1225200572 [Accessed 17 March 2025].
