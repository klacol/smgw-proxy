# Reverse Proxy für ein Smart Meter Gateway

Der Einbau eines Smart Meter Gateways (z.B. ein Theben Conexa) erfolgt durch den Messstellenbetreiber. Das SMGW hat einen Ethernet-Port, den man mit dem häuslichen LAN verbinden kann. In der Sprache der Energiewirtschaft ist das der HAN-Port (HAN = Home Area Network).

Dabei hat der Endkunde keinen Einfluss auf die Vergabe der IP-Adresse für den HAN-Port. Derzeit scheint es auch die Praxis zu geben, dass viele Messstellenbetreiber die SMGW mit einer festen IP-Adresse in einem beliebigen Subnetz ausliefern. Diese IP-Adresse wird nicht mit dem Haus- oder Wohnungseigentümer abgestimmt. Auch die Nutzung des DHCP-Protokolls zur dynamischen IP-Adressvergabe ist leider kein Standard in der Energiewirtschaft.

Das bedeutet, dass man sich als Haus- oder Wohnungseigentümer Gedanken machen muss, wie man den HAN-Portal erreichen kann. Die Erläuterung der SMGW-Hersteller ist nutzlos, weil sie vorsieht, dass man den eigenen Computer in das Subnetz des HAN-Ports verbinden muss. Damit kann der Computer nicht gleichzeitig für anderen Dienste genutzt werden. Zudem kann man mit dieser Konfiguration das SMGW nicht von einem Heimautomationssystem transparent über TCP erreichen.

Für eine transparente Erreichbarkeit kann man jedoch  ein Zusatzgerät vor das SMGW schalten, wie z.B. einen Raspberry Pi. Das könnte so aussehen:

```mermaid
flowchart TD
    A(SMGW: 10.11.120.2) <-->|LAN| B(10.11.120.1 
    Proxy z.B. auf RPI5
    192.168.0.10)
    B <-->|Wifi| C(Wifi AP)
    C <--> F(192.168.0.11 
    Laptop)
    C <--> D(Switch)
    D <--> E(192.168.0.12
    Home Assistant)
```

## Netzwerkkonfiguration

### wlan0: WLan Netzwerkport des Raspberry Pi

Der Raspberry Pi wird im Heim-Wlan registriert (z.B. über die Fritzbox). Die dynamisch vergebene IP-Adresse wird dann die Adresse, über die das SMGW zukünftig erreicht werden kann. Es wird empfohlen das Gerät in der Fritzbox so zu konfigurieren, dass es immer dynamisch [die gleiche IP-Adresse zugewiesen bekommt](https://fritz.com/service/wissensdatenbank/dok/FRITZ-Box-7590/201_Netzwerkgerat-immer-die-gleiche-IP-Adresse-von-FRITZ-Box-zuweisen-lassen/). Für andere Wlan-Systeme gelten andere Verfahren.


### eth0: LAN-Netzwerkport des Raspberry Pi 

Der LAN-Netzwerkport des Raspberry Pi wird direkt mit einem LAN-Kabel verbunden mit dem HAN-Port des SMGW. Der Port bekomme in Linux einer festen IP-Adresse im selben Subnetz wie das SMGW 

Im Beispiel hier: 
- Das SMGW hat vom Messstellenbetreiber fest die ``10.11.120.2`` bekommen
- Der LAN-Netzwerkport des Raspberry Pi bekommt die feste IP ``10.11.120.1``

Die Konfiguration in Raspberry Pi OS kann wie folgt durchgeführt werden:

```shell
sudo nano /etc/dhcpcd.conf
```

Am Ende der Datei Folgendes hinzufügen:

```shell
sudo nmcli con show
# Suche die Verbindung für eth0, z. B. „Wired connection 1“. Dann:
sudo nmcli con mod "Wired connection 1" ipv4.addresses 10.11.120.1/24
sudo nmcli con mod "Wired connection 1" ipv4.method manual
sudo nmcli con mod "Wired connection 1" ipv4.gateway ""
sudo nmcli con mod "Wired connection 1" ipv4.dns "8.8.8.8 8.8.4.4"
sudo nmcli con down "Wired connection 1" 
sudo nmcli con up "Wired connection 1"
```

Dann Raspberry Pi neu starten:

```shell
sudo reboot
```

## Source Code für den Proxy

In diesem Repository liegt der Code für einen Proxy in der Programmiersprache GO in der Datei ``reverse_proxy.go``. Er wird folgendermassen auf einem Raspberry Pi installiert (z.B. mit PI OS als Betriebssystem):

```shell
# Linux aktualisieren und GO installieren
sudo apt update && sudo apt upgrade -y
sudo apt install golang git -y

# Go-Proxy kompilieren
git clone https://github.com/klacol/smgw-proxy
cd smgw-proxy


```

Um den reverse_proxy nach jedem Neustart automatisch zu starten und die Logs einzusehen, empfiehlt sich ein systemd-Service. So geht’s:

Erstelle eine systemd-Service-Datei, z. B. ``/etc/systemd/system/reverse_proxy``.service:

Füge Folgendes ein (Pfad und User ggf. anpassen):

```shell 
[Unit]
Description=Reverse Proxy für SMGW
After=network-online.target

[Service]
ExecStart=/home/pi/smgw-proxy/reverse_proxy
WorkingDirectory=/home/pi/smgw-proxy
Restart=always
User=pi
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Service aktivieren und starten:

```shell 
sudo systemctl daemon-reload
sudo systemctl enable reverse_proxy
sudo systemctl start reverse_proxy
```


## Aufrufen:

Das SMGW sollte nun unter der IP-Adresse erreichbar sein, die der WLan Netzwerkport des Raspberry Pi bekommen hat. Der Standardport ist 8080. 

z.B. http://192.168.0.101:8080/

Die Requests werden im Log ausgegeben. Das Log kann auf dem Raspberry Pi so eingesehen werden:

```shell 
journalctl -u reverse_proxy -f
```

## Nutzung in Home Assistant:

Nutze nun das SMGW in Home Assistant auf Basis [dieser Anleitung](https://github.com/jannickfahlbusch/ha-ppc-smgw?tab=readme-ov-file#configuration).

* URL = http://192.168.0.101:8080/smgw/m2m/ETHE0300186023.sm/json
* Username = ****
* Password = ***
* Update Interval = 1

## Hinweis

Diese Anleitung ist insgesamt viel zu komplex für einen normaler deutschen Menschen, der einfach nur das SMGW für seine Energiewende nutzen will. Daher sollten die Messstellenbetreiber IMHO die SMGW's so ausliefern, dass sie für normale Menschen nutzbar sind. Dazu müssen sie DHCP aktiviert haben am HAN/LAN-Port.