# Security News Radar - Projektinformationen

Diese Datei dokumentiert den aktuellen Aufbau und die wichtigsten Betriebsdaten,
damit spaetere Anpassungen konsistent vorgenommen werden koennen. Zugangsdaten,
SSH-Schluessel und andere Geheimnisse gehoeren nicht in dieses Repository.

## Webseite und Layout

- Oeffentliche Adresse: `https://security-news-radar.de`
- Die Seite wird statisch durch `security_news.py` erzeugt.
- Die aktive mehrsprachige Vorlage beginnt in `render_language_site()`.
- Der Inhalt liegt auf grossen Bildschirmen in einer mittigen Spalte mit einer
  nominellen Aufteilung von 15 Prozent Rand, 70 Prozent Inhalt und 15 Prozent Rand.
- Die Inhaltsbreite ist auf 1320 Pixel begrenzt, damit Zeilen auf sehr breiten
  Monitoren gut lesbar bleiben.
- Unter 1181 Pixeln nutzt die Seite die verfuegbare Breite mit 20 Pixel Rand.
- Unter 721 Pixeln bleiben 14 Pixel Rand; das Dashboard wird einspaltig.
- Die vier Dashboard-Fenster stehen auf Desktop im 2x2-Raster. Ihre Hoehe ist
  vertikal veraenderbar, und der Inhalt jedes Fensters kann separat scrollen.
- Es gibt genau einen Theme-Schalter im Kopfbereich. Die Auswahl wird lokal im
  Browser gespeichert; ohne Auswahl folgt die Seite dem Systemmodus.
- Die Hauptschriftgroesse betraegt 15 Pixel. Ueberschrift und Unterzeile sind
  bewusst kompakter als in der ersten Version.

## Bedienung und Inhalte

- Sprachen: Deutsch und Englisch
- Filter: Freitextsuche und Quelle
- Sortierung: Datum oder Kritikalitaet
- Ausgaben: HTML-Seiten und RSS-Feeds je Sprache
- Quellen: NVD, EUVD, CISA KEV und konfigurierte RSS-Feeds

## Lokaler Aufbau

- Generator: `security_news.py`
- Konfiguration: `config.json` beziehungsweise `config.example.json`
- Statische Ressourcen: `assets/`
- Lokale Standardausgabe: `public/`
- Testlauf ohne Benachrichtigungen: `run.sh --no-notify`

## Produktiver Betrieb

- Server: `server01.koettel.de`
- Projektpfad: `/opt/security-news`
- Web-Ausgabe: `/opt/apache/html`
- Dienst: `security-news.service`
- Zeitsteuerung: `security-news.timer`
- Git-Branch: `main`

Eine Veroeffentlichung erfolgt gebuendelt: lokal pruefen, nach GitHub pushen,
auf dem Server aktualisieren und danach den Dienst einmal ausfuehren. Vor
produktiven Aenderungen muessen vorhandene lokale Serveraenderungen respektiert
und duerfen nicht ungefragt verworfen werden.

## Pruefung vor Veroeffentlichung

1. Python-Syntax pruefen.
2. Seiten lokal neu erzeugen.
3. Eingebettetes JavaScript syntaktisch pruefen.
4. Sicherstellen, dass nur ein Theme-Schalter vorhanden ist.
5. Desktop- und Mobilregeln auf Ueberlauf und zu schmale Inhalte kontrollieren.
6. Aenderungsumfang und unbeabsichtigte Dateiaenderungen pruefen.
7. Nach der Veroeffentlichung die Live-Seite visuell kontrollieren.
