# UniFi Batch · WLAN, VLAN & RADIUS

<!-- badges:start -->
[![CI](https://github.com/BartelLuis/UniBatch/actions/workflows/ci.yml/badge.svg)](https://github.com/BartelLuis/UniBatch/actions/workflows/ci.yml)
[![Docker und Browser](https://github.com/BartelLuis/UniBatch/actions/workflows/docker.yml/badge.svg)](https://github.com/BartelLuis/UniBatch/actions/workflows/docker.yml)
[![Lint](https://github.com/BartelLuis/UniBatch/actions/workflows/lint.yml/badge.svg)](https://github.com/BartelLuis/UniBatch/actions/workflows/lint.yml)
[![Security](https://github.com/BartelLuis/UniBatch/actions/workflows/security.yml/badge.svg)](https://github.com/BartelLuis/UniBatch/actions/workflows/security.yml)
[![Secret Scan](https://github.com/BartelLuis/UniBatch/actions/workflows/secrets.yml/badge.svg)](https://github.com/BartelLuis/UniBatch/actions/workflows/secrets.yml)
[![Dependabot-Konfiguration](https://github.com/BartelLuis/UniBatch/actions/workflows/dependabot.yml/badge.svg)](https://github.com/BartelLuis/UniBatch/actions/workflows/dependabot.yml)
![Python 3.14](docs/badges/python.svg)
![Lokale UniFi API](docs/badges/local-api.svg)
<!-- badges:end -->

Intern betriebenes Webwerkzeug für die lokale Verwaltung von WLANs, VLANs und RADIUS-Profilen auf mehreren UniFi OS Servern. Für den Betrieb mit 12 Servern und über 1.000 Sites ausgelegt; eine dauerhafte Simulation mit **12 Servern und 1.200 Sites** ist enthalten. Die Anwendung verwendet lokale UniFi APIs, ohne UniFi-Cloud, externe Browserressourcen oder Telemetrie. Die klassische lokale RADIUS-API wird je Server ausdrücklich aktiviert.

## Funktionen

- Einheitliche Administrationsoberfläche mit gruppierter Navigation, kompakter Betriebsübersicht, Statusanzeigen, Tabellen und gegliederten Formularen. Benutzer-, Rollen- und Servereditoren öffnen sich bei Bedarf; Bestätigungen und Eingaben erfolgen in Dialogen mit Fokusverwaltung und Tastatursteuerung. Die mobile Navigation unterstützt Tastatur und Escape.
- Zentrale Serververwaltung mit internen HTTPS-Adressen, lokalen API-Keys, CA-Datei, Verbindungstest, Aktivierung und Deaktivierung in der GUI.
- Gespeicherter Site-Katalog, regelmäßige Synchronisierung, Suche, Server-/Tagfilter, lokale Tags und Seitennavigation. Auswahl über mehrere Seiten/Server und Auswahl sämtlicher Suchtreffer ohne Konfigurationsabruf für jede Site.
- WLANs und VLANs anlegen, ändern und löschen. Geführte Formulare und erweiterte JSON-Eingabe für die dokumentierten WLAN-Felder.
- WPA2/WPA3 Personal und Enterprise, VLAN-Zuordnung und RADIUS-Profil-Auflösung über lokale Namen je Site; weitere Einstellungen wie Isolation, Frequenzen, Roaming, mDNS und Zeitpläne über JSON.
- RADIUS-Profile anlegen, ändern und löschen: bis zu acht Authentifizierungs- und Accounting-Server mit IPv4-Adresse, Port und Shared Secret, Accounting-Zwischenupdates und dynamische WLAN-VLAN-Zuweisung. Dieselben Vorlagen, Vorschauen, Freigaben, Pilotziele und Wiederherstellungen wie für WLAN/VLAN. Verwendete, geschützte oder unvollständig lesbare Profile werden gegen Löschen bzw. Änderungen gesperrt.
- VLANs sind ausschließlich `UNMANAGED`: keine UniFi-Gateway-, Routing-, DHCP-Server- oder Firewallverwaltung. Standardnetz/VLAN 1 ist geschützt. Vor VLAN-Löschungen werden Verwendungsreferenzen geprüft; erzwungenes Löschen ist gesperrt.
- Verschlüsselte, wiederverwendbare Vorlagen. Vorlagen werden serverseitig angewendet; Geheimnisse erscheinen in der GUI ausschließlich maskiert.
- Dauerhafte Hintergrundaufträge mit Feldvorschau, Vier-Augen-Freigabe, bis zu 20.000 Zielobjekten pro Auftrag, Pilotzielen, Wartungsfenster, Abbruch und Fortschritt je Ziel.
- Bis zu sechs Server gleichzeitig; pro UniFi OS Server jeweils ein Schreibzugriff. Fehler können den Auftrag stoppen; bereits laufende Anfragen an andere Server müssen noch abgeschlossen werden.
- Wiederherstellung bestätigter Änderungen als neuer Auftrag mit eigener Vorschau und Freigabe. Erneute Planung sicher fehlgeschlagener Ziele; unklare Schreibresultate werden nie automatisch wiederholt.
- GUI-Verwaltung lokaler Konten, eigener Rollen, Server-Berechtigungsbereiche, Kennwörter und LDAP/AD-Anbindung. Sofortiger Sitzungswiderruf bei lokalen Rechteänderungen.
- Audit-Ereignisse mit Hashverkettung und HMAC, Integritätsprüfung und JSON-Export; Auftragsberichte ohne Geheimnisse.

## Simulation starten

```powershell
docker compose -f compose.demo.yaml up --build -d
```

**<http://localhost:8080>** öffnen. Die Simulation sendet keine Anfragen an echte UniFi-Systeme. Sie hat drei vorangelegte Konten:

Der Demo-Port kann über `DEMO_PORT` in einer lokalen `.env` angepasst werden. In diesem Workspace läuft die geprüfte Docker-Simulation auf **<http://localhost:8090>**, weil Docker Port 8080 als belegt meldet. Die passende Einstellung ist bereits in der ignorierten `.env` hinterlegt. Für eine separate Installation dient `.env.example` als Vorlage.

| Konto | Passwort | Verwendung |
| --- | --- | --- |
| admin | admin-demo-2026 | Benutzer, Rollen, Server und LDAP konfigurieren |
| operator | demo-operator-2026 | Vorschau erstellen und freigegebene Aufträge ausführen |
| approver | demo-approver-2026 | Aufträge einer anderen Person freigeben |

Beispiel: als `operator` Sites auswählen, WLAN „Verwaltung“ ändern und Vorschau erstellen; als `approver` prüfen und freigeben; als `operator` ausführen. Für VLANs heißt die Beispielkonfiguration „Verwaltungsnetz“. Pro Site existieren außerdem „Gast“, „Gastnetz“ und das geschützte „Default“. Das simulierte Enterprise-Profil heißt „Behörden-RADIUS“.

Demo-Daten einschließlich GUI-Konten und Konfigurationsänderungen bleiben im separaten Docker-Volume `demo-data` erhalten. Demo und Produktivbetrieb dürfen kein Datenverzeichnis teilen; die Anwendung erzwingt die Trennung beim Start. Simulation und Produktivbetrieb nicht gleichzeitig auf demselben Port starten.

Ohne Docker, ausschließlich zur lokalen Entwicklung:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
$env:DEMO_MODE='true'
$env:APP_ORIGIN='http://localhost:8080'
$env:DATA_DIR='data/demo-v2'
.venv\Scripts\python -m uvicorn app.main:app_factory --factory --host 127.0.0.1 --port 8080 --no-proxy-headers
```

## Produktivbetrieb im internen Netz

Bei einem Upgrade vom ersten Prototyp das Datenvolume vorher sichern. Dessen Tabellen `jobs` und `audit` bleiben in der Datei erhalten, werden in der neuen GUI aber nicht angezeigt. Offene Prototyp-Aufträge neu planen und die bisherige Historie entsprechend eurem Archivierungsverfahren aufbewahren.

1. Anwendungsschlüssel und ein persönliches lokales Administrationskonto erzeugen. Passwörter werden interaktiv abgefragt:

   ```powershell
   .venv\Scripts\python -m app.manage key --file secrets/encryption_key
   .venv\Scripts\python -m app.manage user --file secrets/users.json --name notfall-admin --role admin
   ```

   Bei der ersten Inbetriebnahme wird `users.json` einmalig übernommen. Danach gelten die Konten aus der Datenbank und werden in der GUI verwaltet. Die letzte aktive globale lokale Administration ist gegen Deaktivierung und Rechteentzug geschützt. Weitere persönliche Konten und eigene Rollen über **Benutzer & Rollen** anlegen. Die Anwendung verlangt im Produktivbetrieb eine lokale Administration als Wiederherstellungszugang. [Details zu Identitäten und LDAP](docs/identity.md).

2. `config/servers.example.json` nach `config/servers.json` kopieren. Die Beispielkonfiguration kann einen initialen Server enthalten; weitere elf Server über die GUI hinzufügen. Für eine vollständige Erstübernahme können auch alle zwölf in der Datei stehen. Nach der Erstübernahme sind Änderungen über die GUI maßgeblich. Beim Import verweisen `key_file` und `ca_file` auf gemountete Secret-Dateien.
3. `secrets/unifi_01` mit dem lokalen API-Key und `secrets/internal_ca.pem` mit der internen CA-Kette bereitstellen. Zusätzliche CA-Dateien im Container unter `/run/secrets` einbinden. GUI-API-Keys werden verschlüsselt gespeichert; sie werden nie zurückgegeben. Hostdateien mit restriktiven ACLs versehen.
4. In `compose.yaml` **`ALLOWED_CONTROLLER_HOSTS` auf die exakten Hostnamen aller zwölf Server setzen**. Diese vom Betreiber festgelegte Liste begrenzt auch GUI-Administratoren. Zusätzlich auf Netzwerkebene ausgehende Verbindungen auf diese Server und die AD-DCs begrenzen. Die Anwendung akzeptiert nur RFC1918-/ULA-Ziele, pinnt die geprüfte DNS-IP für den Zugriff und prüft TLS einschließlich des ursprünglichen Hostnamens. UniFi-Cloud-Endpunkte sind ausgeschlossen.
5. Einen internen HTTPS-Reverse-Proxy vor den nur auf `127.0.0.1:8080` veröffentlichten Dienst setzen. **`APP_ORIGIN` muss exakt der Browser-URL entsprechen**, ohne abschließenden Slash. Benutzerzugriff über HTTP ist im Produktivbetrieb nicht vorgesehen. Bei einem separaten Proxy-Host die Netzwerkbindung ausdrücklich auf das erlaubte Proxysegment anpassen.
6. `docker compose up --build -d` starten und die Serververbindung/Vorschauen testen. Schreibzugriffe beginnen gesperrt (`ENABLE_WRITES=false`). Die genaue installierte UniFi-Network-Version und das vollständige GET/PUT-Verhalten auf dedizierten Test-Sites prüfen. Danach `ENABLE_WRITES=true` gezielt setzen und den Dienst neu erstellen.

Der Container läuft als UID 10001 mit schreibgeschütztem Root-Dateisystem, ohne Linux-Capabilities, mit `no-new-privileges` und Ressourcenlimits. Das Image initialisiert das Datenvolume mit passenden Rechten. Beim Ersetzen durch einen Host-Bindmount muss UID 10001 auf dessen Datenverzeichnis schreiben können.

## LDAP/AD einrichten

Die Anbindung ist in der GUI unter **Verzeichnis** konfigurierbar. Dazu wird kein LDAP-Compose-Override benötigt, sofern die CA bereits gemountet ist. Das Service-Bind-Passwort liegt verschlüsselt in der Datenbank. Gruppen-DNs werden Rollen zugeordnet; Benutzer melden sich als `ad:benutzer` an. Ein Benutzer muss eindeutig genau einer gemappten Rolle zugeordnet sein.

Alternativ kann `config/ldap.example.json` für die Erstübernahme verwendet werden:

```powershell
docker compose -f compose.yaml -f compose.ldap.yaml up --build -d
```

Dazu `config/ldap.json` und `secrets/ldap_bind_password` bereitstellen. Die Datei wird nur bei der Erstkonfiguration übernommen. Für AD muss das Servicekonto Gruppenmitgliedschaften und Kontostatus lesen können. Bei geplanten Aufträgen werden AD-Rechte und Kontoaktivität über einen Service-Bind erneut geprüft, mit höchstens 60 Sekunden Zwischenspeicherung. Keine Benutzerpasswörter werden dafür gespeichert. [Felder, Gruppenregeln und Kontostatusprüfung](docs/identity.md).

## Batchablauf und Wiederherstellung

1. Sites über Suche, Tags und Serverfilter auswählen. „Alle Suchtreffer“ sammelt auch Sites auf anderen Katalogseiten.
2. WLAN, VLAN oder RADIUS und Anlegen/Ändern/Löschen wählen. Bestehende Objekte werden anhand des exakten Namens je Site aufgelöst; „alle Objekte“ ist eine ausdrückliche zusätzliche Auswahl. Bei WLANs wird ein VLAN-Name auf die jeweilige lokale Netzwerk-ID abgebildet. Enterprise-WLANs verwenden entsprechend einen RADIUS-Profilnamen.
3. Konfiguration, Change-Ticket/Begründung, Parallelität und optional Anzahl der Pilotziele festlegen. Vorschau erstellen und deren Abschluss abwarten. Jedes Ziel muss erfolgreich geplant sein, bevor der Auftrag freigabefähig ist.
4. Eine andere berechtigte Person prüft die Feldunterschiede und gibt den unveränderlichen Auftrag frei. Auch eine Administration kann ihren eigenen Auftrag nicht freigeben.
5. Berechtigte Bediener führen sofort oder im Wartungsfenster aus. Vor jedem Schreibzugriff werden Konfiguration, aktuelle Rechte und Serverkonfiguration geprüft. Nach den Pilotzielen pausiert der Auftrag; seine Fortsetzung erfordert eine weitere Bedienhandlung.
6. Bei Fehlern die Zielresultate prüfen. **`uncertain` bedeutet, dass die Änderung trotz fehlender Bestätigung bereits erfolgt sein kann.** Es gibt für Schreibzugriffe keine automatischen Wiederholungen. Nach Prozessabbruch wird ein laufender/queued Auftrag `interrupted`; er läuft nach dem Neustart nicht automatisch weiter.
7. „Wiederherstellung“ erzeugt für bestätigte `applied`-Ziele einen neuen freigabepflichtigen Auftrag. Geänderte Objekte werden nur zurückgesetzt, wenn sie seit der ursprünglichen Ausführung unverändert sind. Gelöschte Objekte werden neu erstellt und erhalten neue IDs. Neue Objekte können nur gelöscht werden, wenn keine inzwischen hinzugekommenen Referenzen dies verhindern. Bei Wiederherstellung eines pausierten Pilotauftrags wird dessen Fortsetzung gesperrt.

Eine Wiederherstellung ist kein atomarer Rollback über Server oder Sites. Zwischen GET und PUT besteht ohne genutzte ETag-/CAS-Unterstützung ein Zeitfenster für Änderungen im Controller. Parallelbearbeitung während des Wartungsfensters organisatorisch sperren. VLAN-Änderungen können Standortverbindungen unterbrechen; Management-VLANs und Notfallzugänge entsprechend berücksichtigen.

## RADIUS einrichten

Unter **Server → Bearbeiten → RADIUS-Verwaltung** den klassischen lokalen Adapter für den betreffenden UniFi OS Server aktivieren. Im Servermenü prüft **RADIUS-Verbindung testen** die Profile einer synchronisierten Site ausschließlich lesend. Die Standard-API-Key-Anmeldung verwendet den bereits hinterlegten lokalen Schlüssel. Akzeptiert eure installierte Version diesen Schlüssel auf der klassischen API nicht, die Anmeldemethode ausdrücklich auf **Lokales UniFi-OS-Konto** ändern und dessen Benutzername/Passwort hinterlegen. Es gibt keinen automatischen Wechsel zwischen Anmeldemethoden. Das Kontopasswort bleibt verschlüsselt; Sitzungscookie und CSRF-Token bleiben ausschließlich im Arbeitsspeicher.

Der Site-Katalog muss zuvor synchronisiert sein: `internalReference` aus der offiziellen Site-Übersicht verbindet die Integration-API-Site-ID mit dem klassischen lokalen Site-Namen. Vor jeder Ausführung und Pilotfortsetzung wird die offizielle Site-Übersicht einmal je betroffenem Controller erneut gelesen. Fehlende, mehrdeutige oder seit der Planung geänderte Zuordnungen sperren den Schreibzugriff. Der Adapter verwendet ausschließlich `/proxy/network/api/s/{internalReference}/rest/radiusprofile` und feste lokale Leserouten für Verwendungsprüfungen; API-Präfixe, IDs und Anmeldung werden getrennt von der Integration API behandelt.

Die offizielle Integration API stellt für RADIUS derzeit ausschließlich eine [lesende Profilübersicht](https://developer.ui.com/network/v10.3.58/getradiusprofileoverviewpage) bereit. Die Konfiguration verwendet deshalb die **private klassische API**, deren Verhalten je Network-Version vor dem Einsatz auf Test-Sites abzunehmen ist. Feldzuordnung und Anmeldung sind anhand der quelloffenen [aus UniFi generierten Profildefinition](https://raw.githubusercontent.com/paultyng/go-unifi/main/unifi/radius_profile.generated.go) und der [UniFi-API-Client-Implementierung](https://github.com/Art-of-WiFi/UniFi-API-client/blob/main/src/Client.php) umgesetzt. Der Adapter ist produktiv standardmäßig deaktiviert; `ENABLE_WRITES=false` sperrt weiterhin sämtliche produktiven Schreibzugriffe.

Im **Site-Katalog → Details** sind RADIUS-Profile mit maskierten Shared Secrets sichtbar und als Batch-Ziel auswählbar. Im Batch-Editor **RADIUS** wählen und einen Profilnamen angeben. Bei Änderungen bleibt eine Serverliste erhalten, solange sie nicht ausdrücklich ersetzt wird. Für eine Ersatzliste muss jeder Eintrag einen vollständigen neuen Shared Secret enthalten. Beim Anlegen ist mindestens ein Authentifizierungsserver erforderlich; aktiviertes Accounting braucht mindestens einen Accounting-Server. Zwischenupdates setzen aktiviertes Accounting voraus, mit Intervallen von 60 bis 86.400 Sekunden. VLAN-Zuweisung unterstützt deaktiviert, optional oder erforderlich.

Zuerst das RADIUS-Profil ausrollen, danach im WLAN-Auftrag **WPA2/WPA3 Enterprise** und seinen Profilnamen auswählen. Die WLAN-Zuordnung löst diesen Namen je Site über die offizielle Profilübersicht auf; klassische Profil-IDs werden niemals als Integration-API-IDs eingesetzt. Das Tool konfiguriert UniFi-Profile für vorhandene externe RADIUS-Dienste; es installiert oder administriert keinen NPS-/FreeRADIUS-Dienst.

Unbekannte aktive Profilfelder, integrierte Gateway-RADIUS-Profile, RadSec, kabelgebundene VLAN-Zuweisung oder fehlende/maskierte Shared Secrets verhindern Änderungen und Löschungen, damit der vollständige vorherige Zustand wiederherstellbar bleibt. Vor einer Löschung werden WLAN-, Netzwerk-, Port-, Site-Einstellungs- und Geräteverweise geprüft; unmittelbar vor dem Schreibzugriff erfolgt eine erneute Prüfung. Ein Ausfall einer erforderlichen Leseroute sperrt die Löschung. Externe Controller-Änderungen lassen sich durch die private API nicht atomar ausschließen.

Für eine Erstübernahme aus `servers.json` sind zusätzlich `radius_legacy_enabled`, `radius_auth_mode`, `radius_username` und optional `radius_password_file` möglich. Die Passwortdatei bei Kontoanmeldung als eigenes Docker-Secret unter `/run/secrets` einbinden. Spätere Änderungen erfolgen in der Server-GUI; beim Bearbeiten bewahrt ein leeres Passwortfeld das bestehende Passwort. Der Wechsel zurück zu API-Key entfernt die gespeicherten Kontozugangsdaten.

## API und Skalierung

Referenzvertrag ist **UniFi Network 10.1.84**, aus der [offiziellen OpenAPI-Dokumentation](https://developer.ui.com/network/v10.1.84/openapi.json). Lokale Pfade sind `/proxy/network/integration/v1` beziehungsweise konfigurierbar `/integration/v1`. WLANs: `/sites/{siteId}/wifi/broadcasts`; VLANs: `/sites/{siteId}/networks`; Authentifizierung: `X-API-Key`. Die versionsbezogene Dokumentation ist unter [Network → Integrations](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API) verfügbar.

Die Anwendung prüft bekannte Felder, Typen, verschachtelte Pflichtwerte und Grenzen gegen den mitgelieferten Vertrag. Unbekannte Felder und maskierte/unvollständige Geheimnisse werden abgewiesen. „Neueste Version“ muss deshalb anhand der tatsächlich installierten Version abgenommen werden. Es liegen keine realen UniFi- oder AD-Zugangsdaten vor; deren Integration ist noch nicht im Zielnetz validiert. Wenn GET WLAN-Sicherheitswerte maskiert, verweigert die Anwendung eine Änderung bzw. Löschung ohne vollständig rekonstruierbare Konfiguration.

Katalog und Aufträge liegen in SQLite/WAL. Konfigurationen werden nur für ausgewählte Sites gelesen; die GUI rendert 50 Sites pro Seite. Jobdetails werden separat paginiert, Server-Bereiche und Auftragszahlen per SQL abgefragt. HTTP-Verbindungspools, begrenzte Lesewiederholungen und parallele Serververarbeitung vermeiden eine neue Verbindung für jedes Objekt. Der Hintergrunddienst startet maximal drei Planungen und einen Rollout gleichzeitig; Lesezugriffe sind zusätzlich begrenzt.

**Eine Instanz und ein ASGI-Worker je Datenverzeichnis.** Eine Prozesssperre verhindert den gleichzeitigen Start mehrerer Scheduler auf demselben Volume. Hochverfügbarkeit mit getrennten Volumes ist nicht implementiert. Für 12 Server / 1.200 Sites wurde der vollständige Simulationsablauf einschließlich Pilotpause und Fortsetzung automatisiert geprüft. Dessen Laufzeit ist keine Zusage für die reale Infrastruktur.

| Einstellung | Vorgabe | Bedeutung |
| --- | --- | --- |
| `ENABLE_WRITES` | false | Produktive Schreibzugriffe freischalten |
| `INVENTORY_INTERVAL` | 900 | Katalogauffrischung in Sekunden |
| `PREVIEW_TTL` | 86400 | Gültigkeit einer fertigen Vorschau in Sekunden |
| `ALLOWED_CONTROLLER_HOSTS` | Betreiberliste | Exakte erlaubte UniFi-Hostnamen, kommasepariert |
| `APP_ORIGIN` | interne HTTPS-URL | Origin-Prüfung und sichere Cookies |

Serveränderungen, einschließlich API-Key-Rotation, machen bestehende Zielbindungen ungültig: eine neue Vorschau und Freigabe erstellen.

## Audit, Sicherung und Zulassung

Das zentrale Audit-Protokoll ist nur mit `audit.export` und globalem Server-Bereich lesbar. Der paginierte JSON-Export (`/api/audit/export?after=<seq>&limit=10000`) unterstützt die Abholung durch einen intern betriebenen Logcollector. Der Collector muss authentifiziert sein; die Anwendung sendet von sich aus keine Daten an externe Dienste. `/api/audit/verify` prüft die HMAC- und Hashkette. Exportierte Kettenköpfe außerhalb des Anwendungsservers sichern.

HMAC schützt gegen Manipulation ohne Schlüsselzugriff; das lokale Audit ist **keine unabhängige WORM-/revisionssichere Ablage**. Ein Angreifer mit Datenbank und Anwendungsschlüssel kann auch Signaturen erzeugen oder Historie löschen. Für den Behördenbetrieb Exporte in eure unabhängige SIEM-/Archivierungsinfrastruktur übernehmen und Aufbewahrung/Integrität dort absichern. Auditmetadaten, Katalog, Benutzer- und Rollenmetadaten sind nicht spaltenweise verschlüsselt; der Host benötigt Datenträgerverschlüsselung. Auftragspayloads, Vorlagen, API-Keys und LDAP-Bind-Passwort sind mit Fernet verschlüsselt.

Vor einer Sicherung den Dienst stoppen und das **gesamte Datenvolume einschließlich WAL/SHM** konsistent sichern. Den Anwendungsschlüssel getrennt, aber wiederauffindbar hinterlegen. Ohne den ursprünglichen Schlüssel sind verschlüsselte Daten nicht lesbar. Wiederherstellung und Schlüsselrotation nach eurem Betriebsverfahren testen; ein Werkzeug für eine automatische Schlüsselrotation ist nicht enthalten.

Diese Anwendung ist keine behördliche Zulassung oder BSI-Zertifizierung. Vor Produktivfreigabe sind TLS-/PKI-Integration, echtes UniFi-/AD-Verhalten, Rechtevergaben, Penetrationstest, Backups und eure konkreten Schutzbedarfsanforderungen abzunehmen. MFA ist nicht implementiert; falls vorgeschrieben, den Administratorzugang zusätzlich über eure zugelassene MFA-Zugangsschicht schützen. Die Anwendungs-Origin-/CSRF-Prüfung bleibt dabei erforderlich.

## GitHub Actions und Badges

Die Workflows starten bei Pushes, Pull Requests und manuell über **Actions → Run workflow**:

- [CI](.github/workflows/ci.yml): vollständige Backendtests einschließlich des 1.200-Site-Rollouts, JavaScript-Syntax, Produktions-/LDAP-/Demo-Compose-Prüfung und JUnit-Bericht mit Ergebniszusammenfassung.
- [Docker und Browser](.github/workflows/docker.yml): Container bauen, die enthaltene Simulation mit einem separaten Volume starten und beide Browserabläufe für WLAN/VLAN sowie RADIUS ausführen. Screenshots und Containerlogs werden sieben Tage als Artefakte aufgehoben. Erfolgreiche Push-/manuelle Läufe stellen außerdem das getestete Image als `docker-image-<commit>` mit SHA-256-Datei für den Offline-Import bereit. Pull Requests exportieren kein Image-Artefakt. Es erfolgt kein Registry-Push oder Deployment.
- [Lint](.github/workflows/lint.yml): Ruff prüft Python auf Syntax-, Import- und typische Laufzeitfehler; ESLint prüft die Browser-Skripte. Markdownlint prüft README und Dokumentation, Actionlint sämtliche Workflows und Hadolint das Dockerfile einschließlich Warnungen.
- [Security](.github/workflows/security.yml): Bandit untersucht Anwendung und Wartungswerkzeuge; pip-audit prüft alle fixierten Produktionspakete. npm audit prüft auch die JavaScript-Entwicklungswerkzeuge und blockiert ab Schweregrad `moderate`. JSON-Berichte bleiben sieben Tage verfügbar. Der Workflow läuft zusätzlich jeden Montag, damit neue Schwachstellen auch ohne Codeänderung auffallen.
- [Secret Scan](.github/workflows/secrets.yml): Gitleaks durchsucht die vollständige ausgecheckte Git-Historie bei Pushes, Pull Requests, manuell und wöchentlich. Funde lassen den Job fehlschlagen; Logs und JSON-Bericht maskieren die Geheimnisse vollständig.
- [Dependabot-Konfiguration](.github/workflows/dependabot.yml): prüft YAML einschließlich doppelter Schlüssel, Update-Verzeichnisse, Zeitpläne, Zeitzonen und Gruppen. Zusätzliche Dependabot-Optionen werden von GitHub geprüft.

Die Workflows verwenden GitHub-gehostete Ubuntu-24.04-Runner, Python 3.14, Node.js 24 und feste Action-Commit-IDs. Die standardmäßig aktiven Jobs besitzen ausschließlich `contents: read`; Checkout speichert keine Git-Zugangsdaten. Die Prüfungen verwenden simulierte UniFi-Daten und gemockte LDAP-Verbindungen. UniFi-/AD-Schlüssel oder Produktionsdateien werden dafür nicht benötigt. Der Vorbereitungsrunner benötigt Internetzugang für geprüfte Abhängigkeiten, Scanner, Browser und Basisimage; das exportierte Anwendungsimage kann anschließend im internen Netz importiert werden.

Optional enthält der Security-Workflow CodeQL für Python und JavaScript mit `security-extended`. Nach Einrichtung des [erweiterten CodeQL-Setups](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/configuring-advanced-setup-for-code-scanning) die Repository-Variable `ENABLE_CODEQL=true` unter **Settings → Secrets and variables → Actions → Variables** setzen. Für private Repositories muss CodeQL im verwendeten GitHub-Tarif verfügbar sein. Dieser gesonderte Job benötigt zusätzlich `actions: read` und `security-events: write`, um Ergebnisse an GitHubs Code-Scanning-Oberfläche zu melden.

[Dependabot](.github/dependabot.yml) schlägt montags um 06:00 Uhr Europe/Berlin Updates für Python, npm, Docker und Actions vor. Kleine PR-Limits und Gruppen für zusammengehörige Updates begrenzen die Anzahl offener PRs; Updates werden nicht automatisch gemergt. Produktions- und Python-Entwicklungsabhängigkeiten sind zusätzlich in `requirements.lock` und `requirements-dev.lock` mit Release-Hashes fixiert. Die CI prüft Direktpins gegen beide Locks und installiert mit `--require-hashes`. Nach einem freigegebenen Python-Update in einer geprüften Python-3.14-Umgebung die aktualisierten Direktpins installieren und beide Locks regenerieren:

```powershell
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python tools/lock_requirements.py
.venv\Scripts\python tools/lock_requirements.py --dev
.venv\Scripts\python tools/check_requirements.py
```

Die npm-Werkzeuge sind ausschließlich Entwicklungsabhängigkeiten; `npm ci --ignore-scripts` installiert anhand der Integritätswerte in `package-lock.json`. Das Anwendungsimage braucht weder Node.js noch npm. Actionlint, Hadolint und Gitleaks sind in [.github/ci-tools.json](.github/ci-tools.json) mit Version, offizieller Release-URL und SHA-256 für Linux/Windows x86-64 fixiert. [Der Installer](tools/install_ci_tools.py) prüft Downloads vor dem Entpacken und installiert nur die erwartete Binärdatei unter `artifacts/ci-tools`. Neue CLI-Versionen und deren offizielle Release-Prüfsummen gemeinsam im Manifest aktualisieren; dieses eigene Manifest wird nicht automatisch von Dependabot geändert.

[Die Gitleaks-Konfiguration](.gitleaks.toml) übernimmt sämtliche Standardregeln. Nur fünf bekannte synthetische Demo-/Testwerte sind zusammen mit ihren jeweiligen Dateipfaden ausgenommen; die Dateien selbst bleiben vollständig im Scan. Inline-Kommentare `gitleaks:allow` werden in der CI ignoriert.

Die sechs Workflow-Badges zeigen GitHubs dynamischen [Workflow-Status](https://docs.github.com/en/actions/how-tos/monitor-workflows/add-a-status-badge) für [BartelLuis/UniBatch](https://github.com/BartelLuis/UniBatch). Nach dem Push der Workflow-Dateien liefern die ersten GitHub-Läufe deren Status. Python- und API-Badges liegen lokal und bleiben offline lesbar. Für einen Fork die Workflow-Badges auf das neue Repository umstellen:

```powershell
.venv\Scripts\python tools/configure_badges.py OWNER/REPO
```

Das Kommando ändert ausschließlich den markierten Badge-Block der README und akzeptiert auch eine GitHub-Repository-URL. Private Repository-Badges setzen entsprechende GitHub-Zugriffsrechte voraus; die lokalen Technik-Badges bleiben ohne externe Bilddienste lesbar.

## Lokal prüfen und offline bauen

```powershell
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m ruff check app tools tests
.venv\Scripts\python tools/check_requirements.py
.venv\Scripts\python tools/check_dependabot.py
npm ci --ignore-scripts
npm run lint:js
npm run lint:docs
node --check app/static/app.js
node --check app/static/dialog.js
docker compose config --quiet
```

Die zusätzlichen CLI-Prüfungen auf Windows x86-64:

```powershell
.venv\Scripts\python tools/install_ci_tools.py actionlint hadolint gitleaks
& artifacts/ci-tools/actionlint.exe (Get-ChildItem .github/workflows/*.yml).FullName
& artifacts/ci-tools/hadolint.exe --failure-threshold warning Dockerfile
.venv\Scripts\python -m bandit -r app tools
.venv\Scripts\python -m pip_audit --require-hashes --disable-pip --strict -r requirements.lock
npm audit --audit-level=moderate
& artifacts/ci-tools/gitleaks.exe git . --log-opts="--all --full-history --diff-merges=separate" --config=.gitleaks.toml --redact=100 --ignore-gitleaks-allow
```

Der letzte Befehl benötigt einen Git-Checkout mit Historie. In einem heruntergeladenen Quellarchiv stattdessen gezielt die freizugebenden Quelldateien per `gitleaks dir` prüfen; lokale Secret- und Datenverzeichnisse gehören nicht ins Repository.

Bei laufender Simulation:

```powershell
.venv\Scripts\python -m playwright install chromium
$env:UNIFI_BROWSER_URL = 'http://localhost:8090' # URL der tatsächlich laufenden Simulation
.venv\Scripts\python tests/browser_smoke.py
.venv\Scripts\python tests/browser_radius_smoke.py
```

Browser-Screenshots liegen unter `artifacts/`. Testumfang: 1.200-Site-Batch, WLAN-/VLAN-/RADIUS-CRUD, Geheimnismaskierung, Enterprise-Zuordnung, Vier-Augen-Prinzip, Scope-/Rollenregeln, Abbruch vor Writes, Timeouts, Wiederherstellung, Neustart, Audit und lokale TLS-/DNS-Regeln. Für den klassischen RADIUS-Adapter werden außerdem Anmeldung, TLS-/DNS-Pinning, Verwendungsreferenzen und Antworten mit unbekannten Feldern geprüft. Die Simulation ersetzt keine Live-Abnahme im Zielnetz.

Docker-Builds verwenden `requirements.lock` mit fixierten transitiven Paketen und Hashes. Ein geprüftes Wheel-/Image-Repository in eurer Freigabepipeline verwenden. Das fertige Containerimage kann per `docker save` exportiert und im Behördennetz per `docker load` importiert werden. Laufzeitabhängigkeiten werden beim Start nicht heruntergeladen. Basisimage-Digest und freigegebene Paketartefakte in eurer Releasefreigabe festhalten; Internetzugang ist nur bei der Vorbereitung nötig, sofern kein interner Mirror verwendet wird.
