# Konten, Rollen und Verzeichnisanbindung

Die Anmeldung erfolgt mit lokalen Konten oder mit `ad:<Benutzername>` über LDAPS. Lokale Namen werden normalisiert und ohne Beachtung der Groß-/Kleinschreibung verwaltet. Der Präfix `ad:` ist für Verzeichniskonten reserviert. Es gibt keinen Rückfall auf ein lokales Passwort, wenn die Verzeichnisanmeldung fehlschlägt.

## Erstinbetriebnahme

Vor dem ersten Produktivstart die verschlüsselnde Anwendungsschlüsseldatei und eine lokale Administration erzeugen. Passwörter werden interaktiv abgefragt und nicht als Kommandozeilenparameter übergeben:

```powershell
python -m app.manage key --file config/secrets/encryption.key
python -m app.manage user --file config/secrets/users.json --name notfall-admin --role admin
```

`USERS_FILE` verweist im Container auf die bereitgestellte Kontodatei. Die Datei enthält scrypt-Passworthashes, Rollen und einen Server-Bereich. Sie wird genau einmal in die persistente Datenbank übernommen. Die Anwendung startet im Produktivbetrieb nur, wenn eine aktive lokale Rolle mit `users.manage` und `roles.manage` und dem globalen Bereich `['*']` vorhanden ist. Diese Kontrolle gilt auch bei späteren Neustarts. Zwei getrennte lokale Administrationskonten einrichten und deren Zugangsdaten nach dem behördlichen Verfahren hinterlegen.

Nach der Übernahme werden Konten ausschließlich über **Benutzer & Rollen** verwaltet. Die Änderung der Bootstrap-Datei setzt keine Passwörter in einer bestehenden Datenbank zurück. Das Offline-Werkzeug erstellt Bootstrap-Dateien; es verändert keine laufende Installation und ist kein Wiederherstellungswerkzeug für deren Datenbank. Bei vollständigem Zugangsausfall die Anwendung stoppen und eine gesicherte, zusammengehörige Datenbank-/Schlüsselsicherung nach dem Betriebsverfahren wiederherstellen. Die letzte lokale Administration lässt sich über die GUI weder deaktivieren noch ihrer notwendigen Rolle oder ihres globalen Bereichs berauben. Das eigene Konto kann nicht deaktiviert werden. Konten bleiben als deaktivierte Datensätze für historische Aufträge erhalten.

Der Demo-Modus enthält `admin` / `admin-demo-2026`, `operator` / `demo-operator-2026` und `approver` / `demo-approver-2026`. Diese Konten werden im Produktivmodus nicht angelegt.

## Rollen und Server-Bereiche

| Standardrolle | Berechtigungen |
| --- | --- |
| Lesen (`viewer`) | `view` |
| Betrieb (`operator`) | `view`, `plan`, `execute` |
| Freigabe (`approver`) | `view`, `approve` |
| Administration (`admin`) | Alle Berechtigungen |

Zusätzlich verfügbar sind `users.manage`, `roles.manage`, `servers.manage` und `audit.export`. Standardrollen sind unveränderlich. Eigene Rollen können erstellt, bearbeitet und gelöscht werden; eine zugeordnete Rolle muss zuerst von Konten und Verzeichnisgruppen entfernt werden. Jede Rolle benötigt `view`. Das Vier-Augen-Prinzip für Aufträge gilt auch für die Administration: Eine Person kann ihren eigenen Auftrag nicht freigeben.

Der Bereich eines Kontos enthält UniFi-Server-IDs oder ausschließlich `*` für alle Server. Damit werden Katalogzugriff und Aufträge begrenzt. Delegierte Administration kann nur Rollen und Bereiche vergeben, die ihre eigenen Rechte nicht überschreiten. Das gilt auch für bestehende Konten und für die Änderung einer Rolle, die Konten außerhalb des eigenen Bereichs verwenden. Verzeichniseinstellungen ändern kann nur eine Administration mit globalem Server-Bereich.

Rollen-, Bereichs-, Passwort- und Aktivierungsänderungen widerrufen die betroffenen Sitzungen sofort. Ausstehende Aufträge prüfen vor ihrer Ausführung die aktuellen Rechte des Erstellers, der freigebenden Person und der ausführenden Person erneut.

## LDAP / Active Directory

Die GUI speichert die Verzeichniseinstellungen einschließlich Bind-Passwort verschlüsselt. Das Passwort wird weder zurückgegeben noch protokolliert. Beim Speichern ohne neues Bind-Passwort bleibt das vorhandene erhalten. Eine bestehende `LDAP_CONFIG_FILE` kann die Erstkonfiguration bereitstellen; `bind_password_file` verweist darin auf eine eingebundene Secret-Datei. Auch diese Konfiguration wird nur einmal übernommen.

| Einstellung | Bedeutung |
| --- | --- |
| `enabled` | Verzeichnisanmeldung aktivieren |
| `url` | Reine `ldaps://<Host>:636`-Adresse ohne Zugangsdaten, Suchpfad oder Query |
| `base_dn` | Suchbasis für Konten und gegebenenfalls verschachtelte AD-Gruppen |
| `bind_dn` | DN eines Kontos mit ausschließlich erforderlichen Leserechten |
| `bind_password` | Neues Bind-Passwort; nur schreibbar, optional bei späteren Änderungen |
| `ca_file` | Pfad der bereitgestellten CA-Datei im Container; leer verwendet den System-Vertrauensspeicher |
| `role_groups` | Zuordnung `{Rollen-ID: Gruppen-DN}` |
| `scope` | Standard-Server-Bereich neu angelegter Verzeichniskonten |
| `user_attribute` | AD: `sAMAccountName`; beispielsweise OpenLDAP: `uid` |
| `object_class` | AD: `user`; beispielsweise OpenLDAP: `inetOrgPerson` |
| `group_attribute` | Gruppenattribut am Konto, standardmäßig `memberOf` |
| `nested_ad_groups` | Verschachtelte AD-Mitgliedschaften zusätzlich mit Matching-Rule-in-Chain auflösen |

Zertifikatskette und Servername werden geprüft; LDAP-Verweise werden nicht verfolgt. Die Gruppenentscheidung muss genau eine konfigurierte Rolle ergeben. Keine passende oder mehrere passende Rollen führen zur Ablehnung. Verzeichnisgruppen sollten deshalb für die Berechtigungsvergabe eindeutig gestaltet werden. Bei LDAP-Systemen ohne `memberOf` muss ein geeigneter Gruppenattribut-Mechanismus bereitgestellt werden.

Für AD muss das Bind-Konto `userAccountControl`, `msDS-User-Account-Control-Computed` und `accountExpires` lesen können. Deaktivierte, gesperrte, abgelaufene Konten, abgelaufene Passwörter und fehlende Statusattribute werden abgewiesen. Aufträge prüfen AD-Mitgliedschaften und Status über einen erneuten Service-Bind; dafür wird kein Benutzerpasswort gespeichert. Das Ergebnis wird höchstens 60 Sekunden zwischengespeichert. Lokale Änderungen an Konten, Rollen oder Verzeichniskonfiguration heben diesen Zwischenspeicher über die Versionsprüfung auf. Ist LDAPS nicht erreichbar oder die Autorisierung unklar, wird die Ausführung abgewiesen und betroffene Sitzungen werden widerrufen.

Bei anderem `object_class` als `user` werden Gruppenmitgliedschaften geprüft; die Sperr-, Ablauf- und Passwortregeln anderer LDAP-Produkte müssen separat integriert und im Zielverzeichnis abgenommen werden. Änderungen der Verzeichniskonfiguration widerrufen alle Verzeichnissitzungen. Bestehende Verzeichniskonten behalten ihren administrierten Server-Bereich; eine Änderung von `scope` im Verzeichnisformular betrifft neu angelegte Konten.

## Sitzungen und Passwortregeln

Lokale Passwörter benötigen 16 bis 256 Zeichen. Im Demo-Modus haben die fest vorgegebenen Konten kürzere Demonstrationspasswörter. Lokale Passwörter werden mit scrypt und individuellem Zufallssalt gespeichert. **Mein Konto** ermöglicht den Passwortwechsel nach Bestätigung des aktuellen Passworts; danach werden alle Sitzungen des Kontos beendet. Verzeichnispasswörter werden im Verzeichnis geändert.

Sitzungen laufen nach 30 Minuten absolut oder nach 15 Minuten Inaktivität ab. Der Browser erhält ein `HttpOnly`-/`SameSite=Strict`-Cookie, im Produktivmodus zusätzlich `Secure`. Die Datenbank enthält ausschließlich den SHA-256-Hash des Sitzungstokens. Schreibende Anfragen benötigen den konfigurierten Ursprung und einen sitzungsgebundenen CSRF-Token. Anmeldung und Passwortbestätigung werden nach Konto und Quelladresse gedrosselt; die Sperrinformationen überstehen Neustarts. Passwortberechnung und Verzeichniszugriffe sind auf vier gleichzeitige Arbeiten begrenzt.

Die Anwendung enthält keine eigene MFA-Anmeldung. Ein LDAPS-Passwortbind bildet auch keine interaktive AD-MFA ab. Für den Betrieb im Behördennetz müssen die festgelegten Zugangs- und MFA-Anforderungen durch die freigegebene Zugangsschicht erfüllt und überprüft werden.
