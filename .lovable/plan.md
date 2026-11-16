# ROUT: verder vanaf het overdrachtsdossier (eerste stap: grootboek 0265)

## Wat afwijkt van het dossier (gecontroleerd in repo en Neon)
- Neon staat op schema **0283**, niet op 0264: er zijn 277 migraties vastgelegd en 0283 is vandaag om 06:16 toegepast.
- De code staat op `CODE_SCHEMA_LEVEL = "0283"`.
- `0265_booking_ledger.sql` staat al in `db-pending/` (458 regels), niet in `db/`. Daardoor faalt de schemaversie-test niet meer door 0265.
- `src/lib/booking-engine/ledger.ts` bestaat (281 regels). Er is nog geen test voor 0265.
- Dit plan volgt de echte stand. Dossierpunten die al achterhaald zijn, laat ik vallen.

## Deze ronde (alleen code en tests, niets op Neon)
1. **Uitgangssituatie vastleggen.** Ik draai de volledige testsuite en noteer het resultaat. Bestaande fouten los ik niet stilzwijgend op; ik meld ze.
2. **PGlite-integratietest voor 0265**, naar het voorbeeld van `auth-recovery-requests-0263.test.ts`, bovenop een replay van 0000–0283:
   - Directe INSERT, UPDATE, DELETE en TRUNCATE door `rout_app` op `booking_events`, `booking_ledger_salts` en `booking_event_attestations` mislukken.
   - Wijzigingen in `public.bookings` schrijven automatisch een nieuwe schakel in de keten.
   - Elke `entry_hash` is gelijk aan SHA-256(prev_hash || preimage) en komt overeen met `ledger.ts`.
   - Na het wissen van de salt blijft de keten geldig, maar is `detail_commit` niet meer te openen (crypto-shredding).
   - Alle nieuwe SECURITY DEFINER-functies gebruiken `search_path = pg_catalog, pg_temp`. Interne hulpfuncties krijgen `revoke all ... from public, rout_app`.
   - Neon geeft `rout_app` standaard rechten op elke nieuwe tabel; de test controleert dat 0265 die expliciet intrekt.
3. **Fouten in 0265 of ledger.ts herstellen** die de test vindt, waaronder de vlag over `greatest`/`least` zonder schemanaam in de README.
4. **Nummering voorstellen.** 0265 ligt onder de huidige 0283, terwijl de uitrol een vastgelegde voorganger vereist. Ik leg twee opties voor: hernummeren naar **0284** (met schemaniveau 0284), of een uitzondering. Ik kies niet zelf.
5. De suite moet 100% groen zijn. Het bestand blijft in `db-pending/` tot jij GO geeft.

## Daarna (aparte plannen, telkens ter goedkeuring)
- **Fase A:** eerst CLS meten op `/discover/*` en de pagina voor anonieme vragen, met als doel minder dan 0,05. Daarna de lay-out op alle afgesproken breedtes en in landscape, aanraakvlakken van minstens 44x44, AAA-contrast, en metadata en OG-afbeeldingen in de 4 talen.
- **Fase B2–B4:** agenda-OAuth-tokens als RVE1 in `vault_enclave`. Openbare boekingspagina's geven alleen bitmaskers met vrije tijdvakken vrij. MCP mag alleen een `hold` maken; bevestigen vraagt een passkey.
- **Fase C–G:** de worker, routering, vergaderdiensten, betalingen, e-mails en wallet-passes.

## Vaste regels
- Geen Lovable Cloud. Niets wordt op Neon toegepast zonder jouw expliciete GO, en de Neon-koppeling hangt niet aan het project.
- SECURITY DEFINER-regels en EXPAND/CONTRACT-discipline zoals in AGENTS.md. Ruwe tokens komen nooit buiten de kluis.
