# ECS Read-Only Root Filesystem — Werkplan

Prowler check: `ecs_task_definitions_containers_readonly_access`
Aangemaakt: 2026-04-13

## Aanpak
Per applicatie:
1. Branch aanmaken vanuit main/master
2. `readonlyRootFilesystem = true` toevoegen aan elke container definition
3. Waar nodig `tmpfs` mounts of EFS volumes toevoegen voor schrijfbare directories
4. Testen op dev -> uat -> prod
5. PR aanmaken, reviewen, mergen

---

## Gemute (niet te fixen via Terraform)

| Task definition | Reden |
|----------------|-------|
| `sp-task-definition-*` (22 stuks, prod) | Auto-generated door ShinyProxy at runtime. Niet in Terraform beheerd. ShinyProxy maakt deze dynamisch aan bij het starten van gebruikerssessies. |
| `biodiversiteitsportaal-*` (8 stuks, dev) | Overgeslagen op verzoek. Enkel in dev account (632683202044). |
| `download-data-resources` (prod) | VBP pipeline task, valt onder biodiversiteitsportaal beheer. |
| `dwca-to-verbatim` (prod) | VBP pipeline task, valt onder biodiversiteitsportaal beheer. |

---

## Te fixen — per applicatie

### Simpel (1 container)

| # | Task definition | Terraform project | Container(s) | Accounts |
|---|----------------|-------------------|-------------|----------|
| 1 | `adviezen-api` | `inbo-aws-adviezen-terraform` | api | dev, uat, prod |
| 2 | `bruinerat-django` | `inbo-aws-bruinerat-terraform` | bruinerat | prod |
| 3 | `exotenportaal-shinyproxy` | `inbo-aws-exotenportaal-terraform` | exotenportaal-shinyproxy | uat, prod |
| 4 | `faunabeheer-shinyproxy` | `inbo-aws-faunabeheer-terraform` | faunabeheer-shinyproxy | uat, prod |
| 5 | `flora-api` | `inbo-aws-flora-terraform` | api | dev, uat, prod |
| 6 | `inbo-aloft-backlog` | `inbo-aws-aloft-terraform` | sync | uat, prod |
| 7 | `inbo-aloft-baltrad` | `inbo-aws-aloft-terraform` | baltrad | uat, prod |
| 8 | `inbo-bobo-app` | `inbo-aws-bobo-terraform` | bobo-app | dev, uat, prod |
| 9 | `inbo-bodem-dov-etl` | `inbo-aws-bodem-terraform` | dov-etl | uat, prod |
| 10 | `inbo-mne-sampling-task` | te bepalen | mne-sampling-container | shared-infra |
| 11 | `inbo-snipeit-app` | te bepalen | inbo-snipeit-app | shared-infra |
| 12 | `inbo-vis-app` | `inbo-aws-vis-terraform` | vis-app | dev, uat, prod |
| 13 | `inbo-waterbirds-app` | `inbo-aws-waterbirds-terraform` | waterbirds-app | dev, uat, prod |
| 14 | `inbo-watina-app` | `inbo-aws-watina-terraform` | watina-app | dev, uat, prod |
| 15 | `inbo-watina-dov-etl` | `inbo-aws-watina-dov-terraform` | dov-etl | uat |
| 16 | `ipt-app` | `inbo-aws-ipt-terraform` | ipt-tomcat | prod |
| 17 | `ipt-dev-app` | `inbo-aws-ipt-terraform` | ipt-dev-tomcat | prod |
| 18 | `lbt-redis` | `inbo-aws-lbt-terraform` | lbt-redis | prod |
| 19 | `wbe-shinyproxy` | te bepalen | wbe-shinyproxy | uat, prod |
| 20 | `vespadb-redis` | `inbo-aws-vespadb-terraform` | vespadb | uat, prod |

### Medium (2 containers)

| # | Task definition | Terraform project | Container(s) | Accounts |
|---|----------------|-------------------|-------------|----------|
| 21 | `adviezen-webdav` | `inbo-aws-adviezen-terraform` | webdav, dns-updater | dev, uat, prod |
| 22 | `inbo-aloft-sync` | `inbo-aws-aloft-terraform` | sync, aws-otel-collector | uat, prod |
| 23 | `inbo-keycloak-app` | `inbo-aws-keycloak-terraform` | inbo-keycloak-web, inbo-keycloak-fetch-certs | dev, uat, prod |
| 24 | `lbt-app` | `inbo-aws-lbt-terraform` | lbt-django, lbt-celery-worker | prod |
| 25 | `vespadb-django` | `inbo-aws-vespadb-terraform` | vespadb | prod |
| 26 | `vespadb-node` | `inbo-aws-vespadb-terraform` | vespadb | uat, prod |

### Complex (3+ containers)

| # | Task definition | Terraform project | Container(s) | Accounts |
|---|----------------|-------------------|-------------|----------|
| 27 | `meetnetten-app` | `inbo-aws-meetnetten-terraform` | meetnetten-django, meetnetten-django-migrate, meetnetten-celery-worker, meetnetten-celery-beat | uat, prod |

---

## Voortgang

| # | Applicatie | Status | PR | Uitrol (dev/uat/prod) | Opmerkingen |
|---|-----------|--------|-----|----------------------|------------|
| 1 | adviezen-api | [x] | https://github.com/inbo/inbo-aws-adviezen-terraform/pull/3 | dev / uat / prod | init container (non-root); prod nog te doen |
| 2 | bruinerat-django | [x] | https://github.com/inbo/inbo-aws-bruinerat-terraform/pull/1 | | init container (non-root) |
| 3 | exotenportaal-shinyproxy | [x] | https://github.com/inbo/inbo-aws-exotenportaal-terraform/pull/4 | - / uat / prod | init container (non-root) |
| 4 | faunabeheer-shinyproxy | [x] | https://github.com/inbo/inbo-aws-faunabeheer-terraform/pull/7 | - / uat / prod | init container (non-root), incl. wbe |
| 5 | flora-api | [x] | https://github.com/inbo/inbo-aws-flora-terraform/pull/2 | dev / uat / prod | init container (non-root); prod nog te doen |
| 6 | inbo-aloft-backlog | [-] | | n.v.t. | Overgeslagen op verzoek |
| 7 | inbo-aloft-baltrad | [-] | | n.v.t. | Overgeslagen op verzoek |
| 8 | inbo-bobo-app | [x] | https://github.com/inbo/inbo-aws-modules-databeheer-spring-boot-region/pull/1 | dev / uat / prod | Via shared module v1.2.1 |
| 9 | inbo-bodem-dov-etl | [x] | https://github.com/inbo/inbo-aws-bodem-terraform/pull/14 | - / uat / prod | Draait als root, geen init container nodig |
| 10 | inbo-mne-sampling-task | [-] | | n.v.t. | Wacht op bevestiging van Falk of project verdwijnt |
| 11 | inbo-snipeit-app | [x] | https://github.com/inbo/inbo-aws-snipeit-terraform/pull/3 | inbo-shared-infra | Init container kopieert /var/www/html + /etc/apache2 naar writable volumes |
| 12 | inbo-vis-app | [x] | https://github.com/inbo/inbo-aws-vis-terraform/pull/1 | dev / uat / prod | Init container (non-root Spring Boot) |
| 13 | inbo-waterbirds-app | [-] | | n.v.t. | Overgeslagen op verzoek |
| 14 | inbo-watina-app | [x] | https://github.com/inbo/inbo-aws-watina-terraform/pull/2 | - / - / - | Via shared module v1.2.0; nog nergens uitgerold |
| 15 | inbo-watina-dov-etl | [x] | https://github.com/inbo/inbo-aws-watina-dov-terraform/pull/1 | - / uat / - | Draait als root, geen init container nodig |
| 16 | ipt-app | [x] | https://github.com/inbo/inbo-aws-ipt-terraform/pull/2 | - / - / - | Init container kopieert /usr/local/tomcat naar writable volume |
| 17 | ipt-dev-app | [x] | https://github.com/inbo/inbo-aws-ipt-terraform/pull/2 | - / - / - | Samen met ipt-app |
| 18 | lbt-redis | [x] | https://github.com/inbo/inbo-aws-landbouwtellingen-terraform/pull/3 | - / - / prod | tmpfs voor /data |
| 19 | wbe-shinyproxy | [x] | https://github.com/inbo/inbo-aws-faunabeheer-terraform/pull/7 | - / uat / prod | Samen met faunabeheer |
| 20 | vespadb-redis | [-] | | n.v.t. | Applicatie gaat EOL eind april 2026 |
| 21 | adviezen-webdav | [x] | https://github.com/inbo/inbo-aws-adviezen-terraform/pull/3 | dev / uat / prod | Samen met api; dns-updater blijft schrijfbaar; uat en prod nog te doen |
| 22 | inbo-aloft-sync | [-] | | n.v.t. | Overgeslagen op verzoek |
| 23 | inbo-keycloak-app | [x] | https://github.com/inbo/inbo-aws-keycloak-terraform/pull/22 | dev / uat / prod | Init container + tmpfs voor /tmp, /opt/keycloak/data, /opt/keycloak/certs |
| 24 | lbt-app | [x] | https://github.com/inbo/inbo-aws-landbouwtellingen-terraform/pull/3 | - / - / prod | Samen met redis; init container voor /app (collectstatic) |
| 25 | vespadb-django | [-] | | n.v.t. | Applicatie gaat EOL eind april 2026 |
| 26 | vespadb-node | [-] | | n.v.t. | Applicatie gaat EOL eind april 2026 |
| 27 | meetnetten-app | [x] | https://github.com/inbo/inbo-aws-meetnetten-terraform/pull/21 | - / uat / prod | Init container (root) kopieert /home/meetnetten + chmod /tmp; redis was al readonly |

---

## Aandachtspunten

- **Tomcat containers** (ipt): schrijven naar `/usr/local/tomcat/work`, `/tmp`, en logs — tmpfs mounts nodig
- **Django containers** (meetnetten, lbt, bruinerat, vespadb): schrijven naar `/tmp` en mogelijk static files — tmpfs mounts nodig
- **Redis containers**: schrijven naar `/data` — tmpfs of volume mount nodig (data is ephemeral)
- **ShinyProxy containers**: base image draait als non-root, schrijven naar `/tmp` — init container nodig (chmod 1777)
- **Keycloak**: schrijft naar `/opt/keycloak/data` en `/tmp` — tmpfs mounts nodig
- **Spring Boot containers** (waterbirds, watina, vis, bobo, flora): schrijven naar `/tmp` — tmpfs mount nodig
- **Baltrad**: kan schrijven naar diverse data directories — moet per geval bekeken worden
