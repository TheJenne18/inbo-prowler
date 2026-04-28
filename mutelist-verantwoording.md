# Prowler Mutelist Verantwoording

Dit document beschrijft waarom bepaalde Prowler findings gemute zijn als accepted risk.

Laatst bijgewerkt: 2026-04-28

---

## Alle accounts (`*`)

### `guardduty_is_enabled`
**Gemute voor:** alle regions, alle resources
**Reden:** GuardDuty wordt centraal beheerd via de AWS Organizations management account en is gedelegeerd naar het security account. Prowler scant individuele member accounts en detecteert dat GuardDuty niet lokaal geconfigureerd is, maar het is wel actief via de organisatie-brede configuratie.

### `s3_bucket_public_access` / `s3_bucket_public_list_acl`
**Gemute voor:** `aloftdata`, `inbo-aloft-uat-eu-west-1-default`
**Reden:** De aloftdata bucket is bewust publiek toegankelijk. Dit is een open data bucket voor het ALOFT-project (vogelradardata) die publiek beschikbaar moet zijn voor onderzoekers en partners. De UAT-bucket spiegelt deze configuratie voor testdoeleinden.

### `iam_root_hardware_mfa_enabled`
**Gemute voor:** alle accounts
**Reden:** AWS member accounts in een AWS Organization hebben beperkte root account functionaliteit. Hardware MFA is niet vereist voor member accounts waar root login uitgeschakeld is via Organizations. We gebruiken virtuele MFA als extra beveiliging waar dit nog nodig is.

### `ecs_service_no_assign_public_ip`
**Gemute voor:** `inbo-adviezen-cluster/webdav-service`
**Reden:** De WebDAV-service vereist een publiek IP-adres voor de werking. De service is beveiligd via security groups en draait in een publiek subnet by design.

### `inspector2_active_findings_exist`
**Gemute voor:** alle accounts
**Reden:** Inspector2 findings worden apart beheerd en opgelost via een eigen proces. Prowler's check signaleert enkel dat er actieve findings bestaan, zonder context over de ernst of het opvolgproces.

### `iam_role_administratoraccess_policy`
**Gemute voor:** `OrganizationAccountAccessRole`, `inbo-devops-role`, `inbo-devops-github-actions-deployer-role`, `stacksets-exec-*`
**Reden:**
- `OrganizationAccountAccessRole`: AWS-standaard role aangemaakt bij het creëren van member accounts. Wordt niet actief gebruikt maar kan niet verwijderd worden zonder risico.
- `inbo-devops-role`: DevOps team role die volledige toegang nodig heeft voor infrastructuurbeheer. Toegang is beperkt via IAM Identity Center met MFA-vereiste.
- `inbo-devops-github-actions-deployer-role`: CI/CD deployer role. Heeft brede toegang nodig voor Terraform applies over alle services. Beperkt via OIDC federation tot specifieke GitHub repositories.
- `stacksets-exec-*`: AWS CloudFormation StackSets execution roles. Vereist door AWS voor cross-account StackSet operaties.
- `*QuickSetup*`: Is opgezet door Atos

### `iam_user_administrator_access_policy`
**Gemute voor:** `bert.huygens@inbo.be`
**Reden:** Legacy IAM user met AdministratorAccess. Wordt gemigreerd naar IAM Identity Center. Tijdelijk gemute tot migratie afgerond is.

### `awslambda_function_no_secrets_in_code`
**Gemute voor:** `inbo-vbp-biocache-index-management`, `inbo-watina-pressuremeasurement-status-change-function`
**Reden:**
- **inbo-vbp-biocache-index-management**: False positive. De Lambda function bevat een Node.js dependency (npm package) die een private key template/placeholder bevat in de gebundelde code. Dit is geen echte secret maar een patroon in de library code dat door Prowler's regex-detectie als secret wordt herkend.
- **inbo-watina-pressuremeasurement-status-change-function**: False positive. Prowler detecteert een "Hex High Entropy String" in het bestand `about.mappings` (regel 5) in de shadow JAR. Dit bestand is afkomstig van een Eclipse/Spring library dependency en bevat een git commit hash (`c6d5b3bf2ad1176192d6b8084299d5c9d1345046`), geen echte secret. De Lambda zelf haalt database credentials correct op via AWS Secrets Manager.

### `s3_account_level_public_access_blocks`
**Gemute voor:** alle accounts
**Reden:** Account-level S3 Block Public Access is bewust niet ingeschakeld omdat bepaalde S3 buckets (zoals aloftdata) publiek toegankelijk moeten zijn. Public access wordt per bucket beheerd via bucket policies en ACLs.

### `iam_root_credentials_management_enabled`
**Gemute voor:** alle accounts
**Reden:** Root credentials management (centralized root access) is een relatief nieuwe AWS Organizations feature. De uitrol hiervan wordt gepland maar heeft geen directe security impact aangezien root login al beperkt is via Organizations SCP's.

### `awslambda_function_no_secrets_in_variables`
**Gemute voor:** `inbo-watina-calibration-function`
**Reden:** False positive. De environment variable bevat een ARN-referentie naar een secret in Secrets Manager, niet de secret value zelf. Prowler detecteert het woord "secret" in de variabelenaam.

### `ecs_task_definitions_no_environment_secrets`
**Gemute voor:** `inbo-bodem-dov-etl:*`, `inbo-watina-dov-etl:*`
**Reden:** De environment variables bevatten ARN-referenties naar Secrets Manager secrets (DOV_WEB_SERVER_KEYS_SECRET_ARN, DATABASE_CREDENTIALS_SECRET_ARN), niet de plaintext secret values. De applicatie gebruikt deze ARNs om de secrets zelf op te halen uit Secrets Manager at runtime. Prowler herkent "SECRET_ARN" in de variabelenaam als een potentieel secret.

### `iam_role_cross_account_readonlyaccess_policy`
**Gemute voor:** `SnowOrganizationAccount*`, `inbo-biodiversiteitsportaal-developers-role`, `inbo-developers-role`
**Reden:**
- `SnowOrganizationAccount*`: AWS-standaard role voor cross-account toegang vanuit de management account. Read-only variant is een lager risico.
- `inbo-developers-role` / `inbo-biodiversiteitsportaal-developers-role`: Developer roles die bewust cross-account read-only toegang hebben om resources te kunnen inspecteren in andere omgevingen (bijv. prod logs bekijken vanuit dev). Toegang is beperkt via IAM Identity Center.

### `iam_inline_policy_allows_privilege_escalation`
**Gemute voor:** diverse roles
**Reden per resource:**
- `StackSet-CloudHealthRoleUpdate--LambdaExecutionRole-*`: AWS-beheerde CloudHealth integratie role. Kan niet aangepast worden.
- `inbo-faunabeheer-shinyproxy-wbe-task-role` / `inbo-faunabeheer-shinyproxy-faunabeheer-task-role`: ShinyProxy task roles met `ecs:RunTask` + `iam:PassRole`. PassRole is beperkt tot de specifieke portal task roles die ShinyProxy moet starten. Geen reëel escalation pad.
- `inbo-bodem-role`: Role met `ecs:RunTask` + `iam:PassRole` beperkt tot specifieke ECS task roles voor de bodem DOV ETL pipeline.
- `inbo-aloft-eventbridge-scheduler`: EventBridge scheduler role met `iam:PassRole` beperkt tot de specifieke ECS task roles die de scheduler moet triggeren.
- `BillingConsolePolicyMigratorRole`: AWS-beheerde role voor billing console migratie. Tijdelijk en kan niet aangepast worden.
- `inbo-watina-github-actions-deploy-lambda-role`: GitHub Actions CI/CD role met `lambda:UpdateFunctionCode` beperkt tot 2 specifieke Lambda functions (`calibration-function` en `pressuremeasurement-status-change-function`). Role is alleen assumable via OIDC vanuit `repo:inbo/watina-backend`.
- `inbo-exotenportaal-shinyproxy-task-role`: ShinyProxy task role met `ecs:RunTask` + `iam:PassRole`. PassRole is beperkt tot `portal_task_execution_role` en `portal_task_role` — enkel de roles nodig om exotenportaal containers te starten.
- `inbo-watina-dov-role`: DOV integratie role met `ecs:RunTask` + `iam:PassRole`. PassRole is beperkt tot `inbo-watina-dov-etl-task-role` en `inbo-watina-dov-etl-task-execution-role`. Role is alleen assumable door een specifiek extern AWS account (DOV/Vlaamse Overheid).

### `iam_policy_allows_privilege_escalation`
**Gemute voor:** `inbo-vbp-start-pipelines-policy`, `inbo-github-runners-lambda-execution-policy`, `inbo-vbp-additional-dev-permissions`
**Reden:**
- `inbo-vbp-start-pipelines-policy`: Managed policy met `ecs:RunTask` + `iam:PassRole` voor het starten van biodiversiteitsportaal data pipelines. PassRole is beperkt tot specifieke pipeline task roles.
- `inbo-github-runners-lambda-execution-policy`: GitHub self-hosted runners Lambda policy met `ec2:RunInstances` + `iam:PassRole`. Nodig voor het starten van EC2-based GitHub runners. PassRole is beperkt tot de runner instance profile role.
- `inbo-vbp-additional-dev-permissions`: Development-only policy voor het biodiversiteitsportaal team. Bevat bredere IAM rechten die nodig zijn voor development workflows. Enkel toegepast in dev accounts.

### `ecs_task_definitions_containers_readonly_access`
**Gemute voor:** `vbp-*` (biodiversiteitsportaal), `vespadb-*` (vespawatch), `inbo-aloft-*` (aloft), `inbo-waterbirds-*` (waterbirds), `inbo-mne-*` (mne-sampling)
**Reden:**
- **adviezen-webdav**: Deze container is essential = false en ephemeral, dus readonly voegt hier weinig toe
- **vbp-***: De ALA (Atlas of Living Australia) containers vereisen schrijftoegang tot het root filesystem voor runtime configuratie-initialisatie. Elke VBP-service heeft een `config-init` sidecar container die configuratiebestanden schrijft naar het shared filesystem voordat de applicatie start. Dit is een architectuurbeperking van de ALA-software die niet eenvoudig aan te passen is.
- **vespadb-***: Applicatie gaat end-of-life eind april 2026. Investering in security hardening is niet verantwoord.
- **inbo-aloft-***: Overgeslagen op verzoek.
- **inbo-waterbirds-***: Project staat on hold.
- **inbo-mne-***: Mogelijk EOL, bevestiging verwacht in de week van 20 april 2026.

### `ec2_instance_with_outdated_ami`
**Gemute voor:** `i-09cc110fbb1f04ed4` (SQL Server), `i-0ceda6bc49989921f` (n2kmonitoring R analysis)
**Reden:** Beide zijn stateful EC2 instances met grote datavolumes. Een AMI update via Terraform zou de instances herlanceren en alle data vernietigen. AMI updates op deze instances vereisen een gepland maintenance window met snapshots en migratieprocedure. De n2kmonitoring instance heeft expliciet `lifecycle { ignore_changes = [ami] }` in Terraform.

### `iam_role_cross_service_confused_deputy_prevention`
**Gemute voor:** `*CloudHealth*, *QuickSetup*`
**Reden:** CloudHealth integratie roles worden beheerd door VMware/Broadcom CloudHealth. De assume role policies worden extern bepaald en kunnen niet aangepast worden zonder de integratie te breken. And QuickSetup omdat dit roles zijn Atos


### `iam_aws_attached_policy_no_administrative_privileges`
**Gemute voor:** `AdministratorAccess`
**Reden:** De AWS-managed AdministratorAccess policy is gekoppeld aan roles die bewust volledige toegang nodig hebben (zie `iam_role_administratoraccess_policy` hierboven voor de specifieke roles en hun verantwoording).

---

## Account `625469168093` (inbo-uat)

### `ecs_task_definitions_containers_readonly_access`
**Gemute voor:** `sp-task-definition-*`
**Reden:** ShinyProxy task definitions voor faunabeheer, wbe en exotenportaal. De ShinyProxy containers vereisen schrijftoegang tot het root filesystem voor hun werking.

### `iam_role_cross_service_confused_deputy_prevention`
**Gemute voor:** `inbo-waterbirds-*`
**Reden:** Waterbirds ontwikkeling staat on hold waardoor de resources niet meer gedeployed kunnen worden. Op dev is dit wel in orde.

### `s3_bucket_cross_account_access`
**Gemute voor:** `inbo-aloft-uat-eu-west-1-default`, `inbo-exotenportaal-uat-eu-west-1-default`
**Reden:**
- `inbo-aloft-uat-eu-west-1-default`: De ALOFT UAT-bucket heeft bewust cross-account access voor het delen van vogelradardata met externe partners en het ALOFT data platform.
- `inbo-exotenportaal-uat-eu-west-1-default`: Bewuste cross-account read-only access vanuit de prod deployment role (`inbo-fis-exotenportaal-aspbo-deployment-role` in prod account). De bucket policy beperkt toegang tot `GetObject`, `GetObjectTagging` en `ListBucket` voor die ene specifieke role.

### `ecs_service_no_assign_public_ip`
**Gemute voor:** `webdav-service`
**Reden:** Zie adviezen webdav-service hierboven. Zelfde service in UAT-omgeving.

---

## Account `347082780157`

### `rds_instance_transport_encrypted`
**Gemute voor:** `inbo-utility-shared-infra` in `eu-west-1`
**Reden:** Koha (het bibliotheeksysteem) ondersteunt geen encrypted transport naar de RDS database. Dit is een beperking van de applicatie.

---

## Account `800040084629` (inbo-prod)

### `ecs_task_definitions_containers_readonly_access`
**Gemute voor:** `sp-task-definition-*`, `inbo-aws-bodem-etl:2`
**Reden:**
- **sp-task-definition-***: ShinyProxy task definitions voor faunabeheer, wbe en exotenportaal. De ShinyProxy containers vereisen schrijftoegang tot het root filesystem voor hun werking.
- **inbo-aws-bodem-etl:2**: Wacht op bevestiging van developer Johan Van de Wauw om te testen en te bevestigen. Mail gestuurd op 2026-04-14.

### `iam_role_cross_service_confused_deputy_prevention`
**Gemute voor:** `inbo-waterbirds-*`
**Reden:** Waterbirds ontwikkeling staat on hold waardoor de resources niet meer gedeployed kunnen worden. Op dev is dit wel in orde.

### `s3_bucket_cross_account_access`
**Gemute voor:** `inbo-meetnetten-prod-export-datawarehouse`, `aloftdata`
**Reden:**
- `inbo-meetnetten-prod-export-datawarehouse`: Bewuste cross-account access voor het exporteren van meetnetten data naar het INBO datawarehouse in een ander AWS account.
- `aloftdata`: Publieke open data bucket (zie hierboven).

### `ecs_service_no_assign_public_ip`
**Gemute voor:** `webdav-service`
**Reden:** Zie adviezen webdav-service hierboven. Zelfde service in productie-omgeving.
