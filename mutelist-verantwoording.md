# Prowler Mutelist Verantwoording

Dit document beschrijft waarom bepaalde Prowler findings gemute zijn als accepted risk.

Laatst bijgewerkt: 2026-06-30

---

## Alle accounts (`*`)

### `guardduty_is_enabled`
**Gemute voor:** alle regions, alle resources
**Reden:** GuardDuty wordt centraal beheerd via de AWS Organizations management account en is gedelegeerd naar het security account. Prowler scant individuele member accounts en detecteert dat GuardDuty niet lokaal geconfigureerd is, maar het is wel actief via de organisatie-brede configuratie.

### `guardduty_delegated_admin_enabled_all_regions`
**Gemute voor:** alle regions, alle resources
**Reden:** Zelfde reden als `guardduty_is_enabled`. GuardDuty admin delegation gebeurt centraal vanuit de management account; member accounts hoeven dit niet per region zichtbaar te hebben. We gebruiken enkel eu-west-1 actief — voor de andere regions is delegatie niet zinvol.

### `securityhub_enabled`
**Gemute voor:** alle regions, alle resources
**Reden:** Security Hub uitrol is gepland via `inbo-aws-security-hub-terraform` (centraal voor eu-west-1). Findings voor unused regions zijn niet relevant — we gebruiken enkel eu-west-1. Mutelist wordt versmald (regions: eu-west-1 only) zodra de centrale uitrol over alle member accounts is afgerond.

### `s3_bucket_public_access` / `s3_bucket_public_list_acl` / `s3_bucket_level_public_access_block`
**Gemute voor:** `aloftdata`, `inbo-aloft-uat-eu-west-1-default`
**Reden:** De aloftdata bucket is bewust publiek toegankelijk. Dit is een open data bucket voor het ALOFT-project (vogelradardata) die publiek beschikbaar moet zijn voor onderzoekers en partners. Het bucket-level Block Public Access is daarom bewust niet ingeschakeld. De UAT-bucket spiegelt deze configuratie voor testdoeleinden.

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
- `inbo-vbp-pipelines-emr-service-role`: EMR service role met `ec2:RunInstances` + `iam:PassRole`. Beide acties zijn inherent vereist door Amazon EMR om de EC2 instances van het cluster te starten en de instance profile role te koppelen. PassRole is beperkt tot het EMR EC2 instance profile. Dit is de standaard AWS-aanbevolen configuratie voor EMR clusters die door de VBP data pipelines gebruikt worden.

**Toegevoegd 2026-06-30 — Session Manager / ECS-exec gebaseerd (geen `iam:PassRole`).** Prowler vlagt `ssm:StartSession`, `ecs:ExecuteCommand` en `ssm:SendCommand` als priv-esc (je kan zo een shell/command op een instance of task krijgen). Dit is de bedoelde SSH-vervanging; weghalen breekt operationele toegang. Er valt geen `iam:PassRole` te versmallen.
- `inbo-mne-sampling-developers-role`: `ecs:ExecuteCommand` + `ssm:StartSession`/`TerminateSession`, gescoped tot de eigen ECS-cluster/tasks. Standaard "developers kunnen `aws ecs execute-command` in hun eigen app"-patroon.
- `inbo-ckan-developer-role`: `ssm:StartSession` op EC2, tag-gescoped (`ssm:ResourceTag/Name = ckan`). Session Manager als SSH-vervanging.
- `inbo-ckan-lambda-secret-rotation-role`: de wachtwoord-rotatie-Lambda gebruikt `ssm:SendCommand`, gescoped tot het eigen SSM-document en billing-code-getagde instances. Weghalen breekt de credential-rotatie.
- `inbo-vertigis-developer-role`: `ssm:StartSession` op de VertiGIS Windows-server, tag-gescoped. Bedoeld voor remote beheer.
- `inbo-vertigis-external-siggis-user`: externe SigGIS-contractor met `ssm:StartSession` (tag-gescoped) voor remote beheer van de VertiGIS-server. By-design; de statische access key wordt apart opgevolgd (zie `iam_user_*`-checks in het werkplan).
- `inbo-n2kmonitoring-analytics-role`: behoudt bewust `ssm:StartSession` + `ec2:Start/Stop/RebootInstances` op de ranalysis-instance (operators starten daar sessies). Deze SSM/EC2-rechten zijn afgesplitst van het gedeelde S3-doc zodat enkel deze role ze nog heeft (branch `security/n2k-least-privilege-ssm`); de andere n2k-principals (s3-default user, ec2-role, unittest-role) worden zo gefixt en blijven dus niet gemute.

**Toegevoegd 2026-06-30 — EventBridge scheduler met scoped `iam:PassRole`.**
- `inbo-riparias-scheduler`: EventBridge scheduler-role die riparias ECS-taken start (`ecs:RunTask` + `iam:PassRole`, gescoped tot de riparias task roles), analoog aan `inbo-aloft-eventbridge-scheduler`.

### `iam_policy_allows_privilege_escalation`
**Gemute voor:** `inbo-vbp-start-pipelines-policy`, `inbo-github-runners-lambda-execution-policy`, `inbo-vbp-additional-dev-permissions`
**Reden:**
- `inbo-vbp-start-pipelines-policy`: Managed policy met `ecs:RunTask` + `iam:PassRole` voor het starten van biodiversiteitsportaal data pipelines. PassRole is beperkt tot specifieke pipeline task roles.
- `inbo-github-runners-lambda-execution-policy`: GitHub self-hosted runners Lambda policy met `ec2:RunInstances` + `iam:PassRole`. Nodig voor het starten van EC2-based GitHub runners. PassRole is beperkt tot de runner instance profile role.
- `inbo-vbp-additional-dev-permissions`: Development-only policy voor het biodiversiteitsportaal team. Bevat bredere IAM rechten die nodig zijn voor development workflows. Enkel toegepast in dev accounts.
- `inbo-developers-policy` *(toegevoegd 2026-06-30)*: org-brede developer-policy met `ssm:StartSession` (Session Manager als SSH-vervanging) + `ssm:TerminateSession`/`ResumeSession`. Geen `iam:PassRole`. Basis-toegang voor alle developers; weghalen breekt SSM-toegang.
- `inbo-bastion-bastion-ssm-policy` *(toegevoegd 2026-06-30)*: bastion Session Manager-policy, `ssm:StartSession` tag-gescoped tot instances met `Name=bastion`. De bedoelde SSH-vervanging — geen `iam:PassRole`.
- `inbo-auditor-role-boundary` *(toegevoegd 2026-06-30)*: permissions boundary voor de auditor-role. Een boundary beperkt rechten (verleent ze niet); Prowler vlagt het patroon maar het is by-design.

### `ecs_task_definitions_containers_readonly_access`
**Gemute voor:** `inbo-vbp-spatial-service:*` (biodiversiteitsportaal geoserver), `vespadb-*` (vespawatch), `inbo-aloft-*` (aloft), `inbo-waterbirds-*` (waterbirds), `inbo-mne-*` (mne-sampling)
**Reden:**
- **adviezen-webdav**: Deze container is essential = false en ephemeral, dus readonly voegt hier weinig toe
- **inbo-vbp-spatial-service**: De geoserver container vereist schrijftoegang tot het root filesystem voor de GeoServer data directory (workspaces, styles, caches en runtime configuratie). Dit is een beperking van de GeoServer-architectuur en kan niet eenvoudig naar een dedicated volume verplaatst worden zonder ingrijpende aanpassingen aan de ALA (Atlas of Living Australia) deployment.
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

### `secretsmanager_automatic_rotation_enabled`
**Gemute voor:** alle secrets, behalve `*/rds/*`
**Reden:** De meeste secrets in onze Secrets Manager zijn niet automatiseerbaar te roteren: 3rd-party API keys (Keycloak client secrets, Google OAuth/OIDC, GitHub PAT, SMTP credentials), TLS-certificaten en applicatie-internal secrets (JWT keys, web admin passwords) kunnen niet zonder coördinatie met externe systemen of zonder applicatie-downtime worden gerotateerd. RDS-secrets (`*/rds/*`) zijn expliciet uitgesloten via `Exceptions` zodat we daar wel rotation kunnen aanzetten (via AWS-managed master password of een rotation lambda).

### `secretsmanager_has_restrictive_resource_policy`
**Gemute voor:** alle secrets (incl. `*/rds/*`) *(uitgebreid 2026-06-30)*
**Reden:** Onze secrets worden beschermd via IAM-policies (least-privilege per service-role). Een aanvullende Secrets Manager resource policy is een defense-in-depth maatregel maar geen vereiste in onze architectuur. Eerder bleven RDS-secrets via een `Exceptions`-blok zichtbaar met de bedoeling er resource policies aan toe te voegen; dat is heroverwogen. Een resource policy met een vaste reader-principal geeft lockout-risico (applicatie, rotation-lambda, devops, terraform zelf) en moet per secret zorgvuldig bepaald worden; IAM-access wordt als afdoende beschouwd. Daarom zijn nu alle secrets gemute, consistent met de niet-RDS secrets.

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
