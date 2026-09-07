# Prowler AWS Findings - Werkplan

Gegenereerd via `prowler-scripts/fetch_all_fail_findings.py` + `generate_werkplan.py`.
Tellingen zijn **na** lokale mutelist-filter (de Prowler-API past de mutelist niet toe).

## Bronnen en scopes

| Account | UID | Laatste completed scan |
|---|---|---|
| inbo-dev | `632683202044` | 2026-07-12 |
| inbo-shared-infra | `347082780157` | 2026-07-12 |
| inbo-uat | `625469168093` | 2026-07-12 |
| inbo-prod | `800040084629` | 2026-07-12 |

> Scans zijn vers (2 dagen oud, 2026-07-12); alle vier de AWS-accounts hebben een completed scan.

## Totaaloverzicht (actief, na mutelist)

### Actieve findings

| Severity | shared-infra | dev | uat | prod | Totaal |
|---|---|---|---|---|---|
| **CRITICAL** | 0 | 1 | 0 | 1 | **2** |
| **HIGH** | 173 | 26 | 32 | 80 | **311** |
| **MEDIUM** | 545 | 617 | 641 | 928 | **2731** |
| **LOW** | 117 | 228 | 367 | 318 | **1030** |

### Gemute findings (in mutelist.yaml)

| Severity | shared-infra | dev | uat | prod | Totaal |
|---|---|---|---|---|---|
| **CRITICAL** | 3 | 2 | 7 | 6 | **18** |
| **HIGH** | 101 | 204 | 242 | 251 | **798** |
| **MEDIUM** | 2 | 0 | 0 | 0 | **2** |
| **LOW** | 0 | 0 | 0 | 0 | **0** |

## CRITICAL — direct opvolgen (2 actief)

Actieve CRITICAL-findings na mutelist. Hoogste prioriteit: per resource beslissen fixen of (mits verantwoord) muten.

- **dev** — `awslambda_function_no_secrets_in_variables`
  - resource: `inbo-vbp-species-lists-api`
  - Potential secret found in Lambda function inbo-vbp-species-lists-api variables -> Basic Auth Credentials in variable SPRING_APPLICATION_JSON.
- **prod** — `ecs_task_definitions_no_environment_secrets`
  - resource: `sp-task-definition-7aa2bf04-fd30-49f0-8acd-8ee92cfac8f5:1`
  - Potential secrets found in ECS task definition sp-task-definition-7aa2bf04-fd30-49f0-8acd-8ee92cfac8f5 with revision 1: Secrets in container sp-container-7aa2bf04-fd30-49f0-8acd-8ee92cfac8f5-0 -> JSON Web Token on the environment variable SHINYPROXY_OIDC_ACCESS_TOKEN.

## HIGH actieplan (311 actieve findings)

Gegroepeerd per aanpak. Per check het aantal actieve HIGH-findings en de aanpak.

### Opgelost via Terraform-branch deze sessie (wacht op merge + apply + rescan)

- **`rds_cluster_protected_by_backup_plan`** (6) — Branch security/enable-aurora-backups (Aurora=true). Wacht op apply.

### Live-account / CLI-actie (niet via Terraform-code)

- **`ec2_ebs_snapshots_encrypted`** (181) — Bulk re-encrypt (copy-with-encryption + delete oude). Default EBS-encryptie staat al aan in TF.
- **`route53_domains_transferlock_enabled`** (1) — Eenmalige toggle via Route53 Domains.
- **`ec2_ebs_volume_encryption`** (1) — Legacy volumes re-encrypten; default encryptie staat al aan.

### Strategisch / langere doorlooptijd

- **`iam_user_with_temporary_credentials`** (20) — Migratie naar Identity Center/OIDC. Veel zijn service-accounts (SES/ECR) -> per user beslissen of gericht muten.
- **`iam_user_hardware_mfa_enabled`** (20) — Zelfde users als temporary_credentials. Service-accounts kunnen geen hardware-MFA.

### Te reviewen per resource

- **`rds_instance_protected_by_backup_plan`** (21) — Geen Backup=false-tag in TF -> zou gedekt moeten zijn onder opt-out model. Live coverage verifieren; wsl stale.
- **`ecs_task_definitions_containers_readonly_access`** (17) — watina-app al gefixt (v1.2.1, wacht op apply); VBP solr/zk/grafana onder VBP-team; watervogels/riparias = TODO (testen).
- **`vpc_endpoint_connections_trust_boundaries`** (9) — Restrictieve endpoint-policies in inbo-aws-networking-terraform/common-envs/private-link.tf (gedeelde infra).
- **`iam_role_cross_service_confused_deputy_prevention`** (9) — aws:SourceAccount/aws:SourceArn-condities toevoegen aan service-assumed roles.
- **`ec2_networkacl_allow_ingress_any_port`** (8) — Waarschijnlijk default-NACLs van de VPC-module; custom NACL-rules nodig.
- **`secretsmanager_automatic_rotation_enabled`** (4) — RDS-secrets: rotatie instellen of muten. Overige meestal niet rotateerbaar.
- **`iam_role_cross_account_readonlyaccess_policy`** (4) — Cross-account ReadOnlyAccess reviewen per role.
- **`iam_no_custom_policy_permissive_role_assumption`** (4) — Custom policy laat te brede sts:AssumeRole toe; scopen.
- **`ec2_securitygroup_allow_ingress_from_internet_to_any_port`** (2) — SG-regels beperken.
- **`ec2_ebs_volume_snapshots_exists`** (2) — Backup plan of accepteren voor stateless volume.
- **`route53_dangling_ip_subdomain_takeover`** (1) — Dangling DNS-record -> verwijderen of herstellen (subdomain takeover-risico).
- **`sns_topics_kms_encryption_at_rest_enabled`** (1) — KMS-encryptie op SNS-topic aanzetten.

---

## HIGH per check — detail (actieve resources)

### `ec2_ebs_snapshots_encrypted` — 181 (CLI)

- **shared-infra** (145): snap-0009b0d5494fc69fc, snap-000b0726025932622, snap-001535c3b0a001909, snap-00174b38b8d971c67, snap-007ed2f6d9683664b, snap-00934af03e517f19b, snap-009a6d30e0f3c92a8, snap-00a3faecae7b9bc9b, snap-00c26e7860291ee94, snap-00e94466cd4062c75, snap-00ee8dfb140160a17, snap-0111f8c47d5eab8c9, snap-013d2d495bc3b7c02, snap-014a03e847a4bc167, snap-0160e5a431cd8387d, snap-016162e4f5e463c89, snap-01821b7e41b79c2ca, snap-018dcd806e969ec67, snap-01982454d648cfe1f, snap-019ba279d09c16543, snap-0200956b2661e512d, snap-0230a90f20fac8066, snap-023f5633651132a8b, snap-026d2612eb18db84f, snap-027892560f4768788, ... +120 meer
- **prod** (36): snap-0186d8dc4d686d440, snap-01a844f966cddced3, snap-0223b36fe0451012d, snap-028343537714cc9aa, snap-03117573911dc1620, snap-0317a63b6979ecb4f, snap-0390719a76d7182ff, snap-03b12a209ab616f78, snap-040c4a6d754851ce4, snap-04150fbd620dd8eb3, snap-046575c9c662c4126, snap-04a048cc2c2ad655b, snap-04b36561365b6e1d9, snap-05163280c1e6befa1, snap-052209cb689d82d39, snap-0529ea807059bf760, snap-0571faa9291f619ff, snap-05a8f8d9775194581, snap-05c7e1bbc8819fa01, snap-05c8c96d95b25f187, snap-063a46340d82f0717, snap-07b10cd703db5d080, snap-0944633006a2389e6, snap-09ac18ea8950bca48, snap-0a0b3ed9e328c1417, ... +11 meer

### `rds_instance_protected_by_backup_plan` — 21 (REVIEW)

- **shared-infra** (2): inbo-snipeit-mysql, inbo-utility-shared-infra
- **dev** (3): inbo-adviezen-dev, inbo-bookstack-dev, inbo-keycloak-dev
- **uat** (6): inbo-adviezen-uat, inbo-bookstack-uat, inbo-keycloak-uat, inbo-meetnetten-uat, inbo-riparias-uat, inbo-waterbirds-uat
- **prod** (10): inbo-adviezen-prod, inbo-autopsies-prod, inbo-bookstack-prod, inbo-bruinerat-prod, inbo-ckan, inbo-keycloak-prod, inbo-lbt-prod, inbo-meetnetten-prod, inbo-vespadb-prod, inbo-waterbirds-prod

### `iam_user_with_temporary_credentials` — 20 (STRATEGISCH)

- **shared-infra** (6): inbo-aloft-ecr-deployment, inbo-appsheet-s3, inbo-n2kmonitoring-shared-infra-s3-default, inbo-pure-sync-elsevier-user, joris-bongers, otobo-ses-smtp
- **dev** (3): inbo-vbp-biocache-service-email, inbo-vbp-image-service, inbo-vbp-keycloak-email
- **uat** (4): inbo-vbp-BiocacheServiceEmail, inbo-vbp-ImageService, inbo-vbp-KeycloakEmail, johan_van_de_wauw
- **prod** (7): inbo-keycloak-smtp-user-auth-inbo-be, inbo-vbp-BiocacheServiceEmail, inbo-vbp-ImageService, inbo-vbp-KeycloakEmail, inbo-vertigis-external-siggis-user, inbo-vertigis-ses-smtp-inbo-argisenterprise-user, inbo-vertigis-ses-smtp-vespawatch-user

### `iam_user_hardware_mfa_enabled` — 20 (STRATEGISCH)

- **shared-infra** (6): inbo-aloft-ecr-deployment, inbo-appsheet-s3, inbo-n2kmonitoring-shared-infra-s3-default, inbo-pure-sync-elsevier-user, joris-bongers, otobo-ses-smtp
- **dev** (3): inbo-vbp-biocache-service-email, inbo-vbp-image-service, inbo-vbp-keycloak-email
- **uat** (4): inbo-vbp-BiocacheServiceEmail, inbo-vbp-ImageService, inbo-vbp-KeycloakEmail, johan_van_de_wauw
- **prod** (7): inbo-keycloak-smtp-user-auth-inbo-be, inbo-vbp-BiocacheServiceEmail, inbo-vbp-ImageService, inbo-vbp-KeycloakEmail, inbo-vertigis-external-siggis-user, inbo-vertigis-ses-smtp-inbo-argisenterprise-user, inbo-vertigis-ses-smtp-vespawatch-user

### `ecs_task_definitions_containers_readonly_access` — 17 (REVIEW)

- **dev** (4): inbo-vbp-grafana:5, inbo-vbp-solr-efs-1:15, inbo-vbp-zk-solr-efs-1:15, inbo-watina-app:17
- **uat** (7): inbo-vbp-solr-efs-1:1, inbo-vbp-zk-solr-efs-1:1, inbo-watervogels-app:4, riparias-django:5, riparias-rqworker:5, riparias-task:5, riparias-valkey:1
- **prod** (6): inbo-vbp-solr-efs-1:5, inbo-vbp-solr-efs-2:5, inbo-vbp-solr-efs-3:5, inbo-vbp-zk-solr-efs-1:5, inbo-vbp-zk-solr-efs-2:5, inbo-vbp-zk-solr-efs-3:5

### `vpc_endpoint_connections_trust_boundaries` — 9 (REVIEW)

- **shared-infra** (1): vpce-06dfec918937433dc
- **dev** (4): vpce-046bea462bd9d8d1b, vpce-056670b4168f9a6d9, vpce-0823249730edf000d, vpce-089e220ba15c1dfb0
- **uat** (2): vpce-0343d2c46875f5451, vpce-0c687050670c9c5aa
- **prod** (2): vpce-0508bb1f8fa48fd54, vpce-05892ae72609e681f

### `iam_role_cross_service_confused_deputy_prevention` — 9 (REVIEW)

- **shared-infra** (1): inbo-socdash-lambda-edge-role
- **dev** (2): inbo-vbp-backup-restore-role, inbo-vbp-species-lists-api-lambda
- **uat** (2): inbo-vbp-backup-restore-role, inbo-watervogels-app-task-role
- **prod** (4): inbo-rattenapp-fotosync-lambda-role, inbo-shop-lambda, inbo-shop-scheduler, inbo-vbp-backup-restore-role

### `ec2_networkacl_allow_ingress_any_port` — 8 (REVIEW)

- **shared-infra** (2): acl-05809b3f3631fc9bb, acl-0fad35584fdf200f9
- **dev** (2): acl-031c97f07b284f515, acl-0cd81a37a32428da2
- **uat** (2): acl-0ba78d261f869a600, acl-0f5aae098531329ae
- **prod** (2): acl-0315ecacbe3026ab3, acl-0e4f9c972cd192edb

### `rds_cluster_protected_by_backup_plan` — 6 (TF-BRANCH)

- **dev** (2): inbo-vbp-mysql, inbo-vbp-postgres
- **uat** (2): inbo-vbp-mysql, inbo-vbp-postgres
- **prod** (2): inbo-vbp-mysql, inbo-vbp-postgres

### `secretsmanager_automatic_rotation_enabled` — 4 (REVIEW)

- **shared-infra** (1): /inbo/utility/rds/mysql/root
- **dev** (1): /inbo/bookstack/rds/mysql/master
- **uat** (1): /inbo/bookstack/rds/mysql/master
- **prod** (1): /inbo/bookstack/rds/mysql/master

### `iam_role_cross_account_readonlyaccess_policy` — 4 (REVIEW)

- **shared-infra** (1): inbo-auditor-role
- **dev** (1): inbo-auditor-role
- **uat** (1): inbo-auditor-role
- **prod** (1): inbo-auditor-role

### `iam_no_custom_policy_permissive_role_assumption` — 4 (REVIEW)

- **shared-infra** (1): inbo-auditor-role-boundary
- **dev** (1): inbo-auditor-role-boundary
- **uat** (1): inbo-auditor-role-boundary
- **prod** (1): inbo-auditor-role-boundary

### `ec2_securitygroup_allow_ingress_from_internet_to_any_port` — 2 (REVIEW)

- **shared-infra** (2): sg-042bb0ec5df9a0bf8, sg-0d37b7b929577d537

### `ec2_ebs_volume_snapshots_exists` — 2 (REVIEW)

- **shared-infra** (2): vol-0058d94f2c0ab80e7, vol-0b3f7b19c8dd26fba

### `route53_domains_transferlock_enabled` — 1 (CLI)

- **shared-infra** (1): neobiota2026.org

### `route53_dangling_ip_subdomain_takeover` — 1 (REVIEW)

- **shared-infra** (1): Z07544063BQ3MTGPFWWP1/alert.riparias.be./54.228.126.86

### `ec2_ebs_volume_encryption` — 1 (CLI)

- **shared-infra** (1): vol-041c79923a0b2088e

### `sns_topics_kms_encryption_at_rest_enabled` — 1 (REVIEW)

- **prod** (1): inbo-rattenapp-fotosync-alerts

