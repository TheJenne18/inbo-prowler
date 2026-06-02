# Prowler AWS Findings - Werkplan

Gegenereerd op 2026-06-02 via `prowler-scripts/fetch_all_fail_findings.py`

## Bronnen en scopes

| Account | UID | Laatste scan |
|---|---|---|
| inbo-shared-infra | `347082780157` | 2026-05-31 |
| inbo-dev | `632683202044` | 2026-05-31 |
| inbo-uat | `625469168093` | 2026-05-09 |
| inbo-prod | `800040084629` | 2026-05-11 |

> **LET OP:** scans van **inbo-uat en inbo-prod zijn van begin mei** - oudere data. De scheduler voor die accounts staat vast. Plan om opnieuw te scannen.

## Totaaloverzicht

Aantal findings *na* lokale mutelist-filter (de Prowler API past de mutelist niet toe).

| Severity | inbo-shared-infra | inbo-dev | inbo-uat | inbo-prod | Totaal |
|---|---|---|---|---|---|
| **CRITICAL** | 0 | 0 | 0 | 0 | **0** |
| **HIGH** | 189 | 28 | 11 | 181 | **409** |
| **MEDIUM** | 519 | 619 | 544 | 993 | **2675** |
| **LOW** | 122 | 230 | 288 | 305 | **945** |

### Gemute findings (al in `mutelist.yaml`)

| Severity | inbo-shared-infra | inbo-dev | inbo-uat | inbo-prod | Totaal |
|---|---|---|---|---|---|
| CRITICAL | 3 | 2 | 6 | 6 | 17 |
| HIGH | 85 | 191 | 55 | 215 | 546 |
| MEDIUM | 2 | 0 | 77 | 0 | 79 |
| LOW | 0 | 0 | 0 | 0 | 0 |

## Aanbevolen werkvolgorde (HIGH)

Top-down te ontkoppelen in drie blokken:

### Blok A — Quick wins / mutes (groot effect op aantallen, weinig werk)

1. **`guardduty_delegated_admin_enabled_all_regions`** (51) — mutelist toevoegen, niet bruikbare regions.
2. **`securityhub_enabled`** (50) — `inbo-aws-security-hub-terraform` uitrollen of mutelist voor unused regions.
3. **`secretsmanager_automatic_rotation_enabled`** (135) — review per secret; 3rd-party API keys & OIDC zijn niet rotateable → mutelist met patterns. RDS-secrets: rotatie toevoegen.
4. **`secretsmanager_has_restrictive_resource_policy`** (148) — meeste secrets accepted risk (IAM is genoeg); mutelist met patterns of resource-policies toevoegen via terraform.

### Blok B — Echte fixes (HOOG prio, beperkte scope)

5. **`ecs_task_definitions_containers_readonly_access`** (6) — afmaken voor wazuh, vbp-grafana, watina-app, ipt-vbp-app. Volg patroon uit `readonly-rootfs-werkplan.md`.
6. **`iam_role_administratoraccess_policy`** (1, uat: `inbo-adviezen-rds-connect-role`) — least-privilege policy maken.
7. **`route53_domains_transferlock_enabled`** (1: `neobiota2026.org`) — eenmalige toggle.
8. **`ec2_ebs_volume_encryption`** (2) — default EBS encryption enablen op accountniveau, oude volumes herversleutelen.
9. **`iam_inline_policy_allows_privilege_escalation`** (32) — meeste in mutelist (CloudHealth, ShinyProxy etc.); echte fixes voor n2kmonitoring, mne-sampling, ckan, vertigis. Per resource bekijken.
10. **`iam_policy_allows_privilege_escalation`** (5) — `inbo-developers-policy` en `inbo-bastion-bastion-ssm-policy` reviewen.

### Blok C — Strategisch / langere doorlooptijd

11. **`ec2_ebs_snapshots_encrypted`** (252) — cleanup oude orphan-snapshots; remaining: bulk copy-with-encryption + delete old. EBS default encryption permanent enablen.
12. **`rds_instance_protected_by_backup_plan`** + **`rds_cluster_protected_by_backup_plan`** (13+4) — uitbreiden van `inbo-aws-backup-terraform`.
13. **`ec2_ebs_volume_snapshots_exists`** (28) — backup plan of accepteren voor stateless volumes.
14. **`iam_user_with_temporary_credentials`** + **`iam_user_hardware_mfa_enabled`** (17+17, overlappend) — migratie naar IAM Identity Center / OIDC.
15. **`vpc_endpoint_connections_trust_boundaries`** (6) — endpoint policies restrictiever.
16. **`ec2_networkacl_allow_ingress_any_port`** (6) — NACLs reviewen per VPC.
17. **`ec2_securitygroup_allow_ingress_from_internet_to_any_port`** (1) — review.

---


---

# CRITICAL (0 actieve findings)

Geen actieve critical findings (alle 17 zitten in mutelist):

- `iam_root_hardware_mfa_enabled` (4): west-1-<root_account>
- `iam_aws_attached_policy_no_administrative_privileges` (3): west-1-AdministratorAccess
- `ecs_task_definitions_no_environment_secrets` (3): west-1-inbo-bodem-dov-etl:13, west-1-inbo-bodem-dov-etl:3, west-1-inbo-watina-dov-etl:7
- `iam_user_administrator_access_policy` (2): west-1-bert.huygens@inbo.be
- `s3_bucket_public_access` (2): west-1-aloftdata, west-1-inbo-aloft-uat-eu-west-1-default
- `awslambda_function_no_secrets_in_code` (2): west-1-inbo-vbp-biocache-index-management
- `s3_bucket_public_list_acl` (1): west-1-inbo-aloft-uat-eu-west-1-default

---

# HIGH (409 actieve findings)

## 1. `ec2_ebs_snapshots_encrypted` — 252 resources

- **Probleem:** Onversleutelde EBS snapshots bevatten mogelijk gevoelige data zonder rust-encryptie.
- **Fix:** Snapshots zelf zijn immutable. Strategie: (1) maak een copy met encryption enabled, (2) verwijder de oude. Run via script of CLI. Op accountniveau kan ook EBS default encryption aangezet worden.
- **Prioriteit:** Bulk - mass cleanup mogelijk; oude snapshots evalueren of nog nodig

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 148 | **snapshots zelf (niet via terraform)**: west-1-snap-00174b38b8d971c67, west-1-snap-002cf43d187d807e0, west-1-snap-007ed2f6d9683664b, west-1-snap-00827ca732ff5bba1, west-1-snap-009a6d30e0f3c92a8, ... +143 |
| inbo-prod | 104 | **snapshots zelf (niet via terraform)**: west-1-snap-000790c4660b03d9c, west-1-snap-001b968dbd223a0ae, west-1-snap-004c3290813d70840, west-1-snap-0064fef98f1daa3aa, west-1-snap-00695de53670dbf43, ... +99 |

## 2. `iam_inline_policy_allows_privilege_escalation` — 32 resources

- **Probleem:** Inline policies met iam:PassRole + service action kunnen privilege escalation toelaten.
- **Fix:** Beperk iam:PassRole tot specifieke role ARNs. Of accept als de policy al beperkt is (zie mutelist-verantwoording.md).
- **Prioriteit:** Per resource bekijken

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 6 | **AWS managed**: west-1-BillingConsolePolicyMigratorRole/BillingConsolePolicyMigratorRolePolicy<br>**inbo-aws-mne-sampling-terraform**: west-1-inbo-mne-sampling-developers-role/inbo-mne-sampling-developers-role-policy<br>**inbo-aws-n2kmonitoring-terraform**: west-1-inbo-n2kmonitoring-analytics-role/terraform-20250930134320925600000001, west-1-inbo-n2kmonitoring-shared-infra-ec2-role/n2kmonitoring-ec2-s3-policy, west-1-inbo-n2kmonitoring-shared-infra-eu-west-1-unittest-role/terraform-20250127144032629000000001, west-1-inbo-n2kmonitoring-shared-infra-s3-default/inbo-allow-writing-in-inbo-n2kmonitoring-shared-infra-eu-west-1-default |
| inbo-dev | 3 | **AWS managed**: west-1-BillingConsolePolicyMigratorRole/BillingConsolePolicyMigratorRolePolicy<br>**inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-pipelines-emr-service-role/inbo-vbp-pipelines-emr-service-policy<br>**inbo-aws-watina-terraform**: west-1-inbo-watina-github-actions-deploy-lambda-role/inbo-watina-dev-github-actions-lambda-deploy |
| inbo-uat | 10 | **AWS managed**: west-1-BillingConsolePolicyMigratorRole/BillingConsolePolicyMigratorRolePolicy<br>**inbo-aws-aloft-terraform (PRIVATE)**: west-1-inbo-aloft-eventbridge-scheduler/inbo-aloft-eventbridge-sheduler-ftp-policy, west-1-inbo-aloft-eventbridge-scheduler/inbo-aloft-eventbridge-sheduler-sync-policy<br>**inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-pipelines-emr-service-role/inbo-vbp-pipelines-emr-service-policy<br>**inbo-aws-bodem-terraform**: west-1-inbo-bodem-role/inbo-bodem-ecs-task-management-policy<br>**inbo-aws-exotenportaal-terraform**: west-1-inbo-exotenportaal-shinyproxy-task-role/inbo-exotenportaal-shinyproxy-allow-run-exotenportaal-portal-policy<br>**inbo-aws-faunabeheer-terraform**: west-1-inbo-faunabeheer-shinyproxy-faunabeheer-task-role/inbo-faunabeheer-shinyproxy-faunabeheer-allow-run-faunabeheer-portal-policy, west-1-inbo-faunabeheer-shinyproxy-wbe-task-role/inbo-faunabeheer-shinyproxy-wbe-allow-run-wbe-portal-policy<br>**inbo-aws-watina-dov-terraform**: west-1-inbo-watina-dov-role/inbo-watina-dov-ecs-task-management-policy<br>**inbo-aws-watina-terraform**: west-1-inbo-watina-github-actions-deploy-lambda-role/inbo-watina-uat-github-actions-lambda-deploy |
| inbo-prod | 13 | **AWS managed**: west-1-BillingConsolePolicyMigratorRole/BillingConsolePolicyMigratorRolePolicy<br>**inbo-aws-aloft-terraform (PRIVATE)**: west-1-inbo-aloft-eventbridge-scheduler/inbo-aloft-eventbridge-sheduler-ftp-policy, west-1-inbo-aloft-eventbridge-scheduler/inbo-aloft-eventbridge-sheduler-sync-policy<br>**inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-pipelines-emr-service-role/inbo-vbp-pipelines-emr-service-policy<br>**inbo-aws-bodem-terraform**: west-1-inbo-bodem-role/inbo-bodem-ecs-task-management-policy<br>**inbo-aws-ckan-terraform**: west-1-inbo-ckan-developer-role/inbo-ckan-developer-policy, west-1-inbo-ckan-lambda-secret-rotation-role/inbo-ckan-lambda-secret-rotation-policy<br>**inbo-aws-exotenportaal-terraform**: west-1-inbo-exotenportaal-shinyproxy-task-role/inbo-exotenportaal-shinyproxy-allow-run-exotenportaal-portal-policy<br>**inbo-aws-faunabeheer-terraform**: west-1-inbo-faunabeheer-shinyproxy-faunabeheer-task-role/inbo-faunabeheer-shinyproxy-faunabeheer-allow-run-faunabeheer-portal-policy, west-1-inbo-faunabeheer-shinyproxy-wbe-task-role/inbo-faunabeheer-shinyproxy-wbe-allow-run-wbe-portal-policy<br>**inbo-aws-vertigis-terraform**: west-1-inbo-vertigis-developer-role/inbo-vertigis-developer-policy, west-1-inbo-vertigis-external-siggis-user/inbo-vertigis-external-ssm-policy<br>**inbo-aws-watina-terraform**: west-1-inbo-watina-github-actions-deploy-lambda-role/inbo-watina-prod-github-actions-lambda-deploy |

## 3. `ec2_ebs_volume_snapshots_exists` — 28 resources

- **Probleem:** EBS volumes hebben geen recente snapshots.
- **Fix:** Backup plans/AWS Backup configureren waar nodig.
- **Prioriteit:** Per resource - sommige stateless

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 8 | **onbekend**: west-1-vol-0058d94f2c0ab80e7, west-1-vol-0177b8f0ae49e169f, west-1-vol-02ae5a45b6120acb9, west-1-vol-04232ed0dfe89d51e, west-1-vol-0b4bb459de4dfab9d, ... +3 |
| inbo-prod | 20 | **onbekend**: west-1-vol-0064ad98c4569dfe7, west-1-vol-029ff3c675c5dcce4, west-1-vol-02c79a687075c9403, west-1-vol-02e002fba396649d7, west-1-vol-0315bbd69d6eeb80b, ... +15 |

## 4. `iam_user_with_temporary_credentials` — 17 resources

- **Probleem:** IAM users zouden geen long-lived credentials moeten hebben.
- **Fix:** Migreer naar IAM Identity Center / OIDC.
- **Prioriteit:** Migratie naar IAM Identity Center

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 6 | **inbo-aws-aloft-terraform (PRIVATE)**: west-1-inbo-aloft-ecr-deployment<br>**inbo-aws-n2kmonitoring-terraform**: west-1-inbo-n2kmonitoring-shared-infra-s3-default<br>**inbo-aws-pure-terraform**: west-1-inbo-pure-sync-elsevier-user<br>**onbekend**: west-1-inbo-appsheet-s3, west-1-joris-bongers, west-1-otobo-ses-smtp |
| inbo-dev | 3 | **inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-BiocacheServiceEmail, west-1-inbo-vbp-ImageService, west-1-inbo-vbp-KeycloakEmail |
| inbo-prod | 8 | **inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-BiocacheServiceEmail, west-1-inbo-vbp-ImageService, west-1-inbo-vbp-KeycloakEmail<br>**inbo-aws-keycloak-terraform**: west-1-inbo-keycloak-smtp-user-auth-inbo-be<br>**inbo-aws-vertigis-terraform**: west-1-inbo-vertigis-external-siggis-user, west-1-inbo-vertigis-ses-smtp-inbo-argisenterprise-user, west-1-inbo-vertigis-ses-smtp-vespawatch-user<br>**inbo-aws-vespadb-terraform**: west-1-inbo-vespadb-ses-smtp-user |

## 5. `iam_user_hardware_mfa_enabled` — 17 resources

- **Probleem:** IAM users moeten hardware MFA gebruiken.
- **Fix:** Migreer users naar IAM Identity Center, of virtuele MFA als alternatief.
- **Prioriteit:** Migratie naar IAM Identity Center

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 6 | **inbo-aws-aloft-terraform (PRIVATE)**: west-1-inbo-aloft-ecr-deployment<br>**inbo-aws-n2kmonitoring-terraform**: west-1-inbo-n2kmonitoring-shared-infra-s3-default<br>**inbo-aws-pure-terraform**: west-1-inbo-pure-sync-elsevier-user<br>**onbekend**: west-1-inbo-appsheet-s3, west-1-joris-bongers, west-1-otobo-ses-smtp |
| inbo-dev | 3 | **inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-BiocacheServiceEmail, west-1-inbo-vbp-ImageService, west-1-inbo-vbp-KeycloakEmail |
| inbo-prod | 8 | **inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-BiocacheServiceEmail, west-1-inbo-vbp-ImageService, west-1-inbo-vbp-KeycloakEmail<br>**inbo-aws-keycloak-terraform**: west-1-inbo-keycloak-smtp-user-auth-inbo-be<br>**inbo-aws-vertigis-terraform**: west-1-inbo-vertigis-external-siggis-user, west-1-inbo-vertigis-ses-smtp-inbo-argisenterprise-user, west-1-inbo-vertigis-ses-smtp-vespawatch-user<br>**inbo-aws-vespadb-terraform**: west-1-inbo-vespadb-ses-smtp-user |

## 6. `secretsmanager_has_restrictive_resource_policy` — 15 resources

- **Probleem:** Secrets zonder resource policy zijn enkel beperkt via IAM. Aanbevolen is een resource policy.
- **Fix:** Voeg een aws_secretsmanager_secret_policy toe per secret in de relevante terraform projecten. Of accept dit als risk (IAM is genoeg) en zet in mutelist.
- **Prioriteit:** Reviewen - veel resources, mogelijk accepted risk

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **inbo-aws-* (per app secrets)**: west-1-/inbo/utility/rds/mysql/root |
| inbo-dev | 3 | **inbo-aws-* (per app secrets)**: west-1-/inbo/adviezen/rds/postgres/adviezen, west-1-/inbo/bookstack/rds/mysql/master, west-1-/inbo/keycloak/rds/postgres/master |
| inbo-prod | 11 | **inbo-aws-* (per app secrets)**: west-1-/inbo/adviezen/rds/postgres/adviezen, west-1-/inbo/bruinerat/rds/postgres/default, west-1-/inbo/ckan/rds/postgres/inbo, west-1-/inbo/ckan/rds/postgres/inbo_read, west-1-/inbo/ckan/rds/postgres/inbo_write, ... +5<br>**inbo-aws-landbouwtellingen-terraform**: west-1-/inbo/lbt/rds/postgres/landbouwtellingen |

## 7. `rds_instance_protected_by_backup_plan` — 13 resources

- **Probleem:** RDS instance zonder backup plan.
- **Fix:** Voeg toe aan AWS Backup plan in inbo-aws-backup-terraform.
- **Prioriteit:** inbo-aws-backup-terraform aanpassen

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 2 | **inbo-aws-snipeit-terraform**: west-1-inbo-snipeit-mysql<br>**inbo-aws-utility-terraform**: west-1-inbo-utility-shared-infra |
| inbo-dev | 3 | **inbo-aws-adviezen-terraform**: west-1-inbo-adviezen-dev<br>**inbo-aws-bookstack-terraform**: west-1-inbo-bookstack-dev<br>**inbo-aws-keycloak-terraform**: west-1-inbo-keycloak-dev |
| inbo-prod | 8 | **inbo-aws-adviezen-terraform**: west-1-inbo-adviezen-prod<br>**inbo-aws-bruinerat-terraform**: west-1-inbo-bruinerat-prod<br>**inbo-aws-ckan-terraform**: west-1-inbo-ckan<br>**inbo-aws-keycloak-terraform**: west-1-inbo-keycloak-prod<br>**inbo-aws-landbouwtellingen-terraform**: west-1-inbo-lbt-prod<br>**inbo-aws-meetnetten-terraform**: west-1-inbo-meetnetten-prod<br>**inbo-aws-vespadb-terraform**: west-1-inbo-vespadb-prod<br>**inbo-aws-waterbirds-terraform**: west-1-inbo-waterbirds-prod |

## 8. `vpc_endpoint_connections_trust_boundaries` — 6 resources

- **Probleem:** VPC endpoint policies te ruim.
- **Fix:** Restrictieve endpoint policies toevoegen.
- **Prioriteit:** Per endpoint bekijken

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **onbekend**: west-1-vpce-06dfec918937433dc |
| inbo-dev | 4 | **onbekend**: west-1-vpce-046bea462bd9d8d1b, west-1-vpce-056670b4168f9a6d9, west-1-vpce-0823249730edf000d, west-1-vpce-089e220ba15c1dfb0 |
| inbo-prod | 1 | **onbekend**: west-1-vpce-05892ae72609e681f |

## 9. `ecs_task_definitions_containers_readonly_access` — 6 resources

- **Probleem:** Containers moeten read-only root filesystem hebben voor defense in depth.
- **Fix:** Zet readonlyRootFilesystem=true in container definition. Gebruik tmpfs/volumes voor writable paths. Zie readonly-rootfs-werkplan.md voor patroon.
- **Prioriteit:** HOOG - oplosbaar per app, geen breaking changes verwacht

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 3 | **inbo-aws-wazuh-terraform**: west-1-inbo-wazuh-dashboard:8, west-1-inbo-wazuh-indexer:10, west-1-inbo-wazuh-manager:6 |
| inbo-dev | 2 | **inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-grafana:5<br>**inbo-aws-watina-terraform**: west-1-inbo-watina-app:17 |
| inbo-prod | 1 | **inbo-aws-ipt-terraform**: west-1-ipt-vbp-app:3 |

## 10. `ec2_networkacl_allow_ingress_any_port` — 6 resources

- **Probleem:** Network ACL te open.
- **Fix:** Beperk NACL rules.
- **Prioriteit:** Per VPC reviewen

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 2 | **onbekend**: west-1-acl-05809b3f3631fc9bb, west-1-acl-0fad35584fdf200f9 |
| inbo-dev | 2 | **onbekend**: west-1-acl-031c97f07b284f515, west-1-acl-0cd81a37a32428da2 |
| inbo-prod | 2 | **onbekend**: west-1-acl-0315ecacbe3026ab3, west-1-acl-0e4f9c972cd192edb |

## 11. `iam_policy_allows_privilege_escalation` — 5 resources

- **Probleem:** Managed policies met privilege escalation patronen.
- **Fix:** Beperk iam:PassRole tot specifieke ARNs. Soms accepted risk (EMR service).
- **Prioriteit:** Per resource bekijken

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **verschillende (zie resource)**: west-1-inbo-developers-policy |
| inbo-dev | 2 | **verschillende (zie resource)**: west-1-inbo-bastion-bastion-ssm-policy, west-1-inbo-developers-policy |
| inbo-prod | 2 | **verschillende (zie resource)**: west-1-inbo-bastion-bastion-ssm-policy, west-1-inbo-developers-policy |

## 12. `rds_cluster_protected_by_backup_plan` — 4 resources

- **Probleem:** RDS cluster zonder backup plan.
- **Fix:** Voeg toe aan AWS Backup plan.
- **Prioriteit:** inbo-aws-backup-terraform aanpassen

| Account | Aantal | Resources |
|---|---|---|
| inbo-dev | 2 | **inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-mysql, west-1-inbo-vbp-postgres |
| inbo-prod | 2 | **inbo-aws-biodiversiteitsportaal-terraform (PRIVATE)**: west-1-inbo-vbp-mysql, west-1-inbo-vbp-postgres |

## 13. `secretsmanager_automatic_rotation_enabled` — 2 resources

- **Probleem:** Automatische rotatie van secrets is een best practice.
- **Fix:** Niet alle secrets zijn rotateable (3rd party API keys, OIDC secrets). Voor RDS-secrets: stel rotatie in via Secrets Manager. Voor de meeste secrets: accepted risk.
- **Prioriteit:** Reviewen - meeste zijn niet rotateable, mutelist

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **inbo-aws-* (per app secrets)**: west-1-/inbo/utility/rds/mysql/root |
| inbo-dev | 1 | **inbo-aws-* (per app secrets)**: west-1-/inbo/bookstack/rds/mysql/master |

## 14. `ec2_ebs_volume_encryption` — 2 resources

- **Probleem:** EBS volume niet encrypted.
- **Fix:** Enable EBS default encryption op account level.
- **Prioriteit:** Enable default EBS encryption

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **onbekend**: west-1-vol-041c79923a0b2088e |
| inbo-prod | 1 | **onbekend**: west-1-vol-05400ce6c1c3390a1 |

## 15. `s3_bucket_level_public_access_block` — 1 resources

- **Probleem:** Bucket-level public access block is uitgeschakeld.
- **Fix:** Voor aloftdata intentioneel. Voor andere buckets: enable.
- **Prioriteit:** GEMUTE (aloft) / fixen voor andere

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **inbo-aws-pure-terraform**: west-1-inbo-pure-idpm |

## 16. `route53_domains_transferlock_enabled` — 1 resources

- **Probleem:** Route53 domain transfer lock niet enabled.
- **Fix:** Enable transfer lock via Route53.
- **Prioriteit:** Eénmalige fix

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **onbekend**: east-1-neobiota2026.org |

## 17. `ec2_securitygroup_allow_ingress_from_internet_to_any_port` — 1 resources

- **Probleem:** Security group open voor internet.
- **Fix:** Beperk SG rules.
- **Prioriteit:** Per SG reviewen

| Account | Aantal | Resources |
|---|---|---|
| inbo-shared-infra | 1 | **onbekend**: west-1-sg-042bb0ec5df9a0bf8 |

## 18. `iam_role_administratoraccess_policy` — 1 resources

- **Probleem:** Roles met volledige AdministratorAccess.
- **Fix:** Vervang door least-privilege policy. Of accept (DevOps, OrganizationAccountAccessRole).
- **Prioriteit:** Per resource bekijken

| Account | Aantal | Resources |
|---|---|---|
| inbo-uat | 1 | **inbo-aws-adviezen-terraform**: west-1-inbo-adviezen-rds-connect-role |


---

# MEDIUM (2675 actieve findings) — beknopt

Enkel telling per check per account. Voor details zie `/tmp/all_fail_findings.json` of run het script opnieuw.

| Check | shared-infra | dev | uat | prod | Totaal |
|---|---|---|---|---|---|
| `cloudwatch_log_group_kms_encryption_enabled` | 21 | 24 | 39 | 208 | **292** |
| `secretsmanager_secret_rotated_periodically` | 10 | 64 | 62 | 69 | **205** |
| `backup_recovery_point_encrypted` | 76 | - | - | 106 | **182** |
| `cloudwatch_log_group_retention_policy_specific_days_enabled` | 19 | 30 | 45 | 54 | **148** |
| `trustedadvisor_errors_and_warnings` | 30 | 24 | 32 | 50 | **136** |
| `ecr_repositories_tag_immutability` | 57 | 30 | - | 1 | **88** |
| `s3_bucket_no_mfa_delete` | 11 | 21 | 24 | 27 | **83** |
| `s3_bucket_server_access_logging_enabled` | 11 | 21 | 23 | 26 | **81** |
| `s3_bucket_secure_transport_policy` | 10 | 20 | 23 | 25 | **78** |
| `rds_instance_event_subscription_security_groups` | 17 | 17 | 17 | 17 | **68** |
| `inspector2_is_enabled` | 17 | 17 | 17 | 17 | **68** |
| `drs_job_exist` | 17 | 17 | 17 | 17 | **68** |
| `config_recorder_all_regions_enabled` | 17 | 17 | 17 | 17 | **68** |
| `bedrock_model_invocation_logging_enabled` | 17 | 17 | 17 | 17 | **68** |
| `ec2_ebs_volume_protected_by_backup_plan` | 15 | 6 | - | 37 | **58** |
| `efs_not_publicly_accessible` | 3 | 19 | 13 | 22 | **57** |
| `efs_have_backup_enabled` | 3 | 19 | 13 | 22 | **57** |
| `rds_instance_critical_event_subscription` | 17 | 17 | - | 17 | **51** |
| `s3_bucket_kms_encryption` | 6 | 11 | 13 | 17 | **47** |
| `elbv2_logging_enabled` | 5 | 9 | 12 | 17 | **43** |
| `elbv2_waf_acl_attached` | 4 | 9 | 12 | 17 | **42** |
| `ecr_repositories_scan_images_on_push_enabled` | 5 | 30 | - | - | **35** |
| `awslambda_function_no_dead_letter_queue` | 5 | 9 | - | 21 | **35** |
| `rds_cluster_critical_event_subscription` | - | 17 | - | 17 | **34** |
| `stepfunctions_statemachine_logging_enabled` | - | 9 | 9 | 9 | **27** |
| `ecr_repositories_scan_vulnerabilities_in_latest_image` | 26 | - | - | - | **26** |
| `iam_role_access_not_stale_to_bedrock` | 9 | 8 | - | 8 | **25** |
| `elbv2_deletion_protection` | 1 | 9 | 12 | 3 | **25** |
| `rds_instance_integration_cloudwatch_logs` | 2 | 5 | 5 | 10 | **22** |
| `iam_rotate_access_key_90_days` | 7 | 4 | 5 | 6 | **22** |
| `s3_bucket_object_versioning` | - | 9 | 6 | 5 | **20** |
| `rds_instance_multi_az` | 2 | 5 | 5 | 7 | **19** |
| `cloudfront_distributions_logging_enabled` | 3 | 6 | 4 | 6 | **19** |
| `rds_instance_extended_support` | 2 | 5 | - | 10 | **17** |
| `cloudfront_distributions_using_waf` | 2 | 5 | 4 | 6 | **17** |
| `route53_public_hosted_zones_cloudwatch_logging_enabled` | 10 | 1 | 2 | 2 | **15** |
| `cloudformation_stacks_termination_protection_enabled` | 3 | 3 | 3 | 5 | **14** |
| `secretsmanager_secret_unused` | 3 | 3 | 2 | 4 | **12** |
| `efs_multi_az_enabled` | - | 6 | - | 6 | **12** |
| `s3_bucket_acl_prohibited` | 2 | 1 | 5 | 3 | **11** |
| `dynamodb_table_protected_by_backup_plan` | 2 | 3 | 3 | 3 | **11** |
| `rds_instance_deletion_protection` | - | 5 | 5 | - | **10** |
| `autoscaling_group_multiple_instance_types` | 1 | 3 | 3 | 3 | **10** |
| `iam_user_accesskey_unused` | 5 | 2 | 2 | - | **9** |
| `cloudwatch_log_group_no_secrets_in_logs` | 2 | 2 | 2 | 3 | **9** |
| `awslambda_function_env_vars_not_encrypted_with_cmk` | 1 | 4 | - | 4 | **9** |
| `efs_access_point_enforce_root_directory` | - | 1 | 2 | 5 | **8** |
| `ec2_networkacl_allow_ingress_tcp_port_3389` | 2 | 2 | 2 | 2 | **8** |
| `ec2_networkacl_allow_ingress_tcp_port_22` | 2 | 2 | 2 | 2 | **8** |
| `wafv2_webacl_logging_enabled` | 3 | 2 | 1 | 1 | **7** |
| `macie_is_enabled` | 1 | 2 | 2 | 2 | **7** |
| `s3_bucket_event_notifications_enabled` | - | - | 7 | - | **7** |
| `rds_instance_iam_authentication_enabled` | 1 | 1 | 1 | 3 | **6** |
| `rds_cluster_multi_az` | - | 2 | 2 | 2 | **6** |
| `rds_cluster_integration_cloudwatch_logs` | - | 2 | 2 | 2 | **6** |
| `ecs_cluster_container_insights_enabled` | - | 2 | 2 | 2 | **6** |
| `cloudtrail_logs_s3_bucket_access_logging_enabled` | 1 | 2 | 1 | 1 | **5** |
| `cloudtrail_kms_encryption_enabled` | 1 | 2 | 1 | 1 | **5** |
| `cloudtrail_bucket_requires_mfa_delete` | 1 | 2 | 1 | 1 | **5** |
| `rds_instance_protected_by_backup_plan` | - | - | 5 | - | **5** |
| `vpc_endpoint_for_ec2_enabled` | 1 | 1 | 1 | 1 | **4** |
| `vpc_different_regions` | 1 | 1 | 1 | 1 | **4** |
| `networkfirewall_in_all_vpc` | 1 | 1 | 1 | 1 | **4** |
| `iam_user_two_active_access_key` | 1 | 1 | 1 | 1 | **4** |
| `iam_user_console_access_unused` | 1 | 1 | 1 | 1 | **4** |
| `dlm_ebs_snapshot_lifecycle_policy_exists` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_log_metric_filter_unauthorized_api_calls` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_log_metric_filter_security_group_changes` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_log_metric_filter_aws_organizations_changes` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_log_metric_filter_authentication_failures` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_changes_to_vpcs_alarm_configured` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_changes_to_network_route_tables_alarm_configured` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_changes_to_network_gateways_alarm_configured` | 1 | 1 | 1 | 1 | **4** |
| `cloudwatch_changes_to_network_acls_alarm_configured` | 1 | 1 | 1 | 1 | **4** |
| `autoscaling_group_multiple_az` | - | 2 | 2 | - | **4** |
| `account_maintain_different_contact_details_to_security_billing_and_operations` | 1 | 1 | 1 | 1 | **4** |
| `iam_user_with_temporary_credentials` | - | - | 4 | - | **4** |
| `iam_user_hardware_mfa_enabled` | - | - | 4 | - | **4** |
| `elbv2_insecure_ssl_ciphers` | - | - | 2 | 2 | **4** |
| `ssmincidents_enabled_with_plans` | 1 | 1 | - | 1 | **3** |
| `rds_instance_backup_enabled` | - | 3 | - | - | **3** |
| `dynamodb_table_deletion_protection_enabled` | - | 1 | 1 | 1 | **3** |
| `cognito_identity_pool_guest_access_disabled` | - | 1 | 1 | 1 | **3** |
| `vpc_endpoint_multi_az_enabled` | - | 2 | - | - | **2** |
| `rds_cluster_deletion_protection` | - | 2 | - | - | **2** |
| `ec2_securitygroup_allow_ingress_from_internet_to_any_port_from_ip` | - | 1 | - | 1 | **2** |
| `apigatewayv2_api_authorizers_enabled` | 1 | 1 | - | - | **2** |
| `apigatewayv2_api_access_logging_enabled` | 1 | 1 | - | - | **2** |
| `wafv2_webacl_rule_logging_enabled` | 2 | - | - | - | **2** |
| `rds_instance_minor_version_upgrade_enabled` | 1 | - | - | 1 | **2** |
| `iam_user_access_not_stale_to_bedrock` | 1 | - | - | 1 | **2** |
| `ec2_securitygroup_from_launch_wizard` | 1 | - | - | 1 | **2** |
| `ec2_instance_older_than_specific_days` | 2 | - | - | - | **2** |
| `rds_cluster_protected_by_backup_plan` | - | - | 2 | - | **2** |
| `ec2_networkacl_allow_ingress_any_port` | - | - | 2 | - | **2** |
| `cloudtrail_log_file_validation_enabled` | - | 1 | - | - | **1** |
| `elbv2_nlb_tls_termination_enabled` | 1 | - | - | - | **1** |
| `efs_access_point_enforce_user_identity` | 1 | - | - | - | **1** |
| `ec2_instance_managed_by_ssm` | 1 | - | - | - | **1** |
| `vpc_endpoint_connections_trust_boundaries` | - | - | 1 | - | **1** |
| `secretsmanager_automatic_rotation_enabled` | - | - | 1 | - | **1** |
| `rds_cluster_backtrack_enabled` | - | - | 1 | - | **1** |
| `iam_support_role_created` | - | - | 1 | - | **1** |
| `awslambda_function_using_supported_runtimes` | - | - | - | 1 | **1** |


---

# LOW (945 actieve findings) — beknopt

Enkel telling per check per account. Voor details zie `/tmp/all_fail_findings.json` of run het script opnieuw.

| Check | shared-infra | dev | uat | prod | Totaal |
|---|---|---|---|---|---|
| `ecs_task_definitions_logging_block_mode` | 6 | 39 | 84 | 92 | **221** |
| `s3_bucket_cross_region_replication` | 11 | 21 | 24 | 27 | **83** |
| `s3_bucket_object_lock` | 11 | 20 | 24 | 27 | **82** |
| `rds_instance_event_subscription_parameter_groups` | 17 | 17 | 17 | 17 | **68** |
| `accessanalyzer_enabled` | 17 | 17 | 17 | 17 | **68** |
| `s3_bucket_lifecycle_enabled` | 10 | 16 | 19 | 22 | **67** |
| `ec2_securitygroup_not_used` | 5 | 14 | 23 | 14 | **56** |
| `awslambda_function_inside_vpc` | 5 | 6 | 8 | 18 | **37** |
| `ecr_repositories_lifecycle_policy_enabled` | 6 | 30 | - | - | **36** |
| `iam_policy_attached_only_to_group_or_roles` | 7 | 4 | 5 | 10 | **26** |
| `rds_instance_non_default_port` | 2 | 5 | 5 | 10 | **22** |
| `rds_instance_enhanced_monitoring_enabled` | 2 | 5 | 5 | 10 | **22** |
| `cloudfront_distributions_field_level_encryption_enabled` | 3 | 7 | 5 | 7 | **22** |
| `s3_bucket_event_notifications_enabled` | 2 | 10 | - | 6 | **18** |
| `rds_instance_copy_tags_to_snapshots` | 2 | 3 | 5 | 8 | **18** |
| `rds_instance_critical_event_subscription` | - | - | 17 | - | **17** |
| `rds_cluster_critical_event_subscription` | - | - | 17 | - | **17** |
| `ec2_instance_detailed_monitoring_enabled` | 11 | - | - | 4 | **15** |
| `ec2_instance_uses_single_eni` | - | 2 | - | 6 | **8** |
| `rds_cluster_non_default_port` | - | 2 | 2 | 2 | **6** |
| `rds_cluster_copy_tags_to_snapshots` | - | 2 | 2 | 2 | **6** |
| `cloudtrail_insights_exist` | 1 | 2 | 1 | 1 | **5** |
| `cloudtrail_cloudwatch_logging_enabled` | 1 | 2 | 1 | 1 | **5** |
| `iam_check_saml_providers_sts` | 1 | 1 | 1 | 1 | **4** |
| `backup_reportplans_exist` | 1 | 1 | 1 | 1 | **4** |
| `iam_support_role_created` | 1 | 1 | - | 1 | **3** |
| `rds_cluster_backtrack_enabled` | - | 1 | - | 1 | **2** |
| `rds_cluster_deletion_protection` | - | - | 2 | - | **2** |
| `ec2_ebs_volume_protected_by_backup_plan` | - | - | 2 | - | **2** |
| `kms_cmk_are_used` | - | 1 | - | - | **1** |
| `cloudfront_distributions_geo_restrictions_enabled` | - | 1 | - | - | **1** |
| `ssmincidents_enabled_with_plans` | - | - | 1 | - | **1** |
