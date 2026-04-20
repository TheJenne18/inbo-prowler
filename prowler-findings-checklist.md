# Prowler Findings Checklist - INBO

Opgehaald op: 2026-04-11
Bron: prowler.inbo.be (actieve, niet-gemute findings)
Totaal: 111 unieke findings, 8 check-types

## Accounts
- `800040084629` = inbo-prod
- `625469168093` = inbo-uat
- `347082780157` = inbo-shared-infra

---

## CRITICAL

### 1. [x] ECS task definition secrets in environment variables — GEMUTE (false positive, ARN-referenties)
- **Check:** `ecs_task_definitions_no_environment_secrets`
- **Resource:** `inbo-watina-dov-etl` rev 6 (account: 625469168093 / uat)
- **Probleem:** Secrets (DOV_WEB_SERVER_KEYS_SECRET_ARN, DATABASE_CREDENTIALS_SECRET_ARN) staan als plaintext env vars
- **Fix:** Gebruik ECS `secrets` block i.p.v. `environment` om te refereren naar Secrets Manager/SSM
- **Terraform project:** `inbo-aws-watina-dov-terraform`

---

## HIGH - Oplosbaar via Terraform

### 2. [ ] ECS containers zonder read-only root filesystem (87 resources)
- **Check:** `ecs_task_definitions_containers_readonly_access`
- **Probleem:** Containers hebben write access tot root filesystem
- **Fix:** Zet `readonlyRootFilesystem = true` in container definitions, gebruik tmpfs mounts waar nodig
- **Betrokken projecten (gegroepeerd per applicatie):**
  - adviezen (api, webdav)
  - aloft (sync, baltrad, backlog)
  - bobo
  - bodem (dov-etl)
  - bruinerat
  - exotenportaal (shinyproxy)
  - faunabeheer (shinyproxy)
  - flora (api)
  - ipt (app, dev-app)
  - keycloak
  - lbt (app, redis)
  - meetnetten
  - vbp (alle ALA services + shinyproxy task defs)
  - vespadb (django, node, redis)
  - vis
  - waterbirds
  - watina
  - wbe (shinyproxy)
  - snipeit (shared-infra)
  - mne-sampling (shared-infra)
  - dwca-to-verbatim, download-data-resources (vbp pipelines)

### 3. [x] IAM roles zonder confused deputy preventie (8 resources)
- **Check:** `iam_role_cross_service_confused_deputy_prevention`
- **Resources:**
  - `inbo-waterbirds-lambda-secret-rotation-role` (prod + uat) — **PR: https://github.com/inbo/inbo-aws-waterbirds-terraform/pull/8**
  - `inbo-waterbirds-lambda-dbuser-secret-rotation-role` (prod + uat) — **PR: https://github.com/inbo/inbo-aws-waterbirds-terraform/pull/8**
  - `inbo-waterbirds-app-task-role` (prod + uat) — code al correct, needs apply
  - `inbo-role-aws-backups` (uat) — code al correct, needs `terragrunt apply` in `inbo-aws-backup-terraform/global/inbo-uat/global/`
  - `AWS-QuickSetup-StackSet-Local-AdministrationRole` (shared-infra) — AWS managed, niet in Terraform
- **Status:** PR gemaakt voor lambda roles. Backup + app-task-role hebben code al correct, moeten enkel ge-applied worden.
- **Na merge waterbirds PR:** Import bestaande roles in state, dan apply. Zie PR beschrijving voor commando's.

### 4. [x] IAM inline policies met privilege escalation (6 resources) — GEMUTE (accepted risk)
- **Check:** `iam_inline_policy_allows_privilege_escalation`
- **Resources:**
  - `inbo-watina-github-actions-deploy-lambda-role` (prod + uat) — iam:PassRole + lambda:*
  - `inbo-vbp-pipelines-emr-service-role` (prod) — iam:PassRole
  - `inbo-exotenportaal-shinyproxy-task-role` (prod + uat) — ecs:RunTask + iam:PassRole
  - `inbo-watina-dov-role` (uat) — ecs:RunTask + iam:PassRole
- **Fix:** Beperk iam:PassRole tot specifieke resource ARNs
- **Terraform projecten:** `inbo-aws-watina-terraform`, `inbo-aws-watina-dov-terraform`, `inbo-aws-biodiversiteitsportaal-terraform`, `inbo-aws-exotenportaal-terraform`

### 5. [x] IAM managed policies met privilege escalation (3 resources) — GEMUTE (accepted risk)
- **Check:** `iam_policy_allows_privilege_escalation`
- **Resources:**
  - `inbo-vbp-start-pipelines-policy` (prod + uat) — ecs:RunTask + iam:PassRole
  - `inbo-github-runners-lambda-execution-policy` (shared-infra) — ecs:RunTask + iam:PassRole
- **Fix:** Beperk iam:PassRole tot specifieke role ARNs
- **Terraform projecten:** `inbo-aws-biodiversiteitsportaal-terraform`, `inbo-aws-main-terraform` (of github-runners project)

### 6. [x] IAM roles met AdministratorAccess (2 resources)
- **Check:** `iam_role_administratoraccess_policy`
- **Resources:**
  - `inbo-keycloak-ecs-task-execution-role` (uat) — should NOT have admin
  - `AWS-QuickSetup-StackSet-Local-ExecutionRole` (shared-infra) — AWS managed, mogelijk niet in Terraform
- **Fix:** Vervang AdministratorAccess door least-privilege policies
- **Terraform project:** `inbo-aws-keycloak-terraform`

### 7. [~] RDS instance zonder transport encryption (1 resource) — OVERGESLAGEN
- **Check:** `rds_instance_transport_encrypted`
- **Resource:** `inbo-utility-shared-infra` (347082780157 / shared-infra)
- **Fix:** Forceer SSL via parameter group (`rds.force_ssl = 1`)
- **Terraform project:** `inbo-aws-sql-server-terraform` of `inbo-aws-main-terraform`

### 8. [x] S3 bucket cross-account access (1 resource) — GEMUTE (accepted risk, bewuste cross-account read-only)
- **Check:** `s3_bucket_cross_account_access`
- **Resource:** `inbo-exotenportaal-uat-eu-west-1-default` (uat)
- **Fix:** Review en beperk bucket policy
- **Terraform project:** `inbo-aws-exotenportaal-terraform`

### 9. [x] EC2 instances met verouderde AMI (2 resources) — GEMUTE (stateful instances, maintenance window nodig)
- **Check:** `ec2_instance_with_outdated_ami`
- **Resources:** `i-09cc110fbb1f04ed4`, `i-0ceda6bc49989921f` (shared-infra)
- **Fix:** Update AMI naar recente versie
- **Terraform project:** te bepalen (shared-infra EC2)

---

## Overgeslagen / handmatig opgelost

| # | Finding | Reden |
|---|---------|-------|
| 6 | `AWS-QuickSetup-StackSet-Local-ExecutionRole` met AdminAccess (shared-infra) | AWS managed role, niet in Terraform |
| 6 | `inbo-keycloak-ecs-task-execution-role` met AdminAccess (uat) | Handmatig verwijderd via AWS CLI |
| 7 | RDS `inbo-utility-shared-infra` zonder transport encryption (shared-infra) | Overgeslagen op verzoek |
| 3 | `AWS-QuickSetup-StackSet-Local-AdministrationRole` confused deputy (shared-infra) | AWS managed role, niet in Terraform |
| 4 | `inbo-vbp-pipelines-emr-service-role` inline policy privilege escalation (prod+uat) | Overgeslagen op verzoek (biodiversiteitsportaal) |
| 5 | `inbo-vbp-start-pipelines-policy` managed policy privilege escalation (prod+uat) | Overgeslagen op verzoek (biodiversiteitsportaal) |

---

## Volgorde van aanpak (voorstel)

1. **#1** - Critical: ECS secrets in env vars (watina-dov) — hoogste urgentie
2. **#3** - Confused deputy preventie (waterbirds + backup) — past bij onze AWS preferences
3. **#6** - Keycloak execution role met AdminAccess — snel te fixen
4. **#7** - RDS transport encryption — snel te fixen
5. **#4** - Inline policy privilege escalation — 6 resources
6. **#5** - Managed policy privilege escalation — 3 resources
7. **#8** - S3 cross-account access — 1 resource
8. **#2** - ECS readonly root filesystem — 87 resources, bulk-fix via modules
9. **#9** - Verouderde AMIs — afhankelijk van wat erop draait
