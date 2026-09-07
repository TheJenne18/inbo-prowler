# Confused-deputy preventie — openstaande roles

**Status:** open, door anderen op te pakken
**Opgesteld:** 2026-09-07, n.a.v. Prowler-scan 2026-09-05/06
**Check:** `iam_role_cross_service_confused_deputy_prevention` (HIGH)

## Context

Een IAM-role met een `Service`-principal in de assume role policy kan door die AWS-service
worden aangenomen namens *elk* account dat de rol-ARN kent, tenzij je dat beperkt. De fix is
een `condition` met `aws:SourceAccount` (en waar mogelijk `aws:SourceArn`).

Van de 11 actieve findings is er 1 opgelost (watervogels, zie onder). De overige 10 staan
hier beschreven.

## Al gedaan

| Role | Repo | Status |
|---|---|---|
| `inbo-watervogels-app-task-role` | `inbo-aws-watervogels-terraform` | PR [#3](https://github.com/inbo/inbo-aws-watervogels-terraform/pull/3), wacht op review + apply |

In die PR is meteen ook de niet-gevlagde `app-task-execution-role` meegenomen. Het patroon
daaruit is herbruikbaar voor alles hieronder:

```hcl
condition {
  test     = "StringEquals"
  variable = "aws:SourceAccount"
  values   = [data.aws_caller_identity.current.account_id]
}

condition {
  test     = "ArnLike"
  variable = "aws:SourceArn"
  values   = ["arn:aws:<service>:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
}
```

> Voeg condities **enkel** toe aan statements met een `Service`-principal. Bij een
> `AWS`-principal (cross-account trust) hoort `aws:SourceAccount` niet thuis en breek je de
> trust.

## Openstaand — niet-VBP (4 findings)

Deze drie repo's stonden niet lokaal gecloned; ze bestaan wel op GitHub onder `inbo/`.

### 1. `inbo-shop-lambda` — prod

- **Repo:** `inbo-aws-shop-terraform` (default branch: `main`)
- **Bestand:** `global/common-global/iam.tf:5-16`, document `lambda_assume`
- **Principal:** `lambda.amazonaws.com`, geen condities
- **Aanpak:** `aws:SourceAccount` toevoegen. `aws:SourceArn` kan met
  `arn:aws:lambda:<region>:<account>:function:inbo-shop-*`, passend bij de bestaande
  naam-scoping in de permissions.

### 2. `inbo-shop-scheduler` — prod

- **Repo:** `inbo-aws-shop-terraform` (`main`)
- **Bestand:** `global/common-global/iam.tf:102-113`, document `scheduler_assume`
- **Principal:** `scheduler.amazonaws.com`, geen condities
- **Aanpak:** EventBridge Scheduler ondersteunt `aws:SourceAccount` én `aws:SourceArn`
  expliciet — hier kunnen beide netjes. Dit is de minst risicovolle van de vier.

### 3. `inbo-rattenapp-fotosync-lambda-role` — prod

- **Repo:** `inbo-aws-rattenapp-fotosync-terraform` (default branch: `master`)
- **Bestand:** `global/common-global/iam.tf:8-18`, document `lambda_assume`
- **Principal:** `lambda.amazonaws.com`, geen condities
- **Aanpak:** `aws:SourceAccount`. Let op: volgens de comment bovenaan het bestand vertrouwt
  een GCP Workload-Identity-Federation-pool exact deze rol-ARN. De rol-ARN verandert niet door
  deze wijziging, dus dat blijft werken — maar hernoem de rol niet.

### 4. `inbo-socdash-lambda-edge-role` — shared-infra ⚠️

- **Repo:** `inbo-aws-socdash-terraform` (default branch: `master`)
- **Bestand:** `region/common-region/lambda-edge.tf:10-22`, document `assume_role_lambda_edge`
- **Principal:** `edgelambda.amazonaws.com` én `lambda.amazonaws.com`, geen condities

**Waarschuwing — niet zomaar de standaardregel toepassen.** Dit is een Lambda@Edge-functie.
Die wordt gerepliceerd naar edge-locaties en door CloudFront aangenomen, niet vanuit de
account-context waarin hij gedefinieerd is. De door AWS gedocumenteerde trust policy voor
Lambda@Edge is exact deze kale twee-principal-vorm **zonder** condities.

`aws:SourceAccount` toevoegen kan de replicatie breken, en dat merk je **pas bij de volgende
CloudFront-deploy** — niet bij `terraform apply`. Wie dit oppakt moet eerst verifiëren of
Lambda@Edge deze conditiesleutels ondersteunt. Zo niet, dan is de juiste uitkomst een
gerichte mutelist-entry met deze motivatie, niet een fix.

## Openstaand — VBP (6 findings)

Extern op te pakken door het VBP-team, samen met
[`vbp-solr-zookeeper-secret-plan.md`](vbp-solr-zookeeper-secret-plan.md).

| Role | Accounts | Repo |
|---|---|---|
| `inbo-vbp-backup-restore-role` | dev, uat, prod | `inbo-aws-biodiversiteitsportaal-terraform` |
| `inbo-vbp-species-lists-api-lambda` | dev, uat, prod | idem |

Beide volgen het standaardpatroon hierboven; er is geen bijzonderheid zoals bij socdash.
De species-lists-api-rol hoort bij de Lambda uit `region/common-region/lambda_species_lists.tf`.

## Al gemute (9 findings, geen actie)

Ter volledigheid, zodat niemand ze opnieuw onderzoekt:

- `StackSet-CloudHealthRoleUpdate--LambdaExecutionRole-*` (dev, uat, prod, shared-infra) en
  `AWS-QuickSetup-StackSet-Local-AdministrationRole` (shared-infra) — AWS-beheerde roles,
  niet aanpasbaar. Gemute via `*CloudHealth*` / `*QuickSetup*`.
- `inbo-waterbirds-lambda-secret-rotation-role` en
  `inbo-waterbirds-lambda-dbuser-secret-rotation-role` (uat, prod) — gemute via
  `inbo-waterbirds-*` in de account-specifieke blokken.

Zie `mutelist-verantwoording.md` voor de onderbouwing.
