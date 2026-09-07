# VBP Solr — ZooKeeper-wachtwoord staat plaintext in de ECS task definition

**Status:** open, extern uit te voeren door het VBP-team
**Opgesteld:** 2026-09-07, n.a.v. Prowler-scan 2026-09-05/06
**Repo:** `inbo-aws-biodiversiteitsportaal-terraform` (branch `master`)
**Severity:** CRITICAL (5 actieve Prowler-findings)

## Samenvatting

Het ZooKeeper-wachtwoord van de Solr-cluster wordt door Terraform uit Secrets Manager
gelezen en **plaintext geïnterpoleerd in de ECS task definition**. Iedereen met
`ecs:DescribeTaskDefinition` op het account kan het wachtwoord uitlezen, zonder enige
toegang tot Secrets Manager of KMS.

Dit is geen regex-artefact van Prowler maar een reële exposure.

## Betrokken findings

Check `ecs_task_definitions_no_environment_secrets`, severity CRITICAL:

| Account | Resource |
|---|---|
| dev | `inbo-vbp-solr-efs-1:15` |
| uat | `inbo-vbp-solr-efs-1:2` |
| prod | `inbo-vbp-solr-efs-1:5` |
| prod | `inbo-vbp-solr-efs-2:5` |
| prod | `inbo-vbp-solr-efs-3:5` |

Deze zijn **bewust niet gemute** in `mutelist.yaml` — ze blijven zichtbaar tot ze
opgelost zijn. Alle overige CRITICAL-findings van dezelfde checks zijn wél gemute als
geverifieerde false positives (zie `mutelist-verantwoording.md`).

## Twee exposure-punten, niet één

Prowler detecteert er maar één. Een fix die alleen dat punt aanpakt maakt de finding
groen terwijl het wachtwoord nog steeds in de task definition staat — schijnveiligheid.
**Beide moeten aangepakt worden.**

### 1. Env-var `SOLR_ZK_CREDS_AND_ACLS` — `region/common-region/solr-efs/ecs.tf:76-77`

```hcl
{
  name  = "SOLR_ZK_CREDS_AND_ACLS"
  value = "-DzkACLProvider=org.apache.solr.common.cloud.SaslZkACLProvider -DzkCredentialsProvider=org.apache.solr.common.cloud.VMParamsSingleSetCredentialsDigestZkCredentialsProvider -DzkDigestUsername=solr -DzkDigestPassword=${jsondecode(data.aws_secretsmanager_secret_version.zookeeper.secret_string)["solr_password"]}"
},
```

Dit is wat Prowler vlagt.

### 2. Inline `config-init`-commando — `region/common-region/solr-efs/ecs.tf:223-229`

```bash
# Write JAAS client config for Solr -> ZooKeeper SASL authentication
cat <<JAAS_EOF > /var/solr/data/solr-jaas-client.conf
Client {
    org.apache.zookeeper.server.auth.DigestLoginModule required
    username="solr"
    password="${jsondecode(data.aws_secretsmanager_secret_version.zookeeper.secret_string)["solr_password"]}";
};
JAAS_EOF
```

Prowler vlagt dit **niet** — het scant `environment`, niet `command`. Het `command`-veld
is echter net zo goed onderdeel van de task definition en dus even leesbaar.

## Complicaties om rekening mee te houden

**a. Het zookeeper-secret is niet uitbreidbaar.**
`region/common-region/zookeeper-efs/secrets.tf:21-32` heeft:

```hcl
resource "aws_secretsmanager_secret_version" "zookeeper" {
  secret_id = aws_secretsmanager_secret.zookeeper_password.id
  secret_string = jsonencode({
    zookeeper_password = ...
    super_password     = ...
    solr_password      = ...
  })
  lifecycle {
    ignore_changes = [secret_string, ]
  }
}
```

Door `ignore_changes = [secret_string]` wordt de inhoud enkel bij aanmaak geschreven.
Een **nieuwe sleutel toevoegen werkt dus niet** voor bestaande omgevingen — die krijgen
hem nooit. Bestaande sleutels uitlezen via `valueFrom` kan wel gewoon.

**b. De bedrading bestaat al.**
De module heeft al een `secrets`-variabele die naar de containerdefinitie doorloopt:
`region/common-region/solr-efs/vars.tf:37-43` (`list(object({name, valueFrom}))`),
gebruikt op `region/common-region/solr-efs/ecs.tf:85` (`secrets = var.secrets`).
Er hoeft dus geen nieuwe plumbing gebouwd te worden voor de solr-container.
De `config-init`-container heeft nog géén `secrets`-blok — dat moet toegevoegd worden.

## Voorgestelde aanpak

### Deel 1 — config-init (laag risico, geen nieuw secret nodig)

Injecteer het wachtwoord als env-var via het `secrets`-mechanisme en verwijs ernaar in
de heredoc in plaats van het te interpoleren:

1. Voeg aan de `config-init`-container een `secrets`-blok toe:
   ```hcl
   secrets = [
     {
       name      = "ZK_SOLR_PASSWORD"
       valueFrom = "${var.zookeeper_credentials_secret_arn}:solr_password::"
     }
   ]
   ```
   De `:solr_password::`-selector leest die sleutel uit het bestaande JSON-secret —
   geen last van `ignore_changes`.

2. Vervang in het commando de Terraform-interpolatie door een shell-variabele:
   ```bash
   password="$${ZK_SOLR_PASSWORD}";
   ```
   De dubbele `$$` is Terraform-escaping en levert een letterlijke `${ZK_SOLR_PASSWORD}`
   op, die de shell in de container expandeert. De heredoc-delimiter `JAAS_EOF` is
   ongequote, dus expansie binnen het blok werkt.

3. Controleer dat de task execution role `secretsmanager:GetSecretValue` heeft op dit
   secret plus `kms:Decrypt` op de bijhorende key. Voor de solr-container is dat
   vermoedelijk al geregeld via `var.secrets`; verifieer het voor config-init.

### Deel 2 — solr-container (keuze te maken)

Het wachtwoord moet hier binnen één samengestelde JVM-args-string staan, dus het kan
niet zomaar als losse env-var. Twee wegen:

**(a) Volledige string in een nieuw secret.**
Maak een nieuw `aws_secretsmanager_secret` + `_version` (zónder `ignore_changes`) met de
volledige `-DzkACLProvider=... -DzkDigestPassword=<pw>`-string als waarde, samengesteld
in Terraform uit het bestaande zookeeper-secret. Injecteer die via `var.secrets` en haal
`SOLR_ZK_CREDS_AND_ACLS` weg uit `environment`.
*Voordeel:* werkt zeker, geen gedragsverandering in Solr.
*Nadeel:* hetzelfde wachtwoordmateriaal staat nu in twee secrets.

**(b) Nagaan of `-DzkDigestPassword` nog nodig is.**
`SOLR_OPTS` laadt al de JAAS-file met dezelfde credentials
(`-Djava.security.auth.login.config=/var/solr/data/solr-jaas-client.conf`,
`solr-efs/ecs.tf:72-73`). Naast `SaslZkACLProvider` staat echter ook
`VMParamsSingleSetCredentialsDigestZkCredentialsProvider` geconfigureerd, en díe leest
expliciet de system properties `-DzkDigestUsername` / `-DzkDigestPassword`. Mogelijk zijn
beide mechanismen dubbelop en volstaat de JAAS-file alleen — dan kan de hele env-var weg.
*Voordeel:* veruit de netste oplossing, geen tweede secret.
*Nadeel:* vereist verificatie tegen de Solr-documentatie en een test; dit is een
gedragsvraag over de Solr-configuratie, geen infrastructuurvraag.

**Aanbeveling:** eerst (b) onderzoeken. Blijkt het nodig, val terug op (a).

## Verificatie

1. `terraform plan` op dev — verwacht: `SOLR_ZK_CREDS_AND_ACLS` verdwijnt uit
   `environment`, `secrets` krijgt een entry, `command` bevat geen wachtwoord meer.
2. Apply op dev en herstart de Solr-service. Controleer in de logs dat Solr
   authenticeert tegen ZooKeeper (geen `AuthFailed` / `KeeperErrorCode = NoAuth`).
3. Bevestig dat het wachtwoord weg is uit de gerenderde task definition:
   ```
   aws ecs describe-task-definition --task-definition inbo-vbp-solr-efs-1 \
     --query 'taskDefinition.containerDefinitions[].[environment,command]' \
   | grep -i zkdigestpassword
   ```
   Dit hoort **niets** op te leveren.
4. Daarna uat, daarna prod (3 instances — `solr-efs-1/2/3`, één voor één).
5. Na de volgende Prowler-scan horen de 5 CRITICAL-findings verdwenen te zijn.

## Overweging: wachtwoord roteren

Het wachtwoord is sinds de aanmaak van deze task definitions leesbaar geweest voor
iedereen met `ecs:DescribeTaskDefinition`. Oude revisies van de task definition blijven
bovendien opvraagbaar, ook na de fix. Overweeg daarom het `solr_password` te roteren
nadat de fix live is — let op dat `ignore_changes = [secret_string]` betekent dat
Terraform dat niet vanzelf doet.
