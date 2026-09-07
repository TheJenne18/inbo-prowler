# EBS-volume encryptie — bastion & ckan

Opgesteld 2026-06-30.

## Waarom dit plan

Default EBS-encryptie staat in alle accounts aan, maar geldt enkel voor *nieuwe*
volumes. Twee bestaande volumes zijn nog onversleuteld, en zij zijn de **bron** van
zowel de 2 `ec2_ebs_volume_encryption`-findings als de ~230 onversleutelde
`ec2_ebs_snapshots_encrypted`-snapshots (elke AWS Backup / AMI-build van een
onversleuteld volume maakt een onversleutelde snapshot):

| Account | Instance | Volume | Soort | Detail |
|---|---|---|---|---|
| shared-infra | `bastion` (i-0d6cbbfcc12c0908f, ASG `inbo-bastion-asg`) | `vol-041c79923a0b2088e` | **root** /dev/xvda | 8 GB gp3, DeleteOnTermination=true, **stateless** |
| prod | `ckan` (i-0b0e50c4ecd583fe5, t3.medium, **gestopt**) | `vol-05400ce6c1c3390a1` | **data** /dev/sdb | 30 GB gp2, DeleteOnTermination=false, **bevat data** |

KMS-sleutel voor versleuteling: `alias/inbo/aws/ebs/default` (uit `inbo-aws-kms-terraform`).

> Snapshots verwijderen lost niets duurzaam op zolang deze volumes onversleuteld zijn —
> ze komen terug. Eerst versleutelen, dan opruimen.

---

## 1. bastion (shared-infra) — instance refresh, géén code

De launch template (`inbo-aws-bastion-terraform/region/common-region/launch-template.tf`)
zet **al** `encrypted = true` op /dev/xvda. De draaiende instance dateert van vóór die
regel (AMI 2024-08-06) en is daarom nog onversleuteld. bastion is stateless (t4g.nano,
SSM-bastion, `Backup = false`), dus vervangen is risicoloos.

**Stappen:**
1. Start een ASG instance refresh:
   `aws autoscaling start-instance-refresh --auto-scaling-group-name inbo-bastion-asg --region eu-west-1`
   (of simpelweg de instance termineren; de ASG herlanceert vanaf de template.)
2. Wacht tot de nieuwe instance `InService` is en SSM-bereikbaar.
3. Verifieer dat het nieuwe root-volume encrypted is:
   `aws ec2 describe-volumes --filters Name=attachment.instance-id,Values=<nieuw-id> --query 'Volumes[].Encrypted'`

**Resultaat:** `ec2_ebs_volume_encryption` (bastion) weg; oude onversleutelde volume wordt
mee verwijderd (DeleteOnTermination=true). De 53 bestaande AWS Backup recovery points
verlopen vanzelf via de 30-dagen retentie.

**Optionele hardening:** de `tag_specifications` in de launch template tagt enkel de
*instance* met `Backup = false`, niet het *volume* — daardoor wordt het bastion-volume
toch geback-upt (de 53 recovery points). Voeg een `tag_specifications { resource_type =
"volume" ... Backup = false }` toe om onnodige bastion-backups helemaal te stoppen.

---

## 2. ckan (prod) — data-behoudende encryptie van het /dev/sdb-volume

De **root** van ckan is al encrypted (`ec2.tf` → `root_block_device { encrypted = true }`).
Enkel het **30 GB data-volume** (/dev/sdb) is onversleuteld, en het zit **niet in
Terraform** (handmatig aangehangen). De instance is momenteel **gestopt**, dus de swap
kost geen extra downtime. EBS kan niet in-place versleuteld worden → snapshot → encrypted
copy → nieuw volume → omwisselen.

> **Eerst verifiëren:** is deze (gestopte) `ckan_2_11`-instance nog in actief gebruik?
> Zo niet → snapshot als archief + volume verwijderen is voldoende. Zo ja → onderstaande swap.

**Stappen (instance blijft gestopt tijdens de swap):**
1. Veiligheidssnapshot (rollback-anker):
   `aws ec2 create-snapshot --volume-id vol-05400ce6c1c3390a1 --description "ckan-data pre-encrypt 2026-06-30" --region eu-west-1`
2. Encrypted kopie van die snapshot:
   `aws ec2 copy-snapshot --source-region eu-west-1 --source-snapshot-id <snap> --encrypted --kms-key-id alias/inbo/aws/ebs/default --region eu-west-1`
3. Nieuw encrypted volume uit de encrypted snapshot (zelfde AZ, meteen naar gp3):
   `aws ec2 create-volume --snapshot-id <enc-snap> --availability-zone eu-west-1b --volume-type gp3 --encrypted --kms-key-id alias/inbo/aws/ebs/default --region eu-west-1`
4. Oud volume loskoppelen, nieuw aankoppelen op hetzelfde device:
   `aws ec2 detach-volume --volume-id vol-05400ce6c1c3390a1 --region eu-west-1`
   `aws ec2 attach-volume --volume-id <nieuw> --instance-id i-0b0e50c4ecd583fe5 --device /dev/sdb --region eu-west-1`
5. Instance starten (indien hij hoort te draaien) en verifiëren: data aanwezig, mount OK.
   - De filesystem-UUID blijft behouden (kopie van snapshot), dus `/etc/fstab` op UUID werkt ongewijzigd.
6. Na bevestiging: oud onversleuteld volume + de tijdelijke onversleutelde snapshot
   verwijderen. Veiligheidssnapshot eventueel kort bewaren (of encrypted bewaren).

**Resultaat:** `ec2_ebs_volume_encryption` (ckan) weg; nieuwe AWS Backups/AMI's van ckan
zijn voortaan encrypted; de 106 bestaande recovery points verlopen via retentie.

**Hardening:** breng het data-volume in Terraform (`aws_ebs_volume` met `encrypted = true`
+ `aws_volume_attachment`) zodat het niet opnieuw als untracked/onversleuteld kan ontstaan.

---

## 3. Opruimen ná encryptie (niet eerder)

- **AWS Backup recovery points** (53 bastion + 106 ckan): niet handmatig verwijderen —
  verlopen vanzelf binnen 30 dagen zodra de bron encrypted is. (Verwijderen kan enkel via
  `aws backup delete-recovery-point`, en je wilt je DR-backups houden.)
- **65 base-/golden-AMI-snapshots** (shared-infra: `inbo-amazon-linux-2023-arm-base-image`,
  `inbo-github-runners-image`): apart traject voor het image-team. De recentste worden
  actief gebruikt (launch templates). Aanpak: image-pipeline encrypted laten bouwen +
  oude/gesuperseede AMI's selectief deregisteren (eerst checken op launch-template/ASG-
  referenties). **Niet bulk-deregisteren.**
- De 4 oude orphan AMI-snapshots (mei 2023) zijn al verwijderd (2026-06-30).

---

## Verificatie (na uitvoering + nieuwe scan)

- `ec2_ebs_volume_encryption`: 2 → 0.
- `ec2_ebs_snapshots_encrypted`: daalt geleidelijk naarmate oude recovery points verlopen
  en alle nieuwe snapshots encrypted zijn (binnen ~30 dagen voor het backup-deel).
- Controle: `aws ec2 describe-volumes --filters Name=encrypted,Values=false` per account
  → enkel nog (eventueel) niet-gemigreerde resten.
