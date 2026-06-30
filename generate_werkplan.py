#!/usr/bin/env python3
"""Genereert findings-werkplan.md uit de fetch-JSON + mutelist.yaml.

Gebruik:
  ./venv/bin/python generate_werkplan.py <all_fail_findings.json> <mutelist.yaml> > findings-werkplan.md

De fetch-JSON komt uit fetch_all_fail_findings.py (sleutels: scans, findings).
De mutelist wordt lokaal toegepast (de Prowler-API doet dat niet).
"""
import json, sys, collections, fnmatch, yaml

ALIAS = {'347082780157':'shared-infra','632683202044':'dev','625469168093':'uat','800040084629':'prod'}
ORDER = ['347082780157','632683202044','625469168093','800040084629']
SEVS  = ['critical','high','medium','low']

def parse_uid(uid):
    p = uid.split('-')
    if len(p) >= 8 and p[0] == 'prowler':
        return p[3], '-'.join(p[4:7]), '-'.join(p[7:])
    return None, '', uid

def am(v, ps): return any(fnmatch.fnmatch(v, p) for p in ps)

def make_muter(ml):
    accounts = ml['Mutelist']['Accounts']
    def muted(acct, chk, reg, res):
        for ma, body in accounts.items():
            if ma != '*' and ma != acct: continue
            checks = body.get('Checks', {})
            if chk not in checks: continue
            s = checks[chk]
            if not am(reg, s.get('Regions', ['*'])): continue
            if not am(res, s.get('Resources', ['*'])): continue
            exc = s.get('Exceptions') or {}
            if exc.get('Resources') and am(res, exc['Resources']): continue
            if exc.get('Regions') and am(reg, exc['Regions']): continue
            return True
        return False
    return muted

# check_id -> (categorie, korte notitie)
CATEGORIES = {
 'ec2_ebs_snapshots_encrypted':            ('CLI', 'Bulk re-encrypt (copy-with-encryption + delete oude). Default EBS-encryptie staat al aan in TF.'),
 'ec2_ebs_volume_encryption':              ('CLI', 'Legacy volumes re-encrypten; default encryptie staat al aan.'),
 'iam_role_administratoraccess_policy':    ('CLI', 'inbo-adviezen-rds-connect-role: AdministratorAccess is live drift (niet in TF) -> detachen.'),
 'route53_domains_transferlock_enabled':   ('CLI', 'Eenmalige toggle via Route53 Domains.'),
 'rds_cluster_protected_by_backup_plan':   ('TF-BRANCH', 'Branch security/enable-aurora-backups (Aurora=true). Wacht op apply.'),
 's3_bucket_level_public_access_block':    ('TF-BRANCH', 'Branch security/s3-idpm-public-access-block. Wacht op apply.'),
 'iam_inline_policy_allows_privilege_escalation': ('TF-BRANCH', 'Branch security/n2k-least-privilege-ssm (n2k s3-user/ec2-role/unittest). Wacht op apply.'),
 'iam_user_with_temporary_credentials':    ('STRATEGISCH', 'Migratie naar Identity Center/OIDC. Veel zijn service-accounts (SES/ECR) -> per user beslissen of gericht muten.'),
 'iam_user_hardware_mfa_enabled':          ('STRATEGISCH', 'Zelfde users als temporary_credentials. Service-accounts kunnen geen hardware-MFA.'),
 'ecs_task_definitions_containers_readonly_access': ('REVIEW', 'watina-app al gefixt (v1.2.1, wacht op apply); VBP solr/zk/grafana onder VBP-team; watervogels/riparias = TODO (testen).'),
 'rds_instance_protected_by_backup_plan':  ('REVIEW', 'Geen Backup=false-tag in TF -> zou gedekt moeten zijn onder opt-out model. Live coverage verifieren; wsl stale.'),
 'vpc_endpoint_connections_trust_boundaries': ('REVIEW', 'Restrictieve endpoint-policies in inbo-aws-networking-terraform/common-envs/private-link.tf (gedeelde infra).'),
 'iam_role_cross_service_confused_deputy_prevention': ('REVIEW', 'aws:SourceAccount/aws:SourceArn-condities toevoegen aan service-assumed roles.'),
 'ec2_networkacl_allow_ingress_any_port':  ('REVIEW', 'Waarschijnlijk default-NACLs van de VPC-module; custom NACL-rules nodig.'),
 'secretsmanager_automatic_rotation_enabled': ('REVIEW', 'RDS-secrets: rotatie instellen of muten. Overige meestal niet rotateerbaar.'),
 'iam_role_cross_account_readonlyaccess_policy': ('REVIEW', 'Cross-account ReadOnlyAccess reviewen per role.'),
 'iam_no_custom_policy_permissive_role_assumption': ('REVIEW', 'Custom policy laat te brede sts:AssumeRole toe; scopen.'),
 'ec2_securitygroup_allow_ingress_from_internet_to_any_port': ('REVIEW', 'SG-regels beperken.'),
 'sns_topics_kms_encryption_at_rest_enabled': ('REVIEW', 'KMS-encryptie op SNS-topic aanzetten.'),
 'route53_dangling_ip_subdomain_takeover': ('REVIEW', 'Dangling DNS-record -> verwijderen of herstellen (subdomain takeover-risico).'),
 'ec2_ebs_volume_snapshots_exists':        ('REVIEW', 'Backup plan of accepteren voor stateless volume.'),
}
CAT_ORDER = ['TF-BRANCH','CLI','STRATEGISCH','REVIEW']
CAT_TITEL = {
 'TF-BRANCH':'Opgelost via Terraform-branch deze sessie (wacht op merge + apply + rescan)',
 'CLI':'Live-account / CLI-actie (niet via Terraform-code)',
 'STRATEGISCH':'Strategisch / langere doorlooptijd',
 'REVIEW':'Te reviewen per resource',
}

def main():
    data = json.load(open(sys.argv[1]))
    ml = yaml.safe_load(open(sys.argv[2]))
    muted = make_muter(ml)
    scans = data['scans']; findings = data['findings']

    active = collections.defaultdict(lambda: collections.defaultdict(int))   # sev -> acct -> n
    muted_c = collections.defaultdict(lambda: collections.defaultdict(int))
    high_by_check = collections.defaultdict(lambda: collections.defaultdict(list))  # check -> acct -> [res]
    for f in findings:
        acct, reg, res = parse_uid(f['resource_uid'])
        if acct is None: acct, reg, res = f['account_id'], '', f['resource_name']
        sev = f['severity']
        if muted(acct, f['check_id'], reg, res):
            muted_c[sev][acct] += 1
        else:
            active[sev][acct] += 1
            if sev == 'high':
                high_by_check[f['check_id']][acct].append(res)

    o = []
    P = o.append
    P("# Prowler AWS Findings - Werkplan\n")
    P("Gegenereerd via `prowler-scripts/fetch_all_fail_findings.py` + `generate_werkplan.py`.")
    P("Tellingen zijn **na** lokale mutelist-filter (de Prowler-API past de mutelist niet toe).\n")
    P("## Bronnen en scopes\n")
    P("| Account | UID | Laatste completed scan |")
    P("|---|---|---|")
    seen=set()
    for pid, s in scans.items():
        if s['uid'] in seen: continue
        seen.add(s['uid'])
        P(f"| inbo-{s['alias'].replace('inbo-','')} | `{s['uid']}` | {s['scan_date'][:10]} |")
    P("\n> Scans zijn vers (1-7 dagen oud). De mei-data was onvolledig (vastgelopen uat/prod-scans); die undercount is nu gecorrigeerd.\n")

    def sevtable(title, d):
        P(f"### {title}\n")
        P("| Severity | "+" | ".join(ALIAS[a] for a in ORDER)+" | Totaal |")
        P("|---|"+"---|"*(len(ORDER)+1))
        for sev in SEVS:
            row=[d[sev].get(a,0) for a in ORDER]
            P(f"| **{sev.upper()}** | "+" | ".join(str(x) for x in row)+f" | **{sum(row)}** |")
        P("")
    P("## Totaaloverzicht (actief, na mutelist)\n")
    sevtable("Actieve findings", active)
    sevtable("Gemute findings (in mutelist.yaml)", muted_c)

    tot_high = sum(active['high'].values())
    P(f"## HIGH actieplan ({tot_high} actieve findings)\n")
    P("Gegroepeerd per aanpak. Per check het aantal actieve HIGH-findings en de aanpak.\n")
    # group checks by category
    bycat = collections.defaultdict(list)
    for chk, accs in high_by_check.items():
        cat = CATEGORIES.get(chk, ('REVIEW',''))[0]
        bycat[cat].append(chk)
    for cat in CAT_ORDER:
        chks = bycat.get(cat, [])
        if not chks: continue
        P(f"### {CAT_TITEL[cat]}\n")
        chks.sort(key=lambda c:-sum(len(v) for v in high_by_check[c].values()))
        for chk in chks:
            n = sum(len(v) for v in high_by_check[chk].values())
            note = CATEGORIES.get(chk, ('',''))[1]
            P(f"- **`{chk}`** ({n}) — {note}")
        P("")

    P("---\n\n## HIGH per check — detail (actieve resources)\n")
    rows = sorted(high_by_check.items(), key=lambda kv:-sum(len(v) for v in kv[1].values()))
    for chk, accs in rows:
        n = sum(len(v) for v in accs.values())
        cat = CATEGORIES.get(chk, ('REVIEW',''))[0]
        P(f"### `{chk}` — {n} ({cat})\n")
        for a in ORDER:
            names = sorted(set(accs.get(a, [])))
            if not names: continue
            shown = names if len(names) <= 25 else names[:25]+[f"... +{len(names)-25} meer"]
            P(f"- **{ALIAS[a]}** ({len(names)}): "+", ".join(shown))
        P("")
    print("\n".join(o))

if __name__ == '__main__':
    main()
