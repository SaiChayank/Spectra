# Infrastructure as Code (IaC) Documentation
## FinShield AI

**Version:** 0.1 (Draft) | **Classification:** Confidential

---

## 1. Purpose
Defines how FinShield AI infrastructure is provisioned, reviewed, and audited as code — required for reproducibility and for compliance evidence (SOC 2, HIPAA).

## 2. Tooling (Proposed)
| Layer | Tool |
|-------|------|
| Cloud provisioning | Terraform |
| Kubernetes/edge orchestration | Helm + K3s (edge), standard K8s (core) |
| Secrets | Cloud KMS + Terraform-integrated secret injection (never hardcoded) |
| Policy-as-code | OPA/Conftest or Sentinel |

## 3. Repository Structure (Proposed)
```
infra/
  modules/
    networking/
    tee-nodes/
    edge-mec/
    graph-db/
    stream-processing/
    kms/
  environments/
    dev/
    staging/
    production/
  policies/
    opa-rules/
```

## 4. Environment Strategy
| Environment | Purpose | Data Sensitivity |
|-------------|---------|-------------------|
| Dev | Feature development | Synthetic data only |
| Staging | Pre-release validation, Digital Twin testing | Synthetic + anonymized replay data |
| Production | Live customer traffic metadata | Sensitive — full controls apply |

## 5. Required Controls in IaC
- No public-facing storage buckets for metadata stores (enforced via policy-as-code).
- TEE node provisioning must include attestation service bootstrap as a required module dependency.
- All KMS keys defined with rotation policy in code (no manual key creation).
- Network segmentation between tenant workloads defined as code (per Threat Model TB-4).

## 6. Change Management
- All infra changes via pull request; `terraform plan` output required in PR before merge.
- Production apply requires two approvals: one engineering, one security.
- State files stored in encrypted remote backend, never committed to repo.

## 7. Drift Detection
- Scheduled drift-detection job compares live infra state against IaC definitions; discrepancies alert Security Lead.

## 8. Disaster Recovery Tie-In
- All environments reproducible from IaC + versioned data backups — supports Deployment & Rollback Plan.

## 9. Audit Evidence
- `terraform plan`/`apply` logs retained per Data Governance retention schedule for change-control audit trail.
- Policy-as-code test results attached to each infra release.

*Draft — repository does not yet exist; structure and policies to be validated once infra engineering begins.*
