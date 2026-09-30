# Machine-Readable API Specs
## FinShield AI

**Version:** 0.1 (Draft) | **Format:** OpenAPI 3.0 (excerpt) | **Classification:** Confidential

**Note:** Draft contract for engineering alignment — no endpoints are implemented yet.

---

## 1. Purpose
Defines the initial API contract for detection alerts, PQC status, and correlation queries so frontend/dashboard and integrator teams can build against a stable interface.

## 2. OpenAPI Excerpt

```yaml
openapi: 3.0.3
info:
  title: FinShield AI Detection API
  version: 0.1.0-draft
  description: Metadata-only encrypted traffic threat detection API. No payload content is ever accepted or returned by this API.
servers:
  - url: https://api.finshield.example/v1
paths:
  /alerts:
    get:
      summary: List detection alerts
      parameters:
        - name: sector
          in: query
          schema:
            type: string
            enum: [fintech, healthcare, smart_city]
        - name: since
          in: query
          schema:
            type: string
            format: date-time
        - name: min_confidence
          in: query
          schema:
            type: number
      responses:
        '200':
          description: List of alerts
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Alert'

  /pqc/status/{endpoint_id}:
    get:
      summary: Get quantum-readiness classification for an endpoint
      parameters:
        - name: endpoint_id
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: PQC status
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/PqcStatus'

  /correlation/query:
    post:
      summary: Query cross-domain correlation graph
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                entity_hash:
                  type: string
                max_hops:
                  type: integer
                  default: 2
      responses:
        '200':
          description: Correlated entities and edges
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CorrelationResult'

  /compliance/proof:
    post:
      summary: Generate a ZK-proof compliance token for a time window
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                window_start:
                  type: string
                  format: date-time
                window_end:
                  type: string
                  format: date-time
      responses:
        '200':
          description: Compliance token
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ComplianceToken'

components:
  schemas:
    Alert:
      type: object
      properties:
        alert_id:
          type: string
        session_id:
          type: string
        sector:
          type: string
        detection_type:
          type: string
          enum: [pqc_vulnerable, hndl_pattern, adversarial_probe, cross_sector_correlation, timing_anomaly]
        confidence:
          type: number
        model_version:
          type: string
        created_at:
          type: string
          format: date-time

    PqcStatus:
      type: object
      properties:
        endpoint_id:
          type: string
        classification:
          type: string
          enum: [quantum_safe, quantum_vulnerable, unknown]
        last_evaluated:
          type: string
          format: date-time

    CorrelationResult:
      type: object
      properties:
        entities:
          type: array
          items:
            type: string
        edges:
          type: array
          items:
            type: object
            properties:
              from:
                type: string
              to:
                type: string
              relationship:
                type: string

    ComplianceToken:
      type: object
      properties:
        token_id:
          type: string
        window_start:
          type: string
          format: date-time
        window_end:
          type: string
          format: date-time
        proof:
          type: string
          description: Zero-knowledge proof artifact (opaque to API consumer)
```

## 3. Authentication (Convention)
- All endpoints require OAuth2 client-credentials or mTLS for service-to-service calls.
- No endpoint accepts or returns raw payload — request/response schemas structurally exclude payload fields.

## 4. Versioning Convention
- URI-versioned (`/v1`), breaking changes require a new version path; additive changes only within a version.

*Draft contract — subject to change during Phase 1 engineering design review.*
