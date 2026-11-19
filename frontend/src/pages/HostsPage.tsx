import { Banner, Card, EmptyState } from "../components/ui";

/**
 * Hosts (P1): host-centric triage. Not built yet: it needs backend endpoints
 * that do not exist (GET /api/hosts, GET /api/hosts/{host}/evidence,
 * POST /api/hosts/{host}/verdict; frontend-plan §6). Step 6 builds it against
 * proposed shapes in frontend/contract/proposed/.
 */
export default function HostsPage() {
  return (
    <div style={{ display: "grid", gap: 16 }}>
      <Banner title="Planned">
        Host triage ranks hosts by how many independent detectors flagged them. The backend does not offer this yet.
      </Banner>
      <Card>
        <EmptyState title="Hosts are coming">
          This screen will list hosts ranked by evidence, show each host's evidence timeline, and let an analyst record a verdict:
          true, expected (benign but known) or false. Until then, use Alerts &amp; Incidents and Traffic.
        </EmptyState>
      </Card>
    </div>
  );
}
