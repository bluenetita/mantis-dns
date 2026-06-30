import { useEffect, useState } from "react";
import { api, NotFoundError, type CategoryToggle, type Group, type Override, type Policy, type Tenant, type TopDomain } from "./api";
import { FeedManager } from "./FeedManager";
import "./App.css";

// Catalog-backed by default (see services/control/aegis_control/feeds/catalog.json):
// adult, gambling, malware, ads, phishing, tracking. weapons/social/proxies have
// no vetted free source yet — toggle still works, bloom is empty until a feed
// is added for that category via the Feeds tab.
const KNOWN_CATEGORIES = ["adult", "gambling", "weapons", "malware", "ads", "phishing", "tracking", "social", "proxies"];

export default function App() {
  const [tab, setTab] = useState<"policies" | "feeds">("policies");
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<Group | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listTenants().then(setTenants).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    if (!selectedTenant) {
      setGroups([]);
      return;
    }
    api.listGroups(selectedTenant.id).then(setGroups).catch((e) => setError(String(e)));
  }, [selectedTenant]);

  async function handleCreateTenant() {
    const name = prompt("Tenant name?");
    if (!name) return;
    try {
      const tenant = await api.createTenant(name);
      setTenants((prev) => [...prev, tenant]);
    } catch (e) {
      setError(String(e));
    }
  }

  async function handleCreateGroup() {
    if (!selectedTenant) return;
    const name = prompt("Group name?");
    if (!name) return;
    const vpnSubnet = prompt("VPN subnet (CIDR, optional — e.g. 10.8.1.0/24)?") ?? "";
    try {
      const group = await api.createGroup(selectedTenant.id, name, vpnSubnet);
      setGroups((prev) => [...prev, group]);
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="app">
      <h1>Aegis-DNS Policy Editor</h1>
      {error && (
        <div className="error-banner" onClick={() => setError(null)}>
          {error} (click to dismiss)
        </div>
      )}
      <div className="tabs">
        <button className={tab === "policies" ? "active" : ""} onClick={() => setTab("policies")}>
          Policies
        </button>
        <button className={tab === "feeds" ? "active" : ""} onClick={() => setTab("feeds")}>
          Feeds
        </button>
      </div>
      {tab === "feeds" && <FeedManager onError={setError} />}
      {tab === "policies" && (
      <div className="columns">
        <section className="column">
          <h2>Tenants</h2>
          <ul>
            {tenants.map((t) => (
              <li
                key={t.id}
                className={selectedTenant?.id === t.id ? "selected" : ""}
                onClick={() => {
                  setSelectedTenant(t);
                  setSelectedGroup(null);
                }}
              >
                {t.name}
              </li>
            ))}
          </ul>
          <button onClick={handleCreateTenant}>+ New tenant</button>
        </section>

        <section className="column">
          <h2>Groups {selectedTenant ? `(${selectedTenant.name})` : ""}</h2>
          {!selectedTenant && <p className="hint">Select a tenant.</p>}
          <ul>
            {groups.map((g) => (
              <li
                key={g.id}
                className={selectedGroup?.id === g.id ? "selected" : ""}
                onClick={() => setSelectedGroup(g)}
              >
                {g.name} {g.vpn_subnet && <span className="subnet">{g.vpn_subnet}</span>}
              </li>
            ))}
          </ul>
          {selectedTenant && <button onClick={handleCreateGroup}>+ New group</button>}
        </section>

        <section className="column policy-column">
          <h2>Policy {selectedGroup ? `(${selectedGroup.name})` : ""}</h2>
          {!selectedGroup && <p className="hint">Select a group.</p>}
          {selectedGroup && <PolicyEditor group={selectedGroup} onError={setError} />}
        </section>
      </div>
      )}
    </div>
  );
}

function PolicyEditor({ group, onError }: { group: Group; onError: (e: string) => void }) {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [topDomains, setTopDomains] = useState<TopDomain[]>([]);

  useEffect(() => {
    setLoading(true);
    api
      .getPolicy(group.id)
      .then(setPolicy)
      .catch((e) => {
        if (e instanceof NotFoundError) {
          setPolicy({ id: "", group_id: group.id, on_load_failure: "FAIL_OPEN", category_toggles: [], overrides: [] });
        } else {
          onError(String(e));
        }
      })
      .finally(() => setLoading(false));

    api.topDomains(group.id).then(setTopDomains).catch(() => {});
  }, [group.id]);

  if (loading || !policy) return <p>Loading...</p>;

  function toggleCategory(categoryId: string) {
    setPolicy((p) => {
      if (!p) return p;
      const exists = p.category_toggles.find((c) => c.category_id === categoryId);
      const category_toggles: CategoryToggle[] = exists
        ? p.category_toggles.filter((c) => c.category_id !== categoryId)
        : [...p.category_toggles, { category_id: categoryId, action: "ACTION_BLOCK" }];
      return { ...p, category_toggles };
    });
  }

  function addOverride(kind: "allow" | "deny") {
    const domain = prompt(`Domain to ${kind === "allow" ? "always allow" : "always block"}?`);
    if (!domain) return;
    setPolicy((p) => (p ? { ...p, overrides: [...p.overrides, { domain, kind } as Override] } : p));
  }

  function removeOverride(domain: string) {
    setPolicy((p) => (p ? { ...p, overrides: p.overrides.filter((o) => o.domain !== domain) } : p));
  }

  async function save() {
    if (!policy) return;
    setSaving(true);
    try {
      const updated = await api.upsertPolicy(group.id, {
        on_load_failure: policy.on_load_failure,
        category_toggles: policy.category_toggles,
        overrides: policy.overrides,
      });
      setPolicy(updated);
    } catch (e) {
      onError(String(e));
    } finally {
      setSaving(false);
    }
  }

  async function compile() {
    try {
      await api.compileBundle(group.id);
      alert("Bundle compiled and published.");
    } catch (e) {
      onError(String(e));
    }
  }

  return (
    <div>
      <h3>Categories</h3>
      <ul className="categories">
        {KNOWN_CATEGORIES.map((cat) => {
          const enabled = policy.category_toggles.some((c) => c.category_id === cat);
          return (
            <li key={cat}>
              <label>
                <input type="checkbox" checked={enabled} onChange={() => toggleCategory(cat)} />
                {cat}
              </label>
            </li>
          );
        })}
      </ul>

      <h3>Overrides</h3>
      <ul className="overrides">
        {policy.overrides.map((o) => (
          <li key={o.domain}>
            <span className={`tag ${o.kind}`}>{o.kind}</span> {o.domain}{" "}
            <button onClick={() => removeOverride(o.domain)}>x</button>
          </li>
        ))}
      </ul>
      <button onClick={() => addOverride("allow")}>+ Allow domain</button>
      <button onClick={() => addOverride("deny")}>+ Block domain</button>

      <h3>Failure policy</h3>
      <select
        value={policy.on_load_failure}
        onChange={(e) => setPolicy((p) => (p ? { ...p, on_load_failure: e.target.value as Policy["on_load_failure"] } : p))}
      >
        <option value="FAIL_OPEN">Fail open (resolve normally if bundle fails to load)</option>
        <option value="FAIL_CLOSED">Fail closed (block all resolution)</option>
      </select>

      <div className="actions">
        <button onClick={save} disabled={saving}>
          {saving ? "Saving..." : "Save policy"}
        </button>
        <button onClick={compile}>Compile & publish bundle</button>
      </div>

      <h3>Top domains (live telemetry)</h3>
      {topDomains.length === 0 && <p className="hint">No query telemetry yet for this group.</p>}
      <table className="top-domains">
        <tbody>
          {topDomains.map((d) => (
            <tr key={`${d.qname}-${d.decision}`}>
              <td>{d.qname}</td>
              <td className={`tag ${d.decision === "block" ? "deny" : "allow"}`}>{d.decision}</td>
              <td>{d.count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
