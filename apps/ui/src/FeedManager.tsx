import { useEffect, useState } from "react";
import { api, type Feed } from "./api";

export function FeedManager({ onError }: { onError: (e: string) => void }) {
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [loading, setLoading] = useState(true);
  const [ingesting, setIngesting] = useState<string | null>(null);

  function refresh() {
    setLoading(true);
    api
      .listFeeds()
      .then(setFeeds)
      .catch((e) => onError(String(e)))
      .finally(() => setLoading(false));
  }

  useEffect(refresh, []);

  async function toggleEnabled(feed: Feed) {
    try {
      const updated = await api.updateFeed(feed.id, { enabled: !feed.enabled });
      setFeeds((prev) => prev.map((f) => (f.id === feed.id ? updated : f)));
    } catch (e) {
      onError(String(e));
    }
  }

  async function ingestNow(feed: Feed) {
    setIngesting(feed.id);
    try {
      const result = await api.ingestFeedNow(feed.id);
      alert(`${feed.id}: ${result.status} (${result.domain_count} domains)${result.reason ? ` — ${result.reason}` : ""}`);
      refresh();
    } catch (e) {
      onError(String(e));
    } finally {
      setIngesting(null);
    }
  }

  async function removeFeed(feed: Feed) {
    if (!confirm(`Delete feed "${feed.id}"? This stops its auto-updates.`)) return;
    try {
      await api.deleteFeed(feed.id);
      setFeeds((prev) => prev.filter((f) => f.id !== feed.id));
    } catch (e) {
      onError(String(e));
    }
  }

  async function addCustomFeed() {
    const id = prompt("Feed id (unique, e.g. my-custom-feed)?");
    if (!id) return;
    const category_id = prompt("Category id (e.g. adult, gambling, malware)?") ?? "";
    const url = prompt("Feed URL?") ?? "";
    const format = prompt("Format — \"hostfile\" (0.0.0.0 domain lines) or \"domain-list\" (plain domain lines)?", "hostfile") ?? "hostfile";
    if (!category_id || !url) return;
    try {
      const feed = await api.createFeed({
        id,
        category_id,
        url,
        format,
        interval_seconds: 86400,
        license: "",
        provider: "custom",
      });
      setFeeds((prev) => [...prev, feed]);
    } catch (e) {
      onError(String(e));
    }
  }

  if (loading) return <p>Loading feeds...</p>;

  const byCategory = feeds.reduce<Record<string, Feed[]>>((acc, f) => {
    (acc[f.category_id] ??= []).push(f);
    return acc;
  }, {});

  return (
    <div>
      <p className="hint">
        Pre-loaded from a vetted catalog (StevenBlack, The Block List Project, URLhaus). Toggle, edit interval, or
        add your own — changes take effect immediately, no restart needed.
      </p>
      {Object.entries(byCategory).map(([category, categoryFeeds]) => (
        <div key={category} className="feed-category">
          <h3>{category}</h3>
          <table className="feeds-table">
            <thead>
              <tr>
                <th>Feed</th>
                <th>Provider</th>
                <th>Domains</th>
                <th>Interval</th>
                <th>Enabled</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {categoryFeeds.map((f) => (
                <tr key={f.id}>
                  <td>
                    {f.id} {f.from_catalog && <span className="tag catalog">catalog</span>}
                  </td>
                  <td>{f.provider || "—"}</td>
                  <td>{f.last_domain_count ?? "not yet ingested"}</td>
                  <td>{Math.round(f.interval_seconds / 60)}m</td>
                  <td>
                    <input type="checkbox" checked={f.enabled} onChange={() => toggleEnabled(f)} />
                  </td>
                  <td>
                    <button onClick={() => ingestNow(f)} disabled={ingesting === f.id}>
                      {ingesting === f.id ? "..." : "Ingest now"}
                    </button>
                    <button onClick={() => removeFeed(f)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      <button onClick={addCustomFeed}>+ Add custom feed</button>
    </div>
  );
}
