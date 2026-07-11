/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import {
  Avatar,
  Button,
  Card,
  ColorInput,
  FileButton,
  Group,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput,
  Title,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useEffect, useRef, useState } from "react";
import { useBlockPageTemplate, useCompileBundle, useUpsertBlockPageTemplate } from "../api/hooks";
import type { components } from "../api/schema";

const LOGO_MAX_BYTES = 200 * 1024; // server caps the stored data URI at ~220KB post-base64
const LOGO_MIME_RE = /^image\/(png|jpeg|gif|webp|svg\+xml)$/;

function readFileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error ?? new Error("Failed to read file"));
    reader.readAsDataURL(file);
  });
}

type Upsert = components["schemas"]["BlockPageTemplateUpsert"];
type BlockMode = "BLOCK_MODE_NXDOMAIN" | "BLOCK_MODE_ZERO_IP" | "BLOCK_MODE_REDIRECT";

const MODE_OPTIONS = [
  { value: "BLOCK_MODE_NXDOMAIN", label: "NXDOMAIN — bare resolver error (no page)" },
  { value: "BLOCK_MODE_ZERO_IP", label: "0.0.0.0 — dead-end address, connection fails" },
  { value: "BLOCK_MODE_REDIRECT", label: "Redirect — show the block page below" },
];

const DEFAULTS: Upsert = {
  block_mode: "BLOCK_MODE_NXDOMAIN",
  redirect_ipv4: null,
  redirect_ipv6: null,
  ttl_seconds: 30,
  title: null,
  message: null,
  logo_url: null,
  brand_color: null,
  contact_url: null,
  show_domain: true,
  show_category: true,
};

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Mirrors the filter node's render_page (blockpage.rs) closely enough to
 * preview branding. Sample domain/category stand in for a real blocked query. */
function previewHtml(t: Upsert): string {
  const color = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(t.brand_color ?? "")
    ? t.brand_color!
    : "#c0392b";
  const title = escapeHtml(t.title || "Access blocked");
  const message = escapeHtml(
    t.message || "This site has been blocked by your network's content policy."
  );
  let body = "";
  if (t.logo_url) body += `<img class="logo" src="${escapeHtml(t.logo_url)}" alt="">`;
  body += `<h1>${title}</h1><p class="msg">${message}</p>`;
  if (t.show_domain)
    body += `<p class="domain">Requested site: <strong>ads.example.com</strong></p>`;
  if (t.show_category) body += `<p class="reason">Category: <strong>advertising</strong></p>`;
  if (t.contact_url)
    body += `<p class="contact"><a href="${escapeHtml(
      t.contact_url
    )}">Request access or contact your administrator</a></p>`;

  return `<!doctype html><html><head><meta charset="utf-8"><style>
:root{color-scheme:light dark}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f4f4f5;color:#18181b}
.card{max-width:32rem;margin:1rem;padding:2.5rem;background:#fff;border-radius:12px;
box-shadow:0 10px 30px rgba(0,0,0,.08);border-top:6px solid ${color};text-align:center}
.logo{max-height:56px;margin-bottom:1rem}
h1{margin:.25rem 0 1rem;font-size:1.5rem;color:${color}}
.msg{font-size:1.05rem;line-height:1.5}
.domain,.reason{margin:.5rem 0;color:#52525b;font-size:.95rem}
.contact{margin-top:1.5rem}.contact a{color:${color}}
</style></head><body><main class="card">${body}</main></body></html>`;
}

export function BlockPageCard({
  groupId,
  canEdit,
}: {
  groupId: string | undefined;
  canEdit: boolean;
}) {
  const { data: template } = useBlockPageTemplate(groupId);
  const upsert = useUpsertBlockPageTemplate(groupId);
  const compileBundle = useCompileBundle();

  const [form, setForm] = useState<Upsert>(DEFAULTS);
  const [logoUploading, setLogoUploading] = useState(false);
  const resetLogoPicker = useRef<() => void>(null);

  useEffect(() => {
    // template === null means "no override configured yet" → keep defaults.
    if (!template) {
      setForm(DEFAULTS);
      return;
    }
    setForm({
      block_mode: template.block_mode as BlockMode,
      redirect_ipv4: template.redirect_ipv4,
      redirect_ipv6: template.redirect_ipv6,
      ttl_seconds: template.ttl_seconds,
      title: template.title,
      message: template.message,
      logo_url: template.logo_url,
      brand_color: template.brand_color,
      contact_url: template.contact_url,
      show_domain: template.show_domain,
      show_category: template.show_category,
    });
  }, [template]);

  const isRedirect = form.block_mode === "BLOCK_MODE_REDIRECT";
  const missingRedirectIp = isRedirect && !form.redirect_ipv4 && !form.redirect_ipv6;

  function set<K extends keyof Upsert>(key: K, value: Upsert[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  async function uploadLogo(file: File | null) {
    if (!file) return;
    if (!LOGO_MIME_RE.test(file.type)) {
      notifications.show({ message: "Logo must be a PNG, JPEG, GIF, WEBP or SVG image", color: "red" });
      resetLogoPicker.current?.();
      return;
    }
    if (file.size > LOGO_MAX_BYTES) {
      notifications.show({
        message: `Logo must be under ${Math.round(LOGO_MAX_BYTES / 1024)}KB (got ${Math.round(file.size / 1024)}KB)`,
        color: "red",
      });
      resetLogoPicker.current?.();
      return;
    }
    setLogoUploading(true);
    try {
      set("logo_url", await readFileAsDataUrl(file));
    } catch (e) {
      notifications.show({ message: String(e), color: "red" });
    } finally {
      setLogoUploading(false);
      resetLogoPicker.current?.();
    }
  }

  function save() {
    if (!groupId) return;
    upsert.mutate(form, {
      onSuccess: () => {
        // Hot-path fields (mode/redirect target/ttl) only take effect once compiled
        // into the group's bundle — recompile immediately so "save" actually redirects.
        compileBundle.mutate(groupId, {
          onSuccess: () =>
            notifications.show({ message: "Block page saved and published", color: "green" }),
          onError: (e) =>
            notifications.show({
              message: `Block page saved, but publishing the bundle failed: ${String(e)}`,
              color: "red",
            }),
        });
      },
      onError: (e) => notifications.show({ message: String(e), color: "red" }),
    });
  }

  return (
    <Card withBorder>
      <Title order={4} mb="xs">
        Block page
      </Title>
      <Text size="sm" c="dimmed" mb="md">
        What clients get for a blocked domain. Redirect mode points blocked web requests at the
        filter node's block-page listener. Saving publishes the mode/redirect target immediately;
        branding updates apply within a minute.
      </Text>

      <Stack gap="md">
        <Select
          label="When a domain is blocked"
          data={MODE_OPTIONS}
          value={form.block_mode}
          onChange={(v) => v && set("block_mode", v as BlockMode)}
          allowDeselect={false}
          disabled={!canEdit}
        />

        {isRedirect && (
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <TextInput
              label="Redirect IPv4"
              placeholder="10.0.0.53"
              value={form.redirect_ipv4 ?? ""}
              onChange={(e) => set("redirect_ipv4", e.currentTarget.value || null)}
              error={missingRedirectIp ? "Set an IPv4 or IPv6 address" : undefined}
              disabled={!canEdit}
            />
            <TextInput
              label="Redirect IPv6 (optional)"
              placeholder="fd00::53"
              value={form.redirect_ipv6 ?? ""}
              onChange={(e) => set("redirect_ipv6", e.currentTarget.value || null)}
              disabled={!canEdit}
            />
            <NumberInput
              label="TTL (seconds)"
              min={0}
              max={86400}
              value={form.ttl_seconds ?? 30}
              onChange={(v) => set("ttl_seconds", typeof v === "number" ? v : 30)}
              disabled={!canEdit}
            />
          </SimpleGrid>
        )}

        {isRedirect && (
          <>
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput
                label="Title"
                placeholder="Access blocked"
                value={form.title ?? ""}
                onChange={(e) => set("title", e.currentTarget.value || null)}
                disabled={!canEdit}
              />
              <ColorInput
                label="Brand color"
                placeholder="#c0392b"
                value={form.brand_color ?? ""}
                onChange={(v) => set("brand_color", v || null)}
                disabled={!canEdit}
              />
            </SimpleGrid>
            <Textarea
              label="Message"
              placeholder="This site has been blocked by your network's content policy."
              minRows={3}
              value={form.message ?? ""}
              onChange={(e) => set("message", e.currentTarget.value || null)}
              disabled={!canEdit}
            />
            <Stack gap="xs">
              <Text size="sm" fw={500}>
                Logo
              </Text>
              <Group align="center" gap="sm">
                <Avatar
                  src={form.logo_url || null}
                  radius="sm"
                  size={56}
                  style={{ border: "1px solid var(--mantine-color-default-border)" }}
                >
                  {!form.logo_url && "?"}
                </Avatar>
                <FileButton
                  resetRef={resetLogoPicker}
                  onChange={uploadLogo}
                  accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml"
                  disabled={!canEdit || logoUploading}
                >
                  {(props) => (
                    <Button {...props} variant="default" loading={logoUploading}>
                      Upload logo
                    </Button>
                  )}
                </FileButton>
                {form.logo_url && (
                  <Button
                    variant="subtle"
                    color="red"
                    onClick={() => set("logo_url", null)}
                    disabled={!canEdit}
                  >
                    Remove
                  </Button>
                )}
              </Group>
              <Text size="xs" c="dimmed">
                PNG, JPEG, GIF, WEBP or SVG, up to {Math.round(LOGO_MAX_BYTES / 1024)}KB. Or paste a
                hosted image URL instead:
              </Text>
              <TextInput
                placeholder="https://…/logo.png"
                value={form.logo_url && !form.logo_url.startsWith("data:") ? form.logo_url : ""}
                onChange={(e) => set("logo_url", e.currentTarget.value || null)}
                disabled={!canEdit}
              />
            </Stack>
            <TextInput
              label="Contact / request-access URL"
              placeholder="https://…/unblock"
              value={form.contact_url ?? ""}
              onChange={(e) => set("contact_url", e.currentTarget.value || null)}
              disabled={!canEdit}
            />
            <Group>
              <Switch
                label="Show requested domain"
                checked={form.show_domain ?? true}
                onChange={(e) => set("show_domain", e.currentTarget.checked)}
                disabled={!canEdit}
              />
              <Switch
                label="Show block category"
                checked={form.show_category ?? true}
                onChange={(e) => set("show_category", e.currentTarget.checked)}
                disabled={!canEdit}
              />
            </Group>

            <div>
              <Text size="xs" fw={700} tt="uppercase" c="dimmed" mb="xs">
                Live preview
              </Text>
              <iframe
                title="Block page preview"
                srcDoc={previewHtml(form)}
                style={{
                  width: "100%",
                  height: 340,
                  border: "1px solid var(--mantine-color-default-border)",
                  borderRadius: 8,
                }}
              />
            </div>
          </>
        )}

        {canEdit && (
          <Group>
            <Button
              onClick={save}
              loading={upsert.isPending || compileBundle.isPending}
              disabled={missingRedirectIp}
            >
              Save block page
            </Button>
          </Group>
        )}
      </Stack>
    </Card>
  );
}
