import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  Banner,
  ConfirmDialog,
  DataTable,
  Input,
  Modal,
  PasswordInput,
  PermissionDenied,
  RoleChip,
  Select,
  SkewButton,
  TimeValue,
  type Column,
} from "../components/ui";
import { ApiError, api } from "../lib/api";
import type { ManagedUser } from "../lib/types";

type Role = ManagedUser["role"];
const ROLES: { value: Role; label: string }[] = [
  { value: "VIEWER", label: "Viewer: read only" },
  { value: "ANALYST", label: "Analyst: read, investigate, manage incidents" },
  { value: "ADMIN", label: "Admin: everything, including users and models" },
];
const MIN_PASSWORD = 8;

function message(err: unknown): string {
  if (err instanceof ApiError && err.status === 409) return err.message; // "username already exists", "cannot delete your own account"
  return err instanceof Error ? err.message : String(err);
}

type Dialog =
  | { kind: "none" }
  | { kind: "create" }
  | { kind: "edit"; user: ManagedUser }
  | { kind: "delete"; user: ManagedUser }
  | { kind: "totp"; user: ManagedUser };

/** Users admin (users:manage). The server enforces every rule; the UI explains them. */
export default function UsersAdmin({ me }: { me: number }) {
  const [users, setUsers] = useState<ManagedUser[] | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [dialog, setDialog] = useState<Dialog>({ kind: "none" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // form fields (create / edit)
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<Role>("VIEWER");
  const [password, setPassword] = useState("");

  const load = useCallback(() => {
    api
      .users()
      .then((list) => {
        setUsers(list.items);
        setLoadError(null);
      })
      .catch((err: unknown) => setLoadError(err));
  }, []);
  useEffect(load, [load]);

  const open = (d: Dialog) => {
    setError(null);
    setPassword("");
    if (d.kind === "create") {
      setUsername("");
      setRole("VIEWER");
    }
    if (d.kind === "edit") setRole(d.user.role);
    setDialog(d);
  };
  const close = () => {
    setPassword(""); // never keep a typed password after the dialog
    setDialog({ kind: "none" });
  };

  const act = async (fn: () => Promise<string>) => {
    setBusy(true);
    setError(null);
    try {
      const done = await fn();
      close();
      setNotice(done);
      load();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  if (loadError instanceof ApiError && loadError.status === 403) {
    return <PermissionDenied permission="users:manage" what="manage users" />;
  }

  const columns: Column<ManagedUser>[] = [
    {
      key: "username",
      header: "Username",
      sort: (u) => u.username,
      render: (u) => (
        <span>
          {u.username}
          {u.id === me ? <span className="sx-hint"> (you)</span> : null}
        </span>
      ),
    },
    { key: "role", header: "Role", sort: (u) => u.role, render: (u) => <RoleChip role={u.role} /> },
    { key: "created", header: "Created", sort: (u) => u.created_at, render: (u) => <TimeValue ts={u.created_at} /> },
    {
      key: "last",
      header: "Last sign-in",
      sort: (u) => u.last_login_at,
      render: (u) => (u.last_login_at ? <TimeValue ts={u.last_login_at} /> : <span className="sx-hint">never</span>),
    },
    {
      key: "actions",
      header: "Actions",
      render: (u) => (
        <span style={{ display: "inline-flex", gap: 6 }}>
          <SkewButton size="sm" variant="ghost" onClick={() => open({ kind: "edit", user: u })} aria-label={`Edit ${u.username}`}>
            Edit
          </SkewButton>
          <SkewButton size="sm" variant="ghost" onClick={() => open({ kind: "totp", user: u })} aria-label={`Remove two-factor for ${u.username}`}>
            Reset 2FA
          </SkewButton>
          <SkewButton
            size="sm"
            variant="danger"
            disabled={u.id === me}
            title={u.id === me ? "You cannot delete your own account" : undefined}
            onClick={() => open({ kind: "delete", user: u })}
            aria-label={`Delete ${u.username}`}
          >
            Delete
          </SkewButton>
        </span>
      ),
    },
  ];

  const createValid = username.trim().length >= 3 && password.length >= MIN_PASSWORD;
  const editing = dialog.kind === "edit" ? dialog.user : null;
  const editChanged = editing ? role !== editing.role || password.length > 0 : false;
  const editValid = editChanged && (password.length === 0 || password.length >= MIN_PASSWORD);

  const submitCreate = (e: FormEvent) => {
    e.preventDefault();
    if (!createValid || busy) return;
    void act(async () => {
      const u = await api.createUser(username.trim(), password, role);
      return `Created ${u.username} (${u.role}).`;
    });
  };
  const submitEdit = (e: FormEvent) => {
    e.preventDefault();
    if (!editing || !editValid || busy) return;
    const patch: { role?: Role; password?: string } = {};
    if (role !== editing.role) patch.role = role;
    if (password) patch.password = password;
    void act(async () => {
      await api.updateUser(editing.id, patch);
      return patch.password ? `Updated ${editing.username}; their sessions were signed out.` : `Updated ${editing.username}.`;
    });
  };

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <p>Accounts are local to this server. Roles decide what each person can do; the server enforces them.</p>
        <SkewButton icon="+" onClick={() => open({ kind: "create" })}>
          New user
        </SkewButton>
      </div>
      {notice ? (
        <Banner
          title="Done"
          action={
            <SkewButton size="sm" variant="ghost" onClick={() => setNotice(null)}>
              Dismiss
            </SkewButton>
          }
        >
          {notice}
        </Banner>
      ) : null}
      <DataTable
        caption="Users"
        columns={columns}
        rows={users}
        loading={users === null && !loadError}
        error={loadError ? message(loadError) : null}
        onRetry={load}
        rowKey={(u) => u.id}
        empty={{ title: "No users" }}
        initialSort={{ key: "username", dir: "asc" }}
      />

      <Modal
        open={dialog.kind === "create"}
        onClose={close}
        title="New user"
        actions={
          <>
            <SkewButton variant="ghost" onClick={close}>
              Cancel
            </SkewButton>
            <SkewButton type="submit" form="sx-create-user" loading={busy} disabled={!createValid}>
              Create
            </SkewButton>
          </>
        }
      >
        <form id="sx-create-user" onSubmit={submitCreate} style={{ display: "grid", gap: 12 }} noValidate>
          <Input label="Username" value={username} onChange={(e) => setUsername(e.target.value)} hint="3 to 32 characters." autoComplete="off" data-autofocus />
          <Select label="Role" value={role} onChange={(e) => setRole(e.target.value as Role)} options={ROLES} />
          <PasswordInput
            label="Initial password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            hint={`At least ${MIN_PASSWORD} characters. Share it with the person privately.`}
          />
          {error ? (
            <Banner tone="error" title="Not created">
              {error}
            </Banner>
          ) : null}
        </form>
      </Modal>

      <Modal
        open={dialog.kind === "edit"}
        onClose={close}
        title={editing ? `Edit ${editing.username}` : "Edit"}
        actions={
          <>
            <SkewButton variant="ghost" onClick={close}>
              Cancel
            </SkewButton>
            <SkewButton type="submit" form="sx-edit-user" loading={busy} disabled={!editValid}>
              Save
            </SkewButton>
          </>
        }
      >
        <form id="sx-edit-user" onSubmit={submitEdit} style={{ display: "grid", gap: 12 }} noValidate>
          <Select label="Role" value={role} onChange={(e) => setRole(e.target.value as Role)} options={ROLES} />
          <PasswordInput
            label="New password (optional)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            error={password.length > 0 && password.length < MIN_PASSWORD ? `Use at least ${MIN_PASSWORD} characters.` : undefined}
          />
          {password ? (
            <p className="sx-consequence">
              <strong>What happens: </strong>every session of {editing?.username} is signed out, including any open browser.
            </p>
          ) : null}
          {editing?.id === me && role !== "ADMIN" ? (
            <p className="sx-consequence">
              <strong>What happens: </strong>you lose admin rights, including this Users screen. The server refuses if you are the last admin.
            </p>
          ) : null}
          {error ? (
            <Banner tone="error" title="Not saved">
              {error}
            </Banner>
          ) : null}
        </form>
      </Modal>

      <ConfirmDialog
        open={dialog.kind === "delete"}
        title={dialog.kind === "delete" ? `Delete ${dialog.user.username}?` : "Delete user?"}
        confirmLabel="Delete user"
        danger
        busy={busy}
        onCancel={close}
        onConfirm={() =>
          dialog.kind === "delete" &&
          void act(async () => {
            await api.deleteUser(dialog.user.id);
            return `Deleted ${dialog.user.username}.`;
          })
        }
        consequence="The account and its sessions are removed and cannot be restored. Its past actions stay in the audit log. The server refuses to delete the last admin."
      >
        {error ? (
          <Banner tone="error" title="Not deleted">
            {error}
          </Banner>
        ) : null}
      </ConfirmDialog>

      <ConfirmDialog
        open={dialog.kind === "totp"}
        title={dialog.kind === "totp" ? `Remove two-factor for ${dialog.user.username}?` : "Remove two-factor?"}
        confirmLabel="Remove two-factor"
        busy={busy}
        onCancel={close}
        onConfirm={() =>
          dialog.kind === "totp" &&
          void act(async () => {
            await api.resetUserTotp(dialog.user.id);
            return `Two-factor removed for ${dialog.user.username}. They sign in with their password and can set it up again.`;
          })
        }
        consequence="Their authenticator app and recovery codes stop working. Use this when someone lost their device; confirm who is asking first."
      >
        {error ? (
          <Banner tone="error" title="Not removed">
            {error}
          </Banner>
        ) : null}
      </ConfirmDialog>
    </div>
  );
}
