"""Authorization vocabulary: roles and permissions (pure data).

One source of truth for *what each role may do*, shared by the API dependency
that enforces it (:mod:`spectra.api.security`), the user service, tests and
the dashboard (which receives the caller's permission list from
``GET /api/auth/me``).

The model is a classic role -> permissions grant (no hierarchy traversal at
request time): ``ADMIN`` holds every permission, ``ANALYST`` adds the
investigation workflow on top of read-only access, ``VIEWER`` holds read-only
access to the dashboard and reports. Routes declare the permission they need;
a request is allowed when the caller's role carries that permission.

Reserved-but-unbound capabilities (documented so the vocabulary does not
drift as features land): model activate/rollback rides ``model:manage`` when
the model registry exists, and a future settings API rides ``config:manage``.
"""

from __future__ import annotations

# -- permissions (route-facing strings) ---------------------------------------

READ = "read"                      # dashboard + reports (any signed-in user)
INVESTIGATE = "investigate"        # correlation graph, audit data, probes
INCIDENTS = "incidents:manage"     # create/acknowledge/resolve + analyst notes
CAPTURE_MANAGE = "capture:manage"  # start/stop live, import/process/delete
MODEL_MANAGE = "model:manage"      # train the detector
CONFIG_MANAGE = "config:manage"    # advanced configuration (edge link/deploy)
USERS_MANAGE = "users:manage"      # user management

PERMISSIONS: tuple[str, ...] = (
    READ,
    INVESTIGATE,
    INCIDENTS,
    CAPTURE_MANAGE,
    MODEL_MANAGE,
    CONFIG_MANAGE,
    USERS_MANAGE,
)

# -- roles ---------------------------------------------------------------------

ADMIN = "ADMIN"
ANALYST = "ANALYST"
VIEWER = "VIEWER"
ROLES: tuple[str, ...] = (ADMIN, ANALYST, VIEWER)

#: The grant table. ADMIN is the union of every permission by construction.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    VIEWER: frozenset({READ}),
    ANALYST: frozenset({READ, INVESTIGATE, INCIDENTS}),
    ADMIN: frozenset(PERMISSIONS),
}


def permissions_for(role: str) -> list[str]:
    """Ordered permission list for a role (empty for an unknown role)."""
    perms = ROLE_PERMISSIONS.get(role)
    if perms is None:
        return []
    return [p for p in PERMISSIONS if p in perms]


def has_permission(role: str, permission: str) -> bool:
    """Whether ``role`` grants ``permission`` (unknown roles grant none)."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
