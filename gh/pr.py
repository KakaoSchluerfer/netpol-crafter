"""
GitHub integration – branch, commit, and pull-request creation.

Authentication priority (first configured wins):
  1. GitHub App  (GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY* + GITHUB_APP_INSTALLATION_ID)
     → Recommended for production. Scoped to the installation, no human token involved.
  2. Personal Access Token (GITHUB_TOKEN)
     → Acceptable for local dev / small teams. Use a fine-grained PAT with only
       "Contents: read/write" and "Pull requests: read/write" on the target repo.

Repository layout created by this client:
  {policies_path}/
    {namespace}/
      {policy-name}.yaml     ← one file per NetworkPolicy

Branch naming:
  netpol/{namespace}/{policy-name}-{YYYYMMDD-HHMMSS}
"""
from __future__ import annotations

import datetime
import textwrap
from typing import Any

from github import Auth, Github, GithubException
from github.Repository import Repository

from config import AppConfig


class GitHubPRClient:
    def __init__(self, config: AppConfig) -> None:
        self._repo_name = config.github_repo
        self._base_branch = config.github_base_branch
        self._policies_path = config.github_policies_path.rstrip("/")
        self._gh = _build_github_client(config)

    # ── Public API ────────────────────────────────────────────────────────────

    def create_policy_pr(
        self,
        *,
        policy_yaml: str,
        policy_name: str,
        namespace: str,
        policy_dict: dict,
        user_info: dict,
        pr_title: str,
        pr_body: str,
    ) -> str:
        """
        Commit the YAML to a new branch and open a PR.
        Returns the PR HTML URL.
        """
        repo = self._get_repo()
        branch_name = _make_branch_name(namespace, policy_name)
        file_path = f"{self._policies_path}/{namespace}/{policy_name}.yaml"

        _create_branch(repo, branch_name, self._base_branch)
        file_action = _upsert_file(
            repo=repo,
            file_path=file_path,
            content=policy_yaml,
            branch=branch_name,
            commit_message=f"feat(netpol): {policy_name} in {namespace}",
        )

        pr = repo.create_pull(
            title=pr_title,
            body=pr_body,
            head=branch_name,
            base=self._base_branch,
            draft=False,
        )

        # Apply a label if it exists on the repo (best-effort, non-fatal)
        _apply_label(pr, "network-policy")

        return pr.html_url

    def test_connection(self) -> str:
        """Return the authenticated actor's login for a connectivity smoke-test."""
        return self._gh.get_user().login

    def _get_repo(self) -> Repository:
        return self._gh.get_repo(self._repo_name)


# ── GitHub auth factory ───────────────────────────────────────────────────────

def _build_github_client(config: AppConfig) -> Github:
    has_app = all([
        config.github_app_id,
        config.github_app_private_key,
        config.github_app_installation_id,
    ])
    if has_app:
        app_auth = Auth.AppAuth(
            app_id=int(config.github_app_id),
            private_key=config.github_app_private_key,
        )
        install_auth = app_auth.get_installation_auth(
            int(config.github_app_installation_id)
        )
        return Github(auth=install_auth)

    if config.github_token:
        return Github(auth=Auth.Token(config.github_token))

    raise EnvironmentError(
        "GitHub auth not configured. Set GITHUB_TOKEN or "
        "GITHUB_APP_ID + GITHUB_APP_PRIVATE_KEY + GITHUB_APP_INSTALLATION_ID."
    )


# ── Git operations ────────────────────────────────────────────────────────────

def _make_branch_name(namespace: str, policy_name: str) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    return f"netpol/{namespace}/{policy_name}-{ts}"


def _create_branch(repo: Repository, branch_name: str, base_branch: str) -> None:
    base_ref = repo.get_git_ref(f"heads/{base_branch}")
    repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base_ref.object.sha)


def _upsert_file(
    repo: Repository,
    file_path: str,
    content: str,
    branch: str,
    commit_message: str,
) -> str:
    """Create or update a file; returns 'created' or 'updated'."""
    try:
        existing = repo.get_contents(file_path, ref=branch)
        repo.update_file(
            path=file_path,
            message=commit_message,
            content=content,
            sha=existing.sha,  # type: ignore[union-attr]
            branch=branch,
        )
        return "updated"
    except GithubException as exc:
        if exc.status == 404:
            repo.create_file(
                path=file_path,
                message=commit_message,
                content=content,
                branch=branch,
            )
            return "created"
        raise


def _apply_label(pr: Any, label_name: str) -> None:
    try:
        pr.add_to_labels(label_name)
    except GithubException:
        pass  # label doesn't exist on this repo – non-fatal


# ── PR body builder ───────────────────────────────────────────────────────────

def build_pr_body(
    policy_name: str,
    namespace: str,
    policy_dict: dict,
    yaml_str: str,
    user_info: dict,
) -> str:
    from auth.oidc import OIDCAuthenticator

    author = OIDCAuthenticator.display_name(user_info)
    email = user_info.get("email", "")
    spec = policy_dict.get("spec", {})
    policy_types = ", ".join(f"`{t}`" for t in spec.get("policyTypes", []))
    pod_labels = spec.get("podSelector", {}).get("matchLabels")
    pod_sel_str = (
        " ".join(f"`{k}={v}`" for k, v in pod_labels.items())
        if pod_labels
        else "**all pods in namespace**"
    )

    ingress_md = _summarise_direction(spec.get("ingress", []), peer_key="from")
    egress_md = _summarise_direction(spec.get("egress", []), peer_key="to")

    # Triple-backtick fences built with string concat to avoid escaping issues
    fence = "```"

    return textwrap.dedent(f"""\
        ## NetworkPolicy: `{policy_name}`

        > Generated by **NetPol Crafter** – review carefully before merging. \
This PR will be picked up by ArgoCD on merge.

        | Field | Value |
        |---|---|
        | **Namespace** | `{namespace}` |
        | **Policy types** | {policy_types} |
        | **Target pods** | {pod_sel_str} |
        | **Author** | {author} ({email}) |

        ### Ingress rules
        {ingress_md}

        ### Egress rules
        {egress_md}

        ### Generated YAML
        {fence}yaml
        {yaml_str.rstrip()}
        {fence}

        ---
        ### Reviewer checklist
        - [ ] `podSelector` matches the intended workload, not a single ephemeral replica
        - [ ] `namespaceSelector` is not overly broad (avoid selecting all namespaces)
        - [ ] Port restrictions reflect least-privilege for this service
        - [ ] Policy does not block platform traffic: CoreDNS (UDP/TCP 53), metrics scraping, OpenShift SDN health checks
        - [ ] Validated in a non-production namespace before merging to `{namespace}`
        - [ ] Linked to a change ticket or Jira story
    """)


def _summarise_direction(rules: list[dict], peer_key: str) -> str:
    if not rules:
        return "_None – all traffic in this direction is **denied**._"

    lines = []
    for i, rule in enumerate(rules, 1):
        peers = rule.get(peer_key, [])
        ports = rule.get("ports", [])

        peer_parts = []
        for peer in peers:
            ns_sel = peer.get("namespaceSelector", {}).get("matchLabels", {})
            pod_sel = peer.get("podSelector", {}).get("matchLabels", {})
            parts = []
            if ns_sel:
                parts.append("ns: " + " ".join(f"`{k}={v}`" for k, v in ns_sel.items()))
            elif "namespaceSelector" in peer:
                parts.append("ns: **any**")
            if pod_sel:
                parts.append("pod: " + " ".join(f"`{k}={v}`" for k, v in pod_sel.items()))
            elif "podSelector" in peer and not pod_sel:
                parts.append("pod: **any**")
            peer_parts.append(", ".join(parts) or "**any**")

        port_str = (
            " | ".join(f"{p.get('protocol','TCP')}:{p.get('port','*')}" for p in ports)
            if ports
            else "all ports"
        )
        lines.append(f"**Rule {i}:** {' + '.join(peer_parts)} → ports: `{port_str}`")

    return "\n".join(f"- {line}" for line in lines)
