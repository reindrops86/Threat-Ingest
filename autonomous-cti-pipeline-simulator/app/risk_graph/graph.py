from __future__ import annotations

from typing import Any, Iterable

ENTRY_NODE = "internet"
MAX_PATH_DEPTH = 8


RISKS: dict[str, dict[str, Any]] = {
    "public_exposure": {
        "label": "Public internet exposure",
        "category": "exposure",
        "detail": "Application load balancer is reachable from any source address.",
    },
    "rce_cve": {
        "label": "Unauthenticated RCE (CVE)",
        "category": "vulnerability",
        "detail": "RAG API runs a vulnerable inference dependency allowing remote code execution.",
    },
    "admin_privilege": {
        "label": "Overprivileged IAM role",
        "category": "identity",
        "detail": "Inference workload assumes a role with administrative permissions.",
    },
    "plaintext_llm_key": {
        "label": "Plaintext LLM API key",
        "category": "secret",
        "detail": "Model provider key is stored in a container environment variable.",
    },
    "unencrypted_training_data": {
        "label": "Unencrypted training bucket",
        "category": "data",
        "detail": "Training corpus is stored without encryption or access logging.",
    },
    "imds_v1": {
        "label": "IMDSv1 enabled",
        "category": "lateral movement",
        "detail": "Node metadata service allows credential theft from a compromised container.",
    },
    "shadow_ai": {
        "label": "Shadow AI deployment",
        "category": "governance",
        "detail": "Unmanaged notebook deploys a model outside the approved pipeline.",
    },
    "no_egress_control": {
        "label": "Unrestricted egress",
        "category": "exfiltration",
        "detail": "Workload can reach arbitrary external endpoints, enabling model and data leakage.",
    },
}


def build_environment() -> dict[str, Any]:
    """Deterministic cloud and AI environment used by the risk graph simulator."""
    nodes = [
        {"id": ENTRY_NODE, "label": "Internet", "kind": "external", "risks": []},
        {"id": "alb", "label": "Public API gateway", "kind": "network", "risks": ["public_exposure"]},
        {"id": "rag_api", "label": "RAG inference service", "kind": "ai workload", "risks": ["rce_cve"]},
        {"id": "k8s_node", "label": "Kubernetes node", "kind": "compute", "risks": ["imds_v1"]},
        {"id": "inference_role", "label": "Inference IAM role", "kind": "identity", "risks": ["admin_privilege"]},
        {"id": "llm_secret", "label": "LLM provider key", "kind": "secret", "risks": ["plaintext_llm_key"]},
        {"id": "notebook", "label": "Shadow AI notebook", "kind": "ai workload", "risks": ["shadow_ai"]},
        {"id": "vector_db", "label": "Vector store (embeddings)", "kind": "ai data", "risks": [], "crown_jewel": True},
        {"id": "training_bucket", "label": "Training data bucket", "kind": "ai data", "risks": ["unencrypted_training_data"], "crown_jewel": True},
        {"id": "customer_db", "label": "Customer database", "kind": "data", "risks": [], "crown_jewel": True},
        {"id": "external_sink", "label": "Attacker-controlled endpoint", "kind": "external", "risks": ["no_egress_control"], "crown_jewel": True},
    ]
    edges = [
        {"from": ENTRY_NODE, "to": "alb", "relationship": "reaches", "requires": ["public_exposure"]},
        {"from": ENTRY_NODE, "to": "notebook", "relationship": "reaches unmanaged endpoint", "requires": ["shadow_ai"]},
        {"from": "notebook", "to": "inference_role", "relationship": "inherits role", "requires": ["shadow_ai"]},
        {"from": "alb", "to": "rag_api", "relationship": "routes to", "requires": []},
        {"from": "rag_api", "to": "k8s_node", "relationship": "executes on", "requires": ["rce_cve"]},
        {"from": "rag_api", "to": "llm_secret", "relationship": "reads env var", "requires": ["rce_cve", "plaintext_llm_key"]},
        {"from": "k8s_node", "to": "inference_role", "relationship": "steals credentials via IMDS", "requires": ["imds_v1"]},
        {"from": "inference_role", "to": "training_bucket", "relationship": "reads objects", "requires": ["admin_privilege"]},
        {"from": "inference_role", "to": "customer_db", "relationship": "assumes access", "requires": ["admin_privilege"]},
        {"from": "rag_api", "to": "vector_db", "relationship": "queries", "requires": ["rce_cve"]},
        {"from": "notebook", "to": "training_bucket", "relationship": "writes model artifacts", "requires": ["shadow_ai"]},
        {"from": "llm_secret", "to": "external_sink", "relationship": "exfiltrates via model API", "requires": ["no_egress_control"]},
        {"from": "vector_db", "to": "external_sink", "relationship": "leaks embeddings", "requires": ["no_egress_control"]},
    ]
    return {"nodes": nodes, "edges": edges}


def default_enabled_risks() -> list[str]:
    return [risk for risk in RISKS if risk != "shadow_ai"]


def _node_index(environment: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {node["id"]: node for node in environment["nodes"]}


def _live_edges(environment: dict[str, Any], enabled: Iterable[str]) -> list[dict[str, Any]]:
    active = set(enabled)
    return [edge for edge in environment["edges"] if all(risk in active for risk in edge["requires"])]


def find_attack_paths(environment: dict[str, Any], enabled: Iterable[str]) -> list[dict[str, Any]]:
    """Enumerate live paths from the internet to any crown-jewel asset."""
    nodes = _node_index(environment)
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for edge in _live_edges(environment, enabled):
        adjacency.setdefault(edge["from"], []).append(edge)

    paths: list[dict[str, Any]] = []

    def walk(current: str, trail: list[dict[str, Any]], visited: set[str]) -> None:
        if len(trail) >= MAX_PATH_DEPTH:
            return
        for edge in adjacency.get(current, []):
            target = edge["to"]
            if target in visited:
                continue
            next_trail = trail + [edge]
            if nodes[target].get("crown_jewel"):
                paths.append(_score_path(nodes, next_trail, enabled))
            walk(target, next_trail, visited | {target})

    walk(ENTRY_NODE, [], {ENTRY_NODE})
    return sorted(paths, key=lambda path: path["severity_score"], reverse=True)


def _score_path(nodes: dict[str, dict[str, Any]], trail: list[dict[str, Any]], enabled: Iterable[str]) -> dict[str, Any]:
    active = set(enabled)
    sequence = [ENTRY_NODE] + [edge["to"] for edge in trail]
    path_risks: list[str] = []
    for node_id in sequence:
        for risk in nodes[node_id]["risks"]:
            if risk in active and risk not in path_risks:
                path_risks.append(risk)

    categories = {RISKS[risk]["category"] for risk in path_risks}
    target = nodes[sequence[-1]]
    score = 25 * len(categories) + 10 * len(path_risks)
    if target["kind"].startswith("ai"):
        score += 15
    score = min(100, score)

    return {
        "path_id": "-".join(sequence),
        "sequence": sequence,
        "labels": [nodes[node_id]["label"] for node_id in sequence],
        "edges": trail,
        "target": target["label"],
        "target_kind": target["kind"],
        "risks": path_risks,
        "categories": sorted(categories),
        "severity_score": score,
        "severity": _severity(score),
        "toxic_combination": len(categories) >= 3,
        "ai_impact": target["kind"].startswith("ai") or any(nodes[node]["kind"].startswith("ai") for node in sequence),
    }


def _severity(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def rank_remediations(environment: dict[str, Any], enabled: Iterable[str]) -> list[dict[str, Any]]:
    """Rank each active risk by how many critical attack paths removing it eliminates."""
    active = list(enabled)
    baseline = find_attack_paths(environment, active)
    baseline_toxic = sum(1 for path in baseline if path["toxic_combination"])

    ranking: list[dict[str, Any]] = []
    for risk in active:
        remaining = find_attack_paths(environment, [item for item in active if item != risk])
        remaining_toxic = sum(1 for path in remaining if path["toxic_combination"])
        ranking.append(
            {
                "risk": risk,
                "label": RISKS[risk]["label"],
                "category": RISKS[risk]["category"],
                "paths_removed": len(baseline) - len(remaining),
                "toxic_paths_removed": baseline_toxic - remaining_toxic,
                "detail": RISKS[risk]["detail"],
            }
        )
    return sorted(ranking, key=lambda item: (item["toxic_paths_removed"], item["paths_removed"]), reverse=True)


def summarize(environment: dict[str, Any], enabled: Iterable[str]) -> dict[str, Any]:
    paths = find_attack_paths(environment, enabled)
    toxic = [path for path in paths if path["toxic_combination"]]
    return {
        "attack_paths": paths,
        "toxic_combinations": toxic,
        "ai_paths": [path for path in paths if path["ai_impact"]],
        "critical_count": sum(1 for path in paths if path["severity"] == "critical"),
        "remediations": rank_remediations(environment, enabled),
    }
