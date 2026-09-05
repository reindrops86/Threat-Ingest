from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable, List

import matplotlib.pyplot as plt
import networkx as nx


class ThreatActorGraph:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_node(self, node_id: str, node_type: str, **attrs) -> None:
        attrs.setdefault("type", node_type)
        attrs.setdefault("name", node_id)
        self.graph.add_node(node_id, **attrs)

    def add_actor(self, actor_id: str, **attrs) -> None:
        self.add_node(actor_id, "actor", **attrs)

    def add_infrastructure(self, infra_id: str, **attrs) -> None:
        self.add_node(infra_id, "infrastructure", **attrs)

    def add_ttp(self, ttp_id: str, **attrs) -> None:
        self.add_node(ttp_id, "ttp", **attrs)

    def add_campaign(self, campaign_id: str, **attrs) -> None:
        self.add_node(campaign_id, "campaign", **attrs)

    def add_relationship(self, source: str, target: str, rel_type: str, **attrs) -> None:
        self.graph.add_edge(source, target, relationship=rel_type, **attrs)

    def get_neighbors(self, node_id: str) -> List[str]:
        return list(self.graph.neighbors(node_id))

    def find_related_nodes(self, node_id: str, relationship: str | None = None) -> List[str]:
        related = []
        for source, target, data in self.graph.edges(data=True):
            if source == node_id and (relationship is None or data.get("relationship") == relationship):
                related.append(target)
        return related

    def path_between(self, start: str, end: str) -> list[str]:
        try:
            return nx.shortest_path(self.graph, start, end)
        except nx.NetworkXNoPath:
            return []

    def node_summary(self) -> dict:
        summary = defaultdict(int)
        for _, data in self.graph.nodes(data=True):
            summary[data.get("type", "unknown")] += 1
        return dict(summary)

    def list_nodes_by_type(self, node_type: str) -> list[str]:
        return [node for node, data in self.graph.nodes(data=True) if data.get("type") == node_type]

    def visualize(self, output_path: str | Path = "threat_actor_graph.png", figsize: tuple[int, int] = (12, 8)) -> None:
        pos = nx.spring_layout(self.graph, seed=42)
        node_types = {"actor": "#ff7f0e", "infrastructure": "#2ca02c", "ttp": "#1f77b4", "campaign": "#d62728"}
        color_map = [node_types.get(self.graph.nodes[n].get("type"), "#7f7f7f") for n in self.graph.nodes]

        plt.figure(figsize=figsize)
        nx.draw(
            self.graph,
            pos,
            with_labels=True,
            node_color=color_map,
            node_size=1500,
            edge_color="#666666",
            arrows=True,
            font_size=10,
        )
        plt.tight_layout()
        plt.savefig(output_path, dpi=200)
        plt.close()


def build_demo_graph() -> ThreatActorGraph:
    g = ThreatActorGraph()

    # Actors
    g.add_actor(
        "APT29",
        aliases=["Cozy Bear", "IRON HEMLOCK"],
        region="Russia",
        focus="Cyber espionage",
        confidence=0.88,
    )
    g.add_actor(
        "FIN7",
        aliases=["Carbon Spider"],
        region="United States / global",
        focus="Financial theft and POS attacks",
        confidence=0.82,
    )
    g.add_actor(
        "Lazarus Group",
        aliases=["Hidden Cobra"],
        region="North Korea",
        focus="Cybercrime and strategic disruption",
        confidence=0.90,
    )

    # Infrastructure
    g.add_infrastructure(
        "mail-verify[.]com",
        category="domain",
        malicious=True,
        first_seen="2023-02-14",
    )
    g.add_infrastructure(
        "webmail-security[.]net",
        category="domain",
        malicious=True,
        first_seen="2023-03-01",
    )
    g.add_infrastructure(
        "invoice-update[.]cloud",
        category="cdn",
        malicious=True,
        first_seen="2024-01-06",
    )

    # TTPs
    g.add_ttp("Spear Phishing", description="Targeted phishing for credential theft")
    g.add_ttp("Credential Harvesting", description="Collection of session tokens and user credentials")
    g.add_ttp("Living-off-the-land", description="Use of legitimate system tools for stealth")
    g.add_ttp("PowerShell Loader", description="Execution of encoded payloads through PowerShell")

    # Campaigns
    g.add_campaign(
        "Operation Ghost",
        objective="Credential theft against diplomatic targets",
        year=2023,
    )
    g.add_campaign(
        "Trident Finance",
        objective="POS compromise and payment card theft",
        year=2024,
    )
    g.add_campaign(
        "Moonlight Incursion",
        objective="Financial theft and strategic disruption",
        year=2023,
    )

    # Relationships
    g.add_relationship("APT29", "Spear Phishing", "uses")
    g.add_relationship("APT29", "Credential Harvesting", "uses")
    g.add_relationship("APT29", "mail-verify[.]com", "controls")
    g.add_relationship("mail-verify[.]com", "Operation Ghost", "supports")
    g.add_relationship("APT29", "Operation Ghost", "conducts")

    g.add_relationship("FIN7", "PowerShell Loader", "uses")
    g.add_relationship("FIN7", "invoice-update[.]cloud", "controls")
    g.add_relationship("FIN7", "Trident Finance", "conducts")
    g.add_relationship("invoice-update[.]cloud", "Trident Finance", "supports")

    g.add_relationship("Lazarus Group", "Living-off-the-land", "uses")
    g.add_relationship("Lazarus Group", "webmail-security[.]net", "controls")
    g.add_relationship("Lazarus Group", "Moonlight Incursion", "conducts")
    g.add_relationship("webmail-security[.]net", "Moonlight Incursion", "supports")

    g.add_relationship("Spear Phishing", "mail-verify[.]com", "uses")
    g.add_relationship("Credential Harvesting", "mail-verify[.]com", "uses")
    g.add_relationship("PowerShell Loader", "invoice-update[.]cloud", "uses")
    g.add_relationship("Living-off-the-land", "webmail-security[.]net", "uses")

    return g


def main() -> None:
    graph = build_demo_graph()
    print("Node summary:", graph.node_summary())
    print("APT29 related:", graph.find_related_nodes("APT29"))
    print("Path from APT29 to Operation Ghost:", graph.path_between("APT29", "Operation Ghost"))
    print("Actors:", graph.list_nodes_by_type("actor"))
    graph.visualize("threat_actor_graph.png")
    print("Saved graph visualization to threat_actor_graph.png")


if __name__ == "__main__":
    main()
