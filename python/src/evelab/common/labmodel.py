"""Parsed-lab topology records: nodes, their interfaces and networks."""

from dataclasses import dataclass


@dataclass
class Interface:
    id: str
    name: str
    network_id: str | None
    vid: str


@dataclass
class Node:
    id: str
    name: str
    type: str
    template: str
    image: str
    config_attr: str  # "0" | "1" | configset id
    ifaces: list[Interface]


@dataclass
class Network:
    id: str
    type: str
    name: str
    attrs: dict[str, str]

    @property
    def is_cloud(self) -> bool:
        return self.type != "bridge"
