from __future__ import annotations

import json

from forensic_claw.agent.loop import AgentLoop


def test_agent_loop_collects_graph_views_from_knowledge_search_tool_results() -> None:
    messages = [
        {"role": "user", "content": "show db graph"},
        {
            "role": "tool",
            "name": "knowledge_search",
            "content": json.dumps(
                {
                    "query": "powershell 10.0.0.5",
                    "backend": "sqlite",
                    "graphView": {
                        "nodes": [
                            {"id": "source:security.log", "label": "security.log", "kind": "Source"},
                            {"id": "ip:10.0.0.5", "label": "10.0.0.5", "kind": "IP"},
                        ],
                        "edges": [
                            {
                                "id": "source:security.log:MENTIONS:ip:10.0.0.5",
                                "source": "source:security.log",
                                "target": "ip:10.0.0.5",
                                "label": "MENTIONS",
                            }
                        ],
                    },
                }
            ),
        },
    ]

    views = AgentLoop._collect_turn_graph_views(messages, skip=1)

    assert views == [
        {
            "title": "Evidence Relationship Graph",
            "query": "powershell 10.0.0.5",
            "source": "sqlite",
            "nodes": [
                {
                    "id": "source:security.log",
                    "label": "security.log",
                    "kind": "Source",
                    "group": "Source",
                    "degree": 0,
                    "metadata": {
                        "id": "source:security.log",
                        "label": "security.log",
                        "kind": "Source",
                    },
                },
                {
                    "id": "ip:10.0.0.5",
                    "label": "10.0.0.5",
                    "kind": "IP",
                    "group": "IP",
                    "degree": 0,
                    "metadata": {
                        "id": "ip:10.0.0.5",
                        "label": "10.0.0.5",
                        "kind": "IP",
                    },
                },
            ],
            "edges": [
                {
                    "id": "source:security.log:MENTIONS:ip:10.0.0.5",
                    "source": "source:security.log",
                    "target": "ip:10.0.0.5",
                    "label": "MENTIONS",
                    "type": "MENTIONS",
                    "metadata": {
                        "id": "source:security.log:MENTIONS:ip:10.0.0.5",
                        "source": "source:security.log",
                        "target": "ip:10.0.0.5",
                        "label": "MENTIONS",
                    },
                }
            ],
        }
    ]
