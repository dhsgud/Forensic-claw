"""Plot the held-out replay results used in the manuscript."""

import json
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent

if __name__ == "__main__":
    summary = json.loads((ROOT / "results.json").read_text(encoding="utf-8"))["summary"]
    styles = {
        "checklist": ("Checklist", "#777777", ":", "x"),
        "best_fixed_dev": ("Tuned fixed order", "#222222", "--", "s"),
        "greedy": ("Greedy", "#a75718", "-.", "^"),
        "lookahead": ("Lookahead", "#145779", "-", "o"),
    }
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.05), sharey=True, layout="constrained")
    budgets = list(range(1, 6))
    for ax, (condition, label) in zip(
        axes,
        (("standard", "(a) Standard"), ("split_archives", "(b) Profile-specific archives")),
        strict=True,
    ):
        for policy, (name, color, line, marker) in reversed(styles.items()):
            counts = [summary[f"{condition}/{b}/{policy}"]["correct"] for b in budgets]
            ax.plot(
                budgets,
                counts,
                label=name,
                color=color,
                linestyle=line,
                marker=marker,
                markersize=4,
                markerfacecolor="white",
                linewidth=1.2,
            )
        ax.set(
            title=label,
            xlabel="Query budget",
            xticks=budgets,
            yticks=range(0, 17, 4),
            ylim=(-0.7, 17.9),
        )
        ax.grid(axis="y", alpha=0.2)
        ax.spines[["right", "top"]].set_visible(False)
    axes[0].set_ylabel("Correct verdicts (of 16)")
    fig.legend(
        *axes[0].get_legend_handles_labels(),
        loc="outside lower center",
        ncol=4,
        frameon=False,
        fontsize=8,
    )
    fig.savefig(ROOT / "budget-curves.png", dpi=260, facecolor="white")
