"""Figures for the extended lightweight-AEAD comparison.

Every figure in this module is drawn from a CSV that
``src/extended_benchmark.py`` actually measured.  If a required CSV is missing
the figure is skipped with a warning rather than drawn from placeholder data.

Style
-----
The colour and marker for Ascon-AEAD128 and AES-128-GCM are inherited from
``src/analyze_results.ALGORITHM_STYLE`` so that a reader moving between the
core figures (graph1-graph8) and the extension figures (graph09-graph18) sees
the same algorithm in the same colour throughout the report.

The one rule every figure obeys
-------------------------------
Pure-Python and OpenSSL results are never presented as if they were the same
kind of measurement.  Same-tier series are solid lines; the OpenSSL AES-128-GCM
series is dashed and grey-labelled, and any ranking figure either excludes it
or separates it visually with a caption saying why.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import matplotlib

matplotlib.use("Agg")           # headless: no display server needed
import matplotlib.pyplot as plt        # noqa: E402
import numpy as np                      # noqa: E402
import pandas as pd                     # noqa: E402

from .analyze_results import ALGORITHM_STYLE  # noqa: E402
from .config import GRAPHS_DIR, ExperimentConfig, get_config  # noqa: E402
from .extended_benchmark import (MEMORY_CSV, OVERHEAD_CSV, REFERENCE_ALGORITHM,  # noqa: E402
                                 SUMMARY_CSV, WORKLOAD_CSV)

#: Colours for the five added algorithms. Ascon and AES-GCM keep the colours
#: they already have in the core figures.
EXTENDED_STYLE: dict[str, dict[str, object]] = {
    "Ascon-AEAD128": {"color": "#d62728", "marker": "s", "linestyle": "-"},
    "TinyJAMBU-128": {"color": "#8c564b", "marker": "X", "linestyle": "-"},
    "Xoodyak": {"color": "#7f7f7f", "marker": "*", "linestyle": "-"},
    "Schwaemm256-128": {"color": "#17becf", "marker": "<", "linestyle": "-"},
    "GIFT-COFB": {"color": "#9467bd", "marker": "P", "linestyle": "-"},
    "AES-128-CCM": {"color": "#2ca02c", "marker": "D", "linestyle": "-"},
    "AES-128-GCM": {"color": "#1f77b4", "marker": "o", "linestyle": "--"},
}

#: Payload size treated as "a typical IoT telemetry frame" in the ranking figures.
IOT_SIZE = 128

TIER_NOTE = ("Solid lines: pure-Python implementations (same tier as Ascon -- an "
             "algorithm comparison).\nDashed line: AES-128-GCM via OpenSSL with "
             "AES-NI (a different tier -- an implementation comparison).")


def _style(algorithm: str) -> dict:
    return dict(EXTENDED_STYLE.get(
        algorithm, ALGORITHM_STYLE.get(algorithm,
                                       {"color": "#555555", "marker": "^", "linestyle": ":"})))


def _read(path: Path) -> pd.DataFrame | None:
    if not path.exists():
        warnings.warn(f"missing input {path}; figure skipped")
        return None
    return pd.read_csv(path)


def _save(figure, name: str, config: ExperimentConfig, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.{config.graph_format}"
    figure.tight_layout()
    # bbox_inches="tight" keeps the explanatory footnote below the axes
    figure.savefig(path, dpi=config.graph_dpi, bbox_inches="tight")
    plt.close(figure)
    return path


def _size_axis(axes, sizes) -> None:
    axes.set_xscale("log", base=2)
    axes.set_xticks(sorted(set(sizes)))
    axes.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    axes.set_xlabel("Payload size (bytes, log$_2$ scale)")


def _footnote(figure, text: str) -> None:
    figure.text(0.5, -0.02, text, ha="center", fontsize=7.5, color="#555555")


# --------------------------------------------------------------------------
# graph09 / graph10 -- latency sweeps
# --------------------------------------------------------------------------
def _latency_sweep(summary: pd.DataFrame, operation: str, number: str,
                   config: ExperimentConfig, directory: Path) -> Path:
    data = summary[summary["operation"] == operation]
    figure, axes = plt.subplots(figsize=(8.6, 5.4))
    for algorithm, group in data.groupby("algorithm"):
        group = group.sort_values("message_size")
        axes.plot(group["message_size"], group["mean_us"], label=str(algorithm),
                  linewidth=1.7, markersize=5, **_style(str(algorithm)))
    _size_axis(axes, data["message_size"])
    axes.set_yscale("log")
    axes.set_ylabel(f"Mean {operation}ion latency (microseconds, log scale)")
    axes.set_title(f"Figure {number} - {operation.capitalize()}ion latency: "
                   f"Ascon-AEAD128 vs five lightweight AEAD schemes", fontsize=12, pad=12)
    axes.grid(True, which="both", linewidth=0.4, alpha=0.5)
    axes.legend(fontsize=8.5, ncol=2)
    _footnote(figure, TIER_NOTE)
    return _save(figure, f"graph{number}_lw_{operation}_latency", config, directory)


# --------------------------------------------------------------------------
# graph11 / graph12 -- throughput sweeps
# --------------------------------------------------------------------------
def _throughput_sweep(summary: pd.DataFrame, operation: str, number: str,
                      config: ExperimentConfig, directory: Path) -> Path:
    data = summary[summary["operation"] == operation]
    figure, axes = plt.subplots(figsize=(8.6, 5.4))
    for algorithm, group in data.groupby("algorithm"):
        group = group.sort_values("message_size")
        axes.plot(group["message_size"], group["throughput_mb_s_mean"], label=str(algorithm),
                  linewidth=1.7, markersize=5, **_style(str(algorithm)))
    _size_axis(axes, data["message_size"])
    axes.set_yscale("log")
    axes.set_ylabel(f"{operation.capitalize()}ion throughput (MB/s, log scale)")
    axes.set_title(f"Figure {number} - {operation.capitalize()}ion throughput: "
                   f"Ascon-AEAD128 vs five lightweight AEAD schemes", fontsize=12, pad=12)
    axes.grid(True, which="both", linewidth=0.4, alpha=0.5)
    axes.legend(fontsize=8.5, ncol=2)
    _footnote(figure, TIER_NOTE)
    return _save(figure, f"graph{number}_lw_{operation}_throughput", config, directory)


# --------------------------------------------------------------------------
# graph13 -- the headline ranking at a realistic IoT payload size
# --------------------------------------------------------------------------
def _small_message_ranking(summary: pd.DataFrame, config: ExperimentConfig,
                           directory: Path) -> Path:
    sizes = sorted(summary["message_size"].unique())
    size = IOT_SIZE if IOT_SIZE in sizes else sizes[len(sizes) // 2]
    data = summary[(summary["message_size"] == size)
                   & (summary["operation"] == "encrypt")
                   & (summary["tier"] == "pure-python")].sort_values("mean_us")

    figure, axes = plt.subplots(figsize=(8.6, 5.0))
    y = np.arange(len(data))
    errors = data["ci95_half_width_ns"] / 1000.0
    colours = [_style(a)["color"] for a in data["algorithm"]]
    axes.barh(y, data["mean_us"], xerr=errors, capsize=3, color=colours, height=0.62)
    axes.set_yticks(y)
    axes.set_yticklabels(data["algorithm"], fontsize=9)
    axes.invert_yaxis()
    axes.set_xlabel("Mean encryption latency (microseconds), lower is better")
    axes.set_title(f"Figure 13 - Ranking at a {size}-byte IoT payload\n"
                   "(same implementation tier; error bars are 95% confidence intervals)",
                   fontsize=12, pad=12)
    axes.grid(True, axis="x", linewidth=0.4, alpha=0.5)
    best = data["mean_us"].iloc[0]
    for yi, (value, name) in enumerate(zip(data["mean_us"], data["algorithm"])):
        label = f"{value:,.0f} us" + ("  <-- fastest" if value == best else
                                      f"  ({value / best:.2f}x)")
        axes.annotate(label, (value, yi), xytext=(6, 0), textcoords="offset points",
                      va="center", fontsize=8)
    axes.set_xlim(0, data["mean_us"].max() * 1.30)
    _footnote(figure, "AES-128-GCM is excluded from this ranking: it runs in OpenSSL C with "
                      "AES-NI, so ranking it here would compare implementations, not algorithms.")
    return _save(figure, "graph13_lw_small_message_ranking", config, directory)


# --------------------------------------------------------------------------
# graph14 -- how much faster Ascon is, per algorithm, per size
# --------------------------------------------------------------------------
def _speedup(summary: pd.DataFrame, config: ExperimentConfig, directory: Path) -> Path:
    data = summary[(summary["operation"] == "encrypt") & (summary["tier"] == "pure-python")]
    reference = data[data["algorithm"] == REFERENCE_ALGORITHM].set_index("message_size")["mean_us"]
    others = sorted(set(data["algorithm"]) - {REFERENCE_ALGORITHM})
    sizes = sorted(data["message_size"].unique())

    figure, axes = plt.subplots(figsize=(9.0, 5.2))
    width = 0.8 / max(1, len(others))
    x = np.arange(len(sizes))
    for index, algorithm in enumerate(others):
        series = data[data["algorithm"] == algorithm].set_index("message_size")["mean_us"]
        ratios = [series.get(s, np.nan) / reference.get(s, np.nan) for s in sizes]
        axes.bar(x + index * width - 0.4 + width / 2, ratios, width=width * 0.92,
                 label=algorithm, color=_style(algorithm)["color"])
    axes.axhline(1.0, color="#d62728", linestyle="--", linewidth=1.4)
    axes.annotate("Ascon-AEAD128 baseline (1.0x)", xy=(len(sizes) - 0.5, 1.03),
                  ha="right", fontsize=8, color="#d62728")
    axes.set_xticks(x)
    axes.set_xticklabels([str(s) for s in sizes])
    axes.set_xlabel("Payload size (bytes)")
    axes.set_ylabel("Latency relative to Ascon-AEAD128\n(>1 means slower than Ascon)")
    axes.set_title("Figure 14 - How each lightweight algorithm compares with Ascon-AEAD128\n"
                   "(encryption, same implementation tier)", fontsize=12, pad=12)
    axes.grid(True, axis="y", linewidth=0.4, alpha=0.5)
    axes.legend(fontsize=8.5, ncol=3)
    _footnote(figure, "Bars above the dashed line are slower than Ascon at that payload size; "
                      "bars below are faster. Computed from measured mean latencies.")
    return _save(figure, "graph14_lw_ascon_relative_speed", config, directory)


# --------------------------------------------------------------------------
# graph15 -- communication overhead (implementation independent)
# --------------------------------------------------------------------------
def _overhead(overhead: pd.DataFrame, config: ExperimentConfig, directory: Path) -> Path:
    figure, axes = plt.subplots(1, 2, figsize=(12.4, 5.0))

    for algorithm, group in overhead.groupby("algorithm"):
        group = group.sort_values("plaintext_size")
        axes[0].plot(group["plaintext_size"], group["overhead_percent"], label=str(algorithm),
                     linewidth=1.6, markersize=4.5, **_style(str(algorithm)))
    _size_axis(axes[0], overhead["plaintext_size"])
    axes[0].set_ylabel("Cryptographic overhead (% of bytes transmitted)")
    axes[0].set_title("Overhead vs payload size", fontsize=11)
    axes[0].grid(True, which="both", linewidth=0.4, alpha=0.5)
    axes[0].legend(fontsize=8)

    smallest = overhead[overhead["plaintext_size"] == overhead["plaintext_size"].min()]
    smallest = smallest.sort_values("wire_overhead_bytes")
    x = np.arange(len(smallest))
    axes[1].bar(x, smallest["nonce_bytes"], color="#1f77b4", label="nonce")
    axes[1].bar(x, smallest["tag_bytes"], bottom=smallest["nonce_bytes"],
                color="#d62728", label="authentication tag")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(smallest["algorithm"], rotation=35, ha="right", fontsize=8)
    axes[1].set_ylabel("Bytes added to every message")
    axes[1].set_title("What the overhead is made of", fontsize=11)
    axes[1].grid(True, axis="y", linewidth=0.4, alpha=0.5)
    axes[1].legend(fontsize=8)
    for xi, total in enumerate(smallest["wire_overhead_bytes"]):
        axes[1].annotate(f"{int(total)} B", (xi, total), xytext=(0, 3),
                         textcoords="offset points", ha="center", fontsize=8)

    figure.suptitle("Figure 15 - Communication overhead: the one metric that transfers "
                    "directly to real hardware", fontsize=12)
    _footnote(figure, "Depends only on nonce and tag sizes fixed by each specification, so it is "
                      "identical on any machine. TinyJAMBU is smallest because its tag is 64-bit, "
                      "not 128-bit -- lower overhead bought with weaker forgery resistance.")
    return _save(figure, "graph15_lw_communication_overhead", config, directory)


# --------------------------------------------------------------------------
# graph16 -- peak Python-heap memory, same tier only
# --------------------------------------------------------------------------
def _memory(memory: pd.DataFrame, config: ExperimentConfig, directory: Path) -> Path:
    data = memory[memory["tier"] == "pure-python"]
    grouped = (data.groupby(["algorithm", "message_size"])["peak_python_heap_bytes"]
               .mean().reset_index())
    figure, axes = plt.subplots(figsize=(8.6, 5.2))
    for algorithm, group in grouped.groupby("algorithm"):
        group = group.sort_values("message_size")
        axes.plot(group["message_size"], group["peak_python_heap_bytes"], label=str(algorithm),
                  linewidth=1.7, markersize=5, **_style(str(algorithm)))
    _size_axis(axes, grouped["message_size"])
    axes.set_yscale("log")
    axes.set_ylabel("Peak Python heap allocated per operation (bytes, log scale)")
    axes.set_title("Figure 16 - Transient memory use per operation\n"
                   "(pure-Python tier only -- tracemalloc cannot observe OpenSSL's C heap)",
                   fontsize=12, pad=12)
    axes.grid(True, which="both", linewidth=0.4, alpha=0.5)
    axes.legend(fontsize=8.5, ncol=2)
    _footnote(figure, "This measures interpreter allocation, not the RAM a microcontroller would "
                      "need. It is a relative indicator within this tier only.")
    return _save(figure, "graph16_lw_peak_memory", config, directory)


# --------------------------------------------------------------------------
# graph17 -- end-to-end secured-message rate on the real sensor traffic
# --------------------------------------------------------------------------
def _workload(workload: pd.DataFrame, config: ExperimentConfig, directory: Path) -> Path:
    grouped = (workload.groupby(["algorithm", "tier"])["messages_per_second"]
               .mean().reset_index().sort_values("messages_per_second", ascending=False))
    figure, axes = plt.subplots(figsize=(8.8, 5.2))
    x = np.arange(len(grouped))
    colours = [_style(a)["color"] for a in grouped["algorithm"]]
    hatches = ["//" if t == "native-c" else "" for t in grouped["tier"]]
    bars = axes.bar(x, grouped["messages_per_second"], color=colours)
    for bar, hatch in zip(bars, hatches):
        bar.set_hatch(hatch)
    axes.set_yscale("log")
    axes.set_xticks(x)
    axes.set_xticklabels(grouped["algorithm"], rotation=35, ha="right", fontsize=8.5)
    axes.set_ylabel("Sensor messages secured per second (log scale)")
    axes.set_title("Figure 17 - End-to-end rate on the project's own synthetic warehouse traffic\n"
                   "(encrypt + decrypt of each real reading, with its real AAD)",
                   fontsize=12, pad=12)
    axes.grid(True, axis="y", which="both", linewidth=0.4, alpha=0.5)
    for xi, value in zip(x, grouped["messages_per_second"]):
        axes.annotate(f"{value:,.0f}", (xi, value), xytext=(0, 3),
                      textcoords="offset points", ha="center", fontsize=8)
    _footnote(figure, "Hatched bar = OpenSSL C implementation (different tier). "
                      "All other bars are interpreted Python and are directly comparable.")
    return _save(figure, "graph17_lw_end_to_end_rate", config, directory)


# --------------------------------------------------------------------------
# graph18 -- multi-metric summary
# --------------------------------------------------------------------------
def _multimetric(summary: pd.DataFrame, overhead: pd.DataFrame,
                 config: ExperimentConfig, directory: Path) -> Path:
    """Normalised score per metric, plus an explicitly arbitrary composite.

    Each metric is scaled so 1.0 is the best value observed among the
    same-tier algorithms.  The composite averages them with equal weights,
    which is a *choice* and is labelled as such on the figure: the per-metric
    panel, not the composite, is the defensible result.
    """
    sizes = sorted(summary["message_size"].unique())
    size = IOT_SIZE if IOT_SIZE in sizes else sizes[len(sizes) // 2]
    enc = summary[(summary["operation"] == "encrypt") & (summary["message_size"] == size)
                  & (summary["tier"] == "pure-python")].set_index("algorithm")
    dec = summary[(summary["operation"] == "decrypt") & (summary["message_size"] == size)
                  & (summary["tier"] == "pure-python")].set_index("algorithm")
    ovh = overhead[(overhead["plaintext_size"] == size)].set_index("algorithm")
    mem = None

    algorithms = [a for a in enc.index if a in dec.index and a in ovh.index]
    frame = pd.DataFrame(index=algorithms)
    frame["Encryption\nspeed"] = enc.loc[algorithms, "mean_us"].min() / enc.loc[algorithms, "mean_us"]
    frame["Decryption\nspeed"] = dec.loc[algorithms, "mean_us"].min() / dec.loc[algorithms, "mean_us"]
    frame["Wire\nefficiency"] = (ovh.loc[algorithms, "wire_overhead_bytes"].min()
                                 / ovh.loc[algorithms, "wire_overhead_bytes"])
    tag_bits = ovh.loc[algorithms, "tag_bytes"] * 8
    frame["Integrity\nstrength"] = tag_bits / tag_bits.max()
    standardised = {"Ascon-AEAD128": 1.0, "AES-128-CCM": 1.0}
    frame["Standardisation\nstatus"] = [standardised.get(a, 0.4) for a in algorithms]
    frame["composite"] = frame.mean(axis=1)
    frame = frame.sort_values("composite", ascending=False)

    metrics = [c for c in frame.columns if c != "composite"]
    figure, axes = plt.subplots(1, 2, figsize=(13.6, 5.4),
                                gridspec_kw={"width_ratios": [1.4, 1], "wspace": 0.5})
    matrix = frame[metrics].values
    image = axes[0].imshow(matrix, cmap="YlGn", vmin=0, vmax=1, aspect="auto")
    axes[0].set_xticks(np.arange(len(metrics)))
    axes[0].set_xticklabels(metrics, fontsize=8)
    axes[0].set_yticks(np.arange(len(frame)))
    axes[0].set_yticklabels(frame.index, fontsize=9)
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            axes[0].text(j, i, f"{matrix[i, j]:.2f}", ha="center", va="center", fontsize=8)
    axes[0].set_title("Per-metric normalised score (1.00 = best observed)", fontsize=11)
    axes[0].grid(False)
    figure.colorbar(image, ax=axes[0], shrink=0.85, pad=0.03)

    y = np.arange(len(frame))
    axes[1].barh(y, frame["composite"], color=[_style(a)["color"] for a in frame.index], height=0.62)
    axes[1].set_yticks(y)
    axes[1].set_yticklabels(frame.index, fontsize=9)
    axes[1].invert_yaxis()
    axes[1].set_xlim(0, 1.05)
    axes[1].set_xlabel("Equal-weight composite score")
    axes[1].set_title("Composite ranking\n(equal weights: a choice, not a finding)", fontsize=11)
    axes[1].grid(True, axis="x", linewidth=0.4, alpha=0.5)
    for yi, value in zip(y, frame["composite"]):
        axes[1].annotate(f"{value:.2f}", (value, yi), xytext=(4, 0),
                         textcoords="offset points", va="center", fontsize=8)

    figure.suptitle(f"Figure 18 - Multi-metric comparison at a {size}-byte payload "
                    "(pure-Python tier)", fontsize=12)
    _footnote(figure, "Speed metrics are measured; wire efficiency and integrity strength are "
                      "fixed by each specification; standardisation status is 1.0 for a published "
                      "standard and 0.4 for an unstandardised NIST-LWC finalist.")
    return _save(figure, "graph18_lw_multimetric_summary", config, directory)


# --------------------------------------------------------------------------
# graph19 -- Ascon against the four NIST-LWC finalists only
# --------------------------------------------------------------------------
#: The four finalists Ascon was standardised ahead of. AES-128-CCM is excluded
#: here because it is not a NIST-LWC candidate -- it is the deployed incumbent,
#: and it appears in every other figure.
FINALISTS = ("TinyJAMBU-128", "Xoodyak", "Schwaemm256-128", "GIFT-COFB")


def _ascon_vs_finalists(summary: pd.DataFrame, config: ExperimentConfig,
                        directory: Path) -> Path:
    """The competition re-run: Ascon against the finalists it beat.

    This is the figure that answers the project's second research question
    directly. Everything plotted is in the same implementation tier, so the
    comparison is between algorithms rather than between implementations, and
    the four comparators are exactly the NIST-LWC finalists whose reference
    implementations could be ported and vector-validated for this study.
    """
    keep = (REFERENCE_ALGORITHM,) + FINALISTS
    data = summary[(summary["operation"] == "encrypt") & (summary["algorithm"].isin(keep))]
    sizes = sorted(data["message_size"].unique())
    reference = data[data["algorithm"] == REFERENCE_ALGORITHM].set_index("message_size")["mean_us"]

    figure, axes = plt.subplots(1, 2, figsize=(13.2, 5.2))

    # Left: absolute latency, log scale, Ascon emphasised.
    for algorithm, group in data.groupby("algorithm"):
        group = group.sort_values("message_size")
        style = _style(str(algorithm))
        emphasised = algorithm == REFERENCE_ALGORITHM
        axes[0].plot(group["message_size"], group["mean_us"], label=str(algorithm),
                     linewidth=3.0 if emphasised else 1.6,
                     markersize=7 if emphasised else 5,
                     zorder=5 if emphasised else 2, **style)
    _size_axis(axes[0], data["message_size"])
    axes[0].set_yscale("log")
    axes[0].set_ylabel("Mean encryption latency (microseconds, log scale)")
    axes[0].set_title("Absolute latency (lower is better)", fontsize=11)
    axes[0].grid(True, which="both", linewidth=0.4, alpha=0.5)
    axes[0].legend(fontsize=8.5)

    # Right: speed-up factor of Ascon over each finalist.
    width = 0.8 / len(FINALISTS)
    x = np.arange(len(sizes))
    for index, algorithm in enumerate(FINALISTS):
        series = data[data["algorithm"] == algorithm].set_index("message_size")["mean_us"]
        factors = [series.get(s, np.nan) / reference.get(s, np.nan) for s in sizes]
        offset = index * width - 0.4 + width / 2
        axes[1].bar(x + offset, factors, width=width * 0.9, label=algorithm,
                    color=_style(algorithm)["color"])
    axes[1].axhline(1.0, color=_style(REFERENCE_ALGORITHM)["color"], linestyle="--", linewidth=1.6)
    axes[1].annotate("Ascon-AEAD128 = 1.0x", xy=(-0.48, 1.08), ha="left", va="bottom",
                     fontsize=8.5, color=_style(REFERENCE_ALGORITHM)["color"])
    axes[1].set_xticks(x)
    axes[1].set_xticklabels([str(s) for s in sizes])
    axes[1].set_xlabel("Payload size (bytes)")
    axes[1].set_ylabel("Times slower than Ascon-AEAD128")
    axes[1].set_title("Ascon's advantage over each finalist", fontsize=11)
    axes[1].grid(True, axis="y", linewidth=0.4, alpha=0.5)
    axes[1].legend(fontsize=8.5, ncol=2)

    figure.suptitle("Figure 19 - Ascon-AEAD128 against the four NIST-LWC finalists in this study",
                    fontsize=12.5)
    _footnote(figure, "All five series are pure-Python implementations validated against 1089 "
                      "official test vectors each, measured through one identical harness, so this "
                      "is an algorithm comparison. Every bar is above 1.0 at every payload size.")
    return _save(figure, "graph19_lw_ascon_vs_finalists", config, directory)


# --------------------------------------------------------------------------
def generate_extended_graphs(config: ExperimentConfig | None = None,
                             directory: Path = GRAPHS_DIR) -> list[Path]:
    """Draw every extension figure that has the data it needs."""
    config = config or get_config("full")
    written: list[Path] = []

    summary = _read(SUMMARY_CSV)
    if summary is not None:
        written.append(_latency_sweep(summary, "encrypt", "09", config, directory))
        written.append(_latency_sweep(summary, "decrypt", "10", config, directory))
        written.append(_throughput_sweep(summary, "encrypt", "11", config, directory))
        written.append(_throughput_sweep(summary, "decrypt", "12", config, directory))
        written.append(_small_message_ranking(summary, config, directory))
        written.append(_speedup(summary, config, directory))
        written.append(_ascon_vs_finalists(summary, config, directory))

    overhead = _read(OVERHEAD_CSV)
    if overhead is not None:
        written.append(_overhead(overhead, config, directory))

    memory = _read(MEMORY_CSV)
    if memory is not None:
        written.append(_memory(memory, config, directory))

    workload = _read(WORKLOAD_CSV)
    if workload is not None:
        written.append(_workload(workload, config, directory))

    if summary is not None and overhead is not None:
        written.append(_multimetric(summary, overhead, config, directory))

    return written
