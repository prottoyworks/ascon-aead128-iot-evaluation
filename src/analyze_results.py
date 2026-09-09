"""Statistical aggregation and graph generation from measured results only.

Nothing in this module invents, adjusts or smooths a measurement.  Every value
it emits is computed from ``results/raw_results.csv``,
``results/memory_results.csv`` and ``results/overhead_results.csv``, all of
which are produced by ``src/benchmark.py`` from actual execution.

Statistical choices
-------------------
*Both mean and median are reported.*  Timing data on a general-purpose
operating system is right-skewed: a scheduler preemption or an interrupt
lengthens a sample but nothing can shorten it below the true cost.  The mean is
sensitive to that tail; the median is not.  Where they diverge sharply, the
distribution is telling you the machine was noisy, and the report should say so
rather than quietly quoting whichever is more flattering.

*The 95% confidence interval uses Student's t.*  With a finite sample the
normal quantile 1.96 is slightly too narrow; ``scipy`` is deliberately not a
dependency, so the t critical value is taken from a small embedded table with a
fall-back to the normal quantile for large samples.  The interval describes the
precision of the estimated *mean* on this machine -- it says nothing about how
results would transfer to different hardware.

*Throughput is derived, never measured directly.*  ``bytes / seconds``, from
the same samples that produced the latency figures.  Reporting it as an
independent measurement would double-count.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from .config import (
    ALG_AES_GCM,
    ALG_ASCON,
    GRAPHS_DIR,
    MEMORY_RESULTS_CSV,
    OP_DECRYPT,
    OP_ENCRYPT,
    OVERHEAD_RESULTS_CSV,
    RAW_RESULTS_CSV,
    SUMMARY_RESULTS_CSV,
    ExperimentConfig,
)

#: Two-sided Student's t critical values at 95% confidence, by degrees of
#: freedom.  Values beyond the table fall back to the normal quantile, which is
#: accurate to better than 1% for df > 100.
_T_TABLE_95: dict[int, float] = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 15: 2.131, 20: 2.086, 25: 2.060, 30: 2.042,
    40: 2.021, 50: 2.009, 60: 2.000, 80: 1.990, 100: 1.984,
}
_NORMAL_Z_95: float = 1.960

#: Consistent, colour-blind-distinguishable styling for both algorithms.
ALGORITHM_STYLE: dict[str, dict[str, object]] = {
    ALG_AES_GCM: {"color": "#1f77b4", "marker": "o", "linestyle": "-"},
    ALG_ASCON: {"color": "#d62728", "marker": "s", "linestyle": "--"},
}


def t_critical_95(degrees_of_freedom: int) -> float:
    """Two-sided 95% t critical value for `degrees_of_freedom`."""
    if degrees_of_freedom < 1:
        return float("nan")
    if degrees_of_freedom in _T_TABLE_95:
        return _T_TABLE_95[degrees_of_freedom]
    candidates = [df for df in _T_TABLE_95 if df <= degrees_of_freedom]
    if not candidates:
        return _T_TABLE_95[1]
    if degrees_of_freedom > 100:
        return _NORMAL_Z_95
    return _T_TABLE_95[max(candidates)]


@dataclass(frozen=True)
class LoadedResults:
    """The three measured datasets, plus the harness noise floor."""

    timings: pd.DataFrame
    memory: pd.DataFrame
    overhead: pd.DataFrame
    harness_baseline_ns: float | None


def _require(path: Path, what: str) -> Path:
    if not path.is_file():
        raise FileNotFoundError(
            f"{what} not found at {path}.\n"
            "Run a benchmark first:\n"
            "    python main.py benchmark --quick     (fast smoke test)\n"
            "    python main.py benchmark --full      (reportable results)"
        )
    return path


def load_results(
    raw_path: Path = RAW_RESULTS_CSV,
    memory_path: Path = MEMORY_RESULTS_CSV,
    overhead_path: Path = OVERHEAD_RESULTS_CSV,
) -> LoadedResults:
    """Load every measured CSV produced by the benchmark."""
    timings = pd.read_csv(_require(raw_path, "Raw timing results"))
    memory = pd.read_csv(_require(memory_path, "Memory results"))
    overhead = pd.read_csv(_require(overhead_path, "Overhead results"))

    baseline_rows = timings[timings["operation"] == "harness_baseline"]
    baseline = float(baseline_rows["time_ns"].median()) if not baseline_rows.empty else None
    return LoadedResults(timings, memory, overhead, baseline)


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------

def summarise_timings(
    timings: pd.DataFrame, config: ExperimentConfig
) -> pd.DataFrame:
    """Aggregate raw samples by (algorithm, message size, operation).

    Returns a DataFrame with counts, central tendency, dispersion, extremes,
    a 95% confidence interval on the mean, and derived throughput.
    """
    working = timings[timings["algorithm"] != "HARNESS-BASELINE"].copy()

    grouped = working.groupby(["algorithm", "message_size", "operation"], as_index=False)
    summary = grouped.agg(
        samples=("time_ns", "count"),
        mean_ns=("time_ns", "mean"),
        median_ns=("time_ns", "median"),
        stdev_ns=("time_ns", lambda s: s.std(ddof=1)),
        min_ns=("time_ns", "min"),
        max_ns=("time_ns", "max"),
        p95_ns=("time_ns", lambda s: s.quantile(0.95)),
        batch_size=("batch_size", "max"),
        plaintext_size=("plaintext_size", "max"),
        ciphertext_size=("ciphertext_size", "max"),
    )

    # 95% confidence interval on the mean: mean +/- t * (s / sqrt(n)).
    def half_width(row: pd.Series) -> float:
        n = int(row["samples"])
        if n < 2 or not math.isfinite(row["stdev_ns"]):
            return float("nan")
        return t_critical_95(n - 1) * row["stdev_ns"] / math.sqrt(n)

    summary["ci95_half_width_ns"] = summary.apply(half_width, axis=1)
    summary["ci95_lower_ns"] = summary["mean_ns"] - summary["ci95_half_width_ns"]
    summary["ci95_upper_ns"] = summary["mean_ns"] + summary["ci95_half_width_ns"]

    # Convenience columns in human-readable units.
    summary["mean_us"] = summary["mean_ns"] / 1_000.0
    summary["median_us"] = summary["median_ns"] / 1_000.0

    # Throughput, derived from the *median* (robust to scheduler outliers) and
    # from the mean, in megabytes per second and messages per second.
    # Only meaningful where a message was actually processed.
    has_payload = summary["message_size"] > 0
    summary["throughput_mb_s_median"] = 0.0
    summary["throughput_mb_s_mean"] = 0.0
    summary["messages_per_second_median"] = 0.0
    summary.loc[has_payload, "throughput_mb_s_median"] = (
        summary.loc[has_payload, "message_size"] / summary.loc[has_payload, "median_ns"]
    ) * 1_000.0
    # Unit derivation for the x1000 factor above:
    #   1 byte/ns = 1e9 bytes/s = (1e9 / 1e6) MB/s = 1000 MB/s
    # where MB is 10^6 bytes, the convention used throughout this project.
    summary.loc[has_payload, "throughput_mb_s_mean"] = (
        summary.loc[has_payload, "message_size"] / summary.loc[has_payload, "mean_ns"]
    ) * 1_000.0
    summary.loc[has_payload, "messages_per_second_median"] = (
        1_000_000_000.0 / summary.loc[has_payload, "median_ns"]
    )

    summary = summary.sort_values(["operation", "algorithm", "message_size"])
    return summary.reset_index(drop=True)


def summarise_memory(memory: pd.DataFrame) -> pd.DataFrame:
    """Aggregate the tracemalloc pass."""
    grouped = memory.groupby(["algorithm", "message_size", "operation"], as_index=False)
    return grouped.agg(
        samples=("peak_python_heap_bytes", "count"),
        mean_peak_bytes=("peak_python_heap_bytes", "mean"),
        median_peak_bytes=("peak_python_heap_bytes", "median"),
        min_peak_bytes=("peak_python_heap_bytes", "min"),
        max_peak_bytes=("peak_python_heap_bytes", "max"),
    ).sort_values(["operation", "algorithm", "message_size"]).reset_index(drop=True)


def write_summary(summary: pd.DataFrame, path: Path = SUMMARY_RESULTS_CSV) -> Path:
    """Write the aggregated timing statistics."""
    path.parent.mkdir(parents=True, exist_ok=True)
    summary.to_csv(path, index=False)
    return path


# --------------------------------------------------------------------------
# Graphs
# --------------------------------------------------------------------------

def _new_axes(title: str, xlabel: str, ylabel: str):
    """Create a consistently styled figure/axes pair."""
    import matplotlib.pyplot as plt

    figure, axes = plt.subplots(figsize=(8.0, 5.0))
    axes.set_title(title, fontsize=12, pad=12)
    axes.set_xlabel(xlabel, fontsize=10)
    axes.set_ylabel(ylabel, fontsize=10)
    axes.grid(True, which="both", linewidth=0.4, alpha=0.5)
    return figure, axes


def _plot_series(axes, data: pd.DataFrame, x: str, y: str, yerr: str | None = None) -> None:
    """Draw one line per algorithm."""
    for algorithm, group in data.groupby("algorithm"):
        group = group.sort_values(x)
        style = ALGORITHM_STYLE.get(
            str(algorithm), {"color": "#555555", "marker": "^", "linestyle": ":"}
        )
        if yerr is not None and yerr in group and group[yerr].notna().any():
            axes.errorbar(
                group[x], group[y], yerr=group[yerr],
                label=str(algorithm), capsize=3, linewidth=1.6, markersize=5, **style,
            )
        else:
            axes.plot(
                group[x], group[y],
                label=str(algorithm), linewidth=1.6, markersize=5, **style,
            )


def _save(figure, name: str, config: ExperimentConfig, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.{config.graph_format}"
    figure.tight_layout()
    figure.savefig(path, dpi=config.graph_dpi)
    import matplotlib.pyplot as plt

    plt.close(figure)
    return path


def generate_graphs(
    results: LoadedResults,
    summary: pd.DataFrame,
    memory_summary: pd.DataFrame,
    config: ExperimentConfig,
    directory: Path = GRAPHS_DIR,
) -> list[Path]:
    """Produce every figure from measured data.  Returns the paths written."""
    import matplotlib

    # Select the headless backend before any pyplot import, so the figures
    # render on a machine with no display server (CI, a remote shell, or a
    # Windows box with no interactive session).
    matplotlib.use("Agg")

    written: list[Path] = []
    floor = results.harness_baseline_ns

    def annotate_floor(axes) -> None:
        """Draw the harness noise floor so the reader can see it."""
        if floor is None or floor <= 0:
            return
        axes.axhline(
            floor / 1_000.0, color="#888888", linewidth=1.0, linestyle=":",
            label=f"Harness noise floor ({floor/1000.0:.3f} µs)",
        )

    # ---- Graphs 1 & 2: latency vs message size --------------------------
    for operation, index in ((OP_ENCRYPT, 1), (OP_DECRYPT, 2)):
        data = summary[(summary["operation"] == operation) & (summary["message_size"] > 0)]
        if data.empty:
            continue
        data = data.assign(ci_us=data["ci95_half_width_ns"] / 1000.0)
        figure, axes = _new_axes(
            f"{operation.capitalize()} latency vs message size\n"
            "(log-log; error bars = 95% CI on the mean)",
            "Plaintext size (bytes)",
            "Latency per operation (microseconds)",
        )
        _plot_series(axes, data, "message_size", "mean_us", yerr="ci_us")
        annotate_floor(axes)
        axes.set_xscale("log", base=2)
        axes.set_yscale("log")
        axes.set_xticks(list(config.message_sizes))
        axes.set_xticklabels([str(s) for s in config.message_sizes])
        axes.legend(fontsize=8)
        written.append(_save(figure, f"graph{index}_{operation}_latency", config, directory))

    # ---- Graphs 3 & 4: throughput vs message size -----------------------
    for operation, index in ((OP_ENCRYPT, 3), (OP_DECRYPT, 4)):
        data = summary[(summary["operation"] == operation) & (summary["message_size"] > 0)]
        if data.empty:
            continue
        figure, axes = _new_axes(
            f"{operation.capitalize()} throughput vs message size\n"
            "(derived from median latency)",
            "Plaintext size (bytes)",
            "Throughput (MB/s)",
        )
        _plot_series(axes, data, "message_size", "throughput_mb_s_median")
        axes.set_xscale("log", base=2)
        axes.set_yscale("log")
        axes.set_xticks(list(config.message_sizes))
        axes.set_xticklabels([str(s) for s in config.message_sizes])
        axes.legend(fontsize=8)
        written.append(_save(figure, f"graph{index}_{operation}_throughput", config, directory))

    # ---- Graph 5: peak Python-heap allocation ---------------------------
    data = memory_summary[memory_summary["operation"] == OP_ENCRYPT]
    if not data.empty:
        figure, axes = _new_axes(
            "Peak Python-heap allocation during encryption\n"
            "NOT an algorithm memory footprint - see caption",
            "Plaintext size (bytes)",
            "Peak tracemalloc allocation (bytes)",
        )
        _plot_series(axes, data, "message_size", "median_peak_bytes")
        axes.set_xscale("log", base=2)
        axes.set_yscale("log")
        axes.set_xticks(list(config.message_sizes))
        axes.set_xticklabels([str(s) for s in config.message_sizes])
        axes.legend(fontsize=8)
        figure.text(
            0.5, 0.005,
            "tracemalloc observes Python allocations only. AES-GCM's working memory is "
            "allocated inside OpenSSL (C) and is invisible here.",
            ha="center", fontsize=7, style="italic", wrap=True,
        )
        written.append(_save(figure, "graph5_peak_python_memory", config, directory))

    # ---- Graph 6: ciphertext / communication overhead -------------------
    overhead = results.overhead
    if not overhead.empty:
        figure, axes = _new_axes(
            "Cryptographic communication overhead vs plaintext size\n"
            "(authentication tag + transmitted nonce)",
            "Plaintext size (bytes)",
            "Overhead as a percentage of plaintext (%)",
        )
        _plot_series(axes, overhead, "plaintext_size", "overhead_percent")
        axes.set_xscale("log", base=2)
        axes.set_yscale("log")
        axes.set_xticks(list(config.message_sizes))
        axes.set_xticklabels([str(s) for s in config.message_sizes])
        axes.legend(fontsize=8)
        written.append(_save(figure, "graph6_communication_overhead", config, directory))

        # Absolute bytes, which is what a LoRaWAN/BLE payload budget cares about.
        figure, axes = _new_axes(
            "Ciphertext size vs plaintext size",
            "Plaintext size (bytes)",
            "Ciphertext size, including tag (bytes)",
        )
        _plot_series(axes, overhead, "plaintext_size", "ciphertext_size")
        axes.plot(
            sorted(overhead["plaintext_size"].unique()),
            sorted(overhead["plaintext_size"].unique()),
            color="#999999", linestyle=":", linewidth=1.0, label="No expansion (reference)",
        )
        axes.set_xscale("log", base=2)
        axes.set_yscale("log")
        axes.legend(fontsize=8)
        written.append(_save(figure, "graph7_ciphertext_size", config, directory))

    # ---- Graph 8: small-payload focus, 32-512 bytes ---------------------
    small = summary[
        (summary["operation"] == OP_ENCRYPT)
        & (summary["message_size"] > 0)
        & (summary["message_size"] <= 512)
    ]
    if not small.empty:
        figure, axes = _new_axes(
            "Encryption latency for small IoT payloads (32-512 bytes)\n"
            "linear x-axis, logarithmic y-axis; the range most representative "
            "of sensor traffic",
            "Plaintext size (bytes)",
            "Mean latency (microseconds, log scale)",
        )
        small = small.assign(ci_us=small["ci95_half_width_ns"] / 1000.0)
        _plot_series(axes, small, "message_size", "mean_us", yerr="ci_us")
        annotate_floor(axes)
        axes.set_yscale("log")
        axes.legend(fontsize=8)
        written.append(_save(figure, "graph8_small_payload_focus", config, directory))

    return written


# --------------------------------------------------------------------------
# Console reporting
# --------------------------------------------------------------------------

def format_console_summary(
    summary: pd.DataFrame, results: LoadedResults, config: ExperimentConfig
) -> str:
    """Build a plain-text summary for the terminal.

    Deliberately reports *both* algorithms' numbers side by side without
    declaring a winner.  Interpretation belongs in the report, where the
    implementation caveat can be stated alongside it.
    """
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("MEASURED RESULTS SUMMARY")
    lines.append("=" * 78)

    if results.harness_baseline_ns is not None:
        floor_us = results.harness_baseline_ns / 1000.0
        lines.append(
            f"Harness noise floor (median empty-call time): {floor_us:.4f} us.\n"
            "Any latency within a small multiple of this figure is close to the\n"
            "measurement limit of this setup and should be reported as such."
        )
    lines.append("")

    for operation in (OP_ENCRYPT, OP_DECRYPT):
        data = summary[(summary["operation"] == operation) & (summary["message_size"] > 0)]
        if data.empty:
            continue
        lines.append(f"--- {operation.upper()} ---")
        header = (
            f"{'algorithm':<16}{'bytes':>7}{'mean us':>12}{'median us':>12}"
            f"{'sd us':>10}{'MB/s':>10}{'msg/s':>12}"
        )
        lines.append(header)
        lines.append("-" * len(header))
        for _, row in data.iterrows():
            lines.append(
                f"{row['algorithm']:<16}{int(row['message_size']):>7}"
                f"{row['mean_ns']/1000:>12.3f}{row['median_ns']/1000:>12.3f}"
                f"{row['stdev_ns']/1000:>10.3f}"
                f"{row['throughput_mb_s_median']:>10.2f}"
                f"{row['messages_per_second_median']:>12,.0f}"
            )
        lines.append("")

    setup = summary[summary["message_size"] == 0]
    if not setup.empty:
        lines.append("--- SETUP COSTS (reported separately, never inside latency) ---")
        for _, row in setup.iterrows():
            lines.append(
                f"{row['algorithm']:<16}{row['operation']:<16}"
                f"median {row['median_ns']/1000:>10.4f} us"
            )
        lines.append("")

    overhead = results.overhead
    if not overhead.empty:
        lines.append("--- COMMUNICATION OVERHEAD (tag + transmitted nonce) ---")
        header = (
            f"{'algorithm':<16}{'plain':>7}{'cipher':>8}{'tag':>6}{'nonce':>7}"
            f"{'wire ovh':>10}{'% of payload':>14}"
        )
        lines.append(header)
        lines.append("-" * len(header))
        for _, row in overhead.sort_values(["algorithm", "plaintext_size"]).iterrows():
            lines.append(
                f"{row['algorithm']:<16}{int(row['plaintext_size']):>7}"
                f"{int(row['ciphertext_size']):>8}{int(row['tag_bytes']):>6}"
                f"{int(row['nonce_bytes']):>7}{int(row['wire_overhead_bytes']):>10}"
                f"{row['overhead_percent']:>13.1f}%"
            )
        lines.append("")

    lines.append(
        "NOTE: These figures characterise the tested IMPLEMENTATIONS in this\n"
        "software environment, not the intrinsic algorithms. See the limitations\n"
        "section of README.md before drawing any comparative conclusion."
    )
    lines.append("=" * 78)
    return "\n".join(lines)


def analyze(config: ExperimentConfig) -> dict[str, object]:
    """Load, summarise, plot and report.  Returns a dict of artefact paths."""
    results = load_results()
    summary = summarise_timings(results.timings, config)
    memory_summary = summarise_memory(results.memory)
    summary_path = write_summary(summary)

    memory_summary_path = SUMMARY_RESULTS_CSV.parent / "summary_memory.csv"
    memory_summary.to_csv(memory_summary_path, index=False)

    graphs = generate_graphs(results, summary, memory_summary, config)
    return {
        "summary_csv": summary_path,
        "memory_summary_csv": memory_summary_path,
        "graphs": graphs,
        "console": format_console_summary(summary, results, config),
    }
