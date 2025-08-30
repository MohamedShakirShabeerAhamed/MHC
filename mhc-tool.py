#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import requests
import pandas as pd
import numpy as np
import networkx as nx
from dateutil import parser as dateparser

try:
    import ssdeep 
except Exception:  
    ssdeep = None  

try:
    import tlsh  
except Exception:  
    tlsh = None

API_URL = "https://mb-api.abuse.ch/api/v1/"


@dataclass
class Sample:
    sha256: str
    first_seen: Optional[str] = None  # ISO 8601
    file_type: Optional[str] = None
    imphash: Optional[str] = None
    ssdeep_str: Optional[str] = None
    tlsh_str: Optional[str] = None
    malware_family: Optional[str] = None
    tags: Optional[List[str]] = None


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_iso(dt) -> Optional[str]:
    if pd.isna(dt) or dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.astimezone(timezone.utc).isoformat()
    try:
        return dateparser.parse(str(dt)).astimezone(timezone.utc).isoformat()
    except Exception:
        return None


API_KEY = "3a9c096ebe420279b74f20916e2209c53d4561fa64cd22f1"

def mb_post(data):
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": API_KEY}
    r = requests.post(url, data=data, headers=headers)
    r.raise_for_status()
    return r.json()



def mb_get_recent(days: int = 183, max_rows: int = 2000) -> List[Sample]:


    recent = mb_post({"query": "get_recent", "selector": "time"})
    rows = recent.get("data", []) if recent.get("query_status") == "ok" else []

    samples: List[Sample] = []
    for row in rows[:max_rows]:
        samples.append(
            Sample(
                sha256=row.get("sha256_hash"),
                first_seen=row.get("first_seen"),
                file_type=row.get("file_type"),
                imphash=row.get("imphash"),
                ssdeep_str=row.get("ssdeep"),
                tlsh_str=row.get("tlsh"),
                malware_family=row.get("signature"),
                tags=row.get("tags"),
            )
        )
    return samples



def ssdeep_score(a: Optional[str], b: Optional[str]) -> int:
    if ssdeep is None or not a or not b:
        return 0
    try:
        return ssdeep.compare(a, b)  # 0..100
    except Exception:
        return 0


def tlsh_distance(a: Optional[str], b: Optional[str]) -> Optional[int]:
    if tlsh is None or not a or not b:
        return None
    try:
        return tlsh.diff(a, b)  
    except Exception:
        return None



def build_graph(df: pd.DataFrame, min_ssdeep: int = 85, use_tlsh: bool = False, max_edges: int = 2_000_000) -> nx.Graph:
    
    G = nx.Graph()
    for h in df["sha256"].dropna().unique():
        G.add_node(h)

    def add_group_edges(series: pd.Series, label: str):
        nonlocal G
        groups = series.dropna().groupby(series).groups
        for k, idxs in groups.items():
            nodes = df.loc[list(idxs), "sha256"].tolist()
            for i in range(len(nodes)):
                for j in range(i + 1, len(nodes)):
                    G.add_edge(nodes[i], nodes[j], kind=f"exact:{label}")

    add_group_edges(df["imphash"], "imphash")

    add_group_edges(df["ssdeep"], "ssdeep_str")

    if use_tlsh and "tlsh" in df.columns:
        add_group_edges(df["tlsh"], "tlsh_str")

    if ssdeep is not None and "ssdeep" in df.columns:
        def chunk_size(s: Optional[str]) -> Optional[str]:
            if not isinstance(s, str) or ":" not in s:
                return None
            return s.split(":", 1)[0]

        df["_chunk"] = df["ssdeep"].map(chunk_size)
        for chunk, sub in df.dropna(subset=["_chunk"]).groupby("_chunk"):
            nodes = sub["sha256"].tolist()
            hashes = sub["ssdeep"].tolist()
            n = len(nodes)
            if n > 2500:
                continue
            for i in range(n):
                for j in range(i + 1, n):
                    score = ssdeep_score(hashes[i], hashes[j])
                    if score >= min_ssdeep:
                        G.add_edge(nodes[i], nodes[j], kind="fuzzy:ssdeep", score=score)
                        if G.number_of_edges() > max_edges:
                            return G

    if use_tlsh and tlsh is not None and "tlsh" in df.columns:
        df["_tlsh_block"] = df["tlsh"].dropna().map(lambda s: s[:4] if isinstance(s, str) and len(s) >= 4 else None)
        for blk, sub in df.dropna(subset=["_tlsh_block"]).groupby("_tlsh_block"):
            nodes = sub["sha256"].tolist()
            hashes = sub["tlsh"].tolist()
            n = len(nodes)
            if n > 2500:
                continue
            for i in range(n):
                for j in range(i + 1, n):
                    d = tlsh_distance(hashes[i], hashes[j])
                    if d is not None and d <= 35:
                        G.add_edge(nodes[i], nodes[j], kind="fuzzy:tlsh", tlsh_diff=d)
                        if G.number_of_edges() > max_edges:
                            return G

    return G


def graph_to_clusters(G: nx.Graph) -> pd.DataFrame:
    comps = list(nx.connected_components(G))
    rows = []
    for cid, nodes in enumerate(sorted(comps, key=lambda c: -len(c)), start=1):
        for sha in nodes:
            rows.append({"cluster_id": cid, "sha256": sha})
    return pd.DataFrame(rows)


def quantify_reuse(df_clusters: pd.DataFrame, df_samples: pd.DataFrame) -> pd.DataFrame:
    merged = df_clusters.merge(df_samples, on="sha256", how="left")
    agg = (
        merged.groupby("cluster_id")
        .agg(
            n_samples=("sha256", "count"),
            first_seen_min=("first_seen", lambda s: to_iso(s.min())),
            first_seen_max=("first_seen", lambda s: to_iso(s.max())),
            families=("malware_family", lambda s: ", ".join(sorted({x for x in s.dropna().astype(str) if x})))
        )
        .reset_index()
    )
    return agg.sort_values("n_samples", ascending=False)


def six_month_window(df: pd.DataFrame) -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=183)
    df = df.copy()
    df["_dt"] = pd.to_datetime(df["first_seen"], errors="coerce", utc=True)
    return df.loc[df["_dt"] >= cutoff].drop(columns=["_dt"])


def campaign_timeline(df_clusters: pd.DataFrame, df_samples: pd.DataFrame) -> pd.DataFrame:
    merged = six_month_window(df_clusters.merge(df_samples, on="sha256", how="left"))
    merged["date"] = pd.to_datetime(merged["first_seen"], errors="coerce", utc=True).dt.date
    tl = (
        merged.groupby(["cluster_id", "date"]).size().reset_index(name="count")
    )
    return tl


from sklearn.metrics import adjusted_rand_score, homogeneity_score, completeness_score, v_measure_score


def evaluate_clusters(df_clusters: pd.DataFrame, df_labels: pd.DataFrame) -> Dict:
    merged = df_clusters.merge(df_labels, on="sha256", how="inner")
    if merged.empty:
        return {"note": "No overlap between clusters and labels"}

    cl_map = {c: i for i, c in enumerate(sorted(merged["cluster_id"].unique()))}
    y_pred = merged["cluster_id"].map(cl_map).to_numpy()

    camp_map = {c: i for i, c in enumerate(sorted(merged["campaign"].astype(str).unique()))}
    y_true = merged["campaign"].astype(str).map(camp_map).to_numpy()

    ari = float(adjusted_rand_score(y_true, y_pred))
    h = float(homogeneity_score(y_true, y_pred))
    c = float(completeness_score(y_true, y_pred))
    v = float(v_measure_score(y_true, y_pred))

    purity = {}
    for cid, grp in merged.groupby("cluster_id"):
        top = grp["campaign"].value_counts(normalize=True).iloc[0]
        purity[int(cid)] = float(top)

    return {
        "n_labeled": int(len(merged)),
        "n_clusters": int(df_clusters["cluster_id"].nunique()),
        "ari": ari,
        "homogeneity": h,
        "completeness": c,
        "v_measure": v,
        "cluster_purity": purity,
    }



def ensure_dir(path: str):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)


def command_collect(args):
    samples = mb_get_recent(days=args.days, max_rows=args.max)
    rows = []
    for s in samples:
        rows.append(
            {
                "sha256": s.sha256,
                "first_seen": s.first_seen,
                "file_type": s.file_type,
                "imphash": s.imphash,
                "ssdeep": s.ssdeep_str,
                "tlsh": s.tlsh_str,
                "malware_family": s.malware_family,
                "tags": ",".join(s.tags) if s.tags else None,
                "collected_at": iso_now(),
            }
        )
    df = pd.DataFrame(rows).drop_duplicates(subset=["sha256"])
    ensure_dir(args.out)
    df.to_csv(args.out, index=False)
    print(f"[collect] wrote {len(df)} rows to {args.out}")


def command_cluster(args):
    df = pd.read_csv(args.infile)
    G = build_graph(df, min_ssdeep=args.min_ssdeep, use_tlsh=args.use_tlsh)
    clusters = graph_to_clusters(G)

    ensure_dir(args.out_prefix + "_clusters.csv")
    clusters.to_csv(args.out_prefix + "_clusters.csv", index=False)

    reuse = quantify_reuse(clusters, df)
    reuse.to_csv(args.out_prefix + "_reuse.csv", index=False)

    stats = {
        "n_nodes": G.number_of_nodes(),
        "n_edges": G.number_of_edges(),
        "n_clusters": int(clusters["cluster_id"].nunique()),
        "largest_cluster": int(clusters["cluster_id"].value_counts().iloc[0] if not clusters.empty else 0),
        "min_ssdeep": args.min_ssdeep,
        "use_tlsh": bool(args.use_tlsh),
    }
    with open(args.out_prefix + "_stats.json", "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(f"[cluster] clusters={stats['n_clusters']} nodes={stats['n_nodes']} edges={stats['n_edges']}")


def command_timeline(args):
    import matplotlib.pyplot as plt

    clusters = pd.read_csv(args.clusters)
    samples = pd.read_csv(args.samples)
    tl = campaign_timeline(clusters, samples)

    top = tl.groupby("cluster_id")["count"].sum().sort_values(ascending=False).head(args.top).index
    tl_top = tl[tl["cluster_id"].isin(top)]
    piv = tl_top.pivot_table(index="date", columns="cluster_id", values="count", fill_value=0)

    piv = piv.sort_index()
    ax = piv.plot(kind="area", figsize=(12, 6))
    ax.set_title("Campaign Activity (Top Clusters, last ~6 months)")
    ax.set_xlabel("Date")
    ax.set_ylabel("Sample count")
    fig = ax.get_figure()

    ensure_dir(args.out)
    fig.savefig(args.out, bbox_inches="tight")
    print(f"[timeline] saved to {args.out}")


def command_evaluate(args):
    clusters = pd.read_csv(args.clusters)
    labels = pd.read_csv(args.labels)
    if "sha256" not in labels.columns:
        raise SystemExit("labels CSV must include 'sha256' and 'campaign'")
    if "campaign" not in labels.columns:
        raise SystemExit("labels CSV must include 'sha256' and 'campaign'")

    metrics = evaluate_clusters(clusters, labels)
    ensure_dir(args.out)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"[evaluate] wrote metrics to {args.out}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mhc-tool", description="Malware Hash Correlation Tool")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="Collect recent samples from MalwareBazaar (metadata only)")
    c.add_argument("--days", type=int, default=183, help="Days to look back (default ~6 months)")
    c.add_argument("--max", type=int, default=2000, help="Max rows to retain (default 2000)")
    c.add_argument("--out", dest="out", required=True, help="Output CSV path")
    c.set_defaults(func=command_collect)

    k = sub.add_parser("cluster", help="Cluster by exact & fuzzy hashes")
    k.add_argument("--in", dest="infile", required=True, help="Input CSV from 'collect'")
    k.add_argument("--min-ssdeep", type=int, default=85, help="Min ssdeep score to link nodes (0-100)")
    k.add_argument("--use-tlsh", action="store_true", help="Use TLSH fuzzy matching if library+values present")
    k.add_argument("--out-prefix", required=True, help="Prefix for outputs (CSV/JSON)")
    k.set_defaults(func=command_cluster)

    t = sub.add_parser("timeline", help="Render activity timeline for top clusters")
    t.add_argument("--clusters", required=True, help="Clusters CSV")
    t.add_argument("--samples", required=True, help="Samples CSV from 'collect'")
    t.add_argument("--top", type=int, default=8, help="Top-N clusters to chart")
    t.add_argument("--out", required=True, help="Output PNG path")
    t.set_defaults(func=command_timeline)

    e = sub.add_parser("evaluate", help="Evaluate clustering against CTI labels")
    e.add_argument("--clusters", required=True, help="Clusters CSV")
    e.add_argument("--labels", required=True, help="CSV with sha256,campaign[,first_seen]")
    e.add_argument("--out", required=True, help="Output JSON for metrics")
    e.set_defaults(func=command_evaluate)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
