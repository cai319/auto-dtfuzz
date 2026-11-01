from __future__ import annotations

from pathlib import Path

from . import coverage, optimize
from .build import auto_stub_and_rebuild, build
from .runfuzz import run_fuzz
from .util import DtfuzzError, now_iso, read_json, write_json


def _history(workspace) -> list[dict]:
    return read_json(workspace.coverage_dir / "history.json", default=[]) or []


def _stalled(percentages: list[float], config: dict) -> bool:
    stall_rounds = int((config.get("coverage", {}) or {}).get("stall_rounds", 3))
    delta = float((config.get("coverage", {}) or {}).get("stall_delta", 1.0))
    if len(percentages) <= stall_rounds:
        return False
    window = percentages[-stall_rounds - 1 :]
    changes = [current - previous for previous, current in zip(window, window[1:])]
    return all(change < delta for change in changes)


def _stop_reason(config: dict, summary: dict, round_no: int, percentages: list[float]) -> str:
    coverage_cfg = config.get("coverage", {}) or {}
    line_target = float(coverage_cfg.get("line_target", 0) or 0)
    function_target = float(coverage_cfg.get("function_target", 0) or 0)
    max_rounds = int(coverage_cfg.get("max_rounds", 10) or 10)
    if line_target and summary["line"]["percent"] >= line_target:
        return f"line coverage reached {line_target}%"
    if function_target and summary["function"]["percent"] >= function_target:
        return f"function coverage reached {function_target}%"
    if round_no >= max_rounds:
        return f"max rounds reached ({max_rounds})"
    if _stalled(percentages, config):
        return "coverage stalled"
    return ""


def campaign(workspace, config: dict, analysis: dict, mocks: dict, seconds: int | None = None, max_rounds: int | None = None) -> dict:
    build_result = build(workspace, config, analysis)
    if not build_result.get("ok") and (config.get("mocks", {}) or {}).get("auto_stub", False):
        build_result = auto_stub_and_rebuild(workspace, config, analysis, mocks, build_result)
    if not build_result.get("ok"):
        return {
            "ok": False,
            "stage": "build",
            "build": build_result,
            "reason": "build failed: unresolved symbols require human mock rules" if build_result.get("undefined_symbols") else "build failed",
            "pending_mocks": build_result.get("pending_mocks", []),
        }
    coverage_cfg = config.get("coverage", {}) or {}
    rounds = int(max_rounds or coverage_cfg.get("max_rounds", 10) or 10)
    optimizer_mode = (config.get("optimizer", {}) or {}).get("mode") or "none"
    results = []
    stop_reason = ""
    campaign_percentages: list[float] = []
    for index in range(rounds):
        run_result = run_fuzz(workspace, config, analysis, seconds=seconds)
        try:
            summary = coverage.collect(workspace, config, analysis)
        except DtfuzzError as exc:
            results.append({"run": run_result, "coverage": None, "coverage_error": str(exc)})
            stop_reason = f"coverage failed: {exc}"
            break
        results.append({"run": run_result, "coverage": summary})
        campaign_percentages.append(float(summary["line"]["percent"]))
        stop_reason = _stop_reason(config, summary, index + 1, campaign_percentages)
        if stop_reason:
            break
        if optimizer_mode in {"none", "prompt", ""}:
            stop_reason = "optimizer mode requires an agent in the loop; coverage is ready for dtfuzz optimize"
            break
        opt = optimize.optimize(workspace, config, analysis, summary, optimizer_mode)
        if opt.get("mocks_changed"):
            from .generate import generate_artifacts

            mocks = workspace.load_mocks(config)
            generate_artifacts(config, analysis, workspace, mocks)
            rebuild = build(workspace, config, analysis)
            if not rebuild.get("ok") and (config.get("mocks", {}) or {}).get("auto_stub", False):
                rebuild = auto_stub_and_rebuild(workspace, config, analysis, mocks, rebuild)
            if not rebuild.get("ok"):
                stop_reason = "rebuild after mock patch failed"
                break
    final = results[-1] if results else {}
    result = {
        "ok": bool(results),
        "rounds": len(results),
        "stop_reason": stop_reason,
        "optimizer_mode": optimizer_mode,
        "final_coverage": final.get("coverage", {}),
        "history": _history(workspace),
        "finished_at": now_iso(),
    }
    write_json(workspace.root / "campaign.json", result)
    return result
