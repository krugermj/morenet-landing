#!/usr/bin/env python3
"""
Comprehensive client lookup — queries Zammad, MetaBase billing, and XWiki
in a single call and returns combined results.
"""
import sys
import json
import subprocess
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_tool(cmd, timeout=25):
    """Run a tool script and return its output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "PATH": os.environ.get("PATH", "")},
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr.strip() or "No output"}
    except subprocess.TimeoutExpired:
        return {"error": "Tool timed out"}
    except json.JSONDecodeError:
        return {"raw": result.stdout.strip()[:2000]}
    except Exception as e:
        return {"error": str(e)}

def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: client_lookup.py <name>"}))
        sys.exit(1)

    name = sys.argv[1]
    zammad_py = os.path.join(SCRIPT_DIR, "zammad.py")
    metabase_py = os.path.join(SCRIPT_DIR, "metabase.py")
    xwiki_py = os.path.join(SCRIPT_DIR, "xwiki.py")

    # Run all three lookups
    zammad_result = run_tool(["python3", zammad_py, "customer", name])
    billing_result = run_tool(["python3", metabase_py, "client", name])
    wiki_result = run_tool(["python3", xwiki_py, "search", name])

    # Parse wiki output (it prints text, not JSON)
    if "raw" in wiki_result:
        wiki_result = {"text": wiki_result["raw"]}

    combined = {
        "query": name,
        "zammad": zammad_result,
        "billing": billing_result,
        "wiki": wiki_result,
    }

    # Add summary flags
    has_zammad = "user" in zammad_result or ("error" not in zammad_result and "Customer not found" not in json.dumps(zammad_result))
    has_billing = billing_result.get("status") == "OK"
    has_wiki = "text" in wiki_result and "No results found" not in wiki_result.get("text", "No results found")

    combined["_sources_with_data"] = []
    if has_zammad:
        combined["_sources_with_data"].append("zammad")
    if has_billing:
        combined["_sources_with_data"].append("billing")
    if has_wiki:
        combined["_sources_with_data"].append("wiki")

    if not combined["_sources_with_data"]:
        combined["_summary"] = f"⚠️ NO RESULTS FOUND across all systems for '{name}'. Check spelling or try a different name."

    print(json.dumps(combined, indent=2, default=str)[:12000])

if __name__ == "__main__":
    main()
