#!/usr/bin/env python3
"""
Zammad API helper for MoreNET support operations.
Usage: python3 zammad.py <command> [args]

Commands:
  me                      - Show current user info
  tickets [--state open|closed|all] [--limit N]  - List tickets
  ticket <id>             - Get ticket details with articles
  search <query>          - Search tickets
  customer <email>        - Get customer info and their tickets
  groups                  - List available groups
  stats                   - Ticket stats summary (counts by state)
  agents                  - List agents with ticket counts + state breakdown
  aging [--top N]          - Ticket age report: distribution, oldest, stalest
  create --title "..." --body "..." [--customer email] [--group name]
  note <ticket_id> --body "..."  - Add internal note
  update <ticket_id> [--state open|closed|pending] [--owner email]

State IDs (Zammad internal):
  1=new, 2=open, 3=pending reminder, 4=closed, 7=pending close
  Use state_id queries for reliability (state.name with spaces fails).
"""

import os
import sys
import json
import argparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlencode, quote

ZAMMAD_URL = os.environ.get("ZAMMAD_URL", "https://z.ictglobe.support")
ZAMMAD_TOKEN = os.environ.get("ZAMMAD_API_TOKEN", "")

def api(method, endpoint, data=None):
    url = f"{ZAMMAD_URL}/api/v1/{endpoint}"
    headers = {
        "Authorization": f"Token token={ZAMMAD_TOKEN}",
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode()
        print(f"API Error {e.code}: {err}", file=sys.stderr)
        sys.exit(1)

def cmd_me(args):
    print(json.dumps(api("GET", "users/me"), indent=2))

def cmd_tickets(args):
    state_filter = args.state or "open"
    limit = args.limit or 25
    
    if state_filter == "all":
        endpoint = f"tickets?per_page={limit}&sort_by=updated_at&order_by=desc"
    else:
        # Search by state
        endpoint = f"tickets/search?query=state.name:{state_filter}&per_page={limit}&sort_by=updated_at&order_by=desc"
    
    result = api("GET", endpoint)
    tickets = result if isinstance(result, list) else result.get("tickets", result.get("assets", {}).get("Ticket", {}))
    
    if isinstance(tickets, dict):
        tickets = list(tickets.values())
    
    output = []
    for t in tickets[:limit]:
        if isinstance(t, dict):
            output.append({
                "id": t.get("id"),
                "number": t.get("number"),
                "title": t.get("title"),
                "state": t.get("state"),
                "priority": t.get("priority"),
                "customer_id": t.get("customer_id"),
                "updated_at": t.get("updated_at"),
            })
    print(json.dumps(output, indent=2))

def cmd_ticket(args):
    ticket = api("GET", f"tickets/{args.id}")
    articles = api("GET", f"ticket_articles/by_ticket/{args.id}")
    ticket["articles"] = articles
    ticket["state"] = STATE_NAMES.get(ticket.get("state_id"), f"unknown({ticket.get('state_id')})")
    print(json.dumps(ticket, indent=2))

STATE_NAMES = {1: "new", 2: "open", 3: "pending reminder", 4: "closed", 5: "merged", 6: "removed", 7: "pending close"}

def enrich_tickets(tickets):
    """Add human-readable state name to ticket results."""
    if not isinstance(tickets, list):
        return tickets
    for t in tickets:
        t["state"] = STATE_NAMES.get(t.get("state_id"), f"unknown({t.get('state_id')})")
    return tickets

def cmd_search(args):
    query = quote(args.query)
    result = api("GET", f"tickets/search?query={query}&per_page=20")
    print(json.dumps(enrich_tickets(result), indent=2))

def cmd_customer(args):
    result = api("GET", f"users/search?query={quote(args.email)}&per_page=5")
    if result:
        user = result[0] if isinstance(result, list) else result
        user_id = user.get("id")
        # Get their tickets
        tickets = api("GET", f"tickets/search?query=customer_id:{user_id}&per_page=20")
        print(json.dumps({"user": user, "tickets": enrich_tickets(tickets)}, indent=2))
    else:
        print(json.dumps({"error": "Customer not found"}, indent=2))

def cmd_groups(args):
    print(json.dumps(api("GET", "groups"), indent=2))

def cmd_stats(args):
    """Queue summary using state_id queries (reliable, no space-encoding issues)."""
    # State IDs: 1=new, 2=open, 3=pending reminder, 4=closed, 7=pending close
    states = {
        "new": 1,
        "open": 2,
        "pending_reminder": 3,
        "pending_close": 7,
    }
    stats = {}
    total = 0
    for name, sid in states.items():
        data = api("GET", f"tickets/search?query=state_id:{sid}&per_page=1")
        count = len(data) if isinstance(data, list) else 0
        # For accurate count, fetch up to 200
        if count > 0:
            data = api("GET", f"tickets/search?query=state_id:{sid}&per_page=200")
            count = len(data) if isinstance(data, list) else 0
        stats[name] = count
        total += count
    stats["total_non_closed"] = total
    print(json.dumps(stats, indent=2))

def cmd_agents(args):
    """List all agents with their ticket counts and state breakdown."""
    from collections import Counter, defaultdict

    # State IDs: 1=new, 2=open, 3=pending reminder, 7=pending close
    state_map = {1: "new", 2: "open", 3: "pending reminder", 7: "pending close"}

    # Collect all non-closed tickets
    all_tickets = []
    for sid, sname in state_map.items():
        page = 1
        while True:
            data = api("GET", f"tickets/search?query=state_id:{sid}&per_page=200&page={page}")
            if not isinstance(data, list) or not data:
                break
            for t in data:
                all_tickets.append((t["owner_id"], sname))
            if len(data) < 200:
                break
            page += 1

    if not all_tickets:
        print("No non-closed tickets found.")
        return

    # Resolve owner names (cache to avoid repeat lookups)
    owner_ids = set(t[0] for t in all_tickets)
    owner_names = {}
    for oid in owner_ids:
        if oid == 1:
            owner_names[oid] = "Unassigned"
        else:
            try:
                u = api("GET", f"users/{oid}")
                owner_names[oid] = f"{u.get('firstname', '')} {u.get('lastname', '')}".strip() or f"User {oid}"
            except:
                owner_names[oid] = f"User {oid}"

    # Aggregate
    counts = Counter()
    by_state = defaultdict(lambda: Counter())
    for oid, state in all_tickets:
        name = owner_names[oid]
        counts[name] += 1
        by_state[name][state] += 1

    # Output as structured JSON
    result = []
    for name, total in sorted(counts.items(), key=lambda x: -x[1]):
        entry = {"agent": name, "total": total}
        entry.update(by_state[name])
        result.append(entry)

    output = {
        "agents": result,
        "total_tickets": sum(counts.values()),
        "total_agents": len(counts),
    }
    print(json.dumps(output, indent=2))

def cmd_aging(args):
    """Ticket age report: distribution buckets, oldest, stalest, avg by state."""
    from datetime import datetime, timezone
    from collections import defaultdict

    now = datetime.now(timezone.utc)
    state_map = {1: "new", 2: "open", 3: "pending reminder", 7: "pending close"}
    top = args.top or 10

    # Collect all non-closed tickets
    all_tickets = []
    for sid, sname in state_map.items():
        page = 1
        while True:
            data = api("GET", f"tickets/search?query=state_id:{sid}&per_page=200&page={page}")
            if not isinstance(data, list) or not data:
                break
            for t in data:
                created = datetime.fromisoformat(t["created_at"].replace("Z", "+00:00"))
                age_days = (now - created).days
                last_update = t.get("updated_at", t["created_at"])
                updated = datetime.fromisoformat(last_update.replace("Z", "+00:00"))
                stale_days = (now - updated).days
                all_tickets.append({
                    "id": t["id"],
                    "number": t.get("number", ""),
                    "title": t.get("title", "")[:60],
                    "state": sname,
                    "owner_id": t["owner_id"],
                    "created_at": t["created_at"][:10],
                    "age_days": age_days,
                    "last_updated": last_update[:10],
                    "stale_days": stale_days,
                })
            if len(data) < 200:
                break
            page += 1

    if not all_tickets:
        print(json.dumps({"error": "No non-closed tickets found"}))
        return

    # Age distribution buckets
    bucket_defs = [
        ("< 7 days", 0, 7),
        ("7-30 days", 7, 30),
        ("30-90 days", 30, 90),
        ("90-180 days", 90, 180),
        ("> 180 days", 180, 99999),
    ]
    buckets = {}
    for label, lo, hi in bucket_defs:
        buckets[label] = len([t for t in all_tickets if lo <= t["age_days"] < hi])

    # Oldest tickets
    oldest = sorted(all_tickets, key=lambda x: -x["age_days"])[:top]

    # Stalest tickets (longest since last update)
    stalest = sorted(all_tickets, key=lambda x: -x["stale_days"])[:top]

    # Average age by state
    by_state = defaultdict(list)
    for t in all_tickets:
        by_state[t["state"]].append(t["age_days"])

    avg_by_state = {}
    for state, ages in sorted(by_state.items()):
        avg_by_state[state] = {
            "avg_days": round(sum(ages) / len(ages), 1),
            "max_days": max(ages),
            "count": len(ages),
        }

    output = {
        "total_non_closed": len(all_tickets),
        "age_distribution": buckets,
        "avg_by_state": avg_by_state,
        "oldest": [{"number": t["number"], "title": t["title"], "state": t["state"],
                     "age_days": t["age_days"], "created_at": t["created_at"],
                     "stale_days": t["stale_days"], "last_updated": t["last_updated"]}
                    for t in oldest],
        "stalest": [{"number": t["number"], "title": t["title"], "state": t["state"],
                      "stale_days": t["stale_days"], "age_days": t["age_days"],
                      "created_at": t["created_at"], "last_updated": t["last_updated"]}
                     for t in stalest],
    }
    print(json.dumps(output, indent=2))

def cmd_create(args):
    data = {
        "title": args.title,
        "group": args.group or "Users",
        "article": {
            "body": args.body,
            "type": "note",
            "internal": False,
        }
    }
    if args.customer:
        data["customer"] = args.customer
    result = api("POST", "tickets", data)
    print(json.dumps(result, indent=2))

def cmd_note(args):
    data = {
        "ticket_id": args.ticket_id,
        "body": args.body,
        "type": "note",
        "internal": True,
    }
    result = api("POST", "ticket_articles", data)
    print(json.dumps(result, indent=2))

def cmd_update(args):
    data = {}
    if args.state:
        data["state"] = args.state
    if args.owner:
        data["owner"] = args.owner
    if not data:
        print("Nothing to update", file=sys.stderr)
        sys.exit(1)
    result = api("PUT", f"tickets/{args.ticket_id}", data)
    print(json.dumps(result, indent=2))

def main():
    parser = argparse.ArgumentParser(description="Zammad API helper")
    sub = parser.add_subparsers(dest="cmd", required=True)
    
    sub.add_parser("me")
    
    p = sub.add_parser("tickets")
    p.add_argument("--state", choices=["open", "closed", "all"], default="open")
    p.add_argument("--limit", type=int, default=25)
    
    p = sub.add_parser("ticket")
    p.add_argument("id", type=int)
    
    p = sub.add_parser("search")
    p.add_argument("query")
    
    p = sub.add_parser("customer")
    p.add_argument("email")
    
    sub.add_parser("groups")
    sub.add_parser("stats")
    sub.add_parser("agents")
    p = sub.add_parser("aging")
    p.add_argument("--top", type=int, default=10, help="Number of oldest/stalest to show")
    
    p = sub.add_parser("create")
    p.add_argument("--title", required=True)
    p.add_argument("--body", required=True)
    p.add_argument("--customer")
    p.add_argument("--group")
    
    p = sub.add_parser("note")
    p.add_argument("ticket_id", type=int)
    p.add_argument("--body", required=True)
    
    p = sub.add_parser("update")
    p.add_argument("ticket_id", type=int)
    p.add_argument("--state")
    p.add_argument("--owner")
    
    args = parser.parse_args()
    
    if not ZAMMAD_TOKEN:
        print("ZAMMAD_API_TOKEN not set", file=sys.stderr)
        sys.exit(1)
    
    cmd_map = {
        "me": cmd_me, "tickets": cmd_tickets, "ticket": cmd_ticket,
        "search": cmd_search, "customer": cmd_customer, "groups": cmd_groups,
        "stats": cmd_stats, "agents": cmd_agents, "aging": cmd_aging,
        "create": cmd_create, "note": cmd_note, "update": cmd_update,
    }
    cmd_map[args.cmd](args)

if __name__ == "__main__":
    main()
