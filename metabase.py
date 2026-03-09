#!/usr/bin/env python3
"""
MetaBase API helper for MoreNET finance operations.
Usage: python3 metabase.py <command> [args]

Commands:
  client <name>              - Client financial overview (invoices, payments, balance)
  invoices <name> [--months N] - Invoice history for a client (default 6 months)
  outstanding [--min R]      - All clients with outstanding balances
  revenue [--months N]       - Revenue summary (default 12 months)
  annuity <name>             - Recurring billing (MRC) for a client
  search <query>             - Search clients by name, company, or account number
  sql <query>                - Run a raw SQL query (read-only)
  dashboards                 - List available MetaBase dashboards
  cards                      - List available saved questions/cards

Database: ICTInternet_Numista (MySQL, DB ID: 4)
Monetary values stored as cents (BIGINT) — divide by 100 for Rands.
"""

import os
import sys
import json
import argparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError

METABASE_URL = os.environ.get("METABASE_URL", "https://metabase.deploy.ictlabs.app")
METABASE_API_KEY = os.environ.get("METABASE_API_KEY", "")
DB_ID = 4  # ICTInternet_Numista

def api(method, endpoint, data=None):
    url = f"{METABASE_URL}/api/{endpoint}"
    headers = {
        "x-api-key": METABASE_API_KEY,
        "Content-Type": "application/json",
    }
    body = json.dumps(data).encode() if data else None
    req = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode()[:300]
        print(f"API Error {e.code}: {err}", file=sys.stderr)
        return None

def sql_escape(value):
    """Escape a string for safe inclusion in SQL. Prevents SQL injection."""
    if value is None:
        return ""
    s = str(value)
    # Escape backslashes first, then single quotes
    s = s.replace("\\", "\\\\")
    s = s.replace("'", "\\'")
    s = s.replace('"', '\\"')
    s = s.replace("\x00", "")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "\\r")
    s = s.replace("\x1a", "\\Z")
    return s

def run_sql(query):
    """Run a native SQL query against the billing database."""
    result = api("POST", "dataset", {
        "database": DB_ID,
        "type": "native",
        "native": {"query": query}
    })
    if not result:
        return [], []
    cols = [c.get("display_name", c.get("name", "?")) for c in result.get("data", {}).get("cols", [])]
    rows = result.get("data", {}).get("rows", [])
    return cols, rows

def format_money(cents):
    """Convert cents (BIGINT) to Rands string."""
    if cents is None:
        return "R0.00"
    return f"R{cents / 100:,.2f}"

def cmd_client(args):
    """Full client financial overview."""
    name = sql_escape(args.name)
    cols, rows = run_sql(f"""
        SELECT 
            c.id, c.company_name, c.name, c.email, c.mobile, c.telephone,
            c.billing_account_number, c.payment_method, c.stop_supply, c.stop_invoicing,
            c.billing_date, c.terms, c.admin_fees, c.interest_exempt,
            (SELECT COUNT(*) FROM invoices i WHERE i.customer_id = c.id AND i.deleted_at IS NULL) as total_invoices,
            (SELECT SUM(i.outstanding) FROM invoices i WHERE i.customer_id = c.id AND i.deleted_at IS NULL AND i.outstanding > 0) as total_outstanding,
            (SELECT SUM(i.total) FROM invoices i WHERE i.customer_id = c.id AND i.deleted_at IS NULL AND i.date >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)) as revenue_12m
        FROM customers c
        WHERE c.deleted_at IS NULL 
          AND (c.company_name LIKE '%{name}%' OR c.name LIKE '%{name}%' OR c.billing_account_number LIKE '%{name}%')
        LIMIT 10
    """)
    
    if not rows:
        print(json.dumps({"status": "NO RESULTS FOUND", "query": name, "message": f"⚠️ NO RESULTS FOUND: No client in the billing system matches '{name}'. The name may be misspelled."}))
        return
    
    clients = []
    for row in rows:
        client = dict(zip(cols, row))
        cid = int(client.get("id"))
        
        # Get recent invoices
        inv_cols, inv_rows = run_sql(f"""
            SELECT i.number, i.date, i.total/100.0 as total_rands, 
                   i.outstanding/100.0 as outstanding_rands, i.status, i.type
            FROM invoices i 
            WHERE i.customer_id = {cid} AND i.deleted_at IS NULL
            ORDER BY i.date DESC LIMIT 6
        """)
        invoices = [dict(zip(inv_cols, r)) for r in inv_rows]
        
        # Get recent payments
        pay_cols, pay_rows = run_sql(f"""
            SELECT p.reference, p.date, p.amount as amount_rands, i.number as invoice_no
            FROM payments p
            LEFT JOIN invoices i ON p.invoice_id = i.id
            WHERE i.customer_id = {cid}
            ORDER BY p.date DESC LIMIT 5
        """)
        payments = [dict(zip(pay_cols, r)) for r in pay_rows]
        
        # Get annuity/MRC
        ann_cols, ann_rows = run_sql(f"""
            SELECT ai.name, ai.price/100.0 as price_rands, ai.quantity, 
                   (ai.price * ai.quantity)/100.0 as line_total_rands,
                   ai.billing_start_date
            FROM annuity_items ai
            JOIN annuities a ON ai.annuity_id = a.id
            WHERE a.customer_id = {cid} AND ai.deleted_at IS NULL AND a.deleted_at IS NULL
        """)
        annuity_items = [dict(zip(ann_cols, r)) for r in ann_rows]
        mrc_total = sum(item.get("line_total_rands", 0) or 0 for item in annuity_items)
        
        clients.append({
            "company_name": client.get("company_name", ""),
            "contact_name": client.get("name", ""),
            "email": client.get("email", ""),
            "mobile": client.get("mobile", ""),
            "telephone": client.get("telephone", ""),
            "account_number": client.get("billing_account_number", ""),
            "payment_method": client.get("payment_method", ""),
            "stop_supply": bool(client.get("stop_supply")),
            "stop_invoicing": bool(client.get("stop_invoicing")),
            "billing_date": str(client.get("billing_date", "")),
            "terms": client.get("terms"),
            "total_invoices": client.get("total_invoices", 0),
            "total_outstanding_rands": (client.get("total_outstanding") or 0) / 100.0,
            "revenue_12m_rands": (client.get("revenue_12m") or 0) / 100.0,
            "mrc_rands": mrc_total,
            "annuity_items": annuity_items,
            "recent_invoices": invoices,
            "recent_payments": payments,
        })
    
    print(json.dumps({"status": "OK", "clients": clients, "count": len(clients)}, indent=2, default=str))

def cmd_invoices(args):
    """Invoice history for a client."""
    name = sql_escape(args.name)
    months = int(args.months or 6)
    cols, rows = run_sql(f"""
        SELECT i.number, i.date, i.due_date, i.total/100.0 as total_rands, 
               i.outstanding/100.0 as outstanding_rands, i.total_paid/100.0 as paid_rands,
               i.status, i.type, c.company_name, c.name as contact_name
        FROM invoices i
        JOIN customers c ON i.customer_id = c.id
        WHERE c.deleted_at IS NULL AND i.deleted_at IS NULL
          AND (c.company_name LIKE '%{name}%' OR c.name LIKE '%{name}%' OR c.billing_account_number LIKE '%{name}%')
          AND i.date >= DATE_SUB(CURDATE(), INTERVAL {months} MONTH)
        ORDER BY i.date DESC
        LIMIT 50
    """)
    results = [dict(zip(cols, r)) for r in rows]
    if not results:
        print(json.dumps({"status": "NO RESULTS FOUND", "query": args.name, "message": f"⚠️ NO RESULTS FOUND: No invoices found for '{args.name}'. The name may be misspelled."}))
        return
    print(json.dumps({"status": "OK", "invoices": results, "count": len(results), "months": months}, indent=2, default=str))

def cmd_outstanding(args):
    """All clients with outstanding balances."""
    min_amount = int((args.min or 0) * 100)  # Convert Rands to cents
    cols, rows = run_sql(f"""
        SELECT c.company_name, c.name, c.billing_account_number, c.mobile, c.email,
               SUM(i.outstanding)/100.0 as total_outstanding_rands,
               COUNT(i.id) as unpaid_invoices,
               MIN(i.date) as oldest_unpaid_date
        FROM customers c
        JOIN invoices i ON i.customer_id = c.id
        WHERE c.deleted_at IS NULL AND i.deleted_at IS NULL AND i.outstanding > {min_amount}
        GROUP BY c.id
        ORDER BY total_outstanding_rands DESC
        LIMIT 100
    """)
    results = [dict(zip(cols, r)) for r in rows]
    total = sum(r.get("total_outstanding_rands", 0) or 0 for r in results)
    print(json.dumps({"clients": results, "count": len(results), "total_outstanding_rands": total}, indent=2, default=str))

def cmd_revenue(args):
    """Revenue summary by month."""
    months = int(args.months or 12)
    cols, rows = run_sql(f"""
        SELECT DATE_FORMAT(i.date, '%Y-%m') as month,
               SUM(i.total)/100.0 as revenue_rands,
               COUNT(i.id) as invoice_count,
               SUM(i.total_paid)/100.0 as collected_rands,
               SUM(i.outstanding)/100.0 as outstanding_rands
        FROM invoices i
        WHERE i.deleted_at IS NULL AND i.date >= DATE_SUB(CURDATE(), INTERVAL {months} MONTH)
        GROUP BY month
        ORDER BY month DESC
    """)
    results = [dict(zip(cols, r)) for r in rows]
    print(json.dumps({"revenue": results, "months": months}, indent=2, default=str))

def cmd_annuity(args):
    """Recurring billing (MRC) for a client."""
    name = sql_escape(args.name)
    cols, rows = run_sql(f"""
        SELECT c.company_name, c.name as contact_name, c.billing_account_number,
               a.reference, a.frequency, a.billing_date, a.description as annuity_desc,
               ai.name as item_name, ai.code, ai.price/100.0 as price_rands, 
               ai.quantity, (ai.price * ai.quantity)/100.0 as line_total_rands,
               ai.billing_start_date, ai.live_date
        FROM annuity_items ai
        JOIN annuities a ON ai.annuity_id = a.id
        JOIN customers c ON a.customer_id = c.id
        WHERE c.deleted_at IS NULL AND a.deleted_at IS NULL AND ai.deleted_at IS NULL
          AND (c.company_name LIKE '%{name}%' OR c.name LIKE '%{name}%' OR c.billing_account_number LIKE '%{name}%')
        ORDER BY ai.price DESC
    """)
    results = [dict(zip(cols, r)) for r in rows]
    if not results:
        print(json.dumps({"status": "NO RESULTS FOUND", "query": args.name, "message": f"⚠️ NO RESULTS FOUND: No annuity/MRC records found for '{args.name}'. The name may be misspelled."}))
        return
    mrc_total = sum(r.get("line_total_rands", 0) or 0 for r in results)
    print(json.dumps({"status": "OK", "items": results, "count": len(results), "mrc_total_rands": mrc_total}, indent=2, default=str))

def cmd_search(args):
    """Search clients by name, company, or account number."""
    query = sql_escape(args.query)
    cols, rows = run_sql(f"""
        SELECT c.id, c.company_name, c.name, c.email, c.mobile, 
               c.billing_account_number, c.stop_supply, c.payment_method
        FROM customers c
        WHERE c.deleted_at IS NULL
          AND (c.company_name LIKE '%{query}%' OR c.name LIKE '%{query}%' 
               OR c.billing_account_number LIKE '%{query}%' OR c.email LIKE '%{query}%')
        ORDER BY c.company_name
        LIMIT 20
    """)
    results = [dict(zip(cols, r)) for r in rows]
    if not results:
        print(json.dumps({"status": "NO RESULTS FOUND", "query": args.query, "message": f"⚠️ NO RESULTS FOUND: No clients match '{args.query}'. Check spelling or try a different search term."}))
        return
    print(json.dumps({"status": "OK", "clients": results, "count": len(results)}, indent=2, default=str))

def cmd_sql(args):
    """Run a raw SQL query (read-only)."""
    cols, rows = run_sql(args.query)
    results = [dict(zip(cols, r)) for r in rows]
    print(json.dumps({"columns": cols, "rows": results, "count": len(results)}, indent=2, default=str))

def cmd_dashboards(args):
    """List available MetaBase dashboards."""
    result = api("GET", "search?models=dashboard")
    if result:
        for item in result.get("data", []):
            print(f"ID:{item['id']:4} | {item['name']}")

def cmd_cards(args):
    """List available saved questions/cards."""
    result = api("GET", "search?models=card")
    if result:
        for item in result.get("data", [])[:30]:
            print(f"ID:{item['id']:4} | {item['name']}")

def main():
    parser = argparse.ArgumentParser(description="MetaBase finance helper for MoreNET")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("client")
    p.add_argument("name")

    p = sub.add_parser("invoices")
    p.add_argument("name")
    p.add_argument("--months", type=int, default=6)

    p = sub.add_parser("outstanding")
    p.add_argument("--min", type=float, default=0, help="Minimum outstanding in Rands")

    p = sub.add_parser("revenue")
    p.add_argument("--months", type=int, default=12)

    p = sub.add_parser("annuity")
    p.add_argument("name")

    p = sub.add_parser("search")
    p.add_argument("query")

    p = sub.add_parser("sql")
    p.add_argument("query")

    sub.add_parser("dashboards")
    sub.add_parser("cards")

    args = parser.parse_args()

    if not METABASE_API_KEY:
        print("METABASE_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    cmd_map = {
        "client": cmd_client, "invoices": cmd_invoices, "outstanding": cmd_outstanding,
        "revenue": cmd_revenue, "annuity": cmd_annuity, "search": cmd_search,
        "sql": cmd_sql, "dashboards": cmd_dashboards, "cards": cmd_cards,
    }
    cmd_map[args.cmd](args)

if __name__ == "__main__":
    main()
