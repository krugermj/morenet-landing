#!/usr/bin/env python3
"""
XWiki API helper for MoreNET documentation.
Usage: python3 xwiki.py <command> [args]

Commands:
  spaces                     - List all spaces
  pages <space>              - List pages in a space (dot-separated for nested)
  page <space> <page>        - Get page content (dot-separated space)
  get <page_id>              - Get page by full ID (from search results)
  search <query>             - Search wiki (content + title + name)
  attachments <space> <page> - List page attachments
  tree [space]               - Show wiki structure

Examples:
  xwiki.py search "Michael Hewitt"
  xwiki.py get "xwiki:Other FNO.Comtel.Michael Hewitt.WebHome"
  xwiki.py page "Other FNO.Comtel.Michael Hewitt" WebHome
"""

import os
import sys
import json
import argparse
import base64
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import quote, urlencode

XWIKI_URL = os.environ.get("XWIKI_URL", "https://wiki.morenet.co.za")
XWIKI_USER = os.environ.get("XWIKI_USER", "")
XWIKI_PASS = os.environ.get("XWIKI_PASS", "")

def api(endpoint):
    url = f"{XWIKI_URL}/rest/{endpoint}"
    auth = base64.b64encode(f"{XWIKI_USER}:{XWIKI_PASS}".encode()).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "Accept": "application/json",
    }
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        err = e.read().decode()
        print(f"API Error {e.code}: {err}", file=sys.stderr)
        sys.exit(1)

def cmd_spaces(args):
    data = api("wikis/xwiki/spaces")
    spaces = data.get("spaces", [])
    for s in spaces:
        name = s.get("name", "")
        home = s.get("home", "")
        print(f"{name}")

def cmd_pages(args):
    space_path = space_to_rest_path(args.space)
    data = api(f"wikis/xwiki/spaces/{space_path}/pages")
    pages = data.get("pageSummaries", [])
    for p in pages:
        name = p.get("name", "")
        title = p.get("title", name)
        print(f"{name}: {title}")

def cmd_page(args):
    # Support dot-separated nested space paths (e.g. "Other FNO.Comtel.Michael Hewitt")
    space_path = space_to_rest_path(args.space)
    page = quote(args.page)
    data = api(f"wikis/xwiki/spaces/{space_path}/pages/{page}")
    
    print(f"Title: {data.get('title', 'N/A')}")
    print(f"Author: {data.get('author', 'N/A')}")
    print(f"Modified: {data.get('modified', 'N/A')}")
    print(f"Version: {data.get('version', 'N/A')}")
    print("\n--- Content ---\n")
    print(data.get("content", "No content"))

def space_to_rest_path(space_dotted):
    """Convert dot-separated space path to REST URL path.
    e.g. 'Other FNO.Comtel.Michael Hewitt' -> 'Other%20FNO/spaces/Comtel/spaces/Michael%20Hewitt'
    """
    parts = space_dotted.split(".")
    return "/spaces/".join(quote(p) for p in parts)

def cmd_search(args):
    query = quote(args.query)
    # Search both content and title for better recall
    scopes = ["content", "title", "name"]
    seen_ids = set()
    all_results = []

    for scope in scopes:
        data = api(f"wikis/xwiki/search?q={query}&scope={scope}")
        for r in data.get("searchResults", []):
            rid = r.get("id", "")
            if rid not in seen_ids:
                seen_ids.add(rid)
                all_results.append(r)

    if not all_results:
        print("No results found")
        return

    print(f"Found {len(all_results)} result(s):\n")
    for r in all_results:
        space = r.get("space", "")
        page = r.get("pageName", "")
        title = r.get("title", page)
        score = r.get("score")
        rid = r.get("id", "")
        
        # Build hierarchy breadcrumb if available
        hierarchy = r.get("hierarchy", {})
        crumbs = [item.get("label", "") for item in hierarchy.get("items", [])
                  if item.get("type") in ("space",)]
        breadcrumb = " > ".join(crumbs) if crumbs else space

        score_str = f" (score: {score:.2f})" if score is not None else ""
        print(f"  [{breadcrumb}] {title}{score_str}")
        print(f"    ID: {rid}")
        print(f"    Space path: {space}")
        print()

def cmd_get(args):
    """Fetch a page by its full ID (e.g. 'xwiki:Other FNO.Comtel.Michael Hewitt.WebHome')
    or by dot-separated space.page path."""
    page_id = args.page_id
    
    # Strip wiki prefix if present
    if ":" in page_id:
        page_id = page_id.split(":", 1)[1]
    
    # Split into parts - last part is page name, rest is space path
    parts = page_id.split(".")
    if len(parts) < 2:
        print(f"Invalid page ID: {args.page_id}. Use format: Space.SubSpace.PageName", file=sys.stderr)
        sys.exit(1)
    
    page_name = parts[-1]
    space_dotted = ".".join(parts[:-1])
    space_path = space_to_rest_path(space_dotted)
    
    data = api(f"wikis/xwiki/spaces/{space_path}/pages/{quote(page_name)}")
    
    print(f"Title: {data.get('title', 'N/A')}")
    print(f"Author: {data.get('author', 'N/A')}")
    print(f"Modified: {data.get('modified', 'N/A')}")
    print(f"Version: {data.get('version', 'N/A')}")
    print(f"Space: {space_dotted}")
    print("\n--- Content ---\n")
    print(data.get("content", "No content"))

def cmd_attachments(args):
    space_path = space_to_rest_path(args.space)
    page = quote(args.page)
    data = api(f"wikis/xwiki/spaces/{space_path}/pages/{page}/attachments")
    attachments = data.get("attachments", [])
    
    if not attachments:
        print("No attachments")
        return
    
    for a in attachments:
        name = a.get("name", "")
        size = a.get("size", 0)
        author = a.get("author", "")
        print(f"{name} ({size} bytes) - {author}")

def cmd_tree(args):
    """Show wiki structure."""
    data = api("wikis/xwiki/spaces")
    spaces = data.get("spaces", [])
    
    for s in spaces:
        name = s.get("name", "")
        if args.space and name != args.space:
            continue
        print(f"📁 {name}/")
        
        try:
            pages_data = api(f"wikis/xwiki/spaces/{quote(name)}/pages")
            pages = pages_data.get("pageSummaries", [])
            for p in pages[:10]:  # Limit to 10 per space
                pname = p.get("name", "")
                title = p.get("title", pname)
                print(f"   📄 {pname}: {title}")
            if len(pages) > 10:
                print(f"   ... and {len(pages) - 10} more")
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description="XWiki API helper")
    sub = parser.add_subparsers(dest="cmd", required=True)
    
    sub.add_parser("spaces")
    
    p = sub.add_parser("pages")
    p.add_argument("space")
    
    p = sub.add_parser("page")
    p.add_argument("space")
    p.add_argument("page")
    
    p = sub.add_parser("search")
    p.add_argument("query")
    
    p = sub.add_parser("get")
    p.add_argument("page_id", help="Full page ID (e.g. 'xwiki:Space.SubSpace.Page' or 'Space.SubSpace.Page')")

    p = sub.add_parser("attachments")
    p.add_argument("space")
    p.add_argument("page")
    
    p = sub.add_parser("tree")
    p.add_argument("space", nargs="?", default=None)
    
    args = parser.parse_args()
    
    if not XWIKI_USER or not XWIKI_PASS:
        print("XWIKI_USER and XWIKI_PASS not set", file=sys.stderr)
        sys.exit(1)
    
    cmd_map = {
        "spaces": cmd_spaces,
        "pages": cmd_pages,
        "page": cmd_page,
        "get": cmd_get,
        "search": cmd_search,
        "attachments": cmd_attachments,
        "tree": cmd_tree,
    }
    cmd_map[args.cmd](args)

if __name__ == "__main__":
    main()
