# Graph Report - driveos-server  (2026-08-30)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 31 nodes · 30 edges · 4 communities (3 shown, 1 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `cbc726d3`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- server.js
- dependencies
- package.json
- getSpotifyToken

## God Nodes (most connected - your core abstractions)
1. `getSpotifyToken()` - 2 edges
2. `querySpotifyTracks()` - 2 edges
3. `express` - 2 edges
4. `uuid` - 2 edges
5. `ws` - 2 edges
6. `scripts` - 2 edges
7. `adminClients` - 1 edges
8. `app` - 1 edges
9. `blacklist` - 1 edges
10. `devices` - 1 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Import Cycles
- None detected.

## Communities (4 total, 1 thin omitted)

### Community 0 - "server.js"
Cohesion: 0.12
Nodes (11): adminClients, app, blacklist, devices, express, fingerprintBlacklist, http, path (+3 more)

### Community 1 - "dependencies"
Cohesion: 0.29
Nodes (7): express, dependencies, express, uuid, ws, uuid, ws

### Community 2 - "package.json"
Cohesion: 0.33
Nodes (5): main, name, scripts, start, version

## Knowledge Gaps
- **18 isolated node(s):** `adminClients`, `app`, `blacklist`, `devices`, `express` (+13 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `dependencies` connect `dependencies` to `package.json`?**
  _High betweenness centrality (0.110) - this node is a cross-community bridge._
- **What connects `adminClients`, `app`, `blacklist` to the rest of the system?**
  _18 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `server.js` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._