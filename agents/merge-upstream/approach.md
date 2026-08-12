Good question. Several layers to validate. Here's the recommended approach:

  ---
  1. Pre/Post Snapshot Comparison

  Before running new code, capture a baseline from the current prod/staging Neo4j:

  // Count all node labels
  CALL apoc.meta.stats() YIELD labels, relTypesCount
  RETURN labels, relTypesCount;

  // Or without APOC:
  MATCH (n) RETURN labels(n) AS label, count(n) AS count
  ORDER BY count DESC;

  // All relationship types + counts
  MATCH ()-[r]->() RETURN type(r) AS rel, count(r) AS count ORDER BY count DESC;

  Save output to a file. After running new sync, run same queries and diff.

  ---
  2. Property Coverage Check

  Upstream migrated many nodes to NodeSchema — property names may have changed (e.g., camelCase → snake_case).

  // Check what properties exist on a node type
  MATCH (n:EC2Instance) RETURN keys(n) AS props LIMIT 1;

  // Find nodes with NULL on critical fields
  MATCH (n:EC2Instance) WHERE n.instanceid IS NULL RETURN count(n);
  MATCH (n:AWSAccount) WHERE n.id IS NULL RETURN count(n);

  Key things to check per node type:
  - id field present and non-null
  - lastupdated set (means sync wrote it)
  - firstseen set

  ---
  3. Relationship Integrity

  // Check AWSAccount → EC2Instance relationship still exists
  MATCH (a:AWSAccount)-[:RESOURCE]->(e:EC2Instance)
  RETURN count(e) AS ec2_count_via_account;

  // Orphaned nodes (no relationships at all) — shouldn't happen for most types
  MATCH (n:EC2Instance) WHERE NOT (n)--() RETURN count(n) AS orphans;

  ---
  4. Field Name Regression Check

  Upstream renamed some fields. Build a diff script:

  # compare_schemas.py — run against old and new Neo4j instances
  from neo4j import GraphDatabase

  def get_schema(uri):
      driver = GraphDatabase.driver(uri, auth=None)
      with driver.session() as s:
          # Get all properties per label
          result = s.run("""
              MATCH (n)
              WITH labels(n)[0] AS label, keys(n) AS props
              UNWIND props AS prop
              RETURN label, collect(DISTINCT prop) AS properties
              ORDER BY label
          """)
          return {r["label"]: set(r["properties"]) for r in result}

  old = get_schema("bolt://old-neo4j:7687")
  new = get_schema("bolt://new-neo4j:7687")

  for label in set(old) | set(new):
      old_props = old.get(label, set())
      new_props = new.get(label, set())
      removed = old_props - new_props
      added = new_props - old_props
      if removed or added:
          print(f"\n{label}:")
          if removed: print(f"  REMOVED: {removed}")
          if added:   print(f"  ADDED:   {added}")

  ---
  5. Specific High-Risk Areas from This Merge

  Based on what changed, focus validation on these:

  ┌───────────────┬───────────────────────────────────────┬───────────────────────────────────────────────────────────────────────┐
  │     Area      │             What changed              │                                 Check                                 │
  ├───────────────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ EC2 instances │ NodeSchema pattern, dropped UserData  │ MATCH (n:EC2Instance) RETURN count(n), n.instanceid LIMIT 5           │
  ├───────────────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ GCP nodes     │ New IAM permission edges, SA keys     │ MATCH ()-[:HAS_PERMISSION]->() RETURN count(*)                        │
  ├───────────────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ Console links │ cloudconsolelink now optional         │ MATCH (n:EC2Instance) WHERE n.consolelink IS NOT NULL RETURN count(n) │
  ├───────────────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ Cleanup jobs  │ JSON cleanup → Python cleanup         │ Check stale nodes still get deleted post-sync                         │
  ├───────────────┼───────────────────────────────────────┼───────────────────────────────────────────────────────────────────────┤
  │ Azure roles   │ AzureRoleAssignment.scope index added │ Index exists: :schema in Neo4j browser                                │
  └───────────────┴───────────────────────────────────────┴───────────────────────────────────────────────────────────────────────┘

  ---
  ---
  6. Automated Test Strategy

  Run a sync against a staging Neo4j with known test data, then assert:
  ---
  6. Automated Test Strategy

  Run a sync against a staging Neo4j with known test data, then assert:

  # Run sync
  cartography --neo4j-uri bolt://localhost:7687 --aws-sync-all-profiles

  # Run validation queries via cypher-shell or script
  cypher-shell -a bolt://localhost:7687 \
    "MATCH (n:EC2Instance) WHERE n.id IS NULL RETURN count(n) AS null_ids" \
    | grep "0"  # should be 0

  ---
  Practical Recommendation

  1. Before deploying: run apoc.meta.stats() on prod, save output
  2. Staging first: deploy to staging, run full sync, compare schema snapshot
  3. Use the diff script above for property-level regression
  4. Check counts: node counts within 5% of expected = healthy
  5. Spot-check relationships: pick 3-5 critical paths (AWSAccount→EC2Instance, GCPProject→GCPInstance, etc.)

  The lastupdated field is your best signal — if it matches the sync run timestamp, the node was written successfully by the new code.
