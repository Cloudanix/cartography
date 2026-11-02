# Cypher that resolves `entity.email` (a member of a resource's IAM policy) to a principal of the syncing
# organization. iam.py hangs users and groups off the organization and service accounts and domains off its
# projects. Principal nodes are matched by email and other customers' principals are in the same graph: without
# the anchor, a member naming another customer's service account linked that customer's node to this resource.
# Needs $WORKSPACE_ID and $GCP_ORGANIZATION_ID; binds `principal`.
ORG_PRINCIPAL_MATCH = """
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(org:GCPOrganization{id: $GCP_ORGANIZATION_ID})
    MATCH (principal:GCPPrincipal{email: entity.email})
    WHERE (org)-[:RESOURCE]->(principal) OR (org)-[:OWNER]->(:GCPProject)-[:RESOURCE]->(principal)
"""
