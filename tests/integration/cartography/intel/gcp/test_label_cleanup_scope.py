from cartography.intel.gcp import label

TEST_UPDATE_TAG = 123456789
PARAMS = {
    'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': 'ws-lbl', 'GCP_ORGANIZATION_ID': 'org-lbl',
    'GCP_PROJECT_ID': 'proj-lbl', 'LIMIT_SIZE': 1000,
}


def test_label_cleanup_keeps_other_services_labels(neo4j_session):
    # Both labels are stale; cleaning GCPInstance labels must leave the dataset's (its service may be withheld).
    neo4j_session.run(
        """
        MERGE (p:GCPProject{id: $p})<-[:OWNER]-(:GCPOrganization{id: $org})<-[:OWNER]-(:CloudanixWorkspace{id: $ws})
        MERGE (p)-[:RESOURCE]->(:GCPInstance{id: 'lbl-vm'})
            -[:LABELED{lastupdated: 1}]->(:GCPLabel{id: 'lbl-vm/label/env', lastupdated: 1})
        MERGE (p)-[:RESOURCE]->(:GCPBigqueryDataset{id: 'lbl-ds'})
            -[:LABELED{lastupdated: 1}]->(:GCPLabel{id: 'lbl-ds/label/env', lastupdated: 1})
        """,
        p=PARAMS['GCP_PROJECT_ID'], org=PARAMS['GCP_ORGANIZATION_ID'], ws=PARAMS['WORKSPACE_ID'],
    )

    label.cleanup_labels(neo4j_session, PARAMS, 'GCPInstance')

    ids = {r['id'] for r in neo4j_session.run("MATCH (l:GCPLabel) WHERE l.id STARTS WITH 'lbl-' RETURN l.id AS id")}
    assert ids == {'lbl-ds/label/env'}
