def start_rippling_ingestion(neo4j_session, config):
    from cartography.intel.rippling.ingestion import start_rippling_ingestion as _start

    return _start(neo4j_session, config)
