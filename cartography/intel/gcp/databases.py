import json
import logging
from typing import Dict
from typing import List
from typing import Optional

import neo4j
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

@timeit
def get_sql_instances(sql: Resource,project_id: str) -> List[Dict]:
    """
        Returns a list of sql instances for a given project.
        
        :type sql: Resource
        :param sql: The sql resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Sql Instances
    """
    try:
        sql_instances = []
        request = sql.instances().list(project=f"projects/{project_id}")
        while request is not None:
            response = request.execute()
            if response.get('items',[]):
                for item in response['items']:
                    item['id'] = f"project/{project_id}/instances/{item['name']}"
                    sql_instances.append(item)
            request = sql.instances().list_next(previous_request=request, previous_response=response)
        return sql_instances
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
            logger.warning(
                (
                    "Could not retrieve Sql Instances on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise

@timeit
def get_sql_users(sql: Resource,project_id: str) -> List[Dict]:
    """
        Returns a list of sql instance users for a given project.
        
        :type sql: Resource
        :param sql: The sql resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Sql Instance Users
    """
    sql_instances = get_sql_instances(sql,project_id)
    for inst in sql_instances:
        try:
            sql_users = []
            request = sql.users().list(project=f"projects/{project_id}",instance=inst['name'])
            while request is not None:
                response = request.execute()
                if response.get('items',[]):
                    for item in response['items']:
                        item['id'] = f"project/{project_id}/instances/{inst['name']}/users/{item['name']}"
                        sql_users.append(item)
                    while 'nextPageToken' in response:
                        request = sql.users().list(project=project_id,instance=inst['name'],pageToken=response['nextPAgeToken'])
                        while request is not None:
                            response = request.execute()
                            if response.get('items',[]):
                                for item in response['items']:
                                    item['id'] = f"project/{project_id}/instances/{inst['name']}/users/{item['name']}"
                                    sql_users.append(item)
            return sql_users
        except HttpError as e:
            err = json.loads(e.content.decode('utf-8'))['error']
            if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
                logger.warning(
                    (
                        "Could not retrieve Sql Instance Users on project %s due to permissions issues. Code: %s, Message: %s"
                    ), project_id, err['code'], err['message'],
            )
                return []
            else:
                raise
            
@timeit
def get_bigtable_instances(bigtable:Resource,project_id:str) -> List[Dict]:
    """
        Returns a list of bigtable instances for a given project.
        
        :type bigtable: Resource
        :param bigtable: The bigtable resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Bigtable Instances
    """
    try:
        bigtable_instances = []
        request = bigtable.projects().instances().list(parent=f"projects/{project_id}")
        while request is not None:
            response = request.execute()
            if response.get('instances',[]):
                for instance in response['instances']:
                    instance['id'] = instance['name']
                    bigtable_instances.append(instance)
            request = bigtable.projects().instances().list_next(previous_request=request, previous_response=response)
        return bigtable_instances
    except HttpError as e:
            err = json.loads(e.content.decode('utf-8'))['error']
            if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
                logger.warning(
                    (
                        "Could not retrieve Bigtable Instances on project %s due to permissions issues. Code: %s, Message: %s"
                    ), project_id, err['code'], err['message'],
            )
                return []
            else:
                raise
            
@timeit
def get_bigtable_clusters(bigtable:Resource,project_id:str) -> List[Dict]:
    """
        Returns a list of bigtable clusters for a given project.
        
        :type bigtable: Resource
        :param bigtable: The bigtable resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Bigtable Clusters
    """
    instances = get_bigtable_instances(bigtable,project_id)
    for instance in instances:
        try:
            bigtable_clusters = []
            request = bigtable.projects().instances().clusters().list(parent=f"projects/{project_id}/instances/{instance['name']}")
            while request is not None:
                response = request.execute()
                if response.get('clusters',[]):
                    for cluster in response['clusters']:
                        cluster['instance_name'] = instance.get('name')
                        cluster['id'] = cluster['name']
                        bigtable_clusters.append(cluster)
                request = bigtable.projects().instances().clusters().list_next(previous_request=request, previous_response=response)
            return bigtable_clusters
        except HttpError as e:
            err = json.loads(e.content.decode('utf-8'))['error']
            if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
                logger.warning(
                    (
                        "Could not retrieve Bigtable Instance Clusters on project %s due to permissions issues. Code: %s, Message: %s"
                    ), project_id, err['code'], err['message'],
            )
                return []
            else:
                raise
            
@timeit
def get_bigtable_cluster_backups(bigtable:Resource,project_id:str) -> List[Dict]:
    """
        Returns a list of bigtable cluster backups for a given project.
        
        :type bigtable: Resource
        :param bigtable: The bigtable resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Bigtable Cluster Backups
    """
    clusters = get_bigtable_clusters(bigtable, project_id)
    for cluster in clusters:
        try:
            cluster_backups = []
            request = bigtable.projects().instances().clusters().backup().list(parent=f"projects/{project_id}/instances/{cluster['instance_name']}/clusters/{cluster['name']}")
            while request is not None:
                response = request.execute()
                if response.get('backups',[]):
                    for backup in response['backups']:
                        backup['id'] = backup['name']
                        cluster_backups.append(backup)
                request = bigtable.projects().instances().clusters().backup().list_next(previous_request=request, previous_response=response)
            return cluster_backups
        except HttpError as e:
            err = json.loads(e.content.decode('utf-8'))['error']
            if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
                logger.warning(
                    (
                        "Could not retrieve Bigtable Instance Clusters Backups on project %s due to permissions issues. Code: %s, Message: %s"
                    ), project_id, err['code'], err['message'],
            )
                return []
            else:
                raise
            
@timeit
def get_get_bigtable_tables(bigtable:Resource,project_id:str) -> List[Dict]:
    """
        Returns a list of bigtable tables for a given project.
        
        :type bigtable: Resource
        :param bigtable: The bigtable resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Bigtable Tables
    """
    instances = get_bigtable_instances(bigtable,project_id)
    for instance in instances:
        try:
            bigtable_tables = []
            request = bigtable.projects().instances().tables().list(parent=f"projects/{project_id}/instances/{instance['name']}")
            while request is not None:
                response = request.execute()
                if response.get('tables',[]):
                    for table in response['tables']:
                        table['id'] = table['name']
                        bigtable_tables.append(table)
                request = bigtable.projects().instances().tables().list_next(previous_request=request, previous_response=response)
            return bigtable_tables
        except HttpError as e:
            err = json.loads(e.content.decode('utf-8'))['error']
            if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
                logger.warning(
                    (
                        "Could not retrieve Bigtable Instance Tables on project %s due to permissions issues. Code: %s, Message: %s"
                    ), project_id, err['code'], err['message'],
            )
                return []
            else:
                raise
            
@timeit
def get_firestore_databases(firestore:Resource,project_id:str) -> List[Dict]:
    """
        Returns a list of firestore databases for a given project.
        
        :type firestore: Resource
        :param firestore: The firestore resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Firestore Databases
    """
    try:
        firestore_databases = []
        request = firestore.projects().databases().list(parent = f"projects/{project_id}")
        while request is not None:
            response = request.execute()
            if response.get('databases',[]):
                for database in response['databases']:
                    database['id'] = database['name']
                    firestore_databases.append(database)
            request = firestore.projects().databases().list_next(previous_request=request, previous_response=response)
        return firestore_databases
    except HttpError as e:
            err = json.loads(e.content.decode('utf-8'))['error']
            if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
                logger.warning(
                    (
                        "Could not retrieve Firestore Databases on project %s due to permissions issues. Code: %s, Message: %s"
                    ), project_id, err['code'], err['message'],
            )
                return []
            else:
                raise
            
@timeit
def get_firestore_indexes(firestore:Resource,project_id:str) -> List[Dict]:
    """
        Returns a list of firestore indexes for a given project.
        
        :type firestore: Resource
        :param firestore: The firestore resource created by googleapiclient.discovery.build()

        :type project_id: str
        :param project_id: Current Google Project Id

        :rtype: list
        :return: List of Firestore Indexes
    """
    databases = get_firestore_databases(firestore,project_id)
    for database in databases:
        try:
            firestore_indexes = []
            request = firestore.projects().databases().collectionGroups().indexes().list(parent = f"{database['name']}/collectionGroups/*")
            while request is not None:
                response = request.execute()
                if response.get('indexes',[]):
                    for index in response['indexes']:
                        index['id'] = index['name']
                        firestore_indexes.append(index)
                request = firestore.projects().databases().collectionGroups().indexes().list(previous_request=request, previous_response=response)
            return firestore_indexes
        except HttpError as e:
            err = json.loads(e.content.decode('utf-8'))['error']
            if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
                logger.warning(
                    (
                        "Could not retrieve Firestore Indexes on project %s due to permissions issues. Code: %s, Message: %s"
                    ), project_id, err['code'], err['message'],
            )
                return []
            else:
                raise
            
@timeit
def load_sql_instances(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]],project_id: str,update_tag: int) -> None:
    session.write_transaction(_load_sql_instances_tx, data_list,project_id, update_tag)

@timeit
def _load_sql_instances_tx(tx:neo4j.Transaction,instances: List[Dict],project_id: str,gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type instances_resp: List
        :param instances_resp: A list of SQL Instances

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_sql_instances = """
    UNWIND {instances} as instance
    MERGE(i:GCPSQLInstance{id:{instance.id}})
    ON CREATE SET
        i.firstseen = timestamp()
    SET
        i.state = instance.state,
        i.databaseVersion = instance.databaseVersion,
        i.masterInstanceName = instance.MasterInstanceName,
        i.maxDiskSize = instance.maxDiskSize,
        i.currentDiskSize = instance.currentDiskSize,
        i.instanceType = instance.instanceType,
        i.connectionName = instance.connectionName,
        i.name = instance.name,
        i.region = instance.region,
        i.gceZone = instance.gceZone,
        i.secondaryGceZone = instance.secondaryGceZone,
        i.satisfiesPzs = instance.satisfiesPzs, 
        i.createTime = instance.createTime
    WITH instance, i
    MATCH (owner:GCPProject{id:{ProjectId}})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET
        r.firstseen = timestamp(),
        r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_sql_instances,
        instances = instances,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )

@timeit
def load_sql_users(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]],project_id: str, update_tag: int) -> None:
    session.write_transaction(_load_sql_users_tx, data_list,project_id, update_tag)

@timeit
def _load_sql_users_tx(tx: neo4j.Transaction,sql_users: List[Dict],project_id: str,gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type users_resp: List
        :param users_resp: A list of SQL Users

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_sql_users = """
    UNWIND {sql_users} as user
    MERGE(u:GCPSQLUser{id:{user.id}})
    ON CREATE SET
        u.firstseen = timestamp()
    SET
        u.name = user.name,
        u.host = user.host,
        u.instance = user.instance,
        u.project = user.project,
        u.type = user.type
    WITH user, u
    MATCH (owner:GCPProject{id:{ProjectId}})-[r1:Resource]->(i:GCPSQLInstance{id:{instance.id}})
    MERGE (owner)-[r1:RESOURCE]->(i)-[r2:uses]<-(u)
    ON CREATE SET
        r1.firstseen = timestamp,
        r2.firstseen = timestamp,
        r1.lastupdated = {gcp_update_tag},
        r2.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_sql_users,
        sql_users = sql_users,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
    
@timeit
def load_bigtable_instances(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]], project_id: str, update_tag: int) -> None:
    session.write_transaction(_load_bigtable_instances_tx, data_list,project_id, update_tag)
    
@timeit
def _load_bigtable_instances_tx(tx: neo4j.Transaction,bigtable_instances: List[Dict],project_id: str,gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type instances_resp: List
        :param instances_resp: A list of Bigtable Instances

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_bigtable_instances = """
    UNWIND {bigtable_instances} as instance
    MERGE (i:GCPBigtableInstance{id:{instance.id}})
    ON CREATE SET
        i.firstseen = timestamp()
    SET
        i.name = instance.name,
        i.displayName = instance.displayName,
        i.state = instance.state,
        i.type = instance.type,
        i.createTime = instance.createTime
    WITH instance, i
    MATCH (owner:GCPProject{id:{ProjectId}})-[r1:Resource]->(i:GCPBigtableInstance{id:{instance.id}})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET
        r.firstseen = timestamp(),
        r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_bigtable_instances,
        bigtable_instances = bigtable_instances,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )

@timeit
def load_bigtable_clusters(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]],project_id: str,update_tag: int) -> None:
    session.write_transaction(_load_bigtable_clusters_tx, data_list,project_id, update_tag)
    
@timeit
def _load_bigtable_clusters_tx(tx: neo4j.Transaction,bigtable_clusters: List[Dict],project_id: str,gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type clusters_resp: List
        :param clusters_resp: A list of Bigtable Instance Clusters

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_bigtable_clusters = """
    UNWIND {bigtable_clusters} as cluster
    MERGE (c:GCPBigtableCluster{id:{cluster.id}})
    ON CREATE SET
        c.firstseen = timestamp()
    SET
        c.name = cluster.name,
        c.location = cluster.name,
        c.state = cluster.state,
        c.serveNodes = cluster.serveNodes,
        c.defaultStorageType = cluster.defaultStorageType
    WITH cluster,c
    MATCH (owner:GCPProject{id:{ProjectId}})-[r1:Resource]->(i:GCPBigtableInstance{id:{instance.id}})-[r2:Resource]->(c:GCPBigtableCluster{id:{cluster.id}})
    MERGE (owner)-[r1:RESOURCE]->(i)-[r2:Resource]->(c)
    ON CREATE SET
        r1.firstseen = timestamp,
        r2.firstseen = timestamp,
        r1.lastupdated = {gcp_update_tag},
        r2.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_bigtable_clusters,
        bigtable_clusters = bigtable_clusters,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )

@timeit    
def load_bigtable_cluster_backups(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]],project_id: str,update_tag: int) -> None:
    session.write_transaction(_load_bigtable_cluster_backups_tx, data_list,project_id, update_tag)

@timeit
def _load_bigtable_cluster_backups_tx(tx: neo4j.Transaction,bigtable_cluster_backups: List[Dict],project_id: str,gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type cluster_backup_resp: List
        :param cluster_backup_resp: A list of Bigtable Instance Cluster Backups

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_bigtable_cluster_backups = """
    UNWIND {bigtable_cluster_backups} as backup
    MERGE (b:GCPBigtableClusterBackup{id:{backup.id}})
    ON CREATE SET
        b.firstseen = timestamp()
    SET
        b.name = backup.name,
        b.sourceTable = backup.sourceTable,
        b.expireTime = backup.expireTime,
        b.startTime = backup.startTime,
        b.endTime = backup.endTime,
        b.sizeBytes = backup.sizeBytes,
        b.state = backup.state
    WITH backup, b
    MATCH (owner:GCPProject{id:{ProjectId}})-[r1:Resource]->(i:GCPBigtableInstance{id:{instance.id}})-[r2:Resource]->(c:GCPBigtableCluster{id:{cluster.id}})-[r3:Resource]->(b:GCPBigTableClusterBackup{id:{backup.id}})
    MERGE (owner)-[r1:RESOURCE]->(i)-[r2:Resource]->(c)-[r3:Resource]-(b)
    ON CREATE SET
        r1.firstseen = timestamp,
        r2.firstseen = timestamp,
        r3.firstseen = timestamp,
        r1.lastupdated = {gcp_update_tag},
        r2.lastupdated = {gcp_update_tag},
        r3.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_bigtable_cluster_backups,
        bigtable_cluster_backups = bigtable_cluster_backups,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
    
@timeit    
def load_bigtable_tables(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]],project_id: str,update_tag: int) -> None:
    session.write_transaction(_load_bigtable_tables_tx, data_list,project_id, update_tag)
    
@timeit
def _load_bigtable_tables_tx(tx: neo4j.Transaction,bigtable_tables: List[Dict],project_id: str,gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type bigtable_table_resp: List
        :param bigtable_table_resp: A list of Bigtable Tables

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_bigtable_tables = """
    UNWIND {bigtable_tables} as table
    MERGE (t:GCPBigtableTable{id:{table.id}})
    ON CREATE SET
        t.firstseen = timestamp()
    SET
        t.name = table.name,
        t.replicationState = table.clusterState.replicationState,
        t.granularity = table.granularity,
        t.sourceType = table.restoreInfo.sourceType
    WITH table, t
    MATCH (owner:GCPProject{id:{ProjectId}})-[r1:Resource]->(i:GCPBigtableInstance{id:{instance.id}})-[r2:Resource]->(c:GCPBigtableTable{id:{table.id}})
    MERGE (owner)-[r1:Resource]->(i)-[r2:Resource]->(t)
    ON CREATE SET
        r1.firstseen = timestamp,
        r2.firstseen = timestamp,
        r1.lastupdated = {gcp_update_tag},
        r2.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_bigtable_tables,
        bigtable_tables = bigtable_tables,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
    
@timeit    
def load_firestore_databases(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]], project_id: str, update_tag: int) -> None:
    session.write_transaction(_load_firestore_databases_tx, data_list,project_id, update_tag)

@timeit
def _load_firestore_databases_tx(tx: neo4j.Transaction, firestore_databases: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type firestore_databases_resp: List
        :param firestore_databases_resp: A list of Firestore Databases

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_firestore_databases = """
    UNWIND {firestore_databases} as database
    MERGE (d:GCPFirestoreDatabase{id:{database.id}})
    ON CREATE SET
        d.firstseen = timestamp()
    SET
        d.name = database.name,
        d.locationId = database.locationId,
        d.type = database.type,
        d.concurrencyMode = database.concurrencyMode,
    WITH database, d
    MATCH (owner:GCPProject{id:{ProjectId}})-[r:Resource]->(d:GCPFirestoreDatabase{id:{database.id}})
    MERGE (owner)-[r:Resource]->(d)
    ON CREATE SET
        r.firstseen = timestamp(),
        r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_firestore_databases,
        firestore_databases = firestore_databases,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
    
@timeit    
def load_firestore_indexes(session: neo4j.Session, data_list: List[Dict[str, Optional[str]]],project_id: str,update_tag: int) -> None:
    session.write_transaction(_load_firestore_indexes_tx, data_list,project_id, update_tag)
    
@timeit
def _load_firestore_indexes_tx(tx: neo4j.Transaction,firestore_indexes: List[Dict],project_id: str,gcp_update_tag: int) -> None:
    """
        :type neo4j_transaction: Neo4j transaction object
        :param neo4j transaction: The Neo4j transaction object

        :type firestore_indexes_resp: List
        :param firestore_indexes_resp: A list of Firestore Databases

        :type project_id: str
        :param project_id: Current Google Project Id

        :type gcp_update_tag: timestamp
        :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with
    """
    ingest_firestore_indexes = """
    UNWIND {firestore_indexes} as index
    MERGE (ix:GCPFirestoreIndex{id:{index.id}})
    ON CREATE SET
        d.firstseen = timestamp()
    SET
        ix.name = index.name,
        ix.queryScope = index.queryScope,
        ix.state = index.state
    MATCH (owner:GCPProject{id:{ProjectId}})-[r1:Resource]->(d:GCPFirestoreDatabase{id:{database.id}})-[r2:Resource]->(ix:GCPFirestoreIndex{id:{index.id}})
    MERGE (owner)-[r1:Resource]->(d)-[r2:Resource]->(ix)
    ON CREATE SET
        r1.firstseen = timestamp(),
        r2.firstseen = timestamp(),
        r1.lastupdated = {gcp_update_tag},
        r2.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_firestore_indexes,
        firestore_indexes = firestore_indexes,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
@timeit
def cleanup_sql(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """
    Delete out-of-date GCP SQL Instances and relationships

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    run_cleanup_job('gcp_sql_cleanup.json', neo4j_session, common_job_parameters)
    
@timeit
def cleanup_bigtable(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """
    Delete out-of-date GCP Bigtable Instances and relationships

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    run_cleanup_job('gcp_bigtable_cleanup.json', neo4j_session, common_job_parameters)
    
@timeit
def cleanup_firestore(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """
    Delete out-of-date GCP Bigtable Instances and relationships

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    run_cleanup_job('gcp_firestore_cleanup.json', neo4j_session, common_job_parameters)

@timeit
def sync_sql(
    neo4j_session: neo4j.Session, sql: Resource, firestore:Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: Dict
) -> None:
    """
    Get GCP Cloud SQL Instances and Users using the Cloud Function resource object, ingest to Neo4j, and clean up old data.

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session

    :type sql: The GCP Cloud SQL resource object created by googleapiclient.discovery.build()
    :param sql: The GCP Cloud SQL resource object
    
    :type bigtable: The GCP Bigtable resource object created by googleapiclient.discovery.build()
    :param sql: The GCP Bigtable resource object
    
    :type firestore: The GCP Firestore resource object created by googleapiclient.discovery.build()
    :param firestore: The GCP Firestore resource object

    :type project_id: str
    :param project_id: The project ID of the corresponding project

    :type gcp_update_tag: timestamp
    :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    logger.info("Syncing GCP Cloud SQL for project %s.", project_id)
    #SQL INSTANCES
    sqlinstances =  get_sql_instances(sql,project_id)
    load_sql_instances(neo4j_session,sqlinstances,project_id,gcp_update_tag)
    #SQL USERS
    users = get_sql_users(sql,project_id)
    load_sql_users(neo4j_session,users,project_id,gcp_update_tag)
    # TODO scope the cleanup to the current project - https://github.com/lyft/cartography/issues/381
    cleanup_sql(neo4j_session, common_job_parameters)
    
@timeit
def sync_bigtable(
    neo4j_session: neo4j.Session, bigtable: Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: Dict
) -> None:
    """
    Get GCP Cloud SQL Instances and Users using the Cloud Function resource object, ingest to Neo4j, and clean up old data.

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session
    
    :type bigtable: The GCP Bigtable resource object created by googleapiclient.discovery.build()
    :param sql: The GCP Bigtable resource object

    :type project_id: str
    :param project_id: The project ID of the corresponding project

    :type gcp_update_tag: timestamp
    :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    logger.info("Syncing GCP Cloud SQL for project %s.", project_id)
    #BIGTABLE INSTANCES
    bigtableinstances = get_bigtable_instances(bigtable,project_id)
    load_bigtable_instances(neo4j_session,bigtableinstances,project_id,gcp_update_tag)
    #BIGTABLE CLUSTERS
    bigtableclusters = get_bigtable_clusters(bigtable,project_id)
    load_bigtable_clusters(neo4j_session,bigtableclusters,project_id,gcp_update_tag)
    #BIGTABLE CLUSTER BACKUPS
    clusterbackups = get_bigtable_cluster_backups(bigtable,project_id)
    load_bigtable_cluster_backups(neo4j_session,clusterbackups,project_id,gcp_update_tag)
    #BIGTABLE TABLES
    bigtabletables = get_get_bigtable_tables(bigtable,project_id)
    load_bigtable_tables(neo4j_session,bigtabletables,project_id,gcp_update_tag)
    # TODO scope the cleanup to the current project - https://github.com/lyft/cartography/issues/381
    cleanup_bigtable(neo4j_session, common_job_parameters)
    
@timeit
def sync_firestore(
    neo4j_session: neo4j.Session, firestore:Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: Dict
) -> None:
    """
    Get GCP Cloud SQL Instances and Users using the Cloud Function resource object, ingest to Neo4j, and clean up old data.

    :type neo4j_session: The Neo4j session object
    :param neo4j_session: The Neo4j session
    
    :type firestore: The GCP Firestore resource object created by googleapiclient.discovery.build()
    :param firestore: The GCP Firestore resource object

    :type project_id: str
    :param project_id: The project ID of the corresponding project

    :type gcp_update_tag: timestamp
    :param gcp_update_tag: The timestamp value to set our new Neo4j nodes with

    :type common_job_parameters: dict
    :param common_job_parameters: Dictionary of other job parameters to pass to Neo4j

    :rtype: NoneType
    :return: Nothing
    """
    logger.info("Syncing GCP Cloud SQL for project %s.", project_id)
    #FIRESTORE DATABASES
    firestoredatabases = get_firestore_databases(firestore,project_id)
    load_firestore_databases(neo4j_session,firestoredatabases,project_id,gcp_update_tag)
    #FIRESTORE INDEXES
    firestoreindexes = get_firestore_indexes(firestore,project_id)
    load_firestore_indexes(neo4j_session,firestoreindexes,project_id,gcp_update_tag)
    # TODO scope the cleanup to the current project - https://github.com/lyft/cartography/issues/381
    cleanup_firestore(neo4j_session, common_job_parameters)