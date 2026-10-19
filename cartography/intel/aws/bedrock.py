import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


def get_boto3_client(boto3_session: boto3.session.Session, service: str, region: str):
    client = boto3_session.client(service, region_name=region, config=get_botocore_config())
    return client


@timeit
def get_bedrock_knowledge_bases_list(
    boto3_session: boto3.session.Session,
    region: str
) -> List[Dict]:
    knowledge_bases: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock-agent", region)
        paginator = client.get_paginator("list_knowledge_bases")
        for page in paginator.paginate():
            knowledge_bases.extend(page["knowledgeBaseSummaries"])

        for kb in knowledge_bases:
            kb["region"] = region
            kb["consolelink"] = aws_console_link.get_console_link(arn=kb["knowledgeBaseArn"])
            
            try:
                detail = client.get_knowledge_base(knowledgeBaseId=kb["knowledgeBaseId"])
                kb_detail = detail.get("knowledgeBase", {})
                kb["roleArn"] = kb_detail.get("roleArn")
                storage_config = kb_detail.get("storageConfiguration", {})
                kb["storageType"] = storage_config.get("type")
                kb["s3BucketArn"] = _extract_storage_s3_bucket_arn(storage_config)
            except Exception as e:
                logger.warning(
                    f"Could not get details for bedrock knowledge base {kb['knowledgeBaseId']}. skipping enrichment. - {e}",
                )
    except Exception as e:
        logger.warning(f"Could not list bedrock knowledge base, skipping... -{e}")
    return knowledge_bases


def _extract_storage_s3_bucket_arn(storage_config: Dict) -> str:
    """
    Knowledge base storage backends vary (OpenSearch Serverless, Pinecone, RDS,
    Redis, MongoDB, S3 vectors). Only the S3 vectors backend references an S3
    bucket; return its ARN when present, else None.
    """
    s3_vectors = storage_config.get("s3VectorsConfiguration", {})
    return s3_vectors.get("vectorBucketArn")

@timeit
def get_bedrock_data_sources_list(
    boto3_session: boto3.session.Session,
    knowledge_bases: List[Dict],
    region: str,
) -> List[Dict]:
    data_sources: List[Dict] = []
    client = get_boto3_client(boto3_session, "bedrock-agent", region)
    # list_data_sources is scoped to a single knowledge base, so iterate the
    # knowledge bases we already collected for this region.
    for kb in knowledge_bases:
        if kb.get("region") != region:
            continue
        knowledge_base_id = kb["knowledgeBaseId"]
        kb_arn = kb["knowledgeBaseArn"]
        try:
            kb_data_sources: List[Dict] = []
            paginator = client.get_paginator("list_data_sources")
            for page in paginator.paginate(knowledgeBaseId=knowledge_base_id):
                kb_data_sources.extend(page["dataSourceSummaries"])

            for ds in kb_data_sources:
                ds["region"] = region
                # Data sources have no standalone ARN; use a composite id of
                # knowledgeBaseId/dataSourceId as the node key.
                ds["id"] = f"{ds['knowledgeBaseId']}/{ds['dataSourceId']}"
                ds["knowledgeBaseArn"] = kb_arn
                # Data sources have no console page of their own; link to the parent knowledge base.
                ds["consolelink"] = aws_console_link.get_console_link(arn=kb_arn)

            data_sources.extend(kb_data_sources)
        except Exception as e:
            logger.warning(
                f"Could not list bedrock data sources for knowledge base {knowledge_base_id}. skipping. - {e}",
            )

    return data_sources

@timeit
def get_bedrock_agents_list(boto3_session: boto3.session.Session, current_aws_account_id: str, region: str) -> List[Dict]:
    bedrock_agents: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock-agent", region)

        paginator = client.get_paginator("list_agents")
        for page in paginator.paginate():
            bedrock_agents.extend(page["agentSummaries"])

        for bedrock_agent in bedrock_agents:
            bedrock_agent["region"] = region
            bedrock_agent["arn"] = f"arn:aws:bedrock:{region}:{current_aws_account_id}:agent/{bedrock_agent['agentId']}"
            bedrock_agent["consolelink"] = aws_console_link.get_console_link(arn=bedrock_agent["arn"])

    except Exception as e:
        logger.warning(
            f"Could not list bedrock agents. skipping. - {e}",
        )
    return bedrock_agents


@timeit
def get_bedrock_agent_action_groups_list(
    boto3_session: boto3.session.Session,
    bedrock_agents: List[Dict],
    region: str,
) -> List[Dict]:
    action_groups: List[Dict] = []
    client = get_boto3_client(boto3_session, "bedrock-agent", region)
    # list_agent_action_groups is scoped to a single agent + version, so iterate
    # the agents we already collected for this region.
    for agent in bedrock_agents:
        if agent.get("region") != region:
            continue
        agent_id = agent["agentId"]
        agent_version = agent.get("latestAgentVersion", "DRAFT")
        agent_arn = agent["arn"]
        try:
            agent_action_groups: List[Dict] = []
            paginator = client.get_paginator("list_agent_action_groups")
            for page in paginator.paginate(agentId=agent_id, agentVersion=agent_version):
                agent_action_groups.extend(page["actionGroupSummaries"])

            for ag in agent_action_groups:
                ag["region"] = region
                ag["agentId"] = agent_id
                ag["agentVersion"] = agent_version
                ag["agentArn"] = agent_arn
                # Action groups have no ARN; use a composite id as the node key.
                ag["id"] = f"{agent_id}/{agent_version}/{ag['actionGroupId']}"
                # Action groups have no console page of their own; link to the parent agent.
                ag["consolelink"] = aws_console_link.get_console_link(arn=agent_arn)
                # The list summary omits the executor; enrich with get_agent_action_group
                # to pull the Lambda the action group invokes.
                try:
                    detail = client.get_agent_action_group(
                        agentId=agent_id,
                        agentVersion=agent_version,
                        actionGroupId=ag["actionGroupId"],
                    )
                    ag_detail = detail.get("agentActionGroup", {})
                    ag["lambdaArn"] = ag_detail.get("actionGroupExecutor", {}).get("lambda")
                    ag["parentActionSignature"] = ag_detail.get("parentActionSignature")
                    ag["createdAt"] = ag_detail.get("createdAt")
                except Exception as e:
                    logger.warning(
                        f"Could not get details for bedrock action group {ag['actionGroupId']} "
                        f"(agent {agent_id}). skipping enrichment. - {e}",
                    )

            action_groups.extend(agent_action_groups)
        except Exception as e:
            logger.warning(
                f"Could not list bedrock agent action groups for agent {agent_id}. skipping. - {e}",
            )

    return action_groups


@timeit
def get_bedrock_flows_list(
    boto3_session: boto3.session.Session,
    region: str,
) -> List[Dict]:
    flows: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock-agent", region)
        paginator = client.get_paginator("list_flows")
        for page in paginator.paginate():
            flows.extend(page["flowSummaries"])

        for flow in flows:
            flow["region"] = region
            flow["consolelink"] = aws_console_link.get_console_link(arn=flow["arn"])
            # The list summary does not include the execution role; enrich each
            # flow with a get_flow call.
            try:
                detail = client.get_flow(flowIdentifier=flow["id"])
                flow["executionRoleArn"] = detail.get("executionRoleArn")
                flow["customerEncryptionKeyArn"] = detail.get("customerEncryptionKeyArn")
            except Exception as e:
                logger.warning(
                    f"Could not get details for bedrock flow {flow['id']}. skipping enrichment. - {e}",
                )
    except Exception as e:
        logger.warning(f"Could not list bedrock flows. skipping. - {e}")
    return flows


@timeit
def get_bedrock_foundation_models_list(
    boto3_session: boto3.session.Session,
    region: str
) -> List[Dict]:
    foundation_models: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock", region)
        response = client.list_foundation_models()
        models = response.get("modelSummaries")

        for model in models:
            model["region"] = region
            model["consolelink"] = aws_console_link.get_console_link(arn=model["modelArn"])
            model["arn"] = model.get("modelArn", "")
            # Flatten list / nested fields to scalars for Neo4j, matching the
            # rest of this module which stores scalar properties.
            model["inputModalitiesStr"] = ",".join(model.get("inputModalities", []) or [])
            model["outputModalitiesStr"] = ",".join(model.get("outputModalities", []) or [])
            model["customizationsSupportedStr"] = ",".join(model.get("customizationsSupported", []) or [])
            model["inferenceTypesSupportedStr"] = ",".join(model.get("inferenceTypesSupported", []) or [])
            model["modelLifecycleStatus"] = model.get("modelLifecycle", {}).get("status")
            foundation_models.append(model)

    except Exception as e:
        logger.warning(f"Could not list bedrock foundation models. skipping. - {e}")
    return foundation_models


@timeit
def get_bedrock_provisioned_throughputs_list(
    boto3_session: boto3.session.Session,
    region: str,
) -> List[Dict]:
    provisioned_throughputs: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock", region)
        paginator = client.get_paginator("list_provisioned_model_throughputs")
        for page in paginator.paginate():
            provisioned_throughputs.extend(page["provisionedModelSummaries"])

        for pt in provisioned_throughputs:
            pt["region"] = region
            pt["consolelink"] = aws_console_link.get_console_link(arn=pt["provisionedModelArn"])
    except Exception as e:
        logger.warning(f"Could not list bedrock provisioned throughputs. skipping. - {e}")
    return provisioned_throughputs


@timeit
def get_bedrock_agent_aliases_list(
    boto3_session: boto3.session.Session,
    bedrock_agents: List[Dict],
    region: str,
) -> List[Dict]:
    agent_aliases: List[Dict] = []
    client = get_boto3_client(boto3_session, "bedrock-agent", region)
    # list_agent_aliases is scoped to a single agent, so iterate the agents we
    # already collected for this region.
    for agent in bedrock_agents:
        if agent.get("region") != region:
            continue
        agent_id = agent["agentId"]
        agent_arn = agent["arn"]
        try:
            agent_alias_list: List[Dict] = []
            paginator = client.get_paginator("list_agent_aliases")
            for page in paginator.paginate(agentId=agent_id):
                agent_alias_list.extend(page["agentAliasSummaries"])

            for alias in agent_alias_list:
                alias["region"] = region
                alias["agentId"] = agent_id
                alias["agentArn"] = agent_arn
                # Agent aliases have no ARN in the summary; use a composite id.
                alias["id"] = f"{agent_id}/{alias['agentAliasId']}"
                alias["consolelink"] = aws_console_link.get_console_link(arn=agent_arn)

            agent_aliases.extend(agent_alias_list)
        except Exception as e:
            logger.warning(
                f"Could not list bedrock agent aliases for agent {agent_id}. skipping. - {e}",
            )

    return agent_aliases


@timeit
def get_bedrock_flow_aliases_list(
    boto3_session: boto3.session.Session,
    bedrock_flows: List[Dict],
    region: str,
) -> List[Dict]:
    flow_aliases: List[Dict] = []
    client = get_boto3_client(boto3_session, "bedrock-agent", region)
    # list_flow_aliases is scoped to a single flow, so iterate the flows we
    # already collected for this region.
    for flow in bedrock_flows:
        if flow.get("region") != region:
            continue
        flow_id = flow["id"]
        flow_arn = flow["arn"]
        try:
            flow_alias_list: List[Dict] = []
            paginator = client.get_paginator("list_flow_aliases")
            for page in paginator.paginate(flowIdentifier=flow_id):
                flow_alias_list.extend(page["flowAliasSummaries"])

            for alias in flow_alias_list:
                alias["region"] = region
                alias["flowArn"] = flow_arn
                alias["consolelink"] = aws_console_link.get_console_link(arn=alias["arn"])

            flow_aliases.extend(flow_alias_list)
        except Exception as e:
            logger.warning(
                f"Could not list bedrock flow aliases for flow {flow_id}. skipping. - {e}",
            )

    return flow_aliases


@timeit
def get_bedrock_prompts_list(
    boto3_session: boto3.session.Session,
    region: str,
) -> List[Dict]:
    prompts: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock-agent", region)
        paginator = client.get_paginator("list_prompts")
        for page in paginator.paginate():
            prompts.extend(page["promptSummaries"])

        for prompt in prompts:
            prompt["region"] = region
            prompt["consolelink"] = aws_console_link.get_console_link(arn=prompt["arn"])
    except Exception as e:
        logger.warning(f"Could not list bedrock prompts. skipping. - {e}")
    return prompts


@timeit
def load_bedrock_knowledge_bases(
    neo4j_session: neo4j.Session,
    bedrock_knowledge_bases: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_knowledge_bases_tx, bedrock_knowledge_bases, current_aws_account_id, aws_update_tag)


@timeit
def load_bedrock_data_sources(
    neo4j_session: neo4j.Session,
    bedrock_data_sources: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_data_sources_tx, bedrock_data_sources, current_aws_account_id, aws_update_tag)


@timeit
def load_bedrock_foundation_models(
    neo4j_session: neo4j.Session,
    bedrock_foundation_models: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_foundation_models_tx, bedrock_foundation_models, current_aws_account_id, aws_update_tag)

@timeit
def _load_bedrock_foundation_models_tx(
    tx: neo4j.Transaction,
    bedrock_foundation_models: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_foundation_models = """
    UNWIND $bedrock_foundation_models AS fm
    MERGE (i:AWSBedrockFoundationModel{arn:fm.arn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = fm.arn,
    i.modelid = fm.modelId
    SET i.name = fm.modelName,
    i.providername = fm.providerName,
    i.inputmodalities = fm.inputModalitiesStr,
    i.outputmodalities = fm.outputModalitiesStr,
    i.customizationssupported = fm.customizationsSupportedStr,
    i.inferencetypessupported = fm.inferenceTypesSupportedStr,
    i.responsestreamingsupported = fm.responseStreamingSupported,
    i.modellifecyclestatus = fm.modelLifecycleStatus,
    i.lastupdated = $aws_update_tag,
    i.region = fm.region,
    i.consolelink = fm.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_bedrock_foundation_models,
        bedrock_foundation_models=bedrock_foundation_models,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def load_bedrock_provisioned_throughputs(
    neo4j_session: neo4j.Session,
    bedrock_provisioned_throughputs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_provisioned_throughputs_tx, bedrock_provisioned_throughputs, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_provisioned_throughputs_tx(
    tx: neo4j.Transaction,
    bedrock_provisioned_throughputs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_provisioned_throughputs = """
    UNWIND $bedrock_provisioned_throughputs AS pt
    MERGE (i:AWSBedrockProvisionedModelThroughput{arn:pt.provisionedModelArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = pt.provisionedModelArn
    SET i.name = pt.provisionedModelName,
    i.status = pt.status,
    i.modelarn = pt.modelArn,
    i.foundationmodelarn = pt.foundationModelArn,
    i.modelunits = pt.modelUnits,
    i.desiredmodelunits = pt.desiredModelUnits,
    i.commitmentduration = pt.commitmentDuration,
    i.creationtime = pt.creationTime,
    i.lastmodifiedtime = pt.lastModifiedTime,
    i.lastupdated = $aws_update_tag,
    i.region = pt.region,
    i.consolelink = pt.consolelink
    WITH i, pt
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN pt.modelArn IS NULL THEN [] ELSE [1] END |
        MERGE (m:AWSBedrockFoundationModel{arn: pt.modelArn})
        MERGE (i)-[pm:PROVISIONS_MODEL]->(m)
        ON CREATE SET pm.firstseen = timestamp()
        SET pm.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_bedrock_provisioned_throughputs,
        bedrock_provisioned_throughputs=bedrock_provisioned_throughputs,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def load_bedrock_agent_aliases(
    neo4j_session: neo4j.Session,
    bedrock_agent_aliases: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_agent_aliases_tx, bedrock_agent_aliases, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_agent_aliases_tx(
    tx: neo4j.Transaction,
    bedrock_agent_aliases: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_agent_aliases = """
    UNWIND $bedrock_agent_aliases AS alias
    MERGE (i:AWSBedrockAgentAlias{id:alias.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = alias.id,
    i.agentaliasid = alias.agentAliasId
    SET i.name = alias.agentAliasName,
    i.status = alias.agentAliasStatus,
    i.agentid = alias.agentId,
    i.createdat = alias.createdAt,
    i.updatedat = alias.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = alias.region,
    i.consolelink = alias.consolelink
    WITH i, alias
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, alias
    MATCH (agent:AWSBedrockAgent{arn: alias.agentArn})
    MERGE (agent)-[haa:HAS_ALIAS]->(i)
    ON CREATE SET haa.firstseen = timestamp()
    SET haa.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_bedrock_agent_aliases,
        bedrock_agent_aliases=bedrock_agent_aliases,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def load_bedrock_flow_aliases(
    neo4j_session: neo4j.Session,
    bedrock_flow_aliases: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_flow_aliases_tx, bedrock_flow_aliases, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_flow_aliases_tx(
    tx: neo4j.Transaction,
    bedrock_flow_aliases: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_flow_aliases = """
    UNWIND $bedrock_flow_aliases AS alias
    MERGE (i:AWSBedrockFlowAlias{arn:alias.arn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = alias.arn,
    i.flowaliasid = alias.id
    SET i.name = alias.name,
    i.flowid = alias.flowId,
    i.createdat = alias.createdAt,
    i.updatedat = alias.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = alias.region,
    i.consolelink = alias.consolelink
    WITH i, alias
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, alias
    MATCH (flow:AWSBedrockFlow{arn: alias.flowArn})
    MERGE (flow)-[hfa:HAS_ALIAS]->(i)
    ON CREATE SET hfa.firstseen = timestamp()
    SET hfa.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_bedrock_flow_aliases,
        bedrock_flow_aliases=bedrock_flow_aliases,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def load_bedrock_prompts(
    neo4j_session: neo4j.Session,
    bedrock_prompts: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_prompts_tx, bedrock_prompts, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_prompts_tx(
    tx: neo4j.Transaction,
    bedrock_prompts: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_prompts = """
    UNWIND $bedrock_prompts AS prompt
    MERGE (i:AWSBedrockPrompt{arn:prompt.arn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = prompt.arn,
    i.promptid = prompt.id
    SET i.name = prompt.name,
    i.description = prompt.description,
    i.version = prompt.version,
    i.createdat = prompt.createdAt,
    i.updatedat = prompt.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = prompt.region,
    i.consolelink = prompt.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_bedrock_prompts,
        bedrock_prompts=bedrock_prompts,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def _load_bedrock_data_sources_tx(
    tx: neo4j.Transaction,
    bedrock_data_sources: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_data_sources = """
    UNWIND $bedrock_data_sources AS ds
    MERGE (i:AWSBedrockDataSource{id:ds.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = ds.id,
    i.datasourceid = ds.dataSourceId
    SET i.name = ds.name,
    i.status = ds.status,
    i.description = ds.description,
    i.knowledgebaseid = ds.knowledgeBaseId,
    i.updatedat = ds.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = ds.region,
    i.consolelink = ds.consolelink
    WITH i, ds
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, ds
    MATCH (kb:AWSBedrockKnowledgeBase{arn: ds.knowledgeBaseArn})
    MERGE (kb)-[hds:HAS_DATA_SOURCE]->(i)
    ON CREATE SET hds.firstseen = timestamp()
    SET hds.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_bedrock_data_sources,
        bedrock_data_sources=bedrock_data_sources,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )

@timeit
def load_bedrock_agents(
    neo4j_session: neo4j.Session,
    bedrock_agents: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_agents_tx, bedrock_agents, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_knowledge_bases_tx(
    tx: neo4j.Transaction,
    bedrock_knowledge_bases: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_knowledge_bases = """
    UNWIND $bedrock_knowledge_bases AS kb
    MERGE (i:AWSBedrockKnowledgeBase{arn:kb.knowledgeBaseArn})
    ON CREATE SET i.firstseen = timestamp(), 
    i.arn = kb.knowledgeBaseArn, 
    i.knowledgebaseid = kb.knowledgeBaseId
    SET i.name = kb.name, 
    i.status = kb.status, 
    i.updatedat = kb.updatedAt,
    i.rolearn = kb.roleArn,
    i.storagetype = kb.storageType,
    i.lastupdated = $aws_update_tag, 
    i.region = kb.region, 
    i.consolelink = kb.consolelink
    WITH i, kb
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN kb.roleArn IS NULL THEN [] ELSE [1] END |
        MERGE (p:AWSPrincipal{arn: kb.roleArn})
        ON CREATE SET p.firstseen = timestamp()
        SET p.lastupdated = $aws_update_tag
        MERGE (i)-[ar:BEDROCK_KB_ASSUMEROLE_ALLOW]->(p)
        ON CREATE SET ar.firstseen = timestamp()
        SET ar.lastupdated = $aws_update_tag
    )
    FOREACH (_ IN CASE WHEN kb.s3BucketArn IS NULL THEN [] ELSE [1] END |
        MERGE (b:S3Bucket{arn: kb.s3BucketArn})
        ON CREATE SET b.firstseen = timestamp()
        SET b.lastupdated = $aws_update_tag
        MERGE (i)-[si:STORES_IN]->(b)
        ON CREATE SET si.firstseen = timestamp()
        SET si.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_bedrock_knowledge_bases,
        bedrock_knowledge_bases=bedrock_knowledge_bases,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )

@timeit
def _load_bedrock_agents_tx(
    tx: neo4j.Transaction,
    bedrock_agents: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_agents = """
    UNWIND $bedrock_agents AS agent
    MERGE (i:AWSBedrockAgent{arn:agent.arn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = agent.arn,
    i.agentid = agent.agentId
    SET i.updatedat = agent.updatedAt,
    i.name = agent.agentName,
    i.status = agent.agentStatus,
    i.latestagentversion = agent.latestAgentVersion,
    i.lastupdated =$aws_update_tag,
    i.region = agent.region,
    i.consolelink = agent.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_bedrock_agents,
        bedrock_agents=bedrock_agents,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def load_bedrock_agent_action_groups(
    neo4j_session: neo4j.Session,
    bedrock_action_groups: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_agent_action_groups_tx, bedrock_action_groups, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_agent_action_groups_tx(
    tx: neo4j.Transaction,
    bedrock_action_groups: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_action_groups = """
    UNWIND $bedrock_action_groups AS ag
    MERGE (i:AWSBedrockAgentActionGroup{id:ag.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = ag.id,
    i.actiongroupid = ag.actionGroupId
    SET i.name = ag.actionGroupName,
    i.status = ag.actionGroupState,
    i.description = ag.description,
    i.agentid = ag.agentId,
    i.agentversion = ag.agentVersion,
    i.parentactionsignature = ag.parentActionSignature,
    i.createdat = ag.createdAt,
    i.updatedat = ag.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = ag.region,
    i.consolelink = ag.consolelink
    WITH i, ag
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, ag
    MATCH (agent:AWSBedrockAgent{arn: ag.agentArn})
    MERGE (agent)-[hag:HAS_ACTION_GROUP]->(i)
    ON CREATE SET hag.firstseen = timestamp()
    SET hag.lastupdated = $aws_update_tag
    WITH i, ag
    FOREACH (_ IN CASE WHEN ag.lambdaArn IS NULL THEN [] ELSE [1] END |
        MERGE (l:AWSLambda{id: ag.lambdaArn})
        ON CREATE SET l.firstseen = timestamp()
        SET l.lastupdated = $aws_update_tag
        MERGE (i)-[inv:INVOKES]->(l)
        ON CREATE SET inv.firstseen = timestamp()
        SET inv.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_bedrock_action_groups,
        bedrock_action_groups=bedrock_action_groups,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def load_bedrock_flows(
    neo4j_session: neo4j.Session,
    bedrock_flows: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_flows_tx, bedrock_flows, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_flows_tx(
    tx: neo4j.Transaction,
    bedrock_flows: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_flows = """
    UNWIND $bedrock_flows AS flow
    MERGE (i:AWSBedrockFlow{arn:flow.arn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = flow.arn,
    i.flowid = flow.id
    SET i.name = flow.name,
    i.status = flow.status,
    i.description = flow.description,
    i.version = flow.version,
    i.executionrolearn = flow.executionRoleArn,
    i.customerencryptionkeyarn = flow.customerEncryptionKeyArn,
    i.createdat = flow.createdAt,
    i.updatedat = flow.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = flow.region,
    i.consolelink = flow.consolelink
    WITH i, flow
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN flow.executionRoleArn IS NULL THEN [] ELSE [1] END |
        MERGE (p:AWSPrincipal{arn: flow.executionRoleArn})
        ON CREATE SET p.firstseen = timestamp()
        SET p.lastupdated = $aws_update_tag
        MERGE (i)-[ar:BEDROCK_FLOW_ASSUMEROLE_ALLOW]->(p)
        ON CREATE SET ar.firstseen = timestamp()
        SET ar.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_bedrock_flows,
        bedrock_flows=bedrock_flows,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_model_customisation_jobs_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    model_customisation_jobs: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock", region)

        paginator = client.get_paginator("list_model_customization_jobs")
        for page in paginator.paginate():
            model_customisation_jobs.extend(page["modelCustomizationJobSummaries"])

        for model_customisation_job in model_customisation_jobs:
            model_customisation_job["region"] = region
            model_customisation_job["consolelink"] = aws_console_link.get_console_link(arn=model_customisation_job['jobArn'])

    except Exception as e:
        logger.warning(
            f"Could not list bedrock model customisation jobs. skipping. - {e}",
        )
    return model_customisation_jobs


@timeit
def load_model_customisation_jobs(
    neo4j_session: neo4j.Session,
    model_customisation_jobs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_model_customisation_jobs_tx, model_customisation_jobs, current_aws_account_id, aws_update_tag)


@timeit
def _load_model_customisation_jobs_tx(
    tx: neo4j.Transaction,
    model_customisation_jobs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_model_customisation_jobs = """
    UNWIND $model_customisation_jobs AS job
    MERGE (e:AWSBedrockCustomisationJob{arn:job.jobArn})
    ON CREATE SET e.firstseen = timestamp(),
    e.arn = job.jobArn,
    e.creationtime = job.creationTime
    SET e.lastmodifiedtime = job.lastModifiedTime,
    e.name = job.jobName,
    e.status = job.status,
    e.lastupdated =$aws_update_tag,
    e.region = job.region,
    e.consolelink = job.consolelink
    WITH e
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(e)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_model_customisation_jobs,
        model_customisation_jobs=model_customisation_jobs,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_bedrock_guardrails_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    bedrock_guardrails: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock", region)

        paginator = client.get_paginator("list_guardrails")
        for page in paginator.paginate():
            bedrock_guardrails.extend(page["guardrails"])

        for bedrock_guardrail in bedrock_guardrails:
            bedrock_guardrail["region"] = region
            bedrock_guardrail["consolelink"] = aws_console_link.get_console_link(arn=bedrock_guardrail['arn'])

    except Exception as e:
        logger.warning(
            f"Could not list bedrock guardrails. skipping. - {e}",
        )
    return bedrock_guardrails


@timeit
def load_bedrock_guardrails(
    neo4j_session: neo4j.Session,
    bedrock_guardrails: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_bedrock_guardrails_tx, bedrock_guardrails, current_aws_account_id, aws_update_tag)


@timeit
def _load_bedrock_guardrails_tx(
    tx: neo4j.Transaction,
    bedrock_guardrails: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_bedrock_guardrails = """
    UNWIND $bedrock_guardrails AS rail
    MERGE (i:AWSBedrockGuardRail{arn:rail.arn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = rail.arn,
    i.createdat = rail.createdAt
    SET i.updatedat = rail.updatedAt,
    i.name = rail.name,
    i.status = rail.status,
    i.version = rail.version,
    i.lastupdated =$aws_update_tag,
    i.region = rail.region,
    i.consolelink = rail.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_bedrock_guardrails,
        bedrock_guardrails=bedrock_guardrails,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_custom_models(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    custom_models: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "bedrock", region)

        paginator = client.get_paginator("list_custom_models")
        for page in paginator.paginate():
            custom_models.extend(page["modelSummaries"])

        for custom_model in custom_models:
            custom_model["region"] = region
            custom_model["consolelink"] = aws_console_link.get_console_link(arn=custom_model['modelArn'])

    except Exception as e:
        logger.warning(
            f"Could not list bedrock custom models. skipping. - {e}",
        )
    return custom_models


@timeit
def load_custom_models(
    neo4j_session: neo4j.Session,
    custom_models: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_custom_models_tx, custom_models, current_aws_account_id, aws_update_tag)


@timeit
def _load_custom_models_tx(
    tx: neo4j.Transaction,
    custom_models: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_custom_models = """
    UNWIND $custom_models AS model
    MERGE (e:AWSBedrockCustomModel{arn:model.modelArn})
    ON CREATE SET e.firstseen = timestamp(),
    e.arn = model.modelArn,
    e.creationtime = model.CreationTime
    SET e.name = model.modelName,
    e.lastupdated =$aws_update_tag,
    e.region = model.region,
    e.consolelink = model.consolelink
    WITH e
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(e)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_custom_models,
        custom_models=custom_models,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_bedrock(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_bedrock_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_bedrock(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: str, current_aws_account_id: str,
    aws_update_tag: int, common_job_parameters: Dict,
) -> None:
    bedrock_agents = []
    for region in regions:
        bedrock_agents.extend(get_bedrock_agents_list(boto3_session, current_aws_account_id, region))

    logger.info(f"Total bedrock agents: {len(bedrock_agents)}")

    load_bedrock_agents(neo4j_session, bedrock_agents, current_aws_account_id, aws_update_tag)

    action_groups_list = []
    for region in regions:
        action_groups_list.extend(get_bedrock_agent_action_groups_list(boto3_session, bedrock_agents, region))

    logger.info(f"Total bedrock agent action groups: {len(action_groups_list)}")

    load_bedrock_agent_action_groups(neo4j_session, action_groups_list, current_aws_account_id, aws_update_tag)

    model_customisation_jobs_list = []
    for region in regions:
        model_customisation_jobs_list.extend(get_model_customisation_jobs_list(boto3_session, region))

    logger.info(f"Total Bedrock model customisation jobs list: {len(model_customisation_jobs_list)}")

    load_model_customisation_jobs(neo4j_session, model_customisation_jobs_list, current_aws_account_id, aws_update_tag)

    bedrock_guardrails_list = []
    for region in regions:
        bedrock_guardrails_list.extend(get_bedrock_guardrails_list(boto3_session, region))

    logger.info(f"Total bedrock guardrails: {len(bedrock_guardrails_list)}")

    load_bedrock_guardrails(neo4j_session, bedrock_guardrails_list, current_aws_account_id, aws_update_tag)

    custom_models_list = []
    for region in regions:
        custom_models_list.extend(get_custom_models(boto3_session, region))

    logger.info(f"Total bedrock custom models: {len(custom_models_list)}")

    load_custom_models(neo4j_session, custom_models_list, current_aws_account_id, aws_update_tag)

    knowledge_bases_list = []
    for region in regions:
        knowledge_bases_list.extend(get_bedrock_knowledge_bases_list(boto3_session, region))

    logger.info(f"Total bedrock knowledge bases: {len(knowledge_bases_list)}")

    load_bedrock_knowledge_bases(neo4j_session, knowledge_bases_list, current_aws_account_id, aws_update_tag)

    data_sources_list = []
    for region in regions:
        data_sources_list.extend(get_bedrock_data_sources_list(boto3_session, knowledge_bases_list, region))

    logger.info(f"Total bedrock data sources: {len(data_sources_list)}")

    load_bedrock_data_sources(neo4j_session, data_sources_list, current_aws_account_id, aws_update_tag)

    flows_list = []
    for region in regions:
        flows_list.extend(get_bedrock_flows_list(boto3_session, region))

    logger.info(f"Total bedrock flows: {len(flows_list)}")

    load_bedrock_flows(neo4j_session, flows_list, current_aws_account_id, aws_update_tag)

    foundation_models_list = []
    for region in regions:
        foundation_models_list.extend(get_bedrock_foundation_models_list(boto3_session, region))

    logger.info(f"Total bedrock foundation models: {len(foundation_models_list)}")

    load_bedrock_foundation_models(neo4j_session, foundation_models_list, current_aws_account_id, aws_update_tag)

    provisioned_throughputs_list = []
    for region in regions:
        provisioned_throughputs_list.extend(get_bedrock_provisioned_throughputs_list(boto3_session, region))

    logger.info(f"Total bedrock provisioned throughputs: {len(provisioned_throughputs_list)}")

    load_bedrock_provisioned_throughputs(neo4j_session, provisioned_throughputs_list, current_aws_account_id, aws_update_tag)

    agent_aliases_list = []
    for region in regions:
        agent_aliases_list.extend(get_bedrock_agent_aliases_list(boto3_session, bedrock_agents, region))

    logger.info(f"Total bedrock agent aliases: {len(agent_aliases_list)}")

    load_bedrock_agent_aliases(neo4j_session, agent_aliases_list, current_aws_account_id, aws_update_tag)

    flow_aliases_list = []
    for region in regions:
        flow_aliases_list.extend(get_bedrock_flow_aliases_list(boto3_session, flows_list, region))

    logger.info(f"Total bedrock flow aliases: {len(flow_aliases_list)}")

    load_bedrock_flow_aliases(neo4j_session, flow_aliases_list, current_aws_account_id, aws_update_tag)

    prompts_list = []
    for region in regions:
        prompts_list.extend(get_bedrock_prompts_list(boto3_session, region))

    logger.info(f"Total bedrock prompts: {len(prompts_list)}")

    load_bedrock_prompts(neo4j_session, prompts_list, current_aws_account_id, aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing Bedrock for account '%s', at %s.", current_aws_account_id, tic)
    sync_bedrock(neo4j_session, boto3_session, regions, current_aws_account_id, update_tag, common_job_parameters)

    cleanup_bedrock(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Bedrock: {toc - tic:0.4f} seconds")
