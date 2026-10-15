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
def get_notebook_instances_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    instances: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_notebook_instances")
        for page in paginator.paginate():
            instances.extend(page["NotebookInstances"])

        for instance in instances:
            instance["region"] = region
            instance["consolelink"] = aws_console_link.get_console_link(arn=instance['NotebookInstanceArn'])
            # The list summary omits role / network / KMS; enrich with describe.
            try:
                detail = client.describe_notebook_instance(
                    NotebookInstanceName=instance["NotebookInstanceName"],
                )
                instance["RoleArn"] = detail.get("RoleArn")
                instance["SubnetId"] = detail.get("SubnetId")
                instance["SecurityGroups"] = detail.get("SecurityGroups", [])
                instance["KmsKeyId"] = detail.get("KmsKeyId")
                instance["DirectInternetAccess"] = detail.get("DirectInternetAccess")
            except Exception as e:
                logger.warning(
                    f"Could not describe sagemaker notebook instance {instance.get('NotebookInstanceName')}. "
                    f"skipping enrichment. - {e}",
                )

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker notebook instances. skipping. - {e}",
        )
    return instances


@timeit
def load_notebook_instances(
    neo4j_session: neo4j.Session,
    instances: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_notebook_instances_tx, instances, current_aws_account_id, aws_update_tag)


@timeit
def _load_notebook_instances_tx(
    tx: neo4j.Transaction,
    instances: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_instances = """
    UNWIND $instances AS instance
    MERGE (i:AWSSagemakerNotebookInstance{arn:instance.NotebookInstanceArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = instance.NotebookInstanceArn,
    i.creationtime = instance.CreationTime
    SET i.lastmodifiedtime = instance.LastModifiedTime,
    i.name = instance.NotebookInstanceName,
    i.status = instance.NotebookInstanceStatus,
    i.url = instance.Url,
    i.instancetype = instance.InstanceType,
    i.defaultcoderepository = instance.DefaultCodeRepository,
    i.rolearn = instance.RoleArn,
    i.kmskeyid = instance.KmsKeyId,
    i.directinternetaccess = instance.DirectInternetAccess,
    i.lastupdated =$aws_update_tag,
    i.region = instance.region,
    i.consolelink = instance.consolelink
    WITH i, instance
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN instance.RoleArn IS NULL THEN [] ELSE [1] END |
        MERGE (p:AWSPrincipal{arn: instance.RoleArn})
        ON CREATE SET p.firstseen = timestamp()
        SET p.lastupdated = $aws_update_tag
        MERGE (i)-[ar:SAGEMAKER_ASSUMEROLE_ALLOW]->(p)
        ON CREATE SET ar.firstseen = timestamp()
        SET ar.lastupdated = $aws_update_tag
    )
    FOREACH (_ IN CASE WHEN instance.SubnetId IS NULL THEN [] ELSE [1] END |
        MERGE (sn:EC2Subnet{subnetid: instance.SubnetId})
        ON CREATE SET sn.firstseen = timestamp()
        SET sn.lastupdated = $aws_update_tag
        MERGE (i)-[insub:IN_SUBNET]->(sn)
        ON CREATE SET insub.firstseen = timestamp()
        SET insub.lastupdated = $aws_update_tag
    )
    FOREACH (sg_id IN instance.SecurityGroups |
        MERGE (sg:EC2SecurityGroup{id: sg_id})
        ON CREATE SET sg.firstseen = timestamp()
        SET sg.lastupdated = $aws_update_tag
        MERGE (i)-[msg:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        ON CREATE SET msg.firstseen = timestamp()
        SET msg.lastupdated = $aws_update_tag
    )
    FOREACH (_ IN CASE WHEN instance.KmsKeyId IS NULL THEN [] ELSE [1] END |
        MERGE (k:KMSKey{id: instance.KmsKeyId})
        ON CREATE SET k.firstseen = timestamp()
        SET k.lastupdated = $aws_update_tag
        MERGE (i)-[enc:ENCRYPTED_BY]->(k)
        ON CREATE SET enc.firstseen = timestamp()
        SET enc.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_instances,
        instances=instances,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_endpoints_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    endpoints: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_endpoints")
        for page in paginator.paginate():
            endpoints.extend(page["Endpoints"])

        for endpoint in endpoints:
            endpoint["region"] = region
            endpoint["consolelink"] = aws_console_link.get_console_link(arn=endpoint['EndpointArn'])
            # The list summary omits the endpoint config name; enrich with describe
            # so we can link the endpoint to its config node.
            try:
                detail = client.describe_endpoint(EndpointName=endpoint["EndpointName"])
                endpoint["EndpointConfigName"] = detail.get("EndpointConfigName")
            except Exception as e:
                logger.warning(
                    f"Could not describe sagemaker endpoint {endpoint.get('EndpointName')}. "
                    f"skipping enrichment. - {e}",
                )

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker endpoints. skipping. - {e}",
        )
    return endpoints


@timeit
def load_endpoints(
    neo4j_session: neo4j.Session,
    endpoints: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_endpoints_tx, endpoints, current_aws_account_id, aws_update_tag)


@timeit
def _load_endpoints_tx(
    tx: neo4j.Transaction,
    endpoints: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_endpoints = """
    UNWIND $endpoints AS endpoint
    MERGE (e:AWSSagemakerEndpoint{arn:endpoint.EndpointArn})
    ON CREATE SET e.firstseen = timestamp(),
    e.arn = endpoint.EndpointArn,
    e.creationtime = endpoint.CreationTime
    SET e.lastmodifiedtime = endpoint.LastModifiedTime,
    e.name = endpoint.EndpointName,
    e.status = endpoint.EndpointStatus,
    e.endpointconfigname = endpoint.EndpointConfigName,
    e.lastupdated =$aws_update_tag,
    e.region = endpoint.region,
    e.consolelink = endpoint.consolelink
    WITH e, endpoint
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(e)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH e, endpoint
    WHERE endpoint.EndpointConfigName IS NOT NULL
    MATCH (ec:AWSSagemakerEndpointConfig{name: endpoint.EndpointConfigName})
    MERGE (e)-[uc:USES_CONFIG]->(ec)
    ON CREATE SET uc.firstseen = timestamp()
    SET uc.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_endpoints,
        endpoints=endpoints,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_training_jobs_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    training_jobs: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_training_jobs")
        for page in paginator.paginate():
            training_jobs.extend(page["TrainingJobSummaries"])

        for training_job in training_jobs:
            training_job["region"] = region
            training_job["consolelink"] = aws_console_link.get_console_link(arn=training_job['TrainingJobArn'])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker training jobs. skipping. - {e}",
        )
    return training_jobs


@timeit
def load_training_jobs(
    neo4j_session: neo4j.Session,
    training_jobs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_training_jobs_tx, training_jobs, current_aws_account_id, aws_update_tag)


@timeit
def _load_training_jobs_tx(
    tx: neo4j.Transaction,
    training_jobs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_training_jobs = """
    UNWIND $training_jobs AS job
    MERGE (i:AWSSagemakerTrainingJob{arn:job.TrainingJobArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = job.TrainingJobArn,
    i.creationtime = job.CreationTime
    SET i.lastmodifiedtime = job.LastModifiedTime,
    i.name = job.TrainingJobName,
    i.status = job.TrainingJobStatus,
    i.trainingplanarn = job.TrainingPlanArn,
    i.lastupdated =$aws_update_tag,
    i.region = job.region,
    i.consolelink = job.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_training_jobs,
        training_jobs=training_jobs,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_models_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    models: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_models")
        for page in paginator.paginate():
            models.extend(page["Models"])

        for model in models:
            model["region"] = region
            model["consolelink"] = aws_console_link.get_console_link(arn=model['ModelArn'])
            # The list summary omits role / network / container image; enrich with describe.
            try:
                detail = client.describe_model(ModelName=model["ModelName"])
                model["ExecutionRoleArn"] = detail.get("ExecutionRoleArn")
                vpc_config = detail.get("VpcConfig", {}) or {}
                model["Subnets"] = vpc_config.get("Subnets", [])
                model["SecurityGroupIds"] = vpc_config.get("SecurityGroupIds", [])
                # Container image URI stored as a property this pass (ECR link deferred).
                primary = detail.get("PrimaryContainer", {}) or {}
                containers = detail.get("Containers", []) or []
                model["ContainerImage"] = primary.get("Image") or (
                    containers[0].get("Image") if containers else None
                )
            except Exception as e:
                logger.warning(
                    f"Could not describe sagemaker model {model.get('ModelName')}. "
                    f"skipping enrichment. - {e}",
                )

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker models. skipping. - {e}",
        )
    return models


@timeit
def load_models(
    neo4j_session: neo4j.Session,
    models: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_models_tx, models, current_aws_account_id, aws_update_tag)


@timeit
def _load_models_tx(
    tx: neo4j.Transaction,
    models: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_models = """
    UNWIND $models AS model
    MERGE (e:AWSSagemakerModel{arn:model.ModelArn})
    ON CREATE SET e.firstseen = timestamp(),
    e.arn = model.ModelArn,
    e.creationtime = model.CreationTime
    SET e.name = model.ModelName,
    e.rolearn = model.ExecutionRoleArn,
    e.containerimage = model.ContainerImage,
    e.lastupdated =$aws_update_tag,
    e.region = model.region,
    e.consolelink = model.consolelink
    WITH e, model
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(e)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN model.ExecutionRoleArn IS NULL THEN [] ELSE [1] END |
        MERGE (p:AWSPrincipal{arn: model.ExecutionRoleArn})
        ON CREATE SET p.firstseen = timestamp()
        SET p.lastupdated = $aws_update_tag
        MERGE (e)-[ar:SAGEMAKER_ASSUMEROLE_ALLOW]->(p)
        ON CREATE SET ar.firstseen = timestamp()
        SET ar.lastupdated = $aws_update_tag
    )
    FOREACH (sn_id IN model.Subnets |
        MERGE (sn:EC2Subnet{subnetid: sn_id})
        ON CREATE SET sn.firstseen = timestamp()
        SET sn.lastupdated = $aws_update_tag
        MERGE (e)-[insub:IN_SUBNET]->(sn)
        ON CREATE SET insub.firstseen = timestamp()
        SET insub.lastupdated = $aws_update_tag
    )
    FOREACH (sg_id IN model.SecurityGroupIds |
        MERGE (sg:EC2SecurityGroup{id: sg_id})
        ON CREATE SET sg.firstseen = timestamp()
        SET sg.lastupdated = $aws_update_tag
        MERGE (e)-[msg:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        ON CREATE SET msg.firstseen = timestamp()
        SET msg.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_models,
        models=models,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_domains_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    domains: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_domains")
        for page in paginator.paginate():
            domains.extend(page["Domains"])

        for domain in domains:
            domain["region"] = region
            domain["consolelink"] = aws_console_link.get_console_link(arn=domain['DomainArn'])
            # The list summary omits role / network / KMS; enrich with describe.
            try:
                detail = client.describe_domain(DomainId=domain["DomainId"])
                domain["ExecutionRole"] = detail.get("DefaultUserSettings", {}).get("ExecutionRole")
                domain["VpcId"] = detail.get("VpcId")
                domain["SubnetIds"] = detail.get("SubnetIds", [])
                domain["KmsKeyId"] = detail.get("KmsKeyId")
            except Exception as e:
                logger.warning(
                    f"Could not describe sagemaker domain {domain.get('DomainId')}. "
                    f"skipping enrichment. - {e}",
                )

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker domains. skipping. - {e}",
        )
    return domains


@timeit
def load_domains(
    neo4j_session: neo4j.Session,
    domains: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_domains_tx, domains, current_aws_account_id, aws_update_tag)


@timeit
def _load_domains_tx(
    tx: neo4j.Transaction,
    domains: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_domains = """
    UNWIND $domains AS domain
    MERGE (i:AWSSagemakerDomain{arn:domain.DomainArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = domain.DomainArn,
    i.creationtime = domain.CreationTime
    SET i.lastmodifiedtime = domain.LastModifiedTime,
    i.name = domain.DomainName,
    i.status = domain.Status,
    i.url = domain.Url,
    i.id = domain.DomainId,
    i.rolearn = domain.ExecutionRole,
    i.vpcid = domain.VpcId,
    i.kmskeyid = domain.KmsKeyId,
    i.lastupdated =$aws_update_tag,
    i.region = domain.region,
    i.consolelink = domain.consolelink
    WITH i, domain
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN domain.ExecutionRole IS NULL THEN [] ELSE [1] END |
        MERGE (p:AWSPrincipal{arn: domain.ExecutionRole})
        ON CREATE SET p.firstseen = timestamp()
        SET p.lastupdated = $aws_update_tag
        MERGE (i)-[ar:SAGEMAKER_ASSUMEROLE_ALLOW]->(p)
        ON CREATE SET ar.firstseen = timestamp()
        SET ar.lastupdated = $aws_update_tag
    )
    FOREACH (_ IN CASE WHEN domain.VpcId IS NULL THEN [] ELSE [1] END |
        MERGE (v:AWSVpc{id: domain.VpcId})
        ON CREATE SET v.firstseen = timestamp()
        SET v.lastupdated = $aws_update_tag
        MERGE (i)-[mv:MEMBER_OF_AWS_VPC]->(v)
        ON CREATE SET mv.firstseen = timestamp()
        SET mv.lastupdated = $aws_update_tag
    )
    FOREACH (sn_id IN domain.SubnetIds |
        MERGE (sn:EC2Subnet{subnetid: sn_id})
        ON CREATE SET sn.firstseen = timestamp()
        SET sn.lastupdated = $aws_update_tag
        MERGE (i)-[insub:IN_SUBNET]->(sn)
        ON CREATE SET insub.firstseen = timestamp()
        SET insub.lastupdated = $aws_update_tag
    )
    FOREACH (_ IN CASE WHEN domain.KmsKeyId IS NULL THEN [] ELSE [1] END |
        MERGE (k:KMSKey{id: domain.KmsKeyId})
        ON CREATE SET k.firstseen = timestamp()
        SET k.lastupdated = $aws_update_tag
        MERGE (i)-[enc:ENCRYPTED_BY]->(k)
        ON CREATE SET enc.firstseen = timestamp()
        SET enc.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_domains,
        domains=domains,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_clusters_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    clusters: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_clusters")
        for page in paginator.paginate():
            clusters.extend(page["ClusterSummaries"])

        for cluster in clusters:
            cluster["region"] = region
            cluster["consolelink"] = aws_console_link.get_console_link(arn=cluster['ClusterArn'])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker clusters. skipping. - {e}",
        )
    return clusters


@timeit
def load_clusters(
    neo4j_session: neo4j.Session,
    clusters: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_clusters_tx, clusters, current_aws_account_id, aws_update_tag)


@timeit
def _load_clusters_tx(
    tx: neo4j.Transaction,
    clusters: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_clusters = """
    UNWIND $clusters AS cluster
    MERGE (i:AWSSagemakerCluster{arn:cluster.ClusterArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = cluster.ClusterArn,
    i.creationtime = cluster.CreationTime
    SET i.name = cluster.ClusterName,
    i.status = cluster.ClusterStatus,
    i.lastupdated =$aws_update_tag,
    i.region = cluster.region,
    i.consolelink = cluster.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_clusters,
        clusters=clusters,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_user_profiles_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    user_profiles: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_user_profiles")
        for page in paginator.paginate():
            user_profiles.extend(page["UserProfiles"])

        for up in user_profiles:
            up["region"] = region
            # User profiles have no ARN in the summary; use a composite id.
            up["id"] = f"{up['DomainId']}/{up['UserProfileName']}"

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker user profiles. skipping. - {e}",
        )
    return user_profiles


@timeit
def load_user_profiles(
    neo4j_session: neo4j.Session,
    user_profiles: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_user_profiles_tx, user_profiles, current_aws_account_id, aws_update_tag)


@timeit
def _load_user_profiles_tx(
    tx: neo4j.Transaction,
    user_profiles: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_user_profiles = """
    UNWIND $user_profiles AS up
    MERGE (i:AWSSagemakerUserProfile{id:up.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = up.id,
    i.creationtime = up.CreationTime
    SET i.name = up.UserProfileName,
    i.status = up.Status,
    i.domainid = up.DomainId,
    i.lastmodifiedtime = up.LastModifiedTime,
    i.lastupdated = $aws_update_tag,
    i.region = up.region
    WITH i, up
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, up
    MATCH (d:AWSSagemakerDomain{id: up.DomainId})
    MERGE (d)-[hup:HAS_USER_PROFILE]->(i)
    ON CREATE SET hup.firstseen = timestamp()
    SET hup.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_user_profiles,
        user_profiles=user_profiles,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_apps_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    apps: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_apps")
        for page in paginator.paginate():
            apps.extend(page["Apps"])

        for app in apps:
            app["region"] = region
            # Apps have no ARN; build a composite id that is unique whether the
            # app belongs to a user profile or a space.
            scope = app.get("UserProfileName") or app.get("SpaceName") or ""
            app["id"] = f"{app['DomainId']}/{scope}/{app.get('AppType', '')}/{app.get('AppName', '')}"

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker apps. skipping. - {e}",
        )
    return apps


@timeit
def load_apps(
    neo4j_session: neo4j.Session,
    apps: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_apps_tx, apps, current_aws_account_id, aws_update_tag)


@timeit
def _load_apps_tx(
    tx: neo4j.Transaction,
    apps: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_apps = """
    UNWIND $apps AS app
    MERGE (i:AWSSagemakerApp{id:app.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = app.id,
    i.creationtime = app.CreationTime
    SET i.name = app.AppName,
    i.apptype = app.AppType,
    i.status = app.Status,
    i.domainid = app.DomainId,
    i.userprofilename = app.UserProfileName,
    i.spacename = app.SpaceName,
    i.lastupdated = $aws_update_tag,
    i.region = app.region
    WITH i, app
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, app
    MATCH (d:AWSSagemakerDomain{id: app.DomainId})
    MERGE (d)-[ha:HAS_APP]->(i)
    ON CREATE SET ha.firstseen = timestamp()
    SET ha.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_apps,
        apps=apps,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_spaces_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    spaces: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_spaces")
        for page in paginator.paginate():
            spaces.extend(page["Spaces"])

        for space in spaces:
            space["region"] = region
            # Spaces have no ARN in the summary; use a composite id.
            space["id"] = f"{space['DomainId']}/{space['SpaceName']}"

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker spaces. skipping. - {e}",
        )
    return spaces


@timeit
def load_spaces(
    neo4j_session: neo4j.Session,
    spaces: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_spaces_tx, spaces, current_aws_account_id, aws_update_tag)


@timeit
def _load_spaces_tx(
    tx: neo4j.Transaction,
    spaces: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_spaces = """
    UNWIND $spaces AS space
    MERGE (i:AWSSagemakerSpace{id:space.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = space.id,
    i.creationtime = space.CreationTime
    SET i.name = space.SpaceName,
    i.status = space.Status,
    i.domainid = space.DomainId,
    i.lastmodifiedtime = space.LastModifiedTime,
    i.lastupdated = $aws_update_tag,
    i.region = space.region
    WITH i, space
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, space
    MATCH (d:AWSSagemakerDomain{id: space.DomainId})
    MERGE (d)-[hs:HAS_SPACE]->(i)
    ON CREATE SET hs.firstseen = timestamp()
    SET hs.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_spaces,
        spaces=spaces,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_feature_groups_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    feature_groups: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_feature_groups")
        for page in paginator.paginate():
            feature_groups.extend(page["FeatureGroupSummaries"])

        for fg in feature_groups:
            fg["region"] = region
            fg["consolelink"] = aws_console_link.get_console_link(arn=fg["FeatureGroupArn"])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker feature groups. skipping. - {e}",
        )
    return feature_groups


@timeit
def load_feature_groups(
    neo4j_session: neo4j.Session,
    feature_groups: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_feature_groups_tx, feature_groups, current_aws_account_id, aws_update_tag)


@timeit
def _load_feature_groups_tx(
    tx: neo4j.Transaction,
    feature_groups: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_feature_groups = """
    UNWIND $feature_groups AS fg
    MERGE (i:AWSSagemakerFeatureGroup{arn:fg.FeatureGroupArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = fg.FeatureGroupArn,
    i.creationtime = fg.CreationTime
    SET i.name = fg.FeatureGroupName,
    i.status = fg.FeatureGroupStatus,
    i.lastupdated = $aws_update_tag,
    i.region = fg.region,
    i.consolelink = fg.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_feature_groups,
        feature_groups=feature_groups,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_code_repositories_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    code_repositories: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_code_repositories")
        for page in paginator.paginate():
            code_repositories.extend(page["CodeRepositorySummaryList"])

        for repo in code_repositories:
            repo["region"] = region
            repo["consolelink"] = aws_console_link.get_console_link(arn=repo["CodeRepositoryArn"])
            repo["RepositoryUrl"] = (repo.get("GitConfig", {}) or {}).get("RepositoryUrl")

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker code repositories. skipping. - {e}",
        )
    return code_repositories


@timeit
def load_code_repositories(
    neo4j_session: neo4j.Session,
    code_repositories: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_code_repositories_tx, code_repositories, current_aws_account_id, aws_update_tag)


@timeit
def _load_code_repositories_tx(
    tx: neo4j.Transaction,
    code_repositories: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_code_repositories = """
    UNWIND $code_repositories AS repo
    MERGE (i:AWSSagemakerCodeRepository{arn:repo.CodeRepositoryArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = repo.CodeRepositoryArn,
    i.creationtime = repo.CreationTime
    SET i.name = repo.CodeRepositoryName,
    i.repositoryurl = repo.RepositoryUrl,
    i.lastmodifiedtime = repo.LastModifiedTime,
    i.lastupdated = $aws_update_tag,
    i.region = repo.region,
    i.consolelink = repo.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_code_repositories,
        code_repositories=code_repositories,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_images_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    images: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_images")
        for page in paginator.paginate():
            images.extend(page["Images"])

        for image in images:
            image["region"] = region
            image["consolelink"] = aws_console_link.get_console_link(arn=image["ImageArn"])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker images. skipping. - {e}",
        )
    return images


@timeit
def load_images(
    neo4j_session: neo4j.Session,
    images: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_images_tx, images, current_aws_account_id, aws_update_tag)


@timeit
def _load_images_tx(
    tx: neo4j.Transaction,
    images: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_images = """
    UNWIND $images AS image
    MERGE (i:AWSSagemakerImage{arn:image.ImageArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = image.ImageArn,
    i.creationtime = image.CreationTime
    SET i.name = image.ImageName,
    i.displayname = image.DisplayName,
    i.status = image.ImageStatus,
    i.lastmodifiedtime = image.LastModifiedTime,
    i.lastupdated = $aws_update_tag,
    i.region = image.region,
    i.consolelink = image.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_images,
        images=images,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_monitoring_schedules_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    schedules: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_monitoring_schedules")
        for page in paginator.paginate():
            schedules.extend(page["MonitoringScheduleSummaries"])

        for schedule in schedules:
            schedule["region"] = region
            schedule["consolelink"] = aws_console_link.get_console_link(arn=schedule["MonitoringScheduleArn"])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker monitoring schedules. skipping. - {e}",
        )
    return schedules


@timeit
def load_monitoring_schedules(
    neo4j_session: neo4j.Session,
    schedules: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_monitoring_schedules_tx, schedules, current_aws_account_id, aws_update_tag)


@timeit
def _load_monitoring_schedules_tx(
    tx: neo4j.Transaction,
    schedules: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_schedules = """
    UNWIND $schedules AS sched
    MERGE (i:AWSSagemakerMonitoringSchedule{arn:sched.MonitoringScheduleArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = sched.MonitoringScheduleArn,
    i.creationtime = sched.CreationTime
    SET i.name = sched.MonitoringScheduleName,
    i.status = sched.MonitoringScheduleStatus,
    i.endpointname = sched.EndpointName,
    i.lastmodifiedtime = sched.LastModifiedTime,
    i.lastupdated = $aws_update_tag,
    i.region = sched.region,
    i.consolelink = sched.consolelink
    WITH i, sched
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, sched
    WHERE sched.EndpointName IS NOT NULL
    MATCH (e:AWSSagemakerEndpoint{name: sched.EndpointName})
    MERGE (i)-[mon:MONITORS]->(e)
    ON CREATE SET mon.firstseen = timestamp()
    SET mon.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_schedules,
        schedules=schedules,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_model_package_groups_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    groups: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_model_package_groups")
        for page in paginator.paginate():
            groups.extend(page["ModelPackageGroupSummaryList"])

        for group in groups:
            group["region"] = region
            group["consolelink"] = aws_console_link.get_console_link(arn=group["ModelPackageGroupArn"])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker model package groups. skipping. - {e}",
        )
    return groups


@timeit
def load_model_package_groups(
    neo4j_session: neo4j.Session,
    groups: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_model_package_groups_tx, groups, current_aws_account_id, aws_update_tag)


@timeit
def _load_model_package_groups_tx(
    tx: neo4j.Transaction,
    groups: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_groups = """
    UNWIND $groups AS group
    MERGE (i:AWSSagemakerModelPackageGroup{arn:group.ModelPackageGroupArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = group.ModelPackageGroupArn,
    i.creationtime = group.CreationTime
    SET i.name = group.ModelPackageGroupName,
    i.status = group.ModelPackageGroupStatus,
    i.description = group.ModelPackageGroupDescription,
    i.lastupdated = $aws_update_tag,
    i.region = group.region,
    i.consolelink = group.consolelink
    WITH i
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_groups,
        groups=groups,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_model_packages_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    packages: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_model_packages")
        for page in paginator.paginate():
            packages.extend(page["ModelPackageSummaryList"])

        for package in packages:
            package["region"] = region
            package["consolelink"] = aws_console_link.get_console_link(arn=package["ModelPackageArn"])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker model packages. skipping. - {e}",
        )
    return packages


@timeit
def load_model_packages(
    neo4j_session: neo4j.Session,
    packages: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_model_packages_tx, packages, current_aws_account_id, aws_update_tag)


@timeit
def _load_model_packages_tx(
    tx: neo4j.Transaction,
    packages: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_packages = """
    UNWIND $packages AS package
    MERGE (i:AWSSagemakerModelPackage{arn:package.ModelPackageArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = package.ModelPackageArn,
    i.creationtime = package.CreationTime
    SET i.name = package.ModelPackageName,
    i.status = package.ModelPackageStatus,
    i.version = package.ModelPackageVersion,
    i.approvalstatus = package.ModelApprovalStatus,
    i.modelpackagegroupname = package.ModelPackageGroupName,
    i.lastupdated = $aws_update_tag,
    i.region = package.region,
    i.consolelink = package.consolelink
    WITH i, package
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, package
    WHERE package.ModelPackageGroupName IS NOT NULL
    MATCH (g:AWSSagemakerModelPackageGroup{name: package.ModelPackageGroupName})
    MERGE (i)-[mo:MEMBER_OF]->(g)
    ON CREATE SET mo.firstseen = timestamp()
    SET mo.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_packages,
        packages=packages,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_pipelines_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    pipelines: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_pipelines")
        for page in paginator.paginate():
            pipelines.extend(page["PipelineSummaries"])

        for pipeline in pipelines:
            pipeline["region"] = region
            pipeline["consolelink"] = aws_console_link.get_console_link(arn=pipeline["PipelineArn"])

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker pipelines. skipping. - {e}",
        )
    return pipelines


@timeit
def load_pipelines(
    neo4j_session: neo4j.Session,
    pipelines: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_pipelines_tx, pipelines, current_aws_account_id, aws_update_tag)


@timeit
def _load_pipelines_tx(
    tx: neo4j.Transaction,
    pipelines: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_pipelines = """
    UNWIND $pipelines AS pipeline
    MERGE (i:AWSSagemakerPipeline{arn:pipeline.PipelineArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = pipeline.PipelineArn,
    i.creationtime = pipeline.CreationTime
    SET i.name = pipeline.PipelineName,
    i.displayname = pipeline.PipelineDisplayName,
    i.rolearn = pipeline.PipelineExecutionRoleArn,
    i.lastmodifiedtime = pipeline.LastModifiedTime,
    i.lastexecutiontime = pipeline.LastExecutionTime,
    i.lastupdated = $aws_update_tag,
    i.region = pipeline.region,
    i.consolelink = pipeline.consolelink
    WITH i, pipeline
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN pipeline.PipelineExecutionRoleArn IS NULL THEN [] ELSE [1] END |
        MERGE (p:AWSPrincipal{arn: pipeline.PipelineExecutionRoleArn})
        ON CREATE SET p.firstseen = timestamp()
        SET p.lastupdated = $aws_update_tag
        MERGE (i)-[ar:SAGEMAKER_ASSUMEROLE_ALLOW]->(p)
        ON CREATE SET ar.firstseen = timestamp()
        SET ar.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_pipelines,
        pipelines=pipelines,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_endpoint_configs_list(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    endpoint_configs: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "sagemaker", region)

        paginator = client.get_paginator("list_endpoint_configs")
        for page in paginator.paginate():
            endpoint_configs.extend(page["EndpointConfigs"])

        for config in endpoint_configs:
            config["region"] = region
            config["consolelink"] = aws_console_link.get_console_link(arn=config["EndpointConfigArn"])
            # The list summary omits variants / KMS; enrich with describe so we
            # can link the config to the models it hosts.
            try:
                detail = client.describe_endpoint_config(
                    EndpointConfigName=config["EndpointConfigName"],
                )
                variants = detail.get("ProductionVariants", []) or []
                config["ModelNames"] = [
                    v["ModelName"] for v in variants if v.get("ModelName")
                ]
                config["KmsKeyId"] = detail.get("KmsKeyId")
            except Exception as e:
                config.setdefault("ModelNames", [])
                logger.warning(
                    f"Could not describe sagemaker endpoint config {config.get('EndpointConfigName')}. "
                    f"skipping enrichment. - {e}",
                )

    except Exception as e:
        logger.warning(
            f"Could not list sagemaker endpoint configs. skipping. - {e}",
        )
    return endpoint_configs


@timeit
def load_endpoint_configs(
    neo4j_session: neo4j.Session,
    endpoint_configs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_endpoint_configs_tx, endpoint_configs, current_aws_account_id, aws_update_tag)


@timeit
def _load_endpoint_configs_tx(
    tx: neo4j.Transaction,
    endpoint_configs: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_endpoint_configs = """
    UNWIND $endpoint_configs AS config
    MERGE (i:AWSSagemakerEndpointConfig{arn:config.EndpointConfigArn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = config.EndpointConfigArn,
    i.creationtime = config.CreationTime
    SET i.name = config.EndpointConfigName,
    i.kmskeyid = config.KmsKeyId,
    i.lastupdated = $aws_update_tag,
    i.region = config.region,
    i.consolelink = config.consolelink
    WITH i, config
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN config.KmsKeyId IS NULL THEN [] ELSE [1] END |
        MERGE (k:KMSKey{id: config.KmsKeyId})
        ON CREATE SET k.firstseen = timestamp()
        SET k.lastupdated = $aws_update_tag
        MERGE (i)-[enc:ENCRYPTED_BY]->(k)
        ON CREATE SET enc.firstseen = timestamp()
        SET enc.lastupdated = $aws_update_tag
    )
    WITH i, config
    UNWIND config.ModelNames AS model_name
    MATCH (m:AWSSagemakerModel{name: model_name})
    MERGE (i)-[h:HOSTS]->(m)
    ON CREATE SET h.firstseen = timestamp()
    SET h.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_endpoint_configs,
        endpoint_configs=endpoint_configs,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_sagemaker(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_sagemaker_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_sagemaker(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: str, current_aws_account_id: str,
    aws_update_tag: int, common_job_parameters: Dict,
) -> None:
    notebook_instances_list = []
    for region in regions:
        notebook_instances_list.extend(get_notebook_instances_list(boto3_session, region))

    logger.info(f"Total notebook instances: {len(notebook_instances_list)}")

    load_notebook_instances(neo4j_session, notebook_instances_list, current_aws_account_id, aws_update_tag)

    # Models must load before endpoint configs (HOSTS), and endpoint configs
    # before endpoints (USES_CONFIG), so load this chain in dependency order.
    models_list = []
    for region in regions:
        models_list.extend(get_models_list(boto3_session, region))

    logger.info(f"Total models: {len(models_list)}")

    load_models(neo4j_session, models_list, current_aws_account_id, aws_update_tag)

    endpoint_configs_list = []
    for region in regions:
        endpoint_configs_list.extend(get_endpoint_configs_list(boto3_session, region))

    logger.info(f"Total endpoint configs: {len(endpoint_configs_list)}")

    load_endpoint_configs(neo4j_session, endpoint_configs_list, current_aws_account_id, aws_update_tag)

    endpoints_list = []
    for region in regions:
        endpoints_list.extend(get_endpoints_list(boto3_session, region))

    logger.info(f"Total endpoints: {len(endpoints_list)}")

    load_endpoints(neo4j_session, endpoints_list, current_aws_account_id, aws_update_tag)

    training_jobs_list = []
    for region in regions:
        training_jobs_list.extend(get_training_jobs_list(boto3_session, region))

    logger.info(f"Total training jobs: {len(training_jobs_list)}")

    load_training_jobs(neo4j_session, training_jobs_list, current_aws_account_id, aws_update_tag)

    domains_list = []
    for region in regions:
        domains_list.extend(get_domains_list(boto3_session, region))

    logger.info(f"Total domains: {len(domains_list)}")

    load_domains(neo4j_session, domains_list, current_aws_account_id, aws_update_tag)

    clusters_list = []
    for region in regions:
        clusters_list.extend(get_clusters_list(boto3_session, region))

    logger.info(f"Total clusters: {len(clusters_list)}")

    load_clusters(neo4j_session, clusters_list, current_aws_account_id, aws_update_tag)

    # Model package groups must load before model packages (MEMBER_OF).
    model_package_groups_list = []
    for region in regions:
        model_package_groups_list.extend(get_model_package_groups_list(boto3_session, region))

    logger.info(f"Total model package groups: {len(model_package_groups_list)}")

    load_model_package_groups(neo4j_session, model_package_groups_list, current_aws_account_id, aws_update_tag)

    model_packages_list = []
    for region in regions:
        model_packages_list.extend(get_model_packages_list(boto3_session, region))

    logger.info(f"Total model packages: {len(model_packages_list)}")

    load_model_packages(neo4j_session, model_packages_list, current_aws_account_id, aws_update_tag)

    pipelines_list = []
    for region in regions:
        pipelines_list.extend(get_pipelines_list(boto3_session, region))

    logger.info(f"Total pipelines: {len(pipelines_list)}")

    load_pipelines(neo4j_session, pipelines_list, current_aws_account_id, aws_update_tag)

    # Studio footprint: user profiles / apps / spaces link to domains (loaded above).
    user_profiles_list = []
    for region in regions:
        user_profiles_list.extend(get_user_profiles_list(boto3_session, region))

    logger.info(f"Total user profiles: {len(user_profiles_list)}")

    load_user_profiles(neo4j_session, user_profiles_list, current_aws_account_id, aws_update_tag)

    apps_list = []
    for region in regions:
        apps_list.extend(get_apps_list(boto3_session, region))

    logger.info(f"Total apps: {len(apps_list)}")

    load_apps(neo4j_session, apps_list, current_aws_account_id, aws_update_tag)

    spaces_list = []
    for region in regions:
        spaces_list.extend(get_spaces_list(boto3_session, region))

    logger.info(f"Total spaces: {len(spaces_list)}")

    load_spaces(neo4j_session, spaces_list, current_aws_account_id, aws_update_tag)

    feature_groups_list = []
    for region in regions:
        feature_groups_list.extend(get_feature_groups_list(boto3_session, region))

    logger.info(f"Total feature groups: {len(feature_groups_list)}")

    load_feature_groups(neo4j_session, feature_groups_list, current_aws_account_id, aws_update_tag)

    code_repositories_list = []
    for region in regions:
        code_repositories_list.extend(get_code_repositories_list(boto3_session, region))

    logger.info(f"Total code repositories: {len(code_repositories_list)}")

    load_code_repositories(neo4j_session, code_repositories_list, current_aws_account_id, aws_update_tag)

    images_list = []
    for region in regions:
        images_list.extend(get_images_list(boto3_session, region))

    logger.info(f"Total images: {len(images_list)}")

    load_images(neo4j_session, images_list, current_aws_account_id, aws_update_tag)

    # Monitoring schedules link to endpoints (loaded above).
    monitoring_schedules_list = []
    for region in regions:
        monitoring_schedules_list.extend(get_monitoring_schedules_list(boto3_session, region))

    logger.info(f"Total monitoring schedules: {len(monitoring_schedules_list)}")

    load_monitoring_schedules(neo4j_session, monitoring_schedules_list, current_aws_account_id, aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing Sagemaker for account '%s', at %s.", current_aws_account_id, tic)
    sync_sagemaker(neo4j_session, boto3_session, regions, current_aws_account_id, update_tag, common_job_parameters)

    cleanup_sagemaker(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Sagemaker: {toc - tic:0.4f} seconds")
