from cartography.util import timeit
import neo4j
from cartography.config import Config
from cartography.util import run_cleanup_job

from cartography.graph.job import GraphJob
from cartography.models.aws.dynamodb.gsi import DynamoDBGSISchema
from cartography.models.aws.dynamodb.tables import DynamoDBTableSchema
from cartography.models.aws.emr import EMRClusterSchema
from cartography.models.aws.inspector.findings import AWSInspectorFindingSchema
from cartography.models.aws.inspector.packages import AWSInspectorPackageSchema
from cartography.models.aws.ssm.instance_information import SSMInstanceInformationSchema
from cartography.models.aws.ssm.instance_patch import SSMInstancePatchSchema
from cartography.models.aws.ec2.images import EC2ImageSchema
from cartography.models.aws.ec2.instances import EC2InstanceSchema
from cartography.models.aws.ec2.reservations import EC2ReservationSchema
from cartography.models.aws.ec2.keypairs import EC2KeyPairSchema
from cartography.models.aws.ec2.networkinterfaces import EC2NetworkInterfaceSchema
from cartography.models.aws.ec2.privateip_networkinterface import EC2PrivateIpNetworkInterfaceSchema
from cartography.models.aws.ec2.securitygroup_instance import EC2SecurityGroupInstanceSchema
from cartography.models.aws.ec2.subnet_instance import EC2SubnetInstanceSchema
from cartography.models.aws.ec2.volumes import EBSVolumeSchema


@timeit
def start_aws_cleanup(neo4j_session: neo4j.Session, config: Config) -> None:
    common_job_parameters = {
        "UPDATE_TAG": config.update_tag,
        "WORKSPACE_ID": config.params["workspace"]["id_string"],
        "AWS_ID": config.params["workspace"]["account_id"],
        "ORGANIZATION_ID": config.params["workspace"]["organization_id"]
    }
    run_cleanup_job('aws_import_tags_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_apigateway_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_client_certificates_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_cloudformation_stack_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_cloudfront_distributions_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_cloudtrail_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_cloudwatch_alarm_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_cloudwatch_flowlog_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_cloudwatch_log_groups_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_cloudwatch_metrics_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_cloudwatch_event_rules_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_cloudwatch_event_buses_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_ecr_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_ecs_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_eks_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_elasticache_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_es_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_users_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_groups_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_elasticsearch_reserved_instance_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_roles_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_groups_membership_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_roles_policy_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_account_access_key_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_principals_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_identitystore_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_kms_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_lambda_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_rds_clusters_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_rds_instances_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_rds_snapshots_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_rds_security_groups_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_redshift_reserved_nodes_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_redshift_clusters_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job('aws_dns_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_route53_domains_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_s3_acl_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job("aws_import_s3_buckets_cleanup.json", neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_secrets_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_securityhub_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_ses_identity_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_sns_topic_subscription_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_sns_topic_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_sqs_queues_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_waf_classic_web_acls_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_waf_v2_web_acls_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_ingest_ec2_auto_scaling_groups_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_ec2_launch_configurations_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_elastic_ip_addresses_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_ec2_launch_templates_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_internet_gateways_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_ingest_load_balancers_v2_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_ingest_load_balancers_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_reserved_instances_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_ec2_route_table_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_ec2_security_groupinfo_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_snapshots_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_tgw_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_ingest_subnets_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_vpc_peering_cleanup.json', neo4j_session, common_job_parameters)

    run_cleanup_job('aws_import_vpc_cleanup.json', neo4j_session, common_job_parameters)

    GraphJob.from_node_schema(EBSVolumeSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(EC2SubnetInstanceSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(DynamoDBTableSchema(), common_job_parameters).run(neo4j_session)
    GraphJob.from_node_schema(DynamoDBGSISchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(EMRClusterSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(AWSInspectorFindingSchema(), common_job_parameters).run(neo4j_session)
    GraphJob.from_node_schema(AWSInspectorPackageSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(SSMInstanceInformationSchema(), common_job_parameters).run(neo4j_session)
    GraphJob.from_node_schema(SSMInstancePatchSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(EC2ImageSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(EC2ReservationSchema(), common_job_parameters).run(neo4j_session)
    GraphJob.from_node_schema(EC2InstanceSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(EC2KeyPairSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(EC2NetworkInterfaceSchema(), common_job_parameters).run(neo4j_session)
    GraphJob.from_node_schema(EC2PrivateIpNetworkInterfaceSchema(), common_job_parameters).run(neo4j_session)

    GraphJob.from_node_schema(EC2SecurityGroupInstanceSchema(), common_job_parameters).run(neo4j_session)

    run_cleanup_job('aws_account_cleanup.json', neo4j_session, common_job_parameters)
