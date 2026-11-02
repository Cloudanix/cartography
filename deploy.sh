#!/usr/bin/env bash
set -e

echo "Skipping deployment since Lambda is not utilized anymore"

# rm -rf package
# mkdir -p package

# mv aws.requirements.txt requirements.txt

# pip install --no-cache-dir -r requirements.txt -t package

# cp -r cartography package/cartography/
# cp -r cloudanix package/cloudanix/
# cp -r config package/config/
# cp -r libraries package/libraries/
# cp -r utils package/utils/
# cp app.py package/
# cp requirements.txt package/

# mv requirements.txt aws.requirements.txt

# cd package

# find . -name "__pycache__" -type d -exec rm -rf {} +
# find . -name "*.pyc" -delete
# find . -name "tests" -type d -exec rm -rf {} +
# find . -name "*.dist-info" -type d -exec rm -rf {} +

# du -sh ./* | sort -hr | head

# zip -r ../function.zip .
# cd ..

# FUNCTION_NAME="cartography-service-prod-cartographyService"

# output=$(aws lambda update-function-code \
#   --function-name $FUNCTION_NAME \
#   --zip-file fileb://function.zip)

# echo $output

# sleep 15

# file_name="scripts/aws.env.prod.yml"

# CDX_APP_ENV=$(yq -r '.CDX_APP_ENV' < "$file_name")
# CDX_LOG_LEVEL=$(yq -r '.CDX_LOG_LEVEL' < "$file_name")
# CDX_SENTRY_DSN=$(yq -r '.CDX_SENTRY_DSN' < "$file_name")
# CDX_APP_NEO4J_URI=$(yq -r '.CDX_APP_NEO4J_URI' < "$file_name")
# CDX_APP_NEO4J_USER=$(yq -r '.CDX_APP_NEO4J_USER' < "$file_name")
# CDX_APP_NEO4J_PWD=$(yq -r '.CDX_APP_NEO4J_PWD' < "$file_name")
# CDX_IN_APP_NEO4J_URI=$(yq -r '.CDX_IN_APP_NEO4J_URI' < "$file_name")
# CDX_IN_APP_NEO4J_USER=$(yq -r '.CDX_IN_APP_NEO4J_USER' < "$file_name")
# CDX_IN_APP_NEO4J_PWD=$(yq -r '.CDX_IN_APP_NEO4J_PWD' < "$file_name")
# CDX_APP_NEO4J_CONNECTION_LIFETIME=$(yq -r '.CDX_APP_NEO4J_CONNECTION_LIFETIME' < "$file_name")
# AWS_STS_REGIONAL_ENDPOINTS=$(yq -r '.AWS_STS_REGIONAL_ENDPOINTS' < "$file_name")
# CDX_DEFAULT_REGION=$(yq -r '.CDX_DEFAULT_REGION' < "$file_name")
# CDX_CROSS_ACCOUNT_ROLE_ARN=$(yq -r '.CDX_CROSS_ACCOUNT_ROLE_ARN' < "$file_name")

# output=$(aws lambda update-function-configuration \
#   --function-name $FUNCTION_NAME \
#   --environment "Variables={CDX_APP_ENV=$CDX_APP_ENV,CDX_LOG_LEVEL=$CDX_LOG_LEVEL,CDX_SENTRY_DSN=$CDX_SENTRY_DSN,CDX_APP_NEO4J_URI=$CDX_APP_NEO4J_URI,CDX_APP_NEO4J_USER=$CDX_APP_NEO4J_USER,CDX_APP_NEO4J_PWD=$CDX_APP_NEO4J_PWD,CDX_IN_APP_NEO4J_URI=$CDX_IN_APP_NEO4J_URI,CDX_IN_APP_NEO4J_USER=$CDX_IN_APP_NEO4J_USER,CDX_IN_APP_NEO4J_PWD=$CDX_IN_APP_NEO4J_PWD,CDX_APP_NEO4J_CONNECTION_LIFETIME=$CDX_APP_NEO4J_CONNECTION_LIFETIME,AWS_STS_REGIONAL_ENDPOINTS=$AWS_STS_REGIONAL_ENDPOINTS,CDX_DEFAULT_REGION=$CDX_DEFAULT_REGION,CDX_CROSS_ACCOUNT_ROLE_ARN=$CDX_CROSS_ACCOUNT_ROLE_ARN")

# echo $output


# # 1. Sort versions numerically in REVERSE (newest at top)
# # 2. Use 'tail -n +6' to start reading from the 6th line onwards
# # 3. This effectively leaves the 5 newest versions alone
# versions_to_delete=$(aws lambda list-versions-by-function --function-name "$FUNCTION_NAME" \
#     --query 'Versions[?Version != `$LATEST`].Version' \
#     --output text | tr '\t' '\n' | sort -nr | tail -n +6)

# for version in $versions_to_delete; do
#     output=$(aws lambda delete-function --function-name "$FUNCTION_NAME" --qualifier "$version")
#     echo "Deleted version $version - $output"
# done
