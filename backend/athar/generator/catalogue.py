"""Permission catalogue and tunables for the estate simulator (SPEC §4.1–§4.3, §5.3).

A `GrantTemplate` is something the simulator can grant in native terms (an AWS managed
policy, an inline statement, an Azure role at a scope, a GCP role on a project). Each
template also records the simulator's OWN reading of the power it confers (`verbs`,
`category`, scope). That reading feeds `ground_truth.py` only — it is what the simulator
did, not a second detector — and it follows the SPEC §5.3 mapping table so the ground
truth agrees with the normaliser by construction (prefix wildcards such as `s3:*` expand
to every verb on that category; `*` is a full wildcard).

Tunables at the bottom are frozen once `tests/generator/test_estate_shape.py` passes for
the default seed (SPEC §4.1).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from athar.domain import VERBS

ALL_VERBS: tuple[str, ...] = VERBS
RWD: tuple[str, ...] = ("read", "write", "delete")
READ: tuple[str, ...] = ("read",)

# The tables below are hand-aligned so they read as tables; `ruff format` would put one entry
# per line and make them unreadable.
# fmt: off
LEVELS: tuple[str, ...] = ("member", "senior", "lead")

# scope tokens → SPEC §5.2 scope level
SCOPE_LEVEL: dict[str, str] = {
    "*": "global",
    "res": "resource",
    "mg": "org",
    "sub": "project",
    "rg": "resource",
    "project": "project",
}


@dataclass(frozen=True)
class GrantTemplate:
    cloud: str
    kind: str  # aws_managed | aws_inline | aws_group | azure_role | gcp_role
    name: str  # policy / role / group name
    scope: str  # aws: "*" | "res:bucket" | "res:table" | "res:function"; azure: mg | sub | rg; gcp: project
    category: str  # SPEC §5.2 category or "*"
    verbs: tuple[str, ...]
    services: tuple[str, ...]  # activity keys: AWS namespaces / Azure resource providers / "-" for GCP
    actions: tuple[str, ...] = ()  # AWS inline actions
    wildcard: bool = False  # unexpanded full wildcard `*` (R1 evidence)
    unmapped: bool = False  # carries an action/role no mapping table knows (R0 bait)
    effect: str = "allow"  # SPEC §5.2 `effect`; `deny` carves scope out of a standing allow

    @property
    def scope_level(self) -> str:
        return SCOPE_LEVEL[self.scope.split(":")[0]]


def _aws_managed(name: str, category: str, verbs: tuple[str, ...], services: tuple[str, ...], **kw: Any) -> GrantTemplate:
    return GrantTemplate("aws", "aws_managed", name, "*", category, verbs, services, **kw)


def _aws_inline(
    name: str, scope: str, category: str, verbs: tuple[str, ...], services: tuple[str, ...], actions: tuple[str, ...], **kw: Any
) -> GrantTemplate:
    return GrantTemplate("aws", "aws_inline", name, scope, category, verbs, services, actions, **kw)


def _az(role: str, scope: str, category: str, verbs: tuple[str, ...], services: tuple[str, ...], **kw: Any) -> GrantTemplate:
    return GrantTemplate("azure", "azure_role", role, scope, category, verbs, services, **kw)


def _gcp(role: str, category: str, verbs: tuple[str, ...], **kw: Any) -> GrantTemplate:
    return GrantTemplate("gcp", "gcp_role", role, "project", category, verbs, ("-",), **kw)


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

AWS_READONLY = _aws_managed("ReadOnlyAccess", "*", READ, ("s3", "ec2", "iam"))
AWS_POWERUSER = _aws_managed("PowerUserAccess", "*", RWD, ("ec2", "s3", "lambda", "dynamodb"))
AWS_ADMIN = _aws_managed("AdministratorAccess", "*", ALL_VERBS, ("iam", "ec2", "s3"), wildcard=True)
AWS_IAM_FULL = _aws_managed("IAMFullAccess", "identity", ("admin", "grant", "impersonate"), ("iam",))
AWS_SECURITY_AUDIT = _aws_managed("SecurityAudit", "security", READ, ("iam", "kms", "guardduty", "cloudtrail"))
AWS_S3_READ = _aws_managed("AmazonS3ReadOnlyAccess", "storage", READ, ("s3",))
AWS_BILLING = _aws_managed("Billing", "billing", ("billing",), ("ce", "aws-portal"))
AWS_NDA_BILLING_RO = _aws_managed("NdaBillingReadOnly", "billing", READ, ("ce",), unmapped=True)

#: The citizen-data guardrail (SPEC §5.2 `effect`). A customer-managed policy holding a single
#: explicit Deny over the citizen data lake, attached to a couple of Data Services accounts whose
#: role baseline still carries `citizen-data-lake` (`s3:*` on the same bucket). Nobody removed the
#: allow; a deny was bolted on instead — the drift story ATHAR tells, and the only way the `deny`
#: half of the `effect` dimension is exercised outside unit tests. `granted_via` is
#: `managed_policy:<name>`, which keeps the deny row's natural key (SPEC §5.1) clear of the inline
#: allow it cancels. The name is deliberately absent from `normaliser/mappings/aws.yaml`: the
#: parser resolves it through the `Policies` array, so the document — not a mapping entry — decides.
AWS_CITIZEN_DENY_POLICY = "NdaCitizenDataGuardrail"
AWS_CITIZEN_DENY = GrantTemplate(
    "aws", "aws_managed", AWS_CITIZEN_DENY_POLICY, "res:citizen", "storage", ALL_VERBS, ("s3",),
    ("s3:*",), effect="deny",
)

AWS_CUSTOMER_MANAGED: frozenset[str] = frozenset({"NdaBillingReadOnly", AWS_CITIZEN_DENY_POLICY})


def citizen_deny_statements(bucket_ref: str) -> list[dict[str, Any]]:
    """The guardrail's policy document: one explicit Deny over the citizen bucket and its objects.

    Built from the bucket ARN the grant itself names rather than a literal, so the document and the
    canonical row can never disagree about what is denied. This is what makes the row come back
    from the normaliser as `effect=deny`: AWS states the effect in the policy document, so a
    guardrail attached without its document parses as an ordinary allow.
    """
    # A grant's scope_ref may already carry the object wildcard. Normalise to the bucket so the
    # pair below reads exactly like the `citizen-data-lake` allow this deny is bolted over --
    # AWS scopes bucket operations and object operations with two different ARNs.
    bucket = bucket_ref[: -len("/*")] if bucket_ref.endswith("/*") else bucket_ref
    return [
        {
            "Sid": "DenyCitizenDataLake",
            "Effect": "Deny",
            "Action": "s3:*",
            "Resource": [bucket, f"{bucket}/*"],
        }
    ]

AWS_S3_RW = _aws_inline(
    "s3-data-readwrite", "res:bucket", "storage", RWD, ("s3",),
    ("s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"),
)
AWS_S3_STAR = _aws_inline("s3-bucket-full", "res:bucket", "storage", ALL_VERBS, ("s3",), ("s3:*",))
AWS_DATA_LAKE = _aws_inline("citizen-data-lake", "res:citizen", "storage", ALL_VERBS, ("s3",), ("s3:*",))
AWS_DDB_RW = _aws_inline(
    "dynamodb-readwrite", "res:table", "data", RWD, ("dynamodb",),
    ("dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"),
)
AWS_DDB_READ = _aws_inline(
    "dynamodb-readonly", "res:table", "data", READ, ("dynamodb",),
    ("dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:DescribeTable"),
)
AWS_LAMBDA_DEPLOY = _aws_inline(
    "lambda-deploy", "res:function", "compute", ("read", "write", "delete"), ("lambda",),
    ("lambda:CreateFunction", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:InvokeFunction", "lambda:DeleteFunction", "lambda:GetFunction"),
)
AWS_LAMBDA_INVOKE = _aws_inline(
    "lambda-invoke", "res:function", "compute", ("read", "write"), ("lambda",),
    ("lambda:InvokeFunction", "lambda:GetFunction", "lambda:ListFunctions"),
)
AWS_EC2_OPS = _aws_inline(
    "ec2-operations", "*", "compute", RWD, ("ec2",),
    ("ec2:RunInstances", "ec2:StartInstances", "ec2:StopInstances", "ec2:TerminateInstances", "ec2:DescribeInstances", "ec2:CreateTags"),
)
AWS_IAM_ROLE_MANAGER = _aws_inline(
    "iam-role-manager", "*", "identity", ("read", "write", "grant", "impersonate"), ("iam",),
    ("iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:PassRole", "iam:GetRole", "iam:ListRoles"),
)
AWS_SEC_OPS = _aws_inline(
    "security-operations", "*", "security", ("read", "write"), ("kms", "guardduty"),
    ("kms:CreateKey", "kms:EnableKeyRotation", "kms:DescribeKey", "guardduty:CreateDetector", "guardduty:GetFindings", "securityhub:BatchUpdateFindings"),
)
AWS_SA_SCOPED_S3 = _aws_inline("service-account-s3", "res:bucket", "storage", ALL_VERBS, ("s3",), ("s3:*",))
AWS_SA_SCOPED_DDB = _aws_inline("service-account-dynamodb", "res:table", "data", ALL_VERBS, ("dynamodb",), ("dynamodb:*",))
AWS_SA_BROAD = _aws_inline(
    "service-account-broad", "*", "*", ALL_VERBS, ("s3", "dynamodb", "sqs", "iam"),
    ("s3:*", "dynamodb:*", "sqs:*", "iam:PassRole"),
)
AWS_IAM_STAR = _aws_inline(
    "iam-admin-legacy", "*", "identity", ("admin", "grant", "impersonate"), ("iam",), ("iam:*",), wildcard=True
)
AWS_EMERGENCY_ADMIN = _aws_inline(
    "emergency-admin", "*", "*", ALL_VERBS, ("iam", "ec2", "s3"), ("*",), wildcard=True
)
AWS_DR_FAILOVER = _aws_inline(
    "dr-failover-runbook", "*", "compute", ("read", "write"), ("ec2", "rds", "route53", "s3"),
    ("ec2:RunInstances", "ec2:StartInstances", "ec2:StopInstances", "rds:RestoreDBInstanceFromDBSnapshot", "rds:PromoteReadReplica", "route53:ChangeResourceRecordSets", "s3:GetObject", "s3:PutObject"),
)


def aws_group_template(slug: str) -> GrantTemplate:
    """Department group membership; the group itself carries ReadOnlyAccess + a read statement."""
    return GrantTemplate("aws", "aws_group", f"grp-{slug}", "*", "*", READ, ("s3", "ec2", "iam"))


def aws_group_read_inline(slug: str) -> GrantTemplate:
    return _aws_inline(f"nda-{slug}-read", "res:bucket", "storage", READ, ("s3",), ("s3:GetObject", "s3:ListBucket"))


AWS_SERVICE_NAMES: dict[str, str] = {
    "s3": "Amazon S3",
    "ec2": "Amazon EC2",
    "iam": "AWS Identity and Access Management (IAM)",
    "lambda": "AWS Lambda",
    "dynamodb": "Amazon DynamoDB",
    "kms": "AWS Key Management Service",
    "guardduty": "Amazon GuardDuty",
    "cloudtrail": "AWS CloudTrail",
    "ce": "AWS Cost Explorer Service",
    "aws-portal": "AWS Billing",
    "sqs": "Amazon SQS",
    "rds": "Amazon RDS",
    "route53": "Amazon Route 53",
    "sts": "AWS Security Token Service",
}

# Managed policy documents: representative statements of the real policies (SPEC §4.6 filler).
AWS_MANAGED_POLICY_DOCUMENTS: dict[str, list[dict[str, Any]]] = {
    "AdministratorAccess": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    "PowerUserAccess": [
        {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole", "iam:ListRoles",
                "organizations:DescribeOrganization", "account:ListRegions", "account:GetAccountInformation",
            ],
            "Resource": "*",
        },
    ],
    "ReadOnlyAccess": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:Get*", "s3:List*", "ec2:Describe*", "iam:Get*", "iam:List*", "lambda:Get*", "lambda:List*",
                "dynamodb:Describe*", "dynamodb:List*", "dynamodb:Get*", "dynamodb:Query", "dynamodb:Scan",
                "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*", "logs:Describe*", "logs:Get*",
                "kms:Describe*", "kms:List*", "rds:Describe*", "sqs:Get*", "sqs:List*",
            ],
            "Resource": "*",
        }
    ],
    "IAMFullAccess": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:*", "organizations:DescribeAccount", "organizations:DescribeOrganization",
                "organizations:DescribeOrganizationalUnit", "organizations:DescribePolicy",
                "organizations:ListChildren", "organizations:ListParents", "organizations:ListPoliciesForTarget",
                "organizations:ListRoots", "organizations:ListPolicies", "organizations:ListTargetsForPolicy",
            ],
            "Resource": "*",
        }
    ],
    "SecurityAudit": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GenerateCredentialReport", "iam:GenerateServiceLastAccessedDetails", "iam:Get*", "iam:List*",
                "s3:GetBucketPolicy", "s3:GetBucketAcl", "s3:GetBucketPublicAccessBlock", "s3:ListAllMyBuckets",
                "ec2:Describe*", "kms:Describe*", "kms:List*", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus",
                "guardduty:Get*", "guardduty:List*", "cloudtrail:Describe*", "cloudtrail:GetTrailStatus",
                "cloudtrail:GetEventSelectors", "config:Describe*", "config:Get*", "securityhub:Get*",
            ],
            "Resource": "*",
        }
    ],
    "AmazonS3ReadOnlyAccess": [
        {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "s3:Describe*", "s3-object-lambda:Get*", "s3-object-lambda:List*"], "Resource": "*"}
    ],
    "Billing": [
        {
            "Effect": "Allow",
            "Action": [
                "aws-portal:ViewBilling", "aws-portal:ViewUsage", "aws-portal:ViewPaymentMethods",
                "aws-portal:ModifyBilling", "budgets:ViewBudget", "budgets:ModifyBudget",
                "ce:GetCostAndUsage", "ce:GetCostForecast", "ce:CreateReport", "ce:UpdateReport",
                "cur:DescribeReportDefinitions", "cur:PutReportDefinition", "purchase-orders:ViewPurchaseOrders",
                "tax:GetTaxRegistration",
            ],
            "Resource": "*",
        }
    ],
    "NdaBillingReadOnly": [
        {
            "Effect": "Allow",
            "Action": [
                "ce:GetCostAndUsage", "ce:GetCostForecast", "ce:GetDimensionValues", "budgets:ViewBudget",
                "aws-portal:ViewBilling", "wellarchitected:ListWorkloads", "wellarchitected:GetWorkload",
            ],
            "Resource": "*",
        }
    ],
}

# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AzureRoleDefinition:
    name: str
    guid: str  # (verify) built-in GUIDs are Microsoft's published values; custom ones come from the seeded RNG
    description: str
    actions: tuple[str, ...]
    not_actions: tuple[str, ...] = ()
    data_actions: tuple[str, ...] = ()
    custom: bool = False


AZURE_ROLE_DEFINITIONS: dict[str, AzureRoleDefinition] = {
    d.name: d
    for d in (
        AzureRoleDefinition(
            "Owner", "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
            "Grants full access to manage all resources, including the ability to assign roles in Azure RBAC.",
            ("*",),
        ),
        AzureRoleDefinition(
            "Contributor", "b24988ac-6180-42a0-ab88-20f7382dd24c",
            "Grants full access to manage all resources, but does not allow you to assign roles in Azure RBAC.",
            ("*",),
            ("Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/elevateAccess/Action", "Microsoft.Blueprint/blueprintAssignments/write", "Microsoft.Blueprint/blueprintAssignments/delete"),
        ),
        AzureRoleDefinition(
            "Reader", "acdd72a7-3385-48ef-bd42-f606fba81ae7",
            "View all resources, but does not allow you to make any changes.",
            ("*/read",),
        ),
        AzureRoleDefinition(
            "User Access Administrator", "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
            "Lets you manage user access to Azure resources.",
            ("*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"),
        ),
        AzureRoleDefinition(
            "Storage Blob Data Contributor", "ba92f5b4-2d11-453d-a403-e96b0029c9fe",
            "Allows for read, write and delete access to Azure Storage blob containers and data.",
            ("Microsoft.Storage/storageAccounts/blobServices/containers/delete", "Microsoft.Storage/storageAccounts/blobServices/containers/read", "Microsoft.Storage/storageAccounts/blobServices/containers/write", "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"),
            (),
            ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action", "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action"),
        ),
        AzureRoleDefinition(
            "Storage Blob Data Reader", "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
            "Allows for read access to Azure Storage blob containers and data.",
            ("Microsoft.Storage/storageAccounts/blobServices/containers/read", "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action"),
            (),
            ("Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",),
        ),
        AzureRoleDefinition(
            "Security Reader", "39bc4728-0917-49c7-9d2c-d95423bc2eb4",
            "View permissions for Microsoft Defender for Cloud.",
            ("Microsoft.Authorization/*/read", "Microsoft.Insights/alertRules/read", "Microsoft.operationalInsights/workspaces/*/read", "Microsoft.Resources/deployments/*/read", "Microsoft.Resources/subscriptions/resourceGroups/read", "Microsoft.Security/*/read", "Microsoft.Support/*/read"),
        ),
        AzureRoleDefinition(
            "Billing Reader", "fa23ad8b-c56e-40d8-ac0c-ce449e1d2c64",
            "Allows read access to billing data.",
            ("Microsoft.Authorization/*/read", "Microsoft.Billing/*/read", "Microsoft.Commerce/*/read", "Microsoft.Consumption/*/read", "Microsoft.Management/managementGroups/read", "Microsoft.CostManagement/*/read", "Microsoft.Support/*"),
        ),
        AzureRoleDefinition(
            "Key Vault Secrets Officer", "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",
            "Perform any action on the secrets of a key vault, except manage permissions.",
            ("Microsoft.Authorization/*/read", "Microsoft.Resources/deployments/*", "Microsoft.Resources/subscriptions/resourceGroups/read", "Microsoft.KeyVault/checkNameAvailability/read", "Microsoft.KeyVault/vaults/read"),
            (),
            ("Microsoft.KeyVault/vaults/secrets/*",),
        ),
        AzureRoleDefinition(
            "Virtual Machine Contributor", "9980e02c-c2be-4d73-94e8-173b1dc7cf3c",
            "Lets you manage virtual machines, but not access to them, and not the virtual network or storage account they're connected to.",
            ("Microsoft.Authorization/*/read", "Microsoft.Compute/availabilitySets/*", "Microsoft.Compute/locations/*", "Microsoft.Compute/virtualMachines/*", "Microsoft.Compute/virtualMachineScaleSets/*", "Microsoft.Compute/disks/write", "Microsoft.Compute/disks/read", "Microsoft.Compute/disks/delete", "Microsoft.Network/networkInterfaces/*", "Microsoft.Resources/deployments/*", "Microsoft.Resources/subscriptions/resourceGroups/read", "Microsoft.Storage/storageAccounts/listKeys/action", "Microsoft.Storage/storageAccounts/read"),
        ),
        AzureRoleDefinition(
            "SQL DB Contributor", "9b7fa17d-e63e-47b0-bb0a-15c516ac86ec",
            "Lets you manage SQL databases, but not access to them.",
            ("Microsoft.Authorization/*/read", "Microsoft.Insights/alertRules/*", "Microsoft.Resources/deployments/*", "Microsoft.Resources/subscriptions/resourceGroups/read", "Microsoft.Sql/locations/*/read", "Microsoft.Sql/servers/databases/*", "Microsoft.Sql/servers/read", "Microsoft.Support/*"),
            ("Microsoft.Sql/managedInstances/databases/currentSensitivityLabels/*", "Microsoft.Sql/servers/databases/auditingSettings/*", "Microsoft.Sql/servers/databases/securityAlertPolicies/*"),
        ),
        AzureRoleDefinition(
            "CustomBillingReader", "",  # GUID assigned from the seeded RNG at write time
            "NDA custom role: read cost exports and billing account scopes for the finance close.",
            ("Microsoft.Billing/billingAccounts/read", "Microsoft.Consumption/*/read", "Microsoft.CostManagement/exports/read", "Microsoft.Advisor/recommendations/read"),
            custom=True,
        ),
        AzureRoleDefinition(
            "NDA Role Definition Author", "",
            "NDA custom role: author custom role definitions for platform landing zones.",
            ("Microsoft.Authorization/roleDefinitions/read", "Microsoft.Authorization/roleDefinitions/write", "Microsoft.Authorization/roleAssignments/read", "Microsoft.Resources/subscriptions/resourceGroups/read"),
            custom=True,
        ),
    )
}

AZ_OWNER_SUB = _az("Owner", "sub", "*", ALL_VERBS, ("Microsoft.Resources", "Microsoft.Authorization", "Microsoft.Compute"))
AZ_OWNER_MG = _az("Owner", "mg", "*", ALL_VERBS, ("Microsoft.Resources", "Microsoft.Authorization"))
AZ_OWNER_RG = _az("Owner", "rg", "*", ALL_VERBS, ("Microsoft.Resources", "Microsoft.Authorization"))
AZ_CONTRIB_SUB = _az("Contributor", "sub", "*", RWD, ("Microsoft.Resources", "Microsoft.Compute", "Microsoft.Storage"))
AZ_CONTRIB_RG = _az("Contributor", "rg", "*", RWD, ("Microsoft.Resources", "Microsoft.Storage"))
AZ_READER_SUB = _az("Reader", "sub", "*", READ, ("Microsoft.Resources",))
AZ_READER_RG = _az("Reader", "rg", "*", READ, ("Microsoft.Resources",))
AZ_UAA_SUB = _az("User Access Administrator", "sub", "identity", ("read", "grant"), ("Microsoft.Authorization",))
AZ_BLOB_CONTRIB_RG = _az("Storage Blob Data Contributor", "rg", "storage", RWD, ("Microsoft.Storage",))
AZ_BLOB_READER_RG = _az("Storage Blob Data Reader", "rg", "storage", READ, ("Microsoft.Storage",))
AZ_SECURITY_READER_SUB = _az("Security Reader", "sub", "security", READ, ("Microsoft.Security",))
AZ_BILLING_READER_SUB = _az("Billing Reader", "sub", "billing", ("billing",), ("Microsoft.Billing", "Microsoft.CostManagement"))
AZ_KV_SECRETS_OFFICER_RG = _az("Key Vault Secrets Officer", "rg", "security", ("read", "write", "delete"), ("Microsoft.KeyVault",))
AZ_VM_CONTRIB_RG = _az("Virtual Machine Contributor", "rg", "compute", RWD, ("Microsoft.Compute",))
AZ_SQL_CONTRIB_RG = _az("SQL DB Contributor", "rg", "data", RWD, ("Microsoft.Sql",))
AZ_CUSTOM_BILLING_SUB = _az("CustomBillingReader", "sub", "billing", READ, ("Microsoft.CostManagement",), unmapped=True)
AZ_ROLE_DEF_AUTHOR_SUB = _az("NDA Role Definition Author", "sub", "identity", ("read", "write"), ("Microsoft.Authorization",))

# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------

GCP_CUSTOM_BILLING_ROLE = "organizations/{org}/roles/CustomBillingReader"

GCP_OWNER = _gcp("roles/owner", "*", ALL_VERBS)
GCP_EDITOR = _gcp("roles/editor", "*", RWD)
GCP_VIEWER = _gcp("roles/viewer", "*", READ)
GCP_BQ_EDITOR = _gcp("roles/bigquery.dataEditor", "data", ("read", "write", "delete"))
GCP_BQ_VIEWER = _gcp("roles/bigquery.dataViewer", "data", READ)
GCP_STORAGE_ADMIN = _gcp("roles/storage.objectAdmin", "storage", RWD)
GCP_STORAGE_VIEWER = _gcp("roles/storage.objectViewer", "storage", READ)
GCP_SA_USER = _gcp("roles/iam.serviceAccountUser", "identity", ("impersonate",))
GCP_SA_ADMIN = _gcp("roles/iam.serviceAccountAdmin", "identity", ("write", "delete", "grant"))
GCP_PROJECT_IAM_ADMIN = _gcp("roles/resourcemanager.projectIamAdmin", "identity", ("read", "grant"))
GCP_SECURITY_REVIEWER = _gcp("roles/iam.securityReviewer", "security", READ)
GCP_COMPUTE_INSTANCE_ADMIN = _gcp("roles/compute.instanceAdmin.v1", "compute", RWD)
GCP_LOGGING_VIEWER = _gcp("roles/logging.viewer", "security", READ)
GCP_CUSTOM_BILLING = _gcp(GCP_CUSTOM_BILLING_ROLE, "billing", (), unmapped=True)

# role → (title, permission count) for IAM Recommender-style `totalPermissionsCount` filler
GCP_ROLE_INFO: dict[str, tuple[str, int]] = {
    "roles/owner": ("Owner", 9800),
    "roles/editor": ("Editor", 8300),
    "roles/viewer": ("Viewer", 3900),
    "roles/bigquery.dataEditor": ("BigQuery Data Editor", 27),
    "roles/bigquery.dataViewer": ("BigQuery Data Viewer", 18),
    "roles/storage.objectAdmin": ("Storage Object Admin", 21),
    "roles/storage.objectViewer": ("Storage Object Viewer", 6),
    "roles/iam.serviceAccountUser": ("Service Account User", 5),
    "roles/iam.serviceAccountAdmin": ("Service Account Admin", 15),
    "roles/resourcemanager.projectIamAdmin": ("Project IAM Admin", 6),
    "roles/iam.securityReviewer": ("Security Reviewer", 230),
    "roles/compute.instanceAdmin.v1": ("Compute Instance Admin (v1)", 310),
    "roles/logging.viewer": ("Logs Viewer", 12),
    GCP_CUSTOM_BILLING_ROLE: ("NDA Custom Billing Reader", 4),
}

# ---------------------------------------------------------------------------
# Regions (SPEC §4.1; APPROVED_REGIONS in config.py)
# ---------------------------------------------------------------------------

HOME_REGION: dict[str, str] = {"aws": "me-central-1", "azure": "uaenorth", "gcp": "me-central1"}
SECONDARY_REGION: dict[str, str] = {"aws": "me-central-1", "azure": "uaecentral", "gcp": "me-central1"}
DRIFT_REGIONS: dict[str, tuple[str, ...]] = {
    "aws": ("eu-west-1", "us-east-1"),
    "azure": ("westeurope", "eastus"),
    "gcp": ("europe-west1", "us-central1"),
}

# ---------------------------------------------------------------------------
# Departments: hiring weights, cloud footprints, home projects
# ---------------------------------------------------------------------------

DEPARTMENT_WEIGHTS: tuple[tuple[str, float], ...] = (
    ("Finance", 0.12),
    ("HR", 0.08),
    ("Platform Engineering", 0.18),
    ("Data Services", 0.15),
    ("Smart Services", 0.16),
    ("Cyber Security", 0.10),
    ("Field Operations", 0.11),
    ("Contractors", 0.10),
)

LEVEL_WEIGHTS: tuple[tuple[str, float], ...] = (("member", 0.70), ("senior", 0.22), ("lead", 0.08))

CloudSet = tuple[str, ...]
DEPARTMENT_CLOUDS: dict[str, tuple[tuple[CloudSet, float], ...]] = {
    "Finance": ((("azure",), 0.5), (("aws",), 0.1), (("aws", "azure"), 0.25), (("azure", "gcp"), 0.1), (("aws", "azure", "gcp"), 0.05)),
    "HR": ((("azure",), 0.7), (("aws", "azure"), 0.2), (("azure", "gcp"), 0.1)),
    "Platform Engineering": ((("aws",), 0.1), (("aws", "azure"), 0.35), (("aws", "gcp"), 0.35), (("aws", "azure", "gcp"), 0.2)),
    "Data Services": ((("gcp",), 0.3), (("aws", "gcp"), 0.25), (("aws",), 0.05), (("azure", "gcp"), 0.25), (("aws", "azure", "gcp"), 0.15)),
    "Smart Services": ((("aws",), 0.25), (("aws", "azure"), 0.45), (("azure",), 0.05), (("aws", "gcp"), 0.2), (("aws", "azure", "gcp"), 0.05)),
    "Cyber Security": ((("aws", "azure"), 0.4), (("aws", "azure", "gcp"), 0.25), (("aws",), 0.1), (("azure",), 0.1), (("aws", "gcp"), 0.15)),
    "Field Operations": ((("aws",), 0.6), (("aws", "azure"), 0.3), (("aws", "gcp"), 0.1)),
    "Contractors": ((("aws",), 0.35), (("azure",), 0.35), (("gcp",), 0.3)),
}

# Department home projects (one per cloud; protected — never retired)
DEPARTMENT_HOME_CLOUDS: dict[str, tuple[str, ...]] = {
    "Finance": ("azure", "aws"),
    "HR": ("azure", "aws"),
    "Platform Engineering": ("aws", "azure", "gcp"),
    "Data Services": ("gcp", "aws", "azure"),
    "Smart Services": ("aws", "azure", "gcp"),
    "Cyber Security": ("aws", "azure", "gcp"),
    "Field Operations": ("aws", "azure"),
    "Contractors": (),
}

HIGH_SENSITIVITY_DEPARTMENTS: frozenset[str] = frozenset({"Finance", "HR", "Data Services", "Smart Services"})

# ---------------------------------------------------------------------------
# Roles: (department, level) → cloud → templates. `GROUP` is replaced per department.
# ---------------------------------------------------------------------------

GROUP = GrantTemplate("aws", "aws_group", "GROUP", "*", "*", READ, ("s3", "ec2", "iam"))

ROLES: dict[tuple[str, str], dict[str, tuple[GrantTemplate, ...]]] = {
    ("Finance", "member"): {"aws": (GROUP, AWS_BILLING), "azure": (AZ_READER_RG, AZ_BILLING_READER_SUB), "gcp": (GCP_VIEWER,)},
    ("Finance", "senior"): {"aws": (GROUP, AWS_BILLING, AWS_S3_RW), "azure": (AZ_CONTRIB_RG, AZ_BILLING_READER_SUB), "gcp": (GCP_BQ_VIEWER,)},
    ("Finance", "lead"): {
        "aws": (GROUP, AWS_BILLING, AWS_NDA_BILLING_RO, AWS_S3_RW),
        "azure": (AZ_CONTRIB_RG, AZ_READER_SUB, AZ_CUSTOM_BILLING_SUB),
        "gcp": (GCP_BQ_EDITOR, GCP_CUSTOM_BILLING),
    },
    ("HR", "member"): {"aws": (GROUP,), "azure": (AZ_READER_RG,)},
    ("HR", "senior"): {"aws": (GROUP, AWS_S3_RW), "azure": (AZ_CONTRIB_RG, AZ_BLOB_CONTRIB_RG)},
    ("HR", "lead"): {"aws": (GROUP, AWS_S3_RW, AWS_DDB_RW), "azure": (AZ_CONTRIB_RG, AZ_SQL_CONTRIB_RG)},
    ("Platform Engineering", "member"): {
        "aws": (GROUP, AWS_EC2_OPS, AWS_LAMBDA_DEPLOY),
        "azure": (AZ_CONTRIB_RG, AZ_VM_CONTRIB_RG),
        "gcp": (GCP_COMPUTE_INSTANCE_ADMIN, GCP_LOGGING_VIEWER),
    },
    ("Platform Engineering", "senior"): {"aws": (GROUP, AWS_POWERUSER), "azure": (AZ_CONTRIB_SUB,), "gcp": (GCP_EDITOR,)},
    ("Platform Engineering", "lead"): {
        "aws": (GROUP, AWS_POWERUSER, AWS_IAM_ROLE_MANAGER),
        "azure": (AZ_CONTRIB_SUB, AZ_UAA_SUB, AZ_ROLE_DEF_AUTHOR_SUB),
        "gcp": (GCP_EDITOR, GCP_PROJECT_IAM_ADMIN, GCP_SA_ADMIN),
    },
    ("Data Services", "member"): {"aws": (GROUP, AWS_S3_READ), "azure": (AZ_READER_RG, AZ_BLOB_READER_RG), "gcp": (GCP_BQ_VIEWER, GCP_STORAGE_VIEWER)},
    ("Data Services", "senior"): {"aws": (GROUP, AWS_DATA_LAKE), "azure": (AZ_BLOB_CONTRIB_RG,), "gcp": (GCP_BQ_EDITOR, GCP_STORAGE_ADMIN)},
    ("Data Services", "lead"): {"aws": (GROUP, AWS_POWERUSER), "azure": (AZ_CONTRIB_RG,), "gcp": (GCP_EDITOR, GCP_SA_USER)},
    ("Smart Services", "member"): {"aws": (GROUP, AWS_DDB_READ, AWS_LAMBDA_INVOKE), "azure": (AZ_READER_RG,), "gcp": (GCP_VIEWER,)},
    ("Smart Services", "senior"): {"aws": (GROUP, AWS_LAMBDA_DEPLOY, AWS_DDB_RW), "azure": (AZ_CONTRIB_RG,), "gcp": (GCP_VIEWER,)},
    ("Smart Services", "lead"): {"aws": (GROUP, AWS_POWERUSER), "azure": (AZ_CONTRIB_SUB,), "gcp": (GCP_EDITOR,)},
    ("Cyber Security", "member"): {"aws": (GROUP, AWS_SECURITY_AUDIT), "azure": (AZ_SECURITY_READER_SUB,), "gcp": (GCP_SECURITY_REVIEWER,)},
    ("Cyber Security", "senior"): {
        "aws": (GROUP, AWS_SECURITY_AUDIT, AWS_SEC_OPS),
        "azure": (AZ_SECURITY_READER_SUB, AZ_KV_SECRETS_OFFICER_RG),
        "gcp": (GCP_SECURITY_REVIEWER, GCP_LOGGING_VIEWER),
    },
    ("Cyber Security", "lead"): {
        "aws": (GROUP, AWS_SECURITY_AUDIT, AWS_IAM_STAR),
        "azure": (AZ_SECURITY_READER_SUB, AZ_UAA_SUB),
        "gcp": (GCP_SECURITY_REVIEWER, GCP_PROJECT_IAM_ADMIN),
    },
    ("Field Operations", "member"): {"aws": (GROUP, AWS_DDB_READ), "azure": (AZ_READER_RG,)},
    ("Field Operations", "senior"): {"aws": (GROUP, AWS_S3_RW, AWS_DDB_RW), "azure": (AZ_READER_RG,)},
    ("Field Operations", "lead"): {"aws": (GROUP, AWS_S3_RW, AWS_DDB_RW, AWS_LAMBDA_INVOKE), "azure": (AZ_CONTRIB_RG,)},
    ("Contractors", "member"): {"aws": (AWS_S3_RW, AWS_LAMBDA_DEPLOY), "azure": (AZ_CONTRIB_RG,), "gcp": (GCP_EDITOR,)},
    ("Contractors", "senior"): {"aws": (AWS_S3_STAR, AWS_DDB_RW, AWS_LAMBDA_DEPLOY), "azure": (AZ_CONTRIB_RG, AZ_BLOB_CONTRIB_RG), "gcp": (GCP_EDITOR, GCP_STORAGE_ADMIN)},
    ("Contractors", "lead"): {"aws": (AWS_S3_STAR, AWS_DDB_RW, AWS_LAMBDA_DEPLOY), "azure": (AZ_CONTRIB_RG, AZ_BLOB_CONTRIB_RG), "gcp": (GCP_EDITOR, GCP_STORAGE_ADMIN)},
}

SERVICE_ACCOUNT_TEMPLATES: dict[str, dict[str, tuple[GrantTemplate, ...]]] = {
    "aws": {"scoped": (AWS_SA_SCOPED_S3, AWS_SA_SCOPED_DDB), "broad": (AWS_SA_BROAD,), "dr": (AWS_DR_FAILOVER,)},
    "azure": {"scoped": (AZ_CONTRIB_RG,), "broad": (AZ_OWNER_SUB,), "dr": (AZ_CONTRIB_SUB,)},
    "gcp": {"scoped": (GCP_EDITOR,), "broad": (GCP_OWNER,), "dr": (GCP_EDITOR,)},
}

INCIDENT_ADMIN: dict[str, GrantTemplate] = {"aws": AWS_EMERGENCY_ADMIN, "azure": AZ_OWNER_SUB, "gcp": GCP_OWNER}
BREAK_GLASS: dict[str, GrantTemplate] = {"aws": AWS_ADMIN, "azure": AZ_OWNER_MG}
SANCTIONED_ADMIN: dict[str, GrantTemplate] = {"azure": AZ_OWNER_SUB, "gcp": GCP_OWNER}
REGION_DRIFT_GRANT: dict[str, GrantTemplate] = {
    "aws": _aws_inline("regional-replica-access", "res:table", "data", RWD, ("dynamodb",), ("dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:DeleteItem")),
    "azure": AZ_CONTRIB_RG,
    "gcp": GCP_EDITOR,
}

# ---------------------------------------------------------------------------
# Tunables (SPEC §4.2 rates; secondary probabilities tuned on seed 42 then frozen)
# ---------------------------------------------------------------------------

EVENT_RATES: tuple[tuple[str, float], ...] = (
    ("new_hire", 8.0),
    ("role_change", 5.0),
    ("departure", 4.0),
    ("project_launch", 2.0),
    ("project_retirement", 2.0),
    ("incident_response", 1.0),
    ("region_drift", 0.5),
    ("mfa_lapse", 0.5),
)
REFERENCE_IDENTITIES = 500  # rates above are for this estate size; smaller estates scale linearly
HUMAN_SHARE = 0.76
NEW_SA_PER_MONTH = 2.5  # 2 launches × ~1.25 service accounts (SA_COUNT_WEIGHTS)
SEEDED_HUMANS = 8  # decoys.py: 2 break-glass + 4 contractors + 2 sanctioned admins
SEEDED_SERVICE_ACCOUNTS = 4  # decoys.py: 3 DR failover + the injection identity

# SPEC §4.2 secondary probabilities (fixed by the SPEC table)
P_ROLE_CHANGE_REVOKES_OLD = 0.25
P_DEPARTURE_REVOKED = 0.6
P_SA_SURVIVES_RETIREMENT = 0.8
P_INCIDENT_ADMIN_REMOVED = 0.3

# Tuned on seed 42 until test_estate_shape passed (40–70 positives), then frozen
P_REGION_DRIFT_HIGH_SENSITIVITY = 0.4
P_LATERAL_MOVE = 0.3
SA_COUNT_WEIGHTS: tuple[tuple[int, float], ...] = ((1, 0.8), (2, 0.15), (3, 0.05))
INCIDENT_HUMAN_WEIGHTS: tuple[tuple[int, float], ...] = ((1, 0.8), (2, 0.2))
INCIDENT_REMOVAL_DELAY_MONTHS = (1, 2)
MIN_RETIREMENT_AGE_MONTHS = 4
NEW_HIRE_LEVEL_WEIGHTS: tuple[tuple[str, float], ...] = (("member", 0.8), ("senior", 0.17), ("lead", 0.03))
LAUNCH_CLOUD_WEIGHTS: tuple[tuple[str, float], ...] = (("aws", 0.45), ("azure", 0.3), ("gcp", 0.25))
DRIFT_CLOUD_WEIGHTS: tuple[tuple[str, float], ...] = (("aws", 0.4), ("azure", 0.35), ("gcp", 0.25))
P_INITIAL_SA_IN_HOME_PROJECT = 0.85
CONTRACT_LENGTH_DAYS = (180, 540)

P_SA_BROAD_AT_LAUNCH = 0.08
P_SA_BROAD_INITIAL = 0.02
P_SA_KEY_MANUAL_ROTATION = 0.03  # keys that are never rotated (R6 bait)
P_HUMAN_HAS_ACCESS_KEY = 0.2
P_HUMAN_KEY_MANUAL_ROTATION = 0.03
KEY_ROTATION_DAYS = 90

ACTIVITY_PROFILES_HUMAN: tuple[tuple[str, float], ...] = (("active", 0.91), ("light", 0.08), ("dormant", 0.01))
ACTIVITY_PROFILES_SERVICE: tuple[tuple[str, float], ...] = (("active", 0.98), ("dormant", 0.02))
P_LIGHT_USER_ACTIVE_MONTH = 0.75
P_SERVICE_USED_HUMAN = 0.85
P_SERVICE_KEY_USED_IN_MONTH = 0.75
OPS_MEAN_HUMAN = 14
OPS_MEAN_SERVICE = 420
INITIAL_ON_LEAVE = 1
INITIAL_DELIVERY_PROJECTS = 26
DECOY_REVIEW_MONTHS_AHEAD = 4  # break-glass / sanctioned review_date = month_end(months + 4)
DR_EXPIRY_MONTHS_AHEAD = 12

# Citizen-data guardrail (AWS_CITIZEN_DENY). The holders are chosen without the RNG — the holders
# of `citizen-data-lake`, in identity-id order — and a deny grant is skipped when usage is
# simulated, so the guardrail draws nothing from the seeded stream and nothing downstream of it
# moves. Measured on seed 42 over six months: 151 of 158 estate files are byte-identical to the
# same estate generated with CITIZEN_DENY_IDENTITIES = 0. The seven that differ are the AWS
# exports carrying the attachment, the event log, the manifest, and two Azure files whose derived
# clock-times shift because two grant reference numbers were consumed. No identity, grant, scope,
# date or activity record changes. `tests/generator/test_citizen_guardrail.py` holds that line.
CITIZEN_DENY_FROM_MONTH = 4
CITIZEN_DENY_IDENTITIES = 2
# fmt: on
