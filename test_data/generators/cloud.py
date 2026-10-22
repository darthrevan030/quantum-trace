"""Generate the AWS-style cloud inventory fixtures in test_data/cloud/, then verify them.

Run from the repository root (needs the cloud scanner registered): uv run python -m test_data.generators.cloud
"""

import json

from test_data.generators.common import TEST_DATA, verify, write

FIXTURE = TEST_DATA / "cloud"
EXPECTED_COUNTS = {"CRITICAL": 6, "MEDIUM": 1, "SAFE": 2, "UNKNOWN": 1}
ACCOUNT, REGION = '123456789012', 'eu-west-1'


def inventories():
    kms = []
    for index, (alias, spec, usage) in enumerate([('legacy-signing', 'RSA_2048', 'SIGN_VERIFY'),
                                                 ('device-signing', 'ECC_NIST_P256', 'SIGN_VERIFY'),
                                                 ('symmetric-storage', 'SYMMETRIC_DEFAULT', 'ENCRYPT_DECRYPT'),
                                                 ('missing-key-spec', None, 'ENCRYPT_DECRYPT'),
                                                 ('pq-signing', 'ML_DSA_65', 'SIGN_VERIFY')], 1):
        key_id = f'00000000-0000-4000-8000-{index:012d}'
        key = {'KeyId': key_id, 'KeyArn': f'arn:aws:kms:{REGION}:{ACCOUNT}:key/{key_id}', 'AliasName': f'alias/demo-{alias}',
               'KeyUsage': usage, 'Origin': 'AWS_KMS',
               'KeyRotationStatus': 'ENABLED' if index == 3 else 'NOT_APPLICABLE'}
        if spec is not None:
            key['KeySpec'] = spec
        kms.append(key)
    certificates = [{'CertificateArn': f'arn:aws:acm:{REGION}:{ACCOUNT}:certificate/00000000-0000-4000-8000-{index:012d}',
                     'DomainName': domain, 'KeyAlgorithm': algorithm, 'SignatureAlgorithm': signature,
                     'Type': 'IMPORTED', 'Status': 'ISSUED'}
                    for index, domain, algorithm, signature in [(1, 'legacy.example.test', 'RSA_2048', 'SHA256WITHRSA'),
                                                                (2, 'portal.example.test', 'EC_prime256v1', 'ECDSA_WITH_SHA256')]]
    listeners = [{'ListenerArn': f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/demo/0000000000000001/{index:016d}',
                  'Protocol': protocol, 'Port': port, 'SslPolicy': policy,
                  'Certificates': [{'CertificateArn': certificates[0]['CertificateArn']}] if protocol == 'HTTPS' else []}
                 for index, protocol, port, policy in [(1, 'HTTPS', 443, 'ELBSecurityPolicy-TLS13-1-2-2021-06'),
                                                       (2, 'HTTPS', 8443, 'ELBSecurityPolicy-2016-08'), (3, 'HTTP', 80, None),
                                                       (4, 'HTTPS', 9443, 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09')]]
    return {'kms_key_inventory.json': {'Keys': kms}, 'acm_certificates.json': {'Certificates': certificates},
            'load_balancer_listeners.json': {'LoadBalancers': [{'LoadBalancerName': 'demo-edge', 'Listeners': listeners}]}}


def generate(target=FIXTURE):
    for name, data in inventories().items():
        write(target, name, json.dumps({'Account': ACCOUNT, 'Region': REGION, 'Synthetic': True, **data}, indent=2) + '\n')


if __name__ == "__main__":
    generate()
    verify("cloud", FIXTURE, EXPECTED_COUNTS)
