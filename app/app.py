#
# Copyright 2023 Full Duplex Media, LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os, logging, json

from aws_tools import CloudFormationResponse
from certificate_authority import CertificateAuthority

Logger = logging.getLogger()
if os.environ.get('LOG_LEVEL', 'INFO') == 'DEBUG':
  Logger.setLevel(logging.DEBUG)
else:
  Logger.setLevel(logging.INFO)
  logging.disable(logging.DEBUG)

SupportedResourceTypes = [
  'Custom::CertificateAuthority',
  'Custom::CertificateInternal',
  'Custom::CertificateExternal',
  'Custom::CertificateDiffieHellman',
  'Custom::CertificatePublic',
  'Custom::CertificateSSH',
  'Custom::CertificatePackage',
  'Custom::CertificateVpnGateway'
]

def handler(event, context):
  try:
    Logger.info(json.dumps(event))

    if event.get('ResourceType') not in SupportedResourceTypes:
      raise Exception(f'Unsupported ResourceType: {event.get("ResourceType")}')

    cfnResponse = CloudFormationResponse(event, context)
    ca = CertificateAuthority(event)

    responseData = None

    if event['RequestType'] in ['Create', 'Update']:
      responseData = ca.get()
    elif event['RequestType'] == 'Delete':
      ca.destroy()

    else:
      raise Exception(f'Unsupported RequestType: {event["RequestType"]}')

    cfnResponse.send(status='SUCCESS', data=responseData)

  except Exception as e:
    Logger.exception(e)
    cfnResponse.send(status='FAILED', reason=str(e))