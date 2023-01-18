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
LogLevel = os.environ.get('LOG_LEVEL', 'INFO')
Logger.setLevel(logging.DEBUG if LogLevel == 'DEBUG' else logging.INFO)

def handler(event, context):

  Logger.debug(json.dumps(event))
  Logger.debug(context)

  try:
    cfn_response = CloudFormationResponse(event, context)
    ca = CertificateAuthority(event)

    if event['RequestType'] == 'Create':
      data = ca.get_certificates()
      Logger.debug(data)
      cfn_response.send(status='SUCCESS', data=data)

    elif event['RequestType'] == 'Update':
      Logger.debug('UPDATE')

    elif event['RequestType'] == 'Delete':
      ca.destroy()
      cfn_response.send(status='SUCCESS')

    else:
      Logger.error(event)
      raise Exception(f'Unexpected RequestType: {event["RequestType"]}')

  except Exception as e:
    Logger.error(e)
    cfn_response.send(status='FAILED', reason=str(e))