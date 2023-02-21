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
import os, logging, re, json
import boto3
import urllib3

Logger = logging.getLogger()
if os.environ.get('LOG_LEVEL', 'INFO') == 'DEBUG':
  Logger.setLevel(logging.DEBUG)
else:
  Logger.setLevel(logging.INFO)
  logging.disable(logging.DEBUG)

class CloudFormationStack:

  def __init__(self, event):
    stackId = event['StackId']

    client = boto3.client('cloudformation')
    response = client.describe_stacks(
      StackName = stackId
    )

    stack = response['Stacks'][0]

    self.name = re.sub(r'^.+-pp-', '', stack['StackName'])

    stack['Tags'] = {k:v for t in stack['Tags'] for k,v in [t.values()]}

    tag = 'aws:servicecatalog:provisionedProductArn'
    self.label = stack['Tags'][tag].split('/')[1]


class CloudFormationResponse:

  def __init__(self, event, context):
    self.event = event
    self.context = context
    self.http = urllib3.PoolManager()

  def send(self,
    status = 'FAILED',
    reason = None,
    data = None,
    physicalResourceId = None,
    noEcho = True
  ):
    url = self.event['ResponseURL']

    if physicalResourceId is None:
      physicalResourceId = self.event.get(
        'PhysicalResourceId',
        self.event.get('ResourceProperties',{}).get('Name','NONE')
      )

    body = dict(
      Status = status,
      PhysicalResourceId = physicalResourceId,
      StackId = self.event['StackId'],
      RequestId = self.event['RequestId'],
      LogicalResourceId = self.event['LogicalResourceId'],
      NoEcho = noEcho,
      Data = data
    )

    if status == 'FAILED':
      if reason is None:
        cloudwatch = self.context['log_stream_name']
        reason = f'Unspecified error, check CloudWatch Logs: {cloudwatch}'
      body['Reason'] = reason    

    body = json.dumps(body)

    headers = {
      'content-type' : '',
      'content-length' : str(len(body))
    }

    try:
      self.http.request('PUT', url, headers=headers, body=body)

    except Exception as e:
      Logger.error("send(...) failed executing http.request(...)")
      Logger.error(body)
      raise Exception(e)