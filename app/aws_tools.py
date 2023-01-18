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
import os, logging, urllib3, json, boto3

Logger = logging.getLogger()
LogLevel = os.environ.get('LOG_LEVEL', 'INFO')
Logger.setLevel(logging.DEBUG if LogLevel == 'DEBUG' else logging.INFO)

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
        self.event.get('ResourceProperties',{}).get('Path','NONE')
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