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
import os, logging, boto3, datetime, shutil

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dh

import certbot.main

Logger = logging.getLogger()
if os.environ.get('LOG_LEVEL', 'INFO') == 'DEBUG':
  Logger.setLevel(logging.DEBUG)
else: # Workaround: certbot aggro DEBUG logs
  Logger.setLevel(logging.INFO)
  logging.disable(logging.DEBUG)

Env = dict(
  Issuer = os.environ['Issuer'],
  PrivateDomain = os.environ['PrivateDomain'],
  PublicDomain = os.environ['PublicDomain'],
  KeyAlias = os.environ['KeyAlias'],
  CertbotEmail = os.environ['CertbotEmail'],
  CertbotStaging = os.environ['CertbotStaging']
)

AwsSsm = boto3.client('ssm')

class CertificateAuthority:

  def __init__(self, event):
    self._ResourceType = event['ResourceType'].split('::Certificate')[1]
    self._Name = event['ResourceProperties']['Name']
    self._Path = event['ResourceProperties']['Path']

    self._publicDomain = f'{self._Name}.{Env["PublicDomain"]}'

    self._certificates = {}
    self._exports = {}

    self.__get_exports()

  def get_certificate(self):
    if self._exports.get(self._ResourceType):
      return self.__export()

    if self._ResourceType == 'Authority':
      self.__make_certificate_authority()
      self.__make_certificate_private(name = 'Internal')
      self.__make_certificate_private(name = 'External')

    elif self._ResourceType == 'DiffieHellman':
      self.__make_certificate_dhparams()

    elif self._ResourceType == 'Public':
      self.__make_certificate_public()

    else:
      raise Exception(f'Missing certificate: {self._ResourceType}')

    return self.__export()

  def destroy(self):
    if self._ResourceType == 'Authority':
      self.__delete_exports()

    elif self._ResourceType == 'Public':
      self.__revoke_certificate_public()

  def __get_exports(self):
    response = AwsSsm.get_parameters_by_path(
      Path = self._Path,
      Recursive = True,
      WithDecryption = True
    )

    if not len(response.get('Parameters', [])):
      Logger.info(f'No exported certificates were found')
      return False

    parameters = response['Parameters']

    while response.get('NextToken'):
      response = AwsSsm.get_parameters_by_path(
        Path = self._Path,
        Recursive = True,
        WithDecryption = True,
        NextToken = response['NextToken']
      )
      parameters += response['Parameters']

    Logger.info(f'Found ({len(parameters)}) exported certificates')

    for parameter in parameters:
      cert = parameter['Name'].split('/')[-2]
      export = parameter['Name'].split('/')[-1]

      if self._exports.get(cert) is None:
        self._exports[cert] = dict()

      self._exports[cert][export] = parameter['Value']

    return True

  def __make_certificate_authority(self, name='Authority'):
    Logger.info('Generating Certificate Authority')

    private_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 2048,
      backend = default_backend()
    )

    subject = issuer = x509.Name([
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, Env['Issuer']),
      x509.NameAttribute(NameOID.COMMON_NAME, self._publicDomain)
    ])

    certificate = x509.CertificateBuilder().subject_name(
      subject
    ).issuer_name(
      issuer
    ).public_key(
      private_key.public_key()
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      datetime.datetime.utcnow()
    ).not_valid_after(
      datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
      x509.BasicConstraints(ca=True, path_length=None),
      critical = True
    ).sign(private_key, hashes.SHA256(), default_backend())

    self._certificates[name] = dict(
      Key = private_key,
      Cert = certificate
    )

    self.__export_certificate(name)
    self.__save_export(name)

  def __make_certificate_private(self, name):
    if name == 'External':
      domains = [self._publicDomain, f'*.{self._publicDomain}']
    else:
      domains = [Env['PrivateDomain'], f'*.{Env["PrivateDomain"]}']

    Logger.info(f'Generating private cert:[{name}] with domains:{domains}')

    private_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 2048,
      backend = default_backend()
    )

    certificate = x509.CertificateBuilder().subject_name(
      x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains.pop(0))
      ])
    ).issuer_name(
      self._certificates['Authority']['Cert'].issuer
    ).public_key(
      private_key.public_key()
    ).serial_number(
      x509.random_serial_number()
    ).not_valid_before(
      datetime.datetime.utcnow()
    ).not_valid_after(
      datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )
    
    if len(domains):
      subjectAltNames = []
      for domain in domains: subjectAltNames.append(x509.DNSName(domain))
      subjectAltNames = x509.SubjectAlternativeName(subjectAltNames)
      certificate.add_extension(subjectAltNames, critical=False)

    certificate = certificate.sign(
      self._certificates['Authority']['Key'],
      hashes.SHA256(),
      default_backend()
    )

    self._certificates[name] = dict(
      Key = private_key,
      Cert = certificate
    )

    self.__export_certificate(name)
    self.__save_export(name)

  def __make_certificate_dhparams(self, name='DiffieHellman'):
    Logger.info('Generating Diffie-Hellman Parameters')

    self._certificates[name] = dict(
      Params = dh.generate_parameters(
        generator = 2,
        key_size = 1024,
        backend = default_backend()
      )
    )

    self.__export_certificate(name)
    self.__save_export(name)

  def __make_certificate_public(self, name='Public'):
    domains = [
      self._publicDomain,
      f'*.{self._publicDomain}'
    ]

    Logger.info(f'Generating public certificate with domains:{domains}')

    folder = "/tmp/certbot"

    arguments = [
      'certonly',
      '--dns-route53',
      '-q',
      '-n',
      '--agree-tos',
      '-d', f'{",".join(domains)}',
      '--email', Env['CertbotEmail'],
      '--dns-route53-propagation-seconds', '30',
      '--config-dir', folder,
      '--work-dir', folder,
      '--logs-dir', folder
    ]

    if Env['CertbotStaging']:
      arguments.append('--test-cert')

    certbot.main.main(arguments)

    path = f'{folder}/live/{domains[0]}'
    with open(f'{path}/privkey.pem', 'r') as f: private_key = f.read()
    with open(f'{path}/cert.pem', 'r') as f: certificate = f.read()
    with open(f'{path}/chain.pem', 'r') as f: chain = f.read()

    path = f'{folder}/renewal'
    with open(f'{path}/{domains[0]}.conf', 'r') as f: conf = f.read()

    shutil.rmtree(folder)

    self._certificates[name] = dict(
      Key = private_key,
      Cert = certificate,
      Chain = chain,
      Conf = conf
    )

    self.__export_certificate(name)
    self.__save_export(name)

  def __revoke_certificate_public(self, name='Public'):
    domain = self._publicDomain
    Logger.info(f'Revoking public certificate for domain:{domain}')

    folder = "/tmp/certbot"

    # path = f'{folder}/live/{domain}'
    # os.makedirs(path)

    # with open(f'{path}/privkey.pem', 'wt', encoding='utf-8') as f:
    #   f.write(self._exports[name]['Key'])
    # with open(f'{path}/cert.pem', 'wt', encoding='utf-8') as f:
    #   f.write(self._exports[name]['Cert'])
    # with open(f'{path}/chain.pem', 'wt', encoding='utf-8') as f:
    #   f.write(self._exports[name]['Chain'])

    import json
    Logger.info(json.dumps(self._exports))
    Logger.info(self._exports[name]['Conf'])

    path = f'{folder}/renewal'
    os.makedirs(path)
    with open(f'{path}/{domain}.conf', 'wt', encoding='utf-8') as f:
      f.write(self._exports[name]['Conf'])

    arguments = [
      'revoke',
      '--cert-name', f'{domain}',
      '--reason', 'cessationofoperation',
      '--config-dir', folder,
      '--work-dir', folder,
      '--logs-dir', folder
      ]

    if Env['CertbotStaging']:
      arguments.append('--test-cert')

    certbot.main.main(arguments)

    self.__delete_export(name)

  def __export_certificate(self, name):
    if name in ['Authority', 'Internal', 'External']:
      self._exports[name] = dict(
        Key = self._certificates[name]['Key'].private_bytes(
          encoding = serialization.Encoding.PEM,
          format = serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm = serialization.NoEncryption()
        ).decode('utf-8'),
        Cert = self._certificates[name]['Cert'].public_bytes(
          encoding = serialization.Encoding.PEM
        ).decode('utf-8')
      )

    elif name == 'DiffieHellman':
      self._exports[name] = dict(
        Params = self._certificates[name]['Params'].parameter_bytes(
          encoding = serialization.Encoding.PEM,
          format = serialization.ParameterFormat.PKCS3
        ).decode('utf-8')
      )

    elif name == 'Public':
      self._exports[name] = self._certificates[name]

  def __save_export(self, name):
    for export in self._exports[name].keys():
      parameter = f'{self._Path}/{name}/{export}'

      Logger.info(f'Saving certificate with parameter:[{parameter}]')
      AwsSsm.put_parameter(
        Name = f'{self._Path}/{name}/{export}',
        Value = self._exports[name][export],
        Type = 'SecureString',
        KeyId = Env['KeyAlias'],
        Overwrite = True
      )

  def __delete_export(self, name):
    for export in self._exports[name].keys():
      parameter = f'{self._Path}/{name}/{export}'

      Logger.info(f'Destroying certificate with parameter:{parameter}')
      AwsSsm.delete_parameter(Name = parameter)

    self._exports.pop(name)

  def __delete_exports(self):
    parameters = []
    for cert in self._exports.keys():
      for export in self._exports[cert].keys():
        parameters.append(f'{self._Path}/{cert}/{export}')

    if not parameters: return

    Logger.info(f'Destroying certificates with parameters:{parameters}')
    AwsSsm.delete_parameters(Names = parameters)

  def __export(self):
    Logger.info(f'Returning certificate:[{self._ResourceType}]')

    if self._ResourceType == 'Authority':
      return dict(
        Cert = self._exports['Authority']['Cert']
      )

    elif self._ResourceType == 'Public':
      return dict(
        Key = self._exports['Public']['Key'],
        Cert = self._exports['Public']['Cert']
      )

    else:
      return self._exports.get(self._ResourceType)