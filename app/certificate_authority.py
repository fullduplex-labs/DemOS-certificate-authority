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
import os, logging, boto3, datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

Logger = logging.getLogger()
LogLevel = os.environ.get('LOG_LEVEL', 'INFO')
Logger.setLevel(logging.DEBUG if LogLevel == 'DEBUG' else logging.INFO)

Env = dict(
  KeyAlias = os.environ.get('KeyAlias')
)

AwsSsm = boto3.client('ssm')

class CertificateAuthority:

  def __init__(self, event):
    self._ResourceType = event['ResourceType'].split('::Certificate')[1]
    self._Path = event['ResourceProperties']['Path']

    self._Issuer = event['ResourceProperties'].get('Issuer')
    self._PrivateDomain = event['ResourceProperties'].get('PrivateDomain')
    self._PublicDomain = event['ResourceProperties'].get('PublicDomain')

    self._certificates = dict(
      Authority = dict(Key=None, Cert=None),
      Internal = dict(Key=None, Cert=None),
      External = dict(Key=None, Cert=None)
      # Public = None
    )

    self._exports = {}

  def get_certificate(self):
    if not self.__get_exports():
      self.__make_certificates()
      self.__export_certificates()
      self.__save_exports()

    return self._exports.get(self._ResourceType)

  def destroy(self):
    if self._ResourceType != 'Authority':
      return

    if self.__get_exports():
      self.__delete_exports()

  def __get_exports(self):
    response = AwsSsm.get_parameters_by_path(
      Path = self._Path,
      Recursive = True,
      WithDecryption = True
    )

    if not len(response.get('Parameters', [])):
      return False

    for parameter in response['Parameters']:
      cert = parameter['Name'].split('/')[-2]
      export = parameter['Name'].split('/')[-1]

      if self._exports.get(cert) is None:
        self._exports[cert] = dict()

      self._exports[cert][export] = parameter['Value']

    return True

  def __make_certificates(self):
    self._certificates['Authority'] = self.__make_certificate_authority()

    self._certificates['Internal'] = self.__make_certificate(
      domains = [self._PrivateDomain, f'*.{self._PrivateDomain}']
    )

    self._certificates['External'] = self.__make_certificate(
      domains = [self._PublicDomain, f'*.{self._PublicDomain}']
    )

  def __make_certificate_authority(self):
    private_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 2048,
      backend = default_backend()
    )

    subject = issuer = x509.Name([
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._Issuer),
      x509.NameAttribute(NameOID.COMMON_NAME, self._PublicDomain)
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

    return dict(Key=private_key, Cert=certificate)

  def __make_certificate(self, domains=[]):
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

    return dict(Key=private_key, Cert=certificate)

  def __export_certificates(self):
    for cert in self._certificates.keys():
      self._exports[cert] = dict(
        Key = self._certificates[cert]['Key'].private_bytes(
          encoding = serialization.Encoding.PEM,
          format = serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm = serialization.NoEncryption()
        ).decode('utf-8'),
        Cert = self._certificates[cert]['Cert'].public_bytes(
          encoding = serialization.Encoding.PEM
        ).decode('utf-8')
      )

  def __save_exports(self):
    for cert in self._exports.keys():
      for export in self._exports[cert].keys():
        AwsSsm.put_parameter(
          Name = f'{self._Path}/{cert}/{export}',
          Value = self._exports[cert][export],
          Type = 'SecureString',
          KeyId = Env['KeyAlias'],
          Overwrite = True
        )

  def __delete_exports(self):
    parameters = []
    for cert in self._exports.keys():
      for export in self._exports[cert].keys():
        parameters.append(f'{self._Path}/{cert}/{export}')

    AwsSsm.delete_parameters(Names=parameters)
