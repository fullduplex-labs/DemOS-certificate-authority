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
import os, logging, datetime, shutil, tarfile
from subprocess import Popen, PIPE

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dh
import boto3
import certbot.main
import jinja2

Logger = logging.getLogger()
if os.environ.get('LOG_LEVEL', 'INFO') == 'DEBUG':
  Logger.setLevel(logging.DEBUG)
else:
  # Workaround: certbot aggro DEBUG logs
  Logger.setLevel(logging.INFO)
  logging.disable(logging.DEBUG)

Env = dict(
  Namespace = os.environ['Namespace'],
  Project = os.environ['Project'],
  Domain = os.environ['Domain'],
  PrivateDomain = os.environ['PrivateDomain'],
  KeyAlias = os.environ.get('KeyAlias', 'alias/aws/ssm'),
  CertbotEmail = os.environ['CertbotEmail'],
  CertbotStaging = os.environ['CertbotStaging'],
  Bucket = os.environ['Bucket'],
  BucketVpnGateway = os.environ['BucketVpnGateway']
)

AwsSsm = boto3.client('ssm')
AwsS3 = boto3.client('s3')
AwsEc2 = boto3.client('ec2')
AwsRegion = boto3.session.Session().region_name

class CertificateAuthority:

  def __init__(self, event):
    self._StackId = event['StackId']
    self._ResourceType = event['ResourceType'].split('::Certificate')[1]
    self._Name = event['ResourceProperties']['Name']
    self._Label = event['ResourceProperties']['Label']

    self._path = (
      f'/{Env["Namespace"]}/{Env["Project"]}/{self._Name}'
      '/Certificates'
    )

    self._issuer = f'{Env["Namespace"]}-{Env["Project"]}'
    self._publicDomain = f'{self._Name}.{AwsRegion}.{Env["Domain"]}'

    self._workDir = f'/tmp/{self._Name}'
    os.makedirs(self._workDir, exist_ok = True)

    self._certificates = {}
    self._exports = {}

    self._keyPair = dict(
      Name = f'{Env["Namespace"]}-{Env["Project"]}-{self._Name}'.lower()
    )

    self._packageUid = 1000
    self._package = dict(
      Bucket = Env['Bucket'],
      Key = f'{self._Name}/certificates.tgz',
      Arn = f'arn:aws:s3:::{Env["Bucket"]}/{self._Name}/certificates.tgz',
      Url = f's3://{Env["Bucket"]}/{self._Name}/certificates.tgz'
    )

    self._vpnProfileToken = self._StackId.split('/')[-1]
    self._vpnProfileTemplate = 'templates/VpnGateway/profile.ovpn'
    self._vpnGateway = dict(
      Bucket = Env['BucketVpnGateway'],
      Key = f'{self._vpnProfileToken}/{self._publicDomain}.ovpn',
      Profile = (
        f'https://{Env["BucketVpnGateway"]}.s3.{AwsRegion}.amazonaws.com'
        f'/{self._vpnProfileToken}/{self._publicDomain}.ovpn'
      )
    )

  def get(self):
    if self._ResourceType == 'Package':
      return self.__get_package()
    else:
      return self.__get_certificate()

  def destroy(self):
    if self._ResourceType == 'Package':
      self.__destroy_package()
    else:
      self.__destroy_certificate()

  def __get_certificate(self):
    self.__fetch_exports()

    if self._exports.get(self._ResourceType):
      return self.__return_export()

    if self._ResourceType == 'Authority':
      self.__make_certificate_authority()
      self.__make_certificate_private(name = 'Internal')
      self.__make_certificate_private(name = 'External')

    elif self._ResourceType == 'DiffieHellman':
      self.__make_certificate_dhparams()

    elif self._ResourceType == 'SSH':
      self.__make_certificate_ssh()
      self.__save_keypair_ssh()

    elif self._ResourceType == 'Public':
      self.__make_certificate_public()

    elif self._ResourceType == 'VpnGateway':
      self.__make_certificate_vpn()
      self.__save_profile_vpn()

    return self.__return_export()

  def __get_package(self):
    if not self.__check_package():
      self.__fetch_exports()
      self.__save_package()

    return self._package

  def __destroy_certificate(self):
    self.__fetch_exports()

    if self._ResourceType == 'Authority':
      self.__delete_exports()

    elif self._ResourceType == 'Public':
      self.__revoke_certificate_public()

    elif self._ResourceType == 'SSH':
      self.__delete_keypair_ssh()

    elif self._ResourceType == 'VpnGateway':
      self.__delete_profile_vpn()

    else:
      self.__delete_export(self._ResourceType)

  def __destroy_package(self):
    if self.__check_package():
      AwsS3.delete_object(
        Bucket = self._package['Bucket'],
        Key = self._package['Key']
      )

  def __fetch_exports(self):
    response = AwsSsm.get_parameters_by_path(
      Path = self._path,
      Recursive = True,
      WithDecryption = True
    )

    if not response.get('Parameters'):
      Logger.info(f'No exported certificates were found')
      return False

    parameters = response['Parameters']

    while response.get('NextToken'):
      response = AwsSsm.get_parameters_by_path(
        Path = self._path,
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

  def __check_profile_vpn(self):
    response = AwsS3.list_objects_v2(
      Bucket = self._vpnGateway['Bucket'],
      Prefix = self._vpnGateway['Key'],
      MaxKeys = 1
    )

    return True if response.get('Contents') else False

  def __check_package(self):
    response = AwsS3.list_objects_v2(
      Bucket = self._package['Bucket'],
      Prefix = self._package['Key'],
      MaxKeys = 1
    )

    return True if response.get('Contents') else False

  def __make_certificate_authority(self, name='Authority'):
    Logger.info('Generating Certificate Authority')

    private_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 2048,
      backend = default_backend()
    )

    subject = issuer = x509.Name([
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._issuer),
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
    if name == 'Internal':
      domains = [Env['PrivateDomain'], f'*.{Env["PrivateDomain"]}']
    elif name == 'External':
      domains = [
        self._publicDomain,
        f'*.{self._publicDomain}',
        f'*.{Env["Domain"]}'
      ]
    else:
      raise Exception(f'Invalid private certificate name: {name}')

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
        key_size = 2048,
        backend = default_backend()
      )
    )

    self.__export_certificate(name)
    self.__save_export(name)

  def __make_certificate_ssh(self, name='SSH'):
    Logger.info(f'Generating certificate for SSH')

    private_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 2048,
      backend = default_backend()
    )

    self._certificates[name] = dict(
      Private = private_key,
      Public = private_key.public_key()
    )

    self.__export_certificate(name)
    self.__save_export(name)

  def __make_certificate_public(self, name='Public'):
    domains = [
      self._publicDomain,
      f'*.{self._publicDomain}',
      f'*.{Env["PrivateDomain"]}'
    ]

    Logger.info(f'Generating public certificate with domains:{domains}')

    folder = f'{self._workDir}/certbot'

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

    self._certificates[name] = dict(
      Key = private_key,
      Cert = certificate,
      Chain = chain
    )

    filename = 'certbot'
    with tarfile.open(f'{self._workDir}/{filename}.tgz', 'w:gz') as tar:
      tar.add(folder, arcname = filename)

    AwsS3.upload_file(
      Filename = f'{self._workDir}/{filename}.tgz',
      Bucket = Env['Bucket'],
      Key = f'{self._Name}/{filename}.tgz'
    )

    shutil.rmtree(folder)

    self.__export_certificate(name)
    self.__save_export(name)

  def __make_certificate_vpn(self, name='VpnGateway'):
    Logger.info('Generating OpenVPN Static TLS Key')

    (vpnKey, err) = Popen(
      '/usr/sbin/openvpn --genkey secret /dev/stdout',
      shell = True,
      stdout = PIPE
    ).communicate()

    if err:
      raise Exception(err)

    self._certificates[name] = dict(
      Key = vpnKey
    )

    self.__export_certificate(name)
    self.__save_export(name)

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

    elif name == 'SSH':
      self._exports[name] = dict(
        Private = self._certificates[name]['Private'].private_bytes(
          encoding = serialization.Encoding.PEM,
          format = serialization.PrivateFormat.PKCS8,
          encryption_algorithm = serialization.NoEncryption()
        ).decode('utf-8'),
        Public = self._certificates[name]['Public'].public_bytes(
          encoding = serialization.Encoding.OpenSSH,
          format = serialization.PublicFormat.OpenSSH,
        ).decode('utf-8')
      )

    elif name  == 'Public':
      self._exports[name] = self._certificates[name]

    elif name == 'VpnGateway':
      self._exports[name] = dict(
        Key = self._certificates[name]['Key'].decode('utf-8')
      )

  def __save_export(self, name):
    for export in self._exports[name].keys():
      parameter = f'{self._path}/{name}/{export}'

      Logger.info(f'Saving certificate with parameter:[{parameter}]')
      AwsSsm.put_parameter(
        Name = f'{self._path}/{name}/{export}',
        Value = self._exports[name][export],
        Type = 'SecureString',
        KeyId = Env['KeyAlias'],
        Overwrite = True
      )

  def __return_export(self):
    Logger.info(f'Returning certificate:[{self._ResourceType}]')

    if self._ResourceType == 'Authority':
      return dict(
        Cert = self._exports['Authority']['Cert']
      )

    elif self._ResourceType == 'SSH':
      return self._exports['SSH'] | self._keyPair

    elif self._ResourceType == 'Public':
      return dict(
        Key = self._exports['Public']['Key'],
        Cert = self._exports['Public']['Cert']
      )

    elif self._ResourceType == 'VpnGateway':
      return dict(
        Profile = self._vpnGateway['Profile']
      )

    else:
      return self._exports.get(self._ResourceType)

  def __save_keypair_ssh(self):
    AwsEc2.import_key_pair(
      KeyName = self._keyPair['Name'],
      PublicKeyMaterial = self._exports['SSH']['Public']
    )

  def __save_profile_vpn(self):
    template = jinja2.Environment(
      loader = jinja2.FileSystemLoader(searchpath='./')
    ).get_template(self._vpnProfileTemplate)

    profile = template.render(dict(
      description = f'{self._Label} ({AwsRegion})',
      endpoint = self._publicDomain,
      authority = self._exports['Authority'],
      internal = self._exports['Internal'],
      vpnGateway = self._exports['VpnGateway']
    ))

    AwsS3.put_object(
      ACL = 'public-read',
      Body = profile,
      Bucket = self._vpnGateway['Bucket'],
      Key = self._vpnGateway['Key']
    )

  def __save_package(self):
    folderName = 'certificates'
    folder = f'{self._workDir}/{folderName}'
    tarFile = f'{folder}.tgz'

    for cert in self._exports:
      os.makedirs(f'{folder}/{cert}'.lower())
      for export in self._exports[cert]:
        exportFile = f'{folder}/{cert}/{export}.pem'.lower()
        print(
          self._exports[cert][export],
          file = open(exportFile, 'w', encoding = 'utf-8')
        )

    def set_tar_options(tarinfo):
      tarinfo.uid = tarinfo.gid = self._packageUid
      return tarinfo

    with tarfile.open(tarFile, 'w:gz') as tar:
      tar.add(folder, arcname=folderName, filter=set_tar_options)

    AwsS3.upload_file(
      Filename = tarFile,
      Bucket = self._package['Bucket'],
      Key = self._package['Key']
    )

    shutil.rmtree(folder)

  def __delete_keypair_ssh(self, name='SSH'):
    AwsEc2.delete_key_pair(
      KeyName = self._keyPair['Name']
    )
    self.__delete_export(name)

  def __revoke_certificate_public(self, name='Public'):
    Logger.info(f'Revoking public certificate for domain:{self._publicDomain}')

    folder = f'{self._workDir}/certbot'
    filename = 'certbot'

    AwsS3.download_file(
      Bucket = Env['Bucket'],
      Key = f'{self._Name}/{filename}.tgz',
      Filename = f'{self._workDir}/{filename}.tgz'
    )

    with tarfile.open(f'{self._workDir}/{filename}.tgz', 'r') as tar:
      tar.extractall(path = self._workDir)

    arguments = [
      'revoke',
      '-n',
      '--delete-after-revoke',
      '--cert-name', self._publicDomain,
      '--reason', 'cessationofoperation',
      '--config-dir', folder,
      '--work-dir', folder,
      '--logs-dir', folder
      ]

    if Env['CertbotStaging']:
      arguments.append('--test-cert')

    try:
      certbot.main.main(arguments)
    except Exception as e:
      Logger.error(str(e))

    AwsS3.delete_object(
      Bucket = Env['Bucket'],
      Key = f'{self._Name}/{filename}.tgz'
    )

    shutil.rmtree(folder)

    self.__delete_export(name)

  def __delete_profile_vpn(self, name='VpnGateway'):
    if self.__check_profile_vpn():
      AwsS3.delete_object(
        Bucket = self._vpnGateway['Bucket'],
        Key = self._vpnGateway['Key']
      )

    self.__delete_export(name)

  def __delete_export(self, name):
    if not self._exports.get(name):
      return

    for export in self._exports[name].keys():
      parameter = f'{self._path}/{name}/{export}'

      Logger.info(f'Destroying certificate with parameter:{parameter}')
      AwsSsm.delete_parameter(Name = parameter)

    self._exports.pop(name)

  def __delete_exports(self):
    parameters = []
    for cert in self._exports.keys():
      for export in self._exports[cert].keys():
        parameters.append(f'{self._path}/{cert}/{export}')

    if not parameters: return

    Logger.info(f'Destroying certificates with parameters:{parameters}')
    AwsSsm.delete_parameters(Names = parameters)
