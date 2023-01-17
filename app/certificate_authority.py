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

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat import backends
from cryptography import x509
from cryptography.x509.oid import NameOID

Logger = logging.getLogger()
LogLevel = os.environ.get('LOG_LEVEL', 'INFO')
Logger.setLevel(logging.DEBUG if LogLevel == 'DEBUG' else logging.INFO)

Env = dict(
  KeyAlias = os.environ.get('KeyAlias')
)

AwsSsm = boto3.client('ssm')

class CertificateAuthority:

  def __init__(self, event):
    self.PublicDomain = event['ResourceProperties']['PublicDomain']
    self.PrivateDomain = event['ResourceProperties']['PrivateDomain']

    self.issuer = 'AWS Serverless Private CA'

    self.private_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 2048,
      backend = backends.default_backend()
    )
    self.public_key = self.private_key.public_key()

    today = datetime.date.today()
    valid_from = datetime.datetime.combine(
      today - datetime.timedelta(days=1),
      datetime.time()
    )
    valid_until = datetime.datetime.combine(
      today + datetime.timedelta(days=365),
      datetime.time()
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
      x509.NameAttribute(NameOID.COMMON_NAME, self.PublicDomain)
    ]))
    builder = builder.issuer_name(x509.Name([
      x509.NameAttribute(NameOID.COMMON_NAME, self.issuer)
    ]))
    builder = builder.not_valid_before(valid_from)
    builder = builder.not_valid_after(valid_until)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(self.public_key)
    builder = builder.add_extension(
      x509.BasicConstraints(ca=True, path_length=None),
      critical=True
    )

    certificate = builder.sign(
      private_key = self.private_key,
      algorithm = hashes.SHA256(),
      backend = backends.default_backend()
    )

    private_bytes = self.private_key.private_bytes(
      encoding = serialization.Encoding.PEM,
      format = serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm = serialization.NoEncryption()
    )

    public_bytes = certificate.public_bytes(
      encoding = serialization.Encoding.PEM
    )

    Logger.debug(private_bytes)
    Logger.debug(public_bytes)
    # openssl x509 -in ca.crt -text -noout

    # load_key = serialization.load_pem_private_key(
    #   private_bytes,
    #   password = None
    # )