# syntax=docker/dockerfile:1.5-labs
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
ARG LAMBDA_RIE_SRC="https://github.com/aws"
ARG LAMBDA_RIE_REPO="aws-lambda-runtime-interface-emulator"
ARG LAMBDA_RIE_RELEASE="releases/latest/download/aws-lambda-rie"
ARG LAMBDA_RIE="${LAMBDA_RIE_SRC}/${LAMBDA_RIE_REPO}/${LAMBDA_RIE_RELEASE}"

ARG DEBIAN_FRONTEND="noninteractive"

FROM ubuntu:22.04 as build-image
ARG DEBIAN_FRONTEND
RUN bash <<EOF
apt-get update
apt-get install -y --no-install-recommends python3 python3-pip
rm -rf /var/lib/apt/lists/*
#
mkdir -p /app
#
# Install AWS Lambda Runtime Interface Client
pip install --target /app awslambdaric
#
# Install Additional Dependencies
pip install --target /app boto3 cryptography certbot-dns-route53 jinja2
EOF

ARG LAMBDA_RIE
ADD ${LAMBDA_RIE} /app/aws-lambda-rie
RUN chmod +x /app/aws-lambda-rie

FROM ubuntu:22.04
COPY --from=build-image /app /app

ARG DEBIAN_FRONTEND
RUN bash <<EOF
apt-get update
apt-get install -y --no-install-recommends \
  python3 python3-pip openvpn
rm -rf /var/lib/apt/lists/*
EOF

COPY app/ /app
RUN chmod +x /app/entrypoint.sh

ENV PYTHONPATH=/app
WORKDIR /app
ENTRYPOINT [ "/app/entrypoint.sh" ]
CMD [ "app.handler" ]