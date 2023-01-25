variable "TAG" {
  default = "latest"
}

variable "PLATFORMS" {
  default = ["linux/arm64"]
}

variable "NO_CACHE" {
  default = false
}

target "default" {
  dockerfile = "Dockerfile"
  tags = ["docker.io/fullduplexlabs/aws-serverless-private-ca:${TAG}"]
  platforms = "${PLATFORMS}"
  no-cache = "${NO_CACHE}"
}