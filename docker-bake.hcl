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
  tags = ["docker.io/fullduplexlabs/aws-openvpn-gateway:${TAG}"]
  platforms = "${PLATFORMS}"
  no-cache = "${NO_CACHE}"
}