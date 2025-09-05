packer {
  required_version = ">= 1.9.0"
}

variable "image_name" { default = "pqc-calibrator-ubuntu-22" }

# NOTE: This is a skeleton. Replace the builder with your cloud/hypervisor target.
source "null" "ubuntu22" {}

build {
  name    = "pqc-calibrator-ubuntu22"
  sources = ["source.null.ubuntu22"]

  provisioner "shell" {
    scripts = [
      "scripts/install_tools.sh",
      "scripts/install_docker.sh",
      "scripts/install_oqs_openssl.sh",
    ]
  }
}
