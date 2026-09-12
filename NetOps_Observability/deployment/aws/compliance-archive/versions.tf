##############################################################################
# Pinned, like every other tool in this repository (CLAUDE.md §6): an unpinned
# provider can change what `apply` does with no change of evidence, and this
# module writes the configuration a licence obligation rests on.
##############################################################################

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }
}

provider "aws" {
  region = var.aws_region

  # NO credentials here, ever. The provider takes them from the environment,
  # from an SSO profile, or from an assumed role. A key in a .tf file is a key
  # in git.
  default_tags {
    tags = var.tags
  }
}
