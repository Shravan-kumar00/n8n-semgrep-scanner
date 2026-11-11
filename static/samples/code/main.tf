# Sample - intentionally risky Terraform (for scanner demos)
provider "aws" {
  region     = "eu-west-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = "acme-reports"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "orders" {
  engine              = "postgres"
  username            = "admin"
  password            = "Terraform-DB-Pass1"
  publicly_accessible = true
  storage_encrypted   = false
}

data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
