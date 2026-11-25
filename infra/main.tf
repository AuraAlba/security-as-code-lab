# Infraestructura de ejemplo. No ejecutar terraform apply.
# Corregido: acceso público bloqueado y cifrado en reposo configurado.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_s3_bucket" "lab_data" {
  bucket = "security-as-code-lab-public-example-123456"
}

resource "aws_s3_bucket_acl" "lab_data_acl" {
  bucket     = aws_s3_bucket.lab_data.id
  acl        = "private"
  depends_on = [aws_s3_bucket_public_access_block.lab_data]
}

resource "aws_s3_bucket_public_access_block" "lab_data" {
  bucket                  = aws_s3_bucket.lab_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab_data_encryption" {
  bucket = aws_s3_bucket.lab_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}