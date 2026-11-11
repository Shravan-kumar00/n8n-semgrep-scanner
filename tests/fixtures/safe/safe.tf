resource "aws_db_instance" "orders" {
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
}
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["10.0.0.0/8"]
  }
}
