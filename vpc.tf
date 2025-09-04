module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.0.1"

  name                          = var.vpc_config.name
  cidr                          = var.vpc_config.cidr
  azs                           = var.vpc_config.azs
  public_subnets                = var.vpc_config.public_subnets
  private_subnets               = var.vpc_config.private_subnets
  default_security_group_egress = var.vpc_config.default_security_group_egress
  enable_nat_gateway            = var.vpc_config.enable_nat
  single_nat_gateway            = var.vpc_config.enable_nat

  tags = var.tags
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "private_subnets" {
  value = module.vpc.private_subnets
}

output "default_security_group_id" {
  value = module.vpc.default_security_group_id
}

output "private_route_table_ids" {
  value = module.vpc.private_route_table_ids
}
