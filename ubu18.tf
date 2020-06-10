provider "aws" {
  region = "eu-central-1"
}

resource "aws_security_group" "sg_ssh" {
  name        = "sg_ssh_ubu18"
  description = "Allow ssh traffic"

  ingress {
    description = "Allow ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }


  tags = {
    Aim     = "bastion"
    Project = "ansible"
    Env     = "dev"
  }
}

variable "ansible_user" {
  type    = string
  default = "ubuntu"
}

variable "private_key" {
  type    = string
  default = "$HOME/.ssh/id_rsa"
}

variable "setup_py" {
  type    = string
  default = <<-EOT
    Content-Type: multipart/mixed; boundary="//"
    MIME-Version: 1.0

    --//
    Content-Type: text/cloud-config; charset="us-ascii"
    MIME-Version: 1.0
    Content-Transfer-Encoding: 7bit
    Content-Disposition: attachment; filename="cloud-config.txt"
    
    #cloud-config
    cloud_final_modules:
    - [scripts-user, always]
    
    --//
    Content-Type: text/x-shellscript; charset="UTF-8"
    MIME-Version: 1.0
    Content-Disposition: attachment; filename="userdata.txt"
    
    #!/bin/bash
    apt update
    apt install -y python-virtualenv python-pip \
        build-essential libssl-dev libffi-dev python-dev nginx
    --//
  EOT
}

resource "aws_instance" "ubu18" {
  ami                         = "ami-00f69856ea899baec"
  instance_type               = "t2.micro"
  key_name                    = "dima_work"
  vpc_security_group_ids      = ["${aws_security_group.sg_ssh.id}"]
  associate_public_ip_address = true
  user_data                   = "${var.setup_py}"
  root_block_device {
    # device_name = "/dev/sda1"
    delete_on_termination = true
  }
  provisioner "local-exec" {
    command = <<EOT
      sleep 30;
	  >invent1.yaml;
	  echo "ubu18:" | tee -a invent1.yaml;
	  echo "  hosts:" | tee -a invent1.yaml;
	  echo "    ${self.public_ip}:" | tee -a invent1.yaml;
          echo "      ansible_user: ${var.ansible_user}" | tee -a invent1.yaml;
          echo "      ansible_ssh_private_key_file: ${var.private_key}" | tee -a invent1.yaml;
      export ANSIBLE_HOST_KEY_CHECKING=False;
	  ansible-playbook -u ${var.ansible_user} --private-key ${var.private_key} -i invent1.yaml playbooks/install_ansible.yaml
    EOT
  }
}

output "public-ip" {
  value = "${aws_instance.ubu18.public_ip}"
}
