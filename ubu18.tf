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
        build-essential libssl-dev libffi-dev python-dev
    --//
  EOT
}

resource "aws_instance" "ubu18" {
  ami                         = "ami-00f69856ea899baec"
  instance_type               = "t2.micro"
  key_name                    = "dima_work"
  vpc_security_group_ids      = ["${aws_security_group.sg_ssh.id}"]
  associate_public_ip_address = true
  user_data                   = var.setup_py
  root_block_device {
    # device_name = "/dev/sda1"
    delete_on_termination = true
  }
  provisioner "remote-exec" {
    connection {
      user = "ubuntu"
      host = "${self.public_ip}"
      private_key = "/home/d_khrapov/.ssh/id_rsa"
    }
    inline = [
      "git clone https://github.com/ansible/ansible.git",
      "cd ansible && pip install virtualenv && virtualenv --prompt '(ansible)' venv",
      ". /home/ubuntu/ansible/venv/bin/activate",
      "pip install -r requirements.txt"
    ]
  }
}

output "public-ip" {
  value = aws_instance.ubu18.public_ip
}
