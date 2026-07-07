{ pkgs }: "${pkgs.python3.withPackages (ps: [ ps.cryptography ])}/bin/python3 ${./vw-client.py}"
